// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! HTTP request handlers for the AVS API.
//!
//! Endpoints:
//! - `POST /attest` - Verify enclave and issue attestation token
//! - `GET /.well-known/jwks.json` - AVS signing public keys
//! - `GET /health` - Service health check

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;
use url::Url;
use utoipa::ToSchema;

use crate::config::Config;
use crate::error::AppError;
use crate::jwk::{Jwk, JwkSet};
use crate::ratls::RaTlsVerifier;

/// Shared application state for request handlers.
pub struct AppState {
    pub config: Config,
    pub encoding_key: EncodingKey,
    pub public_jwk: Jwk,
    pub ratls: Arc<std::sync::Mutex<RaTlsVerifier>>,
}

/// Request payload for /attest.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AttestRequest {
    /// URL of the enclave to attest (must be https).
    pub enclave_url: String,
    /// Optional nonce for replay protection.
    #[serde(default)]
    pub nonce: Option<String>,
    /// User identifier (from Clerk or other auth provider). Defaults to "anonymous".
    #[serde(default)]
    pub user_id: Option<String>,
    /// User role for RBAC. Defaults to "user".
    #[serde(default)]
    pub role: Option<String>,
}

/// Response payload for /attest.
#[derive(Debug, Serialize, ToSchema)]
pub struct AttestResponse {
    /// Signed JWT attestation token.
    pub token: String,
    /// Enclave's public encryption key.
    pub enclave_public_key: Jwk,
    /// Token expiration timestamp (Unix seconds).
    pub expires_at: u64,
}

/// JWT claims issued by the AVS and verified in the browser.
#[derive(Debug, Serialize, ToSchema)]
pub struct AttestationClaims {
    /// Issuer (AVS identifier).
    pub iss: String,
    /// Subject (user identifier).
    pub sub: String,
    /// Audience (target service).
    pub aud: String,
    /// Issued at (Unix timestamp).
    pub iat: u64,
    /// Expiration (Unix timestamp).
    pub exp: u64,
    /// User role for RBAC.
    pub role: String,
    /// Attested enclave URL.
    pub enclave_url: String,
    /// Enclave's public encryption key.
    pub enclave_public_key: Jwk,
    /// Enclave identity policy at time of attestation.
    pub policy: PolicyClaims,
    /// Optional nonce for replay protection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Enclave identity policy embedded into the attestation token.
#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyClaims {
    pub mrenclave: String,
    pub mrsigner: String,
    pub isv_prod_id: String,
    pub isv_svn: String,
}

/// Basic liveness endpoint for ops checks.
#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "Service is healthy")
    )
)]
pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

/// Publish AVS signing key(s) in JWK format for browser verification.
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    tag = "Auth",
    responses(
        (status = 200, description = "AVS public signing key set", body = JwkSet)
    )
)]
pub async fn jwks(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let body = JwkSet {
        keys: vec![state.public_jwk.clone()],
    };
    Json(body)
}

/// Attest an enclave via RA-TLS and issue a signed JWT for browser clients.
///
/// # Flow
///
/// 1. Validates the enclave URL and checks allowlist
/// 2. Connects to enclave over RA-TLS (verifies SGX quote)
/// 3. Fetches enclave's public encryption key
/// 4. Signs a JWT binding user identity, role, and enclave key
///
/// # Security
///
/// - Enclave identity is verified using DCAP attestation
/// - Token binds user to specific enclave measurement
/// - Short-lived tokens prevent long-term credential exposure
#[utoipa::path(
    post,
    path = "/v1/attest",
    tag = "Attestation",
    request_body = AttestRequest,
    responses(
        (status = 200, description = "Signed attestation token", body = AttestResponse),
        (status = 400, description = "Invalid request"),
        (status = 502, description = "Enclave attestation failed")
    )
)]
pub async fn attest(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, AppError> {
    // Parse and validate the enclave URL.
    let mut url = Url::parse(&request.enclave_url)?;
    if url.scheme() != "https" {
        return Err(AppError::EnclaveResponse(
            "enclave_url must be https".to_string(),
        ));
    }

    // Enforce an optional allowlist to avoid SSRF and unsafe targets.
    let host = url
        .host_str()
        .ok_or_else(|| AppError::EnclaveResponse("enclave_url host missing".to_string()))?
        .to_string();

    if !state.config.allowed_enclave_hosts.is_empty()
        && !is_host_allowed(
            &host,
            url.port_or_known_default(),
            &state.config.allowed_enclave_hosts,
        )
    {
        return Err(AppError::EnclaveResponse(
            "enclave host not allowed".to_string(),
        ));
    }

    url.set_path("/v1/attestation/public-key");
    url.set_query(None);

    // RA-TLS handshake to the enclave and fetch its public encryption key.
    let ratls = state.ratls.clone();
    let enclave_public_key =
        tokio::task::spawn_blocking(move || fetch_enclave_public_key(url, ratls)).await??;

    // Create signed JWT with a short lifetime.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| AppError::Config(format!("clock error: {err}")))?;
    let iat = now.as_secs();
    let exp = iat + state.config.token_ttl_secs;

    let claims = AttestationClaims {
        iss: state.config.issuer.clone(),
        sub: request.user_id.unwrap_or_else(|| "anonymous".to_string()),
        aud: "relational-sdk".to_string(),
        iat,
        exp,
        role: request.role.unwrap_or_else(|| "user".to_string()),
        enclave_url: request.enclave_url,
        enclave_public_key: enclave_public_key.clone(),
        policy: PolicyClaims {
            mrenclave: state.config.expected_mrenclave.clone(),
            mrsigner: state.config.expected_mrsigner.clone(),
            isv_prod_id: state.config.expected_isv_prod_id.clone(),
            isv_svn: state.config.expected_isv_svn.clone(),
        },
        nonce: request.nonce,
    };

    let token = encode(&Header::new(Algorithm::ES256), &claims, &state.encoding_key)?;

    Ok(Json(AttestResponse {
        token,
        enclave_public_key,
        expires_at: exp,
    }))
}

/// Allowlist helper: match exact host or host:port.
fn is_host_allowed(host: &str, port: Option<u16>, allowlist: &[String]) -> bool {
    let host_only = host.to_string();
    let host_with_port = port.map(|value| format!("{host}:{value}"));
    allowlist.iter().any(|allowed| {
        if allowed == &host_only {
            return true;
        }
        if let Some(host_port) = &host_with_port {
            if allowed == host_port {
                return true;
            }
        }
        false
    })
}

/// Fetch the enclave's public encryption key over RA-TLS.
fn fetch_enclave_public_key(
    url: Url,
    ratls: Arc<std::sync::Mutex<RaTlsVerifier>>,
) -> Result<Jwk, AppError> {
    let host = url
        .host_str()
        .ok_or_else(|| AppError::EnclaveResponse("enclave_url host missing".to_string()))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| AppError::EnclaveResponse("enclave_url port missing".to_string()))?;
    let path = url.path().to_string();
    let host_header = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };

    let address = format!("{host}:{port}");
    let stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(15)))?;

    // Configure OpenSSL client and attach the RA-TLS verifier callback.
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_verify(SslVerifyMode::PEER);

    let ratls_clone = ratls.clone();
    builder.set_verify_callback(SslVerifyMode::PEER, move |_preverify_ok, x509_ctx| {
        if x509_ctx.error_depth() != 0 {
            return true;
        }
        let cert = match x509_ctx.current_cert() {
            Some(cert) => cert,
            None => return false,
        };
        let der = match cert.to_der() {
            Ok(der) => der,
            Err(_) => return false,
        };
        let guard = match ratls_clone.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        match guard.verify_der(&der) {
            Ok(_) => true,
            Err(err) => {
                warn!(error = %err, "RA-TLS verification failed");
                false
            }
        }
    });

    let connector = builder.build();
    // Perform the TLS handshake (RA-TLS verification happens above).
    let mut tls_stream = connector
        .connect(&host, stream)
        .map_err(|err| AppError::EnclaveResponse(format!("TLS handshake failed: {err}")))?;

    // Minimal HTTP/1.1 request to avoid extra client dependencies.
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    tls_stream.write_all(request.as_bytes())?;
    tls_stream.flush()?;

    let mut response_bytes = Vec::new();
    tls_stream.read_to_end(&mut response_bytes)?;

    // Parse HTTP response to locate the JSON body.
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    let status = response.parse(&response_bytes)?;
    let header_len = match status {
        httparse::Status::Complete(len) => len,
        httparse::Status::Partial => {
            return Err(AppError::EnclaveResponse(
                "incomplete HTTP response".to_string(),
            ))
        }
    };

    let status_code = response.code.unwrap_or(0);
    if status_code != 200 {
        return Err(AppError::EnclaveResponse(format!(
            "enclave returned status {status_code}"
        )));
    }

    let body = &response_bytes[header_len..];
    let jwk: Jwk = serde_json::from_slice(body)?;
    Ok(jwk)
}
