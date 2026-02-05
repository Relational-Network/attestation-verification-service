// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! HTTP request handlers for the AVS API.
//!
//! Endpoints:
//! - `POST /attest` - Verify enclave and issue attestation token
//! - `GET /.well-known/jwks.json` - AVS signing public keys
//! - `GET /health` - Service health check

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use tokio::sync::{mpsc, oneshot};
use tokio::time;
use url::Url;
use utoipa::ToSchema;

use crate::clerk_auth::ClerkAuth;
use crate::config::Config;
use crate::error::AppError;
use crate::jwk::{Jwk, JwkSet};
use crate::ratls::RaTlsVerifier;

// DCAP verification is blocking and uses FFI; keep it off the async runtime.
// We run it in a single dedicated worker thread to avoid DCAP thread-local
// teardown issues observed in Docker.

struct DcapRequest {
    url: Url,
    response_tx: oneshot::Sender<Result<Jwk, String>>,
}

pub struct DcapWorker {
    tx: mpsc::Sender<DcapRequest>,
}

pub fn start_dcap_worker(ratls: RaTlsVerifier) -> DcapWorker {
    let (tx, mut rx) = mpsc::channel::<DcapRequest>(16);

    std::thread::Builder::new()
        .name("dcap-worker".to_string())
        .spawn(move || {
            while let Some(request) = rx.blocking_recv() {
                let result = fetch_enclave_public_key_sync(request.url, &ratls)
                    .map_err(|e| e.to_string());
                let _ = request.response_tx.send(result);
            }
        })
        .expect("Failed to spawn DCAP worker thread");

    DcapWorker { tx }
}

impl DcapWorker {
    pub async fn verify(&self, url: Url) -> Result<Jwk, AppError> {
        let (response_tx, response_rx) = oneshot::channel();
        let request = DcapRequest { url, response_tx };

        self.tx.send(request).await.map_err(|_| {
            AppError::EnclaveResponse("DCAP worker thread died".to_string())
        })?;

        let result = time::timeout(Duration::from_secs(30), response_rx)
            .await
            .map_err(|_| AppError::EnclaveResponse("DCAP verification timeout".to_string()))?;

        match result {
            Ok(Ok(jwk)) => Ok(jwk),
            Ok(Err(err)) => Err(AppError::EnclaveResponse(err)),
            Err(_) => Err(AppError::EnclaveResponse(
                "DCAP worker dropped response".to_string(),
            )),
        }
    }
}

/// Shared application state for request handlers.
pub struct AppState {
    pub config: Config,
    pub encoding_key: EncodingKey,
    pub public_jwk: Jwk,
    pub dcap_worker: DcapWorker,
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
    clerk_auth: ClerkAuth,
    Json(request): Json<AttestRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Extract user info from Clerk auth (if available)
    let (user_id, role) = match clerk_auth.0 {
        Some(user) => {
            // User authenticated via Clerk - use their ID
            // Role is "user" by default; admin role should be verified by dashboard
            (user.user_id, user.role)
        }
        None => {
            // No Clerk auth - check if CLERK_JWKS_URL is configured
            if state.config.clerk_jwks_url.is_some() {
                // Auth is required but not provided
                return Err(AppError::Unauthorized(
                    "Authentication required".to_string(),
                ));
            }
            // Backward compatibility: allow anonymous if Clerk not configured
            warn!("Anonymous attestation request (CLERK_JWKS_URL not configured)");
            (
                request.user_id.unwrap_or_else(|| "anonymous".to_string()),
                request.role.unwrap_or_else(|| "user".to_string()),
            )
        }
    };

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

    let enclave_public_key = state.dcap_worker.verify(url.clone()).await?;

    // Create signed JWT with a short lifetime.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| AppError::Config(format!("clock error: {err}")))?;
    let iat = now.as_secs();
    let exp = iat + state.config.token_ttl_secs;

    let claims = AttestationClaims {
        iss: state.config.issuer.clone(),
        sub: user_id, // Use verified user_id from Clerk (or anonymous if not configured)
        aud: "relational-sdk".to_string(),
        iat,
        exp,
        role, // Use verified role from Clerk (or default if not configured)
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

    // Create JWT header with kid for key rotation support
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(state.config.signing_key_id.clone());

    let token = encode(&header, &claims, &state.encoding_key)?;
    info!(user_id = %claims.sub, role = %claims.role, "Attestation request completed");

    // Return response with Cache-Control: no-store to prevent token caching.
    let response = (
        [(header::CACHE_CONTROL, "no-store")],
        Json(AttestResponse {
            token,
            enclave_public_key,
            expires_at: exp,
        }),
    );
    Ok(response)
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

/// Fetch the enclave's public encryption key over RA-TLS (runs in DCAP worker).
fn fetch_enclave_public_key_sync(url: Url, ratls: &RaTlsVerifier) -> Result<Jwk, AppError> {
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
    let socket_addr: std::net::SocketAddr = address
        .parse()
        .or_else(|_| {
            // DNS resolution needed
            use std::net::ToSocketAddrs;
            address.to_socket_addrs()?.next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "DNS lookup failed")
            })
        })
        .map_err(|e| AppError::EnclaveResponse(format!("invalid address {}: {}", address, e)))?;

    let stream = TcpStream::connect_timeout(&socket_addr, std::time::Duration::from_secs(10))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(15)))?;

    // Configure OpenSSL client for RA-TLS verification.
    // RA-TLS uses self-signed certificates with the SGX quote embedded in an X.509 extension.
    //
    // APPROACH: We disable OpenSSL's built-in verification (since RA-TLS certs are self-signed),
    // complete the TLS handshake, then extract the peer certificate and verify it using the
    // DCAP library AFTER the handshake. This avoids calling the DCAP verification library
    // from within the OpenSSL callback context (which causes segfaults).
    //
    // Security: The certificate is bound to the TLS session - we verify the same cert
    // that was used for key exchange, ensuring we're talking to the attested enclave.
    let mut builder = SslConnector::builder(SslMethod::tls())?;

    // Disable OpenSSL's certificate verification - we'll verify via DCAP after handshake
    // This is safe because:
    // 1. RA-TLS certificates are self-signed (would fail normal verification anyway)
    // 2. We verify the certificate's embedded SGX quote after handshake
    // 3. The certificate is cryptographically bound to the TLS session
    builder.set_verify(SslVerifyMode::NONE);

    let connector = builder.build();

    // Perform the TLS handshake
    let mut tls_stream = connector
        .connect(&host, stream)
        .map_err(|err| AppError::EnclaveResponse(format!("TLS handshake failed: {err}")))?;

    // Get the peer certificate from the completed TLS session
    let peer_cert = tls_stream
        .ssl()
        .peer_certificate()
        .ok_or_else(|| AppError::EnclaveResponse("No peer certificate received".to_string()))?;

    let cert_der = peer_cert
        .to_der()
        .map_err(|e| AppError::EnclaveResponse(format!("Failed to encode certificate: {e}")))?;

    // Now verify the certificate using RA-TLS (DCAP quote verification)
    // This happens OUTSIDE the OpenSSL handshake context
    ratls.verify_der(&cert_der).map_err(|err| {
        warn!(error = %err, "RA-TLS verification failed");
        AppError::EnclaveResponse(format!("RA-TLS attestation failed: {err}"))
    })?;

    // Minimal HTTP/1.1 request to avoid extra client dependencies.
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    tls_stream.write_all(request.as_bytes())?;
    tls_stream.flush()?;

    // Limit response size to prevent OOM from malicious enclave (64KB should be plenty for JWK)
    const MAX_RESPONSE_SIZE: u64 = 64 * 1024;
    let mut response_bytes = Vec::new();
    std::io::Read::take(&mut tls_stream, MAX_RESPONSE_SIZE).read_to_end(&mut response_bytes)?;

    // Parse HTTP response to locate the JSON body.
    let mut headers = [httparse::EMPTY_HEADER; 64]; // Increased from 32 for compatibility
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
