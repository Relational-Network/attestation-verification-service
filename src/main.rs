// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Attestation Verification Service (AVS) for SGX RA-TLS (DCAP)
//!
//! This service bridges the gap between browser clients and SGX enclaves:
//!
//! 1. Receives attestation requests from browser clients
//! 2. Connects to the enclave using RA-TLS
//! 3. Verifies the SGX quote (DCAP attestation)
//! 4. Issues a signed JWT with the enclave's public key
//! 5. Browser verifies JWT using AVS's JWKS and trusts the enclave key
//!
//! # Architecture
//!
//! ```text
//! Browser → AVS (this service) → Enclave (RA-TLS)
//!              ↓
//!         JWT + enclave public key
//!              ↓
//! Browser → Enclave (HTTPS with encrypted payload)
//! ```
//!
//! # Running
//!
//! ```bash
//! # Generate signing key
//! openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out avs-signing-key.pem
//!
//! # Set required environment variables
//! export AVS_SIGNING_KEY_PATH=avs-signing-key.pem
//! export AVS_EXPECTED_MRSIGNER=<hex_mrsigner>
//!
//! # Run the service
//! cargo run
//! ```

mod clerk_auth;
mod config;
mod error;
mod handlers;
mod jwk;
mod ratls;

use axum::{extract::DefaultBodyLimit, routing::get, routing::post, Router};
use dotenvy::dotenv;
use jsonwebtoken::EncodingKey;
use p256::pkcs8::DecodePrivateKey;
use p256::SecretKey;
use rustls::ServerConfig;
use std::fs;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use config::Config;
use error::AppError;
use handlers::{
    attest, health, jwks, start_dcap_worker, AppState, AttestRequest, AttestResponse, AttestationClaims, PolicyClaims,
};
use jwk::{jwk_for_public_key, Jwk, JwkSet};
use ratls::RaTlsVerifier;

// ============================================================================
// OpenAPI Documentation
// ============================================================================

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Attestation Verification Service API",
        version = "0.1.0",
        description = "SGX RA-TLS attestation and JWT issuance for browser clients"
    ),
    paths(
        handlers::health,
        handlers::jwks,
        handlers::attest,
    ),
    components(schemas(
        Jwk,
        JwkSet,
        AttestRequest,
        AttestResponse,
        PolicyClaims,
        AttestationClaims,
    )),
    tags(
        (name = "Health", description = "Health check endpoints"),
        (name = "Auth", description = "Authentication and key endpoints"),
        (name = "Attestation", description = "Enclave attestation endpoints"),
    )
)]
struct ApiDoc;

// ============================================================================
// Application Entry Point
// ============================================================================

/// Entrypoint: initialize logging and fail fast on setup errors.
#[tokio::main(worker_threads = 4)]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if let Err(err) = run().await {
        error!(error = %err, "attestation verification service failed");
        std::process::exit(1);
    }
}

/// Service bootstrap: config, signing key, verifier, router, and listener.
async fn run() -> Result<(), AppError> {
    // Load local .env for developer convenience.
    dotenv().ok();

    // Load runtime config and configure RA-TLS verifier policy.
    let config = Config::from_env().map_err(AppError::Config)?;
    config.apply_ratls_env();

    // Load AVS signing key and expose public JWK to clients.
    if !config.signing_key_path.exists() {
        return Err(AppError::Config(format!(
            "signing key not found at {} (run ./secrets/generate-keys.sh)",
            config.signing_key_path.display()
        )));
    }
    let signing_key_pem = fs::read(&config.signing_key_path)?;
    let encoding_key = EncodingKey::from_ec_pem(&signing_key_pem)?;
    let secret_key = SecretKey::from_pkcs8_pem(
        std::str::from_utf8(&signing_key_pem)
            .map_err(|err| AppError::Config(format!("invalid signing key encoding: {err}")))?,
    )?;
    let mut public_jwk = jwk_for_public_key(&secret_key.public_key(), "sig", "ES256");
    // Override the kid with the configured signing_key_id so it matches JWT headers
    public_jwk.kid = config.signing_key_id.clone();

    // Start the DCAP worker thread for RA-TLS verification.
    let dcap_worker = start_dcap_worker(RaTlsVerifier::new(&config.ratls_verify_lib)?);

    // Shared state for HTTP handlers.
    let state = Arc::new(AppState {
        config: config.clone(),
        encoding_key,
        public_jwk,
        dcap_worker,
    });

    // HTTP routing + Swagger UI for docs.
    // Body limit: 1MB max to prevent DoS
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/attest", post(attest))
        .route("/.well-known/jwks.json", get(jwks))
        .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .layer(DefaultBodyLimit::max(1024 * 1024)) // 1MB max request body
        .with_state(state.clone());

    // Bind listener.
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .map_err(|err| AppError::Config(format!("failed to bind: {err}")))?;

    // Start server with optional TLS.
    if config.tls_enabled() {
        let tls_config = load_tls_config(&config)?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        info!(addr = %config.bind_addr, "AVS listening (HTTPS)");
        serve_tls(listener, app, acceptor).await?;
    } else {
        info!(addr = %config.bind_addr, "AVS listening (HTTP)");
        axum::serve(listener, app)
            .await
            .map_err(|err| AppError::Config(format!("server error: {err}")))?;
    }

    Ok(())
}

/// Load TLS configuration from certificate and key files.
/// Uses pem crate instead of rustls-pemfile (which is unmaintained).
fn load_tls_config(config: &Config) -> Result<ServerConfig, AppError> {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    let cert_path = config.tls_cert_path.as_ref().ok_or_else(|| {
        AppError::Config("TLS cert path required when TLS is enabled".to_string())
    })?;
    let key_path = config
        .tls_key_path
        .as_ref()
        .ok_or_else(|| AppError::Config("TLS key path required when TLS is enabled".to_string()))?;

    // Load certificate chain using pem crate
    let cert_pem = fs::read_to_string(cert_path)
        .map_err(|e| AppError::Config(format!("failed to read cert file: {e}")))?;
    let certs: Vec<CertificateDer<'static>> = pem::parse_many(&cert_pem)
        .map_err(|e| AppError::Config(format!("failed to parse certs: {e}")))?
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| CertificateDer::from(p.into_contents()))
        .collect();

    if certs.is_empty() {
        return Err(AppError::Config(
            "no certificates found in file".to_string(),
        ));
    }

    // Load private key using pem crate
    let key_pem = fs::read_to_string(key_path)
        .map_err(|e| AppError::Config(format!("failed to read key file: {e}")))?;
    let key_parsed = pem::parse_many(&key_pem)
        .map_err(|e| AppError::Config(format!("failed to parse key: {e}")))?
        .into_iter()
        .find(|p| {
            p.tag() == "PRIVATE KEY" || p.tag() == "RSA PRIVATE KEY" || p.tag() == "EC PRIVATE KEY"
        })
        .ok_or_else(|| AppError::Config("no private key found in file".to_string()))?;

    let key = PrivateKeyDer::try_from(key_parsed.into_contents())
        .map_err(|e| AppError::Config(format!("failed to parse private key: {e}")))?;

    // Build TLS config
    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| AppError::Config(format!("TLS config error: {e}")))?;

    Ok(tls_config)
}

/// Serve HTTPS requests using TLS acceptor.
async fn serve_tls(
    listener: TcpListener,
    app: Router,
    acceptor: TlsAcceptor,
) -> Result<(), AppError> {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tower_service::Service;

    loop {
        let (stream, _addr) = listener
            .accept()
            .await
            .map_err(|e| AppError::Config(format!("accept error: {e}")))?;

        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    let hyper_svc = service_fn(move |req| {
                        let mut svc = app.clone();
                        async move { svc.call(req).await }
                    });
                    if let Err(e) = http1::Builder::new().serve_connection(io, hyper_svc).await {
                        tracing::debug!("connection error: {e}");
                    }
                }
                Err(e) => {
                    tracing::debug!("TLS handshake error: {e}");
                }
            }
        });
    }
}
