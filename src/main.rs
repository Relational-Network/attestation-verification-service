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

mod config;
mod error;
mod handlers;
mod jwk;
mod ratls;

use axum::{routing::get, routing::post, Router};
use dotenvy::dotenv;
use jsonwebtoken::EncodingKey;
use p256::pkcs8::DecodePrivateKey;
use p256::SecretKey;
use std::fs;
use std::sync::Arc;
use tracing::{error, info};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use config::Config;
use error::AppError;
use handlers::{attest, health, jwks, AppState, AttestRequest, AttestResponse, AttestationClaims, PolicyClaims};
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
    let signing_key_pem = fs::read(&config.signing_key_path)?;
    let encoding_key = EncodingKey::from_ec_pem(&signing_key_pem)?;
    let secret_key = SecretKey::from_pkcs8_pem(
        std::str::from_utf8(&signing_key_pem)
            .map_err(|err| AppError::Config(format!("invalid signing key encoding: {err}")))?,
    )?;
    let public_jwk = jwk_for_public_key(&secret_key.public_key(), "sig", "ES256");

    // RA-TLS verifier is not thread-safe; guard with a mutex.
    let ratls = Arc::new(std::sync::Mutex::new(RaTlsVerifier::new(
        &config.ratls_verify_lib,
    )?));

    // Shared state for HTTP handlers.
    let state = Arc::new(AppState {
        config,
        encoding_key,
        public_jwk,
        ratls,
    });

    // HTTP routing + Swagger UI for docs.
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/attest", post(attest))
        .route("/.well-known/jwks.json", get(jwks))
        .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .with_state(state.clone());

    // Bind and serve.
    let listener = tokio::net::TcpListener::bind(state.config.bind_addr)
        .await
        .map_err(|err| AppError::Config(format!("failed to bind: {err}")))?;
    info!(addr = %state.config.bind_addr, "AVS listening");

    axum::serve(listener, app)
        .await
        .map_err(|err| AppError::Config(format!("server error: {err}")))?;
    Ok(())
}
