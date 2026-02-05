// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Error types for the Attestation Verification Service.
//!
//! All errors are mapped to appropriate HTTP status codes for API responses.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use thiserror::Error;

/// Errors mapped to HTTP responses and logs.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("invalid enclave URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("PKCS8 error: {0}")]
    Pkcs8(#[from] p256::pkcs8::Error),
    #[error("HTTP parsing error: {0}")]
    HttpParse(#[from] httparse::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("attestation failed: {0}")]
    Attestation(String),
    #[error("enclave response error: {0}")]
    EnclaveResponse(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
}

impl IntoResponse for AppError {
    /// Convert internal errors into JSON responses with useful status codes.
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Url(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Attestation(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::EnclaveResponse(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = Json(serde_json::json!({ "error": message }));
        (status, body).into_response()
    }
}
