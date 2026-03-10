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
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
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
    /// Convert internal errors into sanitized JSON responses.
    ///
    /// Internal error details are logged server-side only. Clients receive generic
    /// messages that do not leak implementation details (file paths, library versions,
    /// OpenSSL internals, etc.).
    fn into_response(self) -> Response {
        // Always log the full error with details for server-side debugging.
        tracing::error!(error = %self, "Request failed");

        let (status, message) = match &self {
            // Client errors — safe to surface the message
            AppError::Url(_) => (StatusCode::BAD_REQUEST, "Invalid enclave URL".to_string()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::Attestation(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            AppError::EnclaveResponse(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            // Server errors — return generic message; details are in the log
            AppError::Config(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal configuration error".to_string(),
            ),
            AppError::Json(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal serialization error".to_string(),
            ),
            AppError::Jwt(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Token signing error".to_string(),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        let body = Json(serde_json::json!({ "error": message }));
        (status, body).into_response()
    }
}
