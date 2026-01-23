// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! JWK types and cryptographic key utilities.
//!
//! This module provides:
//! - JWK struct for representing EC public keys
//! - JWK set for JWKS endpoint
//! - Key derivation from P-256 public keys

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

/// JSON Web Key representation of an EC public key.
///
/// Used both for:
/// - Publishing AVS signing keys via `/.well-known/jwks.json`
/// - Representing enclave encryption keys in attestation tokens
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
    pub kid: String,
}

/// JWK set for publishing AVS signing public keys.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// Build a JWK from a P-256 public key.
///
/// The `kid` is derived from SHA-256 of the uncompressed point, encoded as
/// URL-safe base64 without padding.
///
/// # Arguments
///
/// * `public_key` - The P-256 public key to convert
/// * `use_` - Key usage: "sig" for signing, "enc" for encryption
/// * `alg` - Algorithm: "ES256" for signing, "ECDH-ES" for encryption
pub fn jwk_for_public_key(
    public_key: &p256::PublicKey,
    use_: &'static str,
    alg: &'static str,
) -> Jwk {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let encoded = public_key.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[1..33]);
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[33..65]);

    // Derive kid from public key hash for stable identification.
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let kid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

    Jwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x,
        y,
        use_: use_.to_string(),
        alg: alg.to_string(),
        kid,
    }
}
