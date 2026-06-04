// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Clerk JWT verification for incoming requests.
//!
//! Verifies Clerk-issued JWTs to authenticate users before issuing attestation tokens.
//! Uses OpenSSL for RS256 verification to avoid the vulnerable `rsa` crate (RUSTSEC-2023-0071).
//!
//! **SECURITY NOTE:** We use OpenSSL for RSA operations because the Rust `rsa` crate
//! has an unfixed Marvin Attack vulnerability. Never add dependencies on `rsa` crate.

use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openssl::{bn::BigNum, hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Verifier};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, warn};

use crate::error::AppError;

/// JWKS cache TTL (5 minutes)
const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

/// Public metadata from Clerk user profile
/// Configure in Clerk Dashboard: Users → Select User → Public Metadata
/// Example: { "role": "admin" }
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClerkPublicMetadata {
    /// User role for RBAC (e.g., "admin", "user", "read_only")
    #[serde(default)]
    pub role: Option<String>,
}

/// Clerk JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ClerkClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Issuer (Clerk instance URL)
    pub iss: String,
    /// Audience (may be array or string)
    #[serde(default)]
    pub aud: Option<serde_json::Value>,
    /// Issued at timestamp
    pub iat: u64,
    /// Expiration timestamp
    pub exp: u64,
    /// Authorized party (usually frontend URL)
    #[serde(default)]
    pub azp: Option<String>,
    /// Session ID
    #[serde(default)]
    pub sid: Option<String>,
    /// Public metadata from user profile (includes role)
    /// NOTE: Requires Clerk JWT template to include publicMetadata
    #[serde(default, rename = "publicMetadata")]
    pub public_metadata: Option<ClerkPublicMetadata>,
}

/// Authenticated user info extracted from Clerk JWT
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used for future features
pub struct AuthenticatedUser {
    pub user_id: String,
    pub role: String,
    pub email: Option<String>,
}

/// JWK structure for RS256 keys from Clerk
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields used for deserialization
pub struct ClerkJwk {
    pub kty: String,
    pub kid: String,
    pub alg: Option<String>,
    pub n: Option<String>, // RSA modulus (base64url)
    pub e: Option<String>, // RSA exponent (base64url)
    #[serde(rename = "use")]
    pub key_use: Option<String>,
}

/// JWKS response from Clerk
#[derive(Debug, Deserialize)]
pub struct ClerkJwks {
    pub keys: Vec<ClerkJwk>,
}

/// Cached RSA public key using OpenSSL
struct CachedRsaKey {
    /// OpenSSL PKey for RS256 verification
    pkey: PKey<openssl::pkey::Public>,
}

/// Cached JWKS with expiry
struct CachedJwks {
    keys: HashMap<String, CachedRsaKey>,
    fetched_at: Instant,
}

/// Global JWKS cache.
///
/// Uses `tokio::sync::RwLock` rather than `std::sync::RwLock` so that a panic
/// while holding the write guard (e.g. during JWK parsing) cannot poison the
/// lock and brick all subsequent verification.
static JWKS_CACHE: RwLock<Option<CachedJwks>> = RwLock::const_new(None);

/// Create OpenSSL RSA public key from JWK components
///
/// Uses OpenSSL instead of the `rsa` crate to avoid RUSTSEC-2023-0071.
fn create_rsa_public_key(
    n_b64: &str,
    e_b64: &str,
) -> Result<PKey<openssl::pkey::Public>, AppError> {
    // Decode base64url-encoded modulus and exponent
    let n_bytes = URL_SAFE_NO_PAD
        .decode(n_b64)
        .map_err(|e| AppError::Config(format!("Failed to decode RSA modulus: {}", e)))?;
    let e_bytes = URL_SAFE_NO_PAD
        .decode(e_b64)
        .map_err(|e| AppError::Config(format!("Failed to decode RSA exponent: {}", e)))?;

    // Create OpenSSL BigNums
    let n = BigNum::from_slice(&n_bytes)
        .map_err(|e| AppError::Config(format!("Failed to create BigNum for modulus: {}", e)))?;
    let e = BigNum::from_slice(&e_bytes)
        .map_err(|e| AppError::Config(format!("Failed to create BigNum for exponent: {}", e)))?;

    // Create RSA public key
    let rsa = Rsa::from_public_components(n, e)
        .map_err(|e| AppError::Config(format!("Failed to create RSA key: {}", e)))?;

    // Convert to PKey
    let pkey = PKey::from_rsa(rsa)
        .map_err(|e| AppError::Config(format!("Failed to create PKey: {}", e)))?;

    Ok(pkey)
}

/// Verify RS256 signature using OpenSSL
///
/// Uses OpenSSL instead of the `rsa` crate to avoid RUSTSEC-2023-0071.
fn verify_rs256_signature(
    pkey: &PKey<openssl::pkey::Public>,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, AppError> {
    let mut verifier = Verifier::new(MessageDigest::sha256(), pkey)
        .map_err(|e| AppError::Config(format!("Failed to create verifier: {}", e)))?;

    verifier
        .update(message)
        .map_err(|e| AppError::Config(format!("Failed to update verifier: {}", e)))?;

    let result = verifier
        .verify(signature)
        .map_err(|e| AppError::Unauthorized(format!("Signature verification error: {}", e)))?;

    Ok(result)
}

/// Fetch and cache Clerk JWKS
pub async fn fetch_clerk_jwks(jwks_url: &str) -> Result<(), AppError> {
    debug!("Fetching Clerk JWKS from {}", jwks_url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::Config(format!("Failed to create HTTP client: {}", e)))?;

    let response = client
        .get(jwks_url)
        .send()
        .await
        .map_err(|e| AppError::Config(format!("Failed to fetch Clerk JWKS: {}", e)))?;

    if !response.status().is_success() {
        return Err(AppError::Config(format!(
            "Clerk JWKS request failed with status {}",
            response.status()
        )));
    }

    let jwks: ClerkJwks = response
        .json()
        .await
        .map_err(|e| AppError::Config(format!("Failed to parse Clerk JWKS: {}", e)))?;

    let mut keys = HashMap::new();
    for jwk in jwks.keys {
        if jwk.kty == "RSA" {
            if let (Some(n), Some(e)) = (&jwk.n, &jwk.e) {
                match create_rsa_public_key(n, e) {
                    Ok(pkey) => {
                        keys.insert(jwk.kid.clone(), CachedRsaKey { pkey });
                        debug!("Cached Clerk JWK with kid: {}", jwk.kid);
                    }
                    Err(err) => {
                        warn!("Failed to parse Clerk JWK {}: {}", jwk.kid, err);
                    }
                }
            }
        }
    }

    if keys.is_empty() {
        return Err(AppError::Config(
            "No valid RSA keys found in Clerk JWKS".to_string(),
        ));
    }

    let mut cache = JWKS_CACHE.write().await;
    *cache = Some(CachedJwks {
        keys,
        fetched_at: Instant::now(),
    });

    debug!("Clerk JWKS cached successfully");
    Ok(())
}

/// Decode JWT header without verification
fn decode_jwt_header(token: &str) -> Result<(String, String), AppError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Unauthorized("Invalid JWT format".to_string()));
    }

    let header_json = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| AppError::Unauthorized(format!("Failed to decode JWT header: {}", e)))?;

    #[derive(Deserialize)]
    struct JwtHeader {
        alg: String,
        kid: Option<String>,
    }

    let header: JwtHeader = serde_json::from_slice(&header_json)
        .map_err(|e| AppError::Unauthorized(format!("Failed to parse JWT header: {}", e)))?;

    if header.alg != "RS256" {
        return Err(AppError::Unauthorized(format!(
            "Unsupported algorithm: {}. Only RS256 is supported for Clerk.",
            header.alg
        )));
    }

    let kid = header
        .kid
        .ok_or_else(|| AppError::Unauthorized("Token missing kid in header".to_string()))?;

    Ok((header.alg, kid))
}

/// Decode and verify JWT claims
fn decode_jwt_claims(token: &str) -> Result<ClerkClaims, AppError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Unauthorized("Invalid JWT format".to_string()));
    }

    let claims_json = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| AppError::Unauthorized(format!("Failed to decode JWT claims: {}", e)))?;

    // Debug: log raw claims to see what Clerk is actually sending
    if let Ok(raw) = String::from_utf8(claims_json.clone()) {
        debug!("Raw JWT claims: {}", raw);
    }

    let claims: ClerkClaims = serde_json::from_slice(&claims_json)
        .map_err(|e| AppError::Unauthorized(format!("Failed to parse JWT claims: {}", e)))?;

    Ok(claims)
}

/// Verify a Clerk JWT and extract claims
///
/// If CLERK_EXPECTED_AUD is set, validates the audience claim.
/// Uses OpenSSL for RS256 verification to avoid the vulnerable `rsa` crate.
pub async fn verify_clerk_token(token: &str, jwks_url: &str) -> Result<ClerkClaims, AppError> {
    // Decode header to get kid and algorithm
    let (_alg, kid) = decode_jwt_header(token)?;

    // Split token
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Unauthorized("Invalid JWT format".to_string()));
    }

    let message = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| AppError::Unauthorized(format!("Failed to decode signature: {}", e)))?;

    // Get RSA key from cache, refreshing if needed
    let pkey = get_rsa_key(&kid, jwks_url).await?;

    // Verify signature using OpenSSL
    let valid = verify_rs256_signature(&pkey, message.as_bytes(), &signature)?;
    if !valid {
        return Err(AppError::Unauthorized(
            "Invalid token signature".to_string(),
        ));
    }

    // Decode claims
    let claims = decode_jwt_claims(token)?;

    // Validate expiration
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Config("System time error".to_string()))?
        .as_secs();

    if claims.exp < now {
        return Err(AppError::Unauthorized("Token has expired".to_string()));
    }

    // Pinned-issuer validation: reject tokens whose `iss` doesn't match the
    // configured Clerk instance, even if the signature verifies (defends
    // against accidentally trusting a JWKS URL that serves multiple tenants).
    if let Ok(expected_iss) = std::env::var("CLERK_EXPECTED_ISS") {
        if claims.iss != expected_iss {
            return Err(AppError::Unauthorized(format!(
                "Token issuer mismatch. Expected: {}, got: {}",
                expected_iss, claims.iss
            )));
        }
    }

    // Check if audience validation is configured (N5 fix)
    if let Ok(expected_aud) = std::env::var("CLERK_EXPECTED_AUD") {
        debug!("Validating Clerk token audience: {}", expected_aud);

        let aud_valid = match &claims.aud {
            Some(serde_json::Value::String(aud)) => aud == &expected_aud,
            Some(serde_json::Value::Array(auds)) => auds.iter().any(|a| {
                if let serde_json::Value::String(s) = a {
                    s == &expected_aud
                } else {
                    false
                }
            }),
            _ => false,
        };

        if !aud_valid {
            return Err(AppError::Unauthorized(format!(
                "Token audience mismatch. Expected: {}",
                expected_aud
            )));
        }
    } else {
        debug!("CLERK_EXPECTED_AUD not set, skipping audience validation");
    }

    Ok(claims)
}

/// Get RSA key from cache, refreshing if needed
async fn get_rsa_key(kid: &str, jwks_url: &str) -> Result<PKey<openssl::pkey::Public>, AppError> {
    // Check cache first
    {
        let cache = JWKS_CACHE.read().await;

        if let Some(cached) = &*cache {
            if cached.fetched_at.elapsed() < JWKS_CACHE_TTL {
                if let Some(key) = cached.keys.get(kid) {
                    // Clone the PKey - OpenSSL PKey is reference counted
                    return Ok(key.pkey.clone());
                }
            }
        }
    }

    // Cache miss or expired, refresh
    fetch_clerk_jwks(jwks_url).await?;

    // Try again
    let cache = JWKS_CACHE.read().await;

    if let Some(cached) = &*cache {
        if let Some(key) = cached.keys.get(kid) {
            return Ok(key.pkey.clone());
        }
    }

    Err(AppError::Unauthorized(format!(
        "No matching key found for kid: {}",
        kid
    )))
}

/// Extract user role from Clerk session claims (publicMetadata.role)
///
/// NOTE: Clerk's standard JWT doesn't include publicMetadata by default.
/// For MVP, we'll need to either:
/// 1. Use Clerk Backend API to fetch user metadata
/// 2. Configure Clerk to include role in session claims
/// 3. Default to "user" role
///
/// TODO: Integrate with Clerk Organizations for proper RBAC
#[allow(dead_code)] // Reserved for future Clerk Backend API integration
pub async fn get_user_role(user_id: &str, clerk_secret_key: Option<&str>) -> String {
    // For MVP: If we have Clerk secret key, we could fetch user metadata
    // For now, default to "user" - admin role must be set in Clerk publicMetadata
    // and verified via /api/user endpoint from dashboard

    if clerk_secret_key.is_some() {
        // TODO: Implement Clerk Backend API call to get user metadata
        // GET https://api.clerk.com/v1/users/{user_id}
        debug!("Would fetch role for user {} from Clerk API", user_id);
    }

    // Default role - actual role checking done in dashboard
    "user".to_string()
}

/// Axum extractor for authenticated requests
///
/// Extracts and verifies Clerk JWT from Authorization header.
/// If CLERK_JWKS_URL is not configured, allows unauthenticated requests
/// (for backward compatibility during migration).
pub struct ClerkAuth(pub Option<AuthenticatedUser>);

impl<S> FromRequestParts<S> for ClerkAuth
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Get JWKS URL from environment
        let jwks_url = match std::env::var("CLERK_JWKS_URL") {
            Ok(url) => url,
            Err(_) => {
                // CLERK_JWKS_URL not configured - allow unauthenticated
                // This provides backward compatibility during migration
                debug!("CLERK_JWKS_URL not configured, skipping auth");
                return Ok(ClerkAuth(None));
            }
        };

        // Extract Authorization header
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok());

        let token = match auth_header {
            Some(header) if header.starts_with("Bearer ") => &header[7..],
            _ => {
                // No token provided but auth is required
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "Missing or invalid Authorization header".to_string(),
                ));
            }
        };

        // Verify token
        match verify_clerk_token(token, &jwks_url).await {
            Ok(claims) => {
                // Extract role from publicMetadata (N4 fix)
                // Requires Clerk JWT template to include: {{user.public_metadata}}
                let role = claims
                    .public_metadata
                    .as_ref()
                    .and_then(|m| m.role.clone())
                    .unwrap_or_else(|| {
                        warn!(
                            "No role in publicMetadata for user {}, defaulting to 'user'",
                            claims.sub
                        );
                        "user".to_string()
                    });

                debug!("Authenticated user {} with role {}", claims.sub, role);

                let user = AuthenticatedUser {
                    user_id: claims.sub,
                    role,
                    email: None,
                };
                Ok(ClerkAuth(Some(user)))
            }
            Err(e) => {
                error!("Clerk token verification failed: {:?}", e);
                Err((StatusCode::UNAUTHORIZED, format!("Invalid token: {}", e)))
            }
        }
    }
}
