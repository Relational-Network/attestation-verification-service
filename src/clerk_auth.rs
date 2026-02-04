// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Clerk JWT verification for incoming requests.
//!
//! Verifies Clerk-issued JWTs to authenticate users before issuing attestation tokens.
//! Uses Clerk's JWKS endpoint for key verification.

use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
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
    pub n: Option<String>, // RSA modulus
    pub e: Option<String>, // RSA exponent
    #[serde(rename = "use")]
    pub key_use: Option<String>,
}

/// JWKS response from Clerk
#[derive(Debug, Deserialize)]
pub struct ClerkJwks {
    pub keys: Vec<ClerkJwk>,
}

/// Cached JWKS with expiry
struct CachedJwks {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Instant,
}

/// Global JWKS cache
static JWKS_CACHE: RwLock<Option<CachedJwks>> = RwLock::new(None);

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
                match DecodingKey::from_rsa_components(n, e) {
                    Ok(key) => {
                        keys.insert(jwk.kid.clone(), key);
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

    let mut cache = JWKS_CACHE
        .write()
        .map_err(|_| AppError::Config("Failed to acquire JWKS cache write lock".to_string()))?;
    *cache = Some(CachedJwks {
        keys,
        fetched_at: Instant::now(),
    });

    debug!("Clerk JWKS cached successfully");
    Ok(())
}

/// Get a decoding key from cache, refreshing if needed
async fn get_decoding_key(kid: &str, jwks_url: &str) -> Result<DecodingKey, AppError> {
    // Check cache first
    {
        let cache = JWKS_CACHE
            .read()
            .map_err(|_| AppError::Config("Failed to acquire JWKS cache read lock".to_string()))?;

        if let Some(cached) = &*cache {
            if cached.fetched_at.elapsed() < JWKS_CACHE_TTL {
                if let Some(key) = cached.keys.get(kid) {
                    return Ok(key.clone());
                }
            }
        }
    }

    // Cache miss or expired, refresh
    fetch_clerk_jwks(jwks_url).await?;

    // Try again
    let cache = JWKS_CACHE
        .read()
        .map_err(|_| AppError::Config("Failed to acquire JWKS cache read lock".to_string()))?;

    if let Some(cached) = &*cache {
        if let Some(key) = cached.keys.get(kid) {
            return Ok(key.clone());
        }
    }

    Err(AppError::Unauthorized(format!(
        "No matching key found for kid: {}",
        kid
    )))
}

/// Verify a Clerk JWT and extract claims
///
/// If CLERK_EXPECTED_AUD is set, validates the audience claim.
pub async fn verify_clerk_token(token: &str, jwks_url: &str) -> Result<ClerkClaims, AppError> {
    // Decode header to get kid
    let header = decode_header(token)
        .map_err(|e| AppError::Unauthorized(format!("Invalid token header: {}", e)))?;

    let kid = header
        .kid
        .ok_or_else(|| AppError::Unauthorized("Token missing kid in header".to_string()))?;

    // Get decoding key
    let key = get_decoding_key(&kid, jwks_url).await?;

    // Clerk uses RS256
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;

    // Check if audience validation is configured (N5 fix)
    let expected_aud = std::env::var("CLERK_EXPECTED_AUD").ok();
    if let Some(ref aud) = expected_aud {
        validation.validate_aud = true;
        validation.set_audience(&[aud]);
        debug!("Validating Clerk token audience: {}", aud);
    } else {
        validation.validate_aud = false;
        debug!("CLERK_EXPECTED_AUD not set, skipping audience validation");
    }

    let token_data = decode::<ClerkClaims>(token, &key, &validation)
        .map_err(|e| AppError::Unauthorized(format!("Token verification failed: {}", e)))?;

    Ok(token_data.claims)
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
