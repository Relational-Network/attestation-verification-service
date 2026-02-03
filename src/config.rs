// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Configuration management for the Attestation Verification Service.
//!
//! Loads runtime configuration from environment variables with sensible defaults.
//! Use `.env` file for local development (loaded automatically via dotenvy).

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Default listen address for the AVS API.
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9100";
/// JWT issuer string for browser verification.
pub const DEFAULT_ISSUER: &str = "attestation-verification-service";
/// Default token lifetime in seconds (5 minutes).
pub const DEFAULT_TTL_SECS: u64 = 300;

/// Runtime configuration loaded from environment.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub issuer: String,
    pub token_ttl_secs: u64,
    pub signing_key_path: PathBuf,
    pub signing_key_id: String,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub ratls_verify_lib: PathBuf,
    pub expected_mrsigner: String,
    pub expected_mrenclave: String,
    pub expected_isv_prod_id: String,
    pub expected_isv_svn: String,
    pub allow_debug_enclave: bool,
    pub allow_outdated_tcb: bool,
    pub allow_hw_config_needed: bool,
    pub allow_sw_hardening_needed: bool,
    pub allowed_enclave_hosts: Vec<String>,
    /// Clerk JWKS URL for token verification (optional, enables Clerk auth)
    pub clerk_jwks_url: Option<String>,
}

impl Config {
    /// Check if TLS is enabled (both cert and key paths are set).
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }

    /// Read environment configuration with safe defaults and required checks.
    ///
    /// # Required Environment Variables
    ///
    /// - `AVS_SIGNING_KEY_PATH`: Path to P-256 private key (PEM format)
    /// - `AVS_EXPECTED_MRSIGNER` or `AVS_EXPECTED_MRENCLAVE`: Enclave identity policy
    ///
    /// # Optional Environment Variables
    ///
    /// - `AVS_BIND_ADDR`: Listen address (default: `0.0.0.0:9100`)
    /// - `AVS_ISSUER`: JWT issuer claim (default: `attestation-verification-service`)
    /// - `AVS_TOKEN_TTL_SECS`: Token lifetime (default: `300`)
    /// - `AVS_TLS_CERT_PATH`: Path to TLS certificate (PEM format) - enables HTTPS
    /// - `AVS_TLS_KEY_PATH`: Path to TLS private key (PEM format) - enables HTTPS
    /// - `AVS_RATLS_VERIFY_LIB`: Path to RA-TLS verifier library
    /// - `AVS_EXPECTED_ISV_PROD_ID`: ISV Product ID policy
    /// - `AVS_EXPECTED_ISV_SVN`: ISV Security Version policy
    /// - `AVS_ALLOWED_ENCLAVE_HOSTS`: Comma-separated allowlist
    /// - `AVS_ALLOW_DEBUG_ENCLAVE`: Allow debug enclaves (set to `1`)
    /// - `AVS_ALLOW_OUTDATED_TCB`: Allow outdated TCB (set to `1`)
    /// - `AVS_ALLOW_HW_CONFIG_NEEDED`: Allow hardware config needed (set to `1`)
    /// - `AVS_ALLOW_SW_HARDENING_NEEDED`: Allow software hardening needed (set to `1`)
    /// - `AVS_ALLOWED_ENCLAVE_HOSTS`: Comma-separated allowlist of enclave hosts
    /// - `AVS_SIGNING_KEY_ID`: Key ID for JWT header (default: `avs-signing-key-1`)
    /// - `CLERK_JWKS_URL`: Clerk JWKS URL for token verification (enables Clerk auth)
    pub fn from_env() -> Result<Self, String> {
        let bind_addr = env::var("AVS_BIND_ADDR")
            .unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string())
            .parse()
            .map_err(|err| format!("invalid AVS_BIND_ADDR: {err}"))?;

        let issuer = env::var("AVS_ISSUER").unwrap_or_else(|_| DEFAULT_ISSUER.to_string());
        let token_ttl_secs = env::var("AVS_TOKEN_TTL_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_TTL_SECS);

        let signing_key_path = env::var("AVS_SIGNING_KEY_PATH")
            .map(PathBuf::from)
            .map_err(|_| "AVS_SIGNING_KEY_PATH is required".to_string())?;

        let signing_key_id = env::var("AVS_SIGNING_KEY_ID")
            .unwrap_or_else(|_| "avs-signing-key-1".to_string());

        let tls_cert_path = env::var("AVS_TLS_CERT_PATH").ok().map(PathBuf::from);
        let tls_key_path = env::var("AVS_TLS_KEY_PATH").ok().map(PathBuf::from);

        let ratls_verify_lib = env::var("AVS_RATLS_VERIFY_LIB")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("libra_tls_verify_dcap.so"));

        let expected_mrsigner =
            env::var("AVS_EXPECTED_MRSIGNER").unwrap_or_else(|_| "any".to_string());
        let expected_mrenclave =
            env::var("AVS_EXPECTED_MRENCLAVE").unwrap_or_else(|_| "any".to_string());
        let expected_isv_prod_id =
            env::var("AVS_EXPECTED_ISV_PROD_ID").unwrap_or_else(|_| "any".to_string());
        let expected_isv_svn =
            env::var("AVS_EXPECTED_ISV_SVN").unwrap_or_else(|_| "any".to_string());

        if expected_mrsigner == "any" && expected_mrenclave == "any" {
            return Err("AVS_EXPECTED_MRSIGNER or AVS_EXPECTED_MRENCLAVE must be set".to_string());
        }

        let allow_debug_enclave = env::var("AVS_ALLOW_DEBUG_ENCLAVE")
            .ok()
            .map(|value| value == "1")
            .unwrap_or(false);
        let allow_outdated_tcb = env::var("AVS_ALLOW_OUTDATED_TCB")
            .ok()
            .map(|value| value == "1")
            .unwrap_or(false);
        let allow_hw_config_needed = env::var("AVS_ALLOW_HW_CONFIG_NEEDED")
            .ok()
            .map(|value| value == "1")
            .unwrap_or(false);
        let allow_sw_hardening_needed = env::var("AVS_ALLOW_SW_HARDENING_NEEDED")
            .ok()
            .map(|value| value == "1")
            .unwrap_or(false);

        let allowed_enclave_hosts = env::var("AVS_ALLOWED_ENCLAVE_HOSTS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .collect::<Vec<_>>();

        let clerk_jwks_url = env::var("CLERK_JWKS_URL").ok();

        Ok(Self {
            bind_addr,
            issuer,
            token_ttl_secs,
            signing_key_path,
            signing_key_id,
            tls_cert_path,
            tls_key_path,
            ratls_verify_lib,
            expected_mrsigner,
            expected_mrenclave,
            expected_isv_prod_id,
            expected_isv_svn,
            allow_debug_enclave,
            allow_outdated_tcb,
            allow_hw_config_needed,
            allow_sw_hardening_needed,
            allowed_enclave_hosts,
            clerk_jwks_url,
        })
    }

    /// Apply RA-TLS policy to environment variables for the verifier library.
    pub fn apply_ratls_env(&self) {
        env::set_var("RA_TLS_MRSIGNER", &self.expected_mrsigner);
        env::set_var("RA_TLS_MRENCLAVE", &self.expected_mrenclave);
        env::set_var("RA_TLS_ISV_PROD_ID", &self.expected_isv_prod_id);
        env::set_var("RA_TLS_ISV_SVN", &self.expected_isv_svn);

        env::set_var(
            "RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE",
            if self.allow_debug_enclave { "1" } else { "0" },
        );
        env::set_var(
            "RA_TLS_ALLOW_OUTDATED_TCB_INSECURE",
            if self.allow_outdated_tcb { "1" } else { "0" },
        );
        env::set_var(
            "RA_TLS_ALLOW_HW_CONFIG_NEEDED",
            if self.allow_hw_config_needed {
                "1"
            } else {
                "0"
            },
        );
        env::set_var(
            "RA_TLS_ALLOW_SW_HARDENING_NEEDED",
            if self.allow_sw_hardening_needed {
                "1"
            } else {
                "0"
            },
        );
    }
}
