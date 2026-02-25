// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Key store — provides the 16-byte AES-GCM encryption key for the enclave's
//! `/data` Gramine encrypted FS mount.
//!
//! # Modes
//!
//! | Mode | Trigger | Key source |
//! |------|---------|------------|
//! | Dev / Staging | `AZURE_KEYVAULT_URL` **not** set | `DEV_DATA_KEY_PATH` (hex file) or `DEV_DATA_KEY` (hex env var) |
//! | Prod          | `AZURE_KEYVAULT_URL` set         | Azure Key Vault via Managed Identity (IMDS + REST) |
//!
//! # Staging
//!
//! Staging uses **dev mode** — a random 16-byte key stored as a hex file on the VM.
//! Azure Key Vault is not required. Run these commands once on the staging VM:
//!
//! ```bash
//! # 1. Generate a random data key
//! openssl rand -hex 16 > /opt/iob-micres/secrets/data-key.hex
//! chmod 600 /opt/iob-micres/secrets/data-key.hex
//!
//! # 2. Generate the TLS certificate used by the secret provisioning server (port 4433)
//! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
//!   -keyout /opt/iob-micres/secrets/avs-tls.key \
//!   -out    /opt/iob-micres/secrets/avs-tls.crt \
//!   -days 3650 -subj "/CN=avs-secret-prov" \
//!   -addext "subjectAltName=IP:127.0.0.1"
//!
//! # 3. Trust the cert on the enclave host (Gramine reads /etc/ssl/certs/avs-ca.crt)
//! sudo cp /opt/iob-micres/secrets/avs-tls.crt /etc/ssl/certs/avs-ca.crt
//!
//! # 4. Restart both services
//! sudo systemctl restart avs enclave
//! ```
//!
//! The `avs.service` mounts `/opt/iob-micres/secrets` as `/secrets:ro` and passes
//! `DEV_DATA_KEY_PATH=/secrets/data-key.hex` into the container automatically.
//!
//! # Azure Key Vault (prod)
//!
//! Uses the Azure IMDS endpoint to acquire a token for the VM's managed identity,
//! then calls the Key Vault REST API directly. No Azure SDK crates are required —
//! only `reqwest` (already a dependency) and `serde_json`.
//!
//! This avoids any cryptography crate dependencies that might transitively pull in
//! the vulnerable `rsa` crate (RUSTSEC-2023-0071).
//!
//! ## Setup
//!
//! ```bash
//! # Store a 16-byte key as a 32-character hex string in Key Vault:
//! KEY_HEX=$(openssl rand -hex 16)
//! az keyvault secret set \
//!   --vault-name YOUR_VAULT \
//!   --name relational-data-key \
//!   --value "$KEY_HEX"
//!
//! # Grant the AVS VM's managed identity read access:
//! PRINCIPAL=$(az vm show --name avs-vm --resource-group YOUR_RG \
//!   --query identity.principalId -o tsv)
//! az role assignment create \
//!   --role "Key Vault Secrets User" \
//!   --assignee "$PRINCIPAL" \
//!   --scope "/subscriptions/.../vaults/YOUR_VAULT"
//!
//! # Set environment variables (no credentials needed — IMDS handles auth):
//! AZURE_KEYVAULT_URL=https://YOUR_VAULT.vault.azure.net
//! AZURE_KEYVAULT_KEY_NAME=relational-data-key   # optional, this is the default
//! ```

use crate::error::AppError;

const DEFAULT_KEY_NAME: &str = "relational-data-key";
const KV_API_VERSION: &str = "7.4";

/// Key store: produces the 16-byte `/data` encryption key on demand.
pub struct KeyStore {
    mode: KeyStoreMode,
}

enum KeyStoreMode {
    Dev([u8; 16]),
    AzureKeyVault { vault_url: String, key_name: String },
}

impl KeyStore {
    /// Build from the environment.
    ///
    /// - If `AZURE_KEYVAULT_URL` is set → Azure Key Vault (prod).
    /// - Otherwise → dev mode: reads `DEV_DATA_KEY_PATH` (hex file) or
    ///   `DEV_DATA_KEY` (hex env var).
    pub fn from_env() -> Result<Self, AppError> {
        if let Ok(vault_url) = std::env::var("AZURE_KEYVAULT_URL") {
            let key_name = std::env::var("AZURE_KEYVAULT_KEY_NAME")
                .unwrap_or_else(|_| DEFAULT_KEY_NAME.to_string());
            tracing::info!(%vault_url, %key_name, "KeyStore: Azure Key Vault mode");
            return Ok(Self {
                mode: KeyStoreMode::AzureKeyVault {
                    vault_url,
                    key_name,
                },
            });
        }

        // Dev mode — try file first, then inline env var.
        let hex = if let Ok(path) = std::env::var("DEV_DATA_KEY_PATH") {
            tracing::info!(%path, "KeyStore: dev mode — loading key from file");
            std::fs::read_to_string(&path).map_err(|e| {
                AppError::Config(format!("failed to read DEV_DATA_KEY_PATH {path}: {e}"))
            })?
        } else {
            std::env::var("DEV_DATA_KEY").map_err(|_| {
                AppError::Config(
                    "secret provisioning key not configured: set AZURE_KEYVAULT_URL (prod) \
                     or DEV_DATA_KEY / DEV_DATA_KEY_PATH (dev)"
                        .to_string(),
                )
            })?
        };

        let key = parse_hex_key(hex.trim())?;
        tracing::warn!("KeyStore: DEV mode — using local plaintext key; never use in production");
        Ok(Self {
            mode: KeyStoreMode::Dev(key),
        })
    }

    /// Fetch the 16-byte encryption key.
    pub async fn get_key(&self) -> Result<[u8; 16], AppError> {
        match &self.mode {
            KeyStoreMode::Dev(key) => Ok(*key),
            KeyStoreMode::AzureKeyVault {
                vault_url,
                key_name,
            } => fetch_from_azure_kv(vault_url, key_name).await,
        }
    }
}

/// Parse a 32-character hex string into a 16-byte key.
fn parse_hex_key(hex: &str) -> Result<[u8; 16], AppError> {
    let bytes = hex::decode(hex)
        .map_err(|e| AppError::Config(format!("data key is not valid hex: {e}")))?;
    bytes.try_into().map_err(|_| {
        AppError::Config(format!(
            "data key must be exactly 16 bytes (32 hex chars), got {} chars",
            hex.len()
        ))
    })
}

/// Fetch a secret from Azure Key Vault using the VM's Managed Identity.
///
/// Two-step process:
/// 1. Acquire an OAuth2 bearer token from the Azure IMDS endpoint.
/// 2. Call the Key Vault REST API with that token.
///
/// No Azure SDK crates are needed — plain `reqwest` + `serde_json`.
async fn fetch_from_azure_kv(vault_url: &str, key_name: &str) -> Result<[u8; 16], AppError> {
    let token = acquire_imds_token("https://vault.azure.net").await?;

    // Fetch the secret value from Key Vault.
    let url = format!(
        "{}/secrets/{}?api-version={}",
        vault_url.trim_end_matches('/'),
        key_name,
        KV_API_VERSION
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::Config(format!("failed to build HTTP client: {e}")))?;

    let response = client
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| AppError::Config(format!("Key Vault request failed: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(AppError::Config(format!(
            "Key Vault returned {status}: {body}"
        )));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AppError::Config(format!("Key Vault response parse error: {e}")))?;

    let hex = body
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Config("Key Vault response missing 'value' field".to_string()))?;

    parse_hex_key(hex.trim())
}

/// Acquire an OAuth2 bearer token from the Azure IMDS endpoint for a given resource.
///
/// This only works on Azure VMs with a managed identity assigned.
async fn acquire_imds_token(resource: &str) -> Result<String, AppError> {
    let url = format!(
        "http://169.254.169.254/metadata/identity/oauth2/token\
         ?api-version=2018-02-01&resource={}",
        resource
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| AppError::Config(format!("failed to build IMDS client: {e}")))?;

    let response = client
        .get(&url)
        .header("Metadata", "true")
        .send()
        .await
        .map_err(|e| {
            AppError::Config(format!(
                "IMDS token request failed (is this an Azure VM with managed identity?): {e}"
            ))
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(AppError::Config(format!("IMDS returned {status}: {body}")));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AppError::Config(format!("IMDS response parse error: {e}")))?;

    body.get("access_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Config("IMDS response missing 'access_token'".to_string()))
}
