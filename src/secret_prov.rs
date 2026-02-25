// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Secret provisioning server — wraps Gramine's `libsecret_prov_verify_dcap.so`.
//!
//! Listens on port 4433 for SGX enclave clients. When an enclave connects, the
//! library performs a mutually-attested TLS handshake (the enclave presents its
//! RA-TLS certificate containing a DCAP quote), verifies the SGX measurements via
//! the policy applied by [`RaTlsVerifier`] (already configured in `apply_ratls_env()`),
//! then sends the 16-byte `/data` encryption key to the enclave.
//!
//! Gramine on the enclave side (`libsecret_prov_attest.so` via `LD_PRELOAD`) receives
//! the key and writes it to the `/dev/attestation/keys/data_key` slot, which the
//! encrypted FS mount uses to decrypt `/data` before `main()` runs.
//!
//! # Library
//!
//! Uses `libloading` to dlopen `libsecret_prov_verify_dcap.so` at runtime — consistent
//! with the existing [`crate::ratls`] module pattern. No `build.rs` required.
//!
//! The library is installed with Gramine at:
//! `/usr/lib/x86_64-linux-gnu/libsecret_prov_verify_dcap.so`
//!
//! # Verified function signature (Gramine 1.8, `/usr/include/gramine/secret_prov.h`)
//!
//! ```c
//! int secret_provision_start_server(
//!     uint8_t* secret,         // the key bytes to send (read-only in practice)
//!     size_t   secret_size,    // must be 16
//!     const char* port,        // listening port string, e.g. "4433"
//!     const char* cert_path,   // server TLS certificate path
//!     const char* key_path,    // server TLS private key path
//!     verify_measurements_cb_t m_cb,  // NULL = use RA_TLS_* env vars (set by config)
//!     secret_provision_cb_t    f_cb,  // NULL = send secret then close
//! );
//! ```
//!
//! `m_cb = NULL` delegates measurement verification to the existing `RA_TLS_MRENCLAVE` /
//! `RA_TLS_MRSIGNER` env vars that `Config::apply_ratls_env()` already sets.

use libloading::Library;
use std::ffi::CString;

use crate::error::AppError;

/// Hardcoded port for the secret provisioning endpoint.
pub const SECRET_PROV_PORT: &str = "4433";

/// Default cert/key paths for the TLS listener on port 4433.
/// Overridable via `SECRET_PROV_CERT` / `SECRET_PROV_KEY` env vars.
/// The Docker image sets these to `/secrets/avs-tls.crt` and `/secrets/avs-tls.key`
/// via `ENV` instructions; native dev uses the relative paths below.
const DEFAULT_CERT: &str = "secrets/avs-tls.crt";
const DEFAULT_KEY: &str = "secrets/avs-tls.key";

/// Default library path for the Gramine DCAP secret provisioning verifier.
const DEFAULT_LIB: &str = "/usr/lib/x86_64-linux-gnu/libsecret_prov_verify_dcap.so";

// C function pointer types matching `secret_prov.h`.
// Using `std::os::raw` avoids a `libc` dependency.
use std::os::raw::{c_char, c_int};

type VerifyMeasurementsCb =
    unsafe extern "C" fn(*const c_char, *const c_char, *const c_char, *const c_char) -> c_int;
type SecretProvisionCb = unsafe extern "C" fn(*mut std::ffi::c_void) -> c_int;

type SecretProvisionStartServerFn = unsafe extern "C" fn(
    secret: *mut u8,
    secret_size: usize,
    port: *const c_char,
    cert_path: *const c_char,
    key_path: *const c_char,
    m_cb: Option<VerifyMeasurementsCb>,
    f_cb: Option<SecretProvisionCb>,
) -> c_int;

/// Spawn a dedicated OS thread running the secret provisioning server.
///
/// The server blocks in an accept loop forever, spawning a new thread per connection.
/// If it returns (which only happens on a fatal error), the process exits.
///
/// `key`: exactly 16 bytes — the AES-GCM-128 encryption key for `/data`.
pub fn start_secret_prov_server(key: [u8; 16]) -> Result<(), AppError> {
    let lib_path = std::env::var("SECRET_PROV_VERIFY_LIB")
        .unwrap_or_else(|_| DEFAULT_LIB.to_string());
    let cert_path = std::env::var("SECRET_PROV_CERT")
        .unwrap_or_else(|_| DEFAULT_CERT.to_string());
    let key_path = std::env::var("SECRET_PROV_KEY")
        .unwrap_or_else(|_| DEFAULT_KEY.to_string());

    // Validate cert and key files exist before spawning the thread.
    if !std::path::Path::new(&cert_path).exists() {
        return Err(AppError::Config(format!(
            "secret prov TLS cert not found at '{cert_path}' \
             (run ./secrets/generate-keys.sh or set SECRET_PROV_CERT)"
        )));
    }
    if !std::path::Path::new(&key_path).exists() {
        return Err(AppError::Config(format!(
            "secret prov TLS key not found at '{key_path}' \
             (run ./secrets/generate-keys.sh or set SECRET_PROV_KEY)"
        )));
    }

    // Load library and resolve symbol. We leak the Library handle intentionally:
    // the server thread runs for the entire process lifetime, and the library
    // must remain loaded. This is a controlled, one-time leak.
    let lib = unsafe { Library::new(&lib_path) }.map_err(|e| {
        AppError::Config(format!(
            "failed to load secret prov library at '{lib_path}': {e}\n\
             Install Gramine: sudo apt-get install -y gramine"
        ))
    })?;

    let start_server_fn: SecretProvisionStartServerFn = unsafe {
        let symbol: libloading::Symbol<SecretProvisionStartServerFn> = lib
            .get(b"secret_provision_start_server")
            .map_err(|e| AppError::Config(format!("missing secret_provision_start_server: {e}")))?;
        *symbol
    };

    // Leak the library so it stays loaded after we move into the thread.
    std::mem::forget(lib);

    // Build C strings before moving into the thread.
    let c_port = CString::new(SECRET_PROV_PORT).expect("port is valid C string");
    let c_cert = CString::new(cert_path).map_err(|e| {
        AppError::Config(format!("cert path contains null byte: {e}"))
    })?;
    let c_key = CString::new(key_path).map_err(|e| {
        AppError::Config(format!("key path contains null byte: {e}"))
    })?;

    tracing::info!(
        port = SECRET_PROV_PORT,
        "secret provisioning server starting"
    );

    std::thread::Builder::new()
        .name("secret-prov-server".to_string())
        .spawn(move || {
            // SAFETY: `secret_provision_start_server` reads `secret` but does not store
            // the pointer (verified by Gramine 1.8 source). The key buffer lives for the
            // full duration of the call (which is forever — it never returns on success).
            let mut secret = key; // local copy; mutable for the C ABI
            let ret = unsafe {
                start_server_fn(
                    secret.as_mut_ptr(),
                    secret.len(),
                    c_port.as_ptr(),
                    c_cert.as_ptr(),
                    c_key.as_ptr(),
                    None, // m_cb = NULL → use RA_TLS_* env vars set by apply_ratls_env()
                    None, // f_cb = NULL → send secret and close
                )
            };
            // Only reached on fatal error.
            tracing::error!(ret, "secret_provision_start_server exited unexpectedly");
            std::process::exit(1);
        })
        .map_err(|e| AppError::Config(format!("failed to spawn secret prov thread: {e}")))?;

    Ok(())
}
