// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! RA-TLS verification using Gramine's DCAP verifier library.
//!
//! This module provides a wrapper around the RA-TLS verifier shared library,
//! which validates SGX DCAP quotes embedded in TLS certificates.
//!
//! # Requirements
//!
//! - Gramine's `libra_tls_verify_dcap.so` must be available
//! - Intel DCAP libraries must be installed on the system
//! - PCCS (Provisioning Certificate Caching Service) must be configured

use libloading::Library;
use std::path::Path;

use crate::error::AppError;

/// FFI layout matching Gramine RA-TLS DCAP verifier struct.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RaTlsVerifyCallbackResults {
    pub attestation_scheme: i32,
    pub err_loc: i32,
    pub dcap: DcapResults,
}

/// DCAP verification results.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DcapResults {
    pub func_verify_quote_result: i32,
    pub quote_verification_result: i32,
}

/// Wrapper around the RA-TLS DCAP verifier library.
pub struct RaTlsVerifier {
    _lib: Library,
    verify_fn: unsafe extern "C" fn(*mut u8, usize, *mut RaTlsVerifyCallbackResults) -> i32,
}

// SAFETY: The underlying C library (libra_tls_verify_dcap.so) is thread-safe.
// The verification function does not store any global state and can be called
// concurrently from multiple threads.
unsafe impl Send for RaTlsVerifier {}
unsafe impl Sync for RaTlsVerifier {}

impl RaTlsVerifier {
    /// Load the DCAP verifier library and resolve the verification symbol.
    pub fn new(path: &Path) -> Result<Self, AppError> {
        let lib = unsafe { Library::new(path) }
            .map_err(|err| AppError::Config(format!("failed to load RA-TLS lib: {err}")))?;
        let verify_fn = unsafe {
            let symbol: libloading::Symbol<
                unsafe extern "C" fn(*mut u8, usize, *mut RaTlsVerifyCallbackResults) -> i32,
            > = lib
                .get(b"ra_tls_verify_callback_extended_der")
                .map_err(|err| AppError::Config(format!("missing ra_tls_verify symbol: {err}")))?;
            *symbol
        };
        Ok(Self {
            _lib: lib,
            verify_fn,
        })
    }

    /// Verify an RA-TLS certificate in DER format using DCAP.
    pub fn verify_der(&self, der: &[u8]) -> Result<(), AppError> {
        let mut results = RaTlsVerifyCallbackResults {
            attestation_scheme: 0,
            err_loc: 0,
            dcap: DcapResults {
                func_verify_quote_result: 0,
                quote_verification_result: 0,
            },
        };
        let ret = unsafe {
            (self.verify_fn)(
                der.as_ptr() as *mut u8,
                der.len(),
                &mut results as *mut RaTlsVerifyCallbackResults,
            )
        };
        if ret != 0 {
            return Err(AppError::Attestation(format!(
                "DCAP verification failed: ret={ret}, err_loc={}, quote_result={}, verify_result={}",
                results.err_loc,
                results.dcap.func_verify_quote_result,
                results.dcap.quote_verification_result
            )));
        }
        Ok(())
    }
}
