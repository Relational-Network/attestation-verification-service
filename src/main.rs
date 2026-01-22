// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network
// Attestation Verification Service (AVS) for SGX RA-TLS (DCAP).

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use dotenvy::dotenv;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use libloading::Library;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePrivateKey;
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::task::JoinError;
use tracing::{error, info, warn};
use url::Url;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

// Default listen address for the AVS API.
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9100";
// JWT issuer string for browser verification.
const DEFAULT_ISSUER: &str = "attestation-verification-service";
// Default token lifetime in seconds.
const DEFAULT_TTL_SECS: u64 = 300;

// Runtime configuration loaded from environment.
#[derive(Debug, Clone)]
struct Config {
    bind_addr: SocketAddr,
    issuer: String,
    token_ttl_secs: u64,
    signing_key_path: PathBuf,
    ratls_verify_lib: PathBuf,
    expected_mrsigner: String,
    expected_mrenclave: String,
    expected_isv_prod_id: String,
    expected_isv_svn: String,
    allow_debug_enclave: bool,
    allow_outdated_tcb: bool,
    allow_hw_config_needed: bool,
    allow_sw_hardening_needed: bool,
    allowed_enclave_hosts: Vec<String>,
}

impl Config {
    // Read environment configuration with safe defaults and required checks.
    fn from_env() -> Result<Self, AppError> {
        let bind_addr = env::var("AVS_BIND_ADDR")
            .unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string())
            .parse()
            .map_err(|err| AppError::Config(format!("invalid AVS_BIND_ADDR: {err}")))?;

        let issuer = env::var("AVS_ISSUER").unwrap_or_else(|_| DEFAULT_ISSUER.to_string());
        let token_ttl_secs = env::var("AVS_TOKEN_TTL_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_TTL_SECS);

        let signing_key_path = env::var("AVS_SIGNING_KEY_PATH")
            .map(PathBuf::from)
            .map_err(|_| AppError::Config("AVS_SIGNING_KEY_PATH is required".to_string()))?;

        let ratls_verify_lib = env::var("AVS_RATLS_VERIFY_LIB")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("libra_tls_verify_dcap.so"));

        let expected_mrsigner = env::var("AVS_EXPECTED_MRSIGNER").unwrap_or_else(|_| "any".to_string());
        let expected_mrenclave = env::var("AVS_EXPECTED_MRENCLAVE").unwrap_or_else(|_| "any".to_string());
        let expected_isv_prod_id = env::var("AVS_EXPECTED_ISV_PROD_ID").unwrap_or_else(|_| "any".to_string());
        let expected_isv_svn = env::var("AVS_EXPECTED_ISV_SVN").unwrap_or_else(|_| "any".to_string());

        if expected_mrsigner == "any" && expected_mrenclave == "any" {
            return Err(AppError::Config(
                "AVS_EXPECTED_MRSIGNER or AVS_EXPECTED_MRENCLAVE must be set".to_string(),
            ));
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

        Ok(Self {
            bind_addr,
            issuer,
            token_ttl_secs,
            signing_key_path,
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
        })
    }

    fn apply_ratls_env(&self) {
        // Configure RA-TLS verifier defaults (enclave identity + policy).
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
            if self.allow_hw_config_needed { "1" } else { "0" },
        );
        env::set_var(
            "RA_TLS_ALLOW_SW_HARDENING_NEEDED",
            if self.allow_sw_hardening_needed { "1" } else { "0" },
        );
    }
}

// JSON Web Key representation of an EC public key (used by browser clients).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
    #[serde(rename = "use")]
    use_: String,
    alg: String,
    kid: String,
}

// JWK set for publishing AVS signing public keys.
#[derive(Debug, Clone, Serialize, ToSchema)]
struct JwkSet {
    keys: Vec<Jwk>,
}

// Request payload for /attest.
#[derive(Debug, Deserialize, ToSchema)]
struct AttestRequest {
    enclave_url: String,
    nonce: Option<String>,
}

// Response payload for /attest.
#[derive(Debug, Serialize, ToSchema)]
struct AttestResponse {
    token: String,
    enclave_public_key: Jwk,
    expires_at: u64,
}

// JWT claims issued by the AVS and verified in the browser.
#[derive(Debug, Serialize, ToSchema)]
struct AttestationClaims {
    iss: String,
    sub: String,
    iat: u64,
    exp: u64,
    enclave_url: String,
    enclave_public_key: Jwk,
    policy: PolicyClaims,
    nonce: Option<String>,
}

// Enclave identity policy embedded into the attestation token.
#[derive(Debug, Serialize, ToSchema)]
struct PolicyClaims {
    mrenclave: String,
    mrsigner: String,
    isv_prod_id: String,
    isv_svn: String,
}

// Shared application state for request handlers.
struct AppState {
    config: Config,
    encoding_key: EncodingKey,
    public_jwk: Jwk,
    ratls: Arc<std::sync::Mutex<RaTlsVerifier>>,
}

// Errors mapped to HTTP responses and logs.
#[derive(Debug, Error)]
enum AppError {
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
    #[error("join error: {0}")]
    Join(#[from] JoinError),
    #[error("attestation failed: {0}")]
    Attestation(String),
    #[error("enclave response error: {0}")]
    EnclaveResponse(String),
}

impl IntoResponse for AppError {
    // Convert internal errors into JSON responses with useful status codes.
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Url(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Attestation(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::EnclaveResponse(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = Json(serde_json::json!({ "error": message }));
        (status, body).into_response()
    }
}

// FFI layout matching Gramine RA-TLS verifier structs.
#[repr(C)]
#[derive(Copy, Clone)]
struct RaTlsVerifyCallbackResults {
    attestation_scheme: i32,
    err_loc: i32,
    data: RaTlsVerifyCallbackResultsData,
}

// Union of EPID/DCAP/misc verification outputs.
#[repr(C)]
#[derive(Copy, Clone)]
union RaTlsVerifyCallbackResultsData {
    epid: RaTlsEpidResults,
    dcap: RaTlsDcapResults,
    misc: RaTlsMiscResults,
}

// EPID-only verification results.
#[repr(C)]
#[derive(Copy, Clone)]
struct RaTlsEpidResults {
    ias_enclave_quote_status: [u8; 128],
}

// DCAP-only verification results.
#[repr(C)]
#[derive(Copy, Clone)]
struct RaTlsDcapResults {
    func_verify_quote_result: i32,
    quote_verification_result: i32,
}

// Reserved for future verifier extensions.
#[repr(C)]
#[derive(Copy, Clone)]
struct RaTlsMiscResults {
    reserved: [u8; 128],
}

// Wrapper around the RA-TLS verifier library.
struct RaTlsVerifier {
    _lib: Library,
    verify_fn: unsafe extern "C" fn(*mut u8, usize, *mut RaTlsVerifyCallbackResults) -> i32,
}

impl RaTlsVerifier {
    // Load the verifier shared library and resolve the verification symbol.
    fn new(path: &Path) -> Result<Self, AppError> {
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
        Ok(Self { _lib: lib, verify_fn })
    }

    fn verify_der(&self, der: &[u8]) -> Result<(), AppError> {
        // Verify the RA-TLS certificate and embedded SGX quote with DCAP.
        let mut results = RaTlsVerifyCallbackResults {
            attestation_scheme: 0,
            err_loc: 0,
            data: RaTlsVerifyCallbackResultsData {
                misc: RaTlsMiscResults { reserved: [0u8; 128] },
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
            let detail = unsafe {
                let dcap = results.data.dcap;
                format!(
                    "ra_tls_verify_callback_extended_der failed: ret={ret}, scheme={}, err_loc={}, dcap=({}, {})",
                    results.attestation_scheme,
                    results.err_loc,
                    dcap.func_verify_quote_result,
                    dcap.quote_verification_result
                )
            };
            return Err(AppError::Attestation(detail));
        }
        Ok(())
    }
}

// Entrypoint: initialize logging and fail fast on setup errors.
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

// Service bootstrap: config, signing key, verifier, router, and listener.
async fn run() -> Result<(), AppError> {
    // Load local .env for developer convenience.
    dotenv().ok();
    // Load runtime config and configure RA-TLS verifier policy.
    let config = Config::from_env()?;
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
        .route("/attest", post(attest))
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

// Basic liveness endpoint for ops checks.
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Service is healthy")
    )
)]
async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

// Publish AVS signing key(s) in JWK format for browser verification.
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    responses(
        (status = 200, description = "AVS public signing key set", body = JwkSet)
    )
)]
async fn jwks(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let body = JwkSet {
        keys: vec![state.public_jwk.clone()],
    };
    Json(body)
}

// Attest an enclave via RA-TLS and issue a signed JWT for browser clients.
#[utoipa::path(
    post,
    path = "/attest",
    request_body = AttestRequest,
    responses(
        (status = 200, description = "Signed attestation token", body = AttestResponse),
        (status = 400, description = "Invalid request"),
        (status = 502, description = "Enclave attestation failed")
    )
)]
async fn attest(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, AppError> {
    // Parse and validate the enclave URL.
    let mut url = Url::parse(&request.enclave_url)?;
    if url.scheme() != "https" {
        return Err(AppError::EnclaveResponse(
            "enclave_url must be https".to_string(),
        ));
    }

    // Enforce an optional allowlist to avoid SSRF and unsafe targets.
    let host = url
        .host_str()
        .ok_or_else(|| AppError::EnclaveResponse("enclave_url host missing".to_string()))?
        .to_string();

    if !state.config.allowed_enclave_hosts.is_empty()
        && !is_host_allowed(&host, url.port_or_known_default(), &state.config.allowed_enclave_hosts)
    {
        return Err(AppError::EnclaveResponse("enclave host not allowed".to_string()));
    }

    url.set_path("/attestation/public-key");
    url.set_query(None);

    // RA-TLS handshake to the enclave and fetch its public encryption key.
    let ratls = state.ratls.clone();
    let enclave_public_key =
        tokio::task::spawn_blocking(move || fetch_enclave_public_key(url, ratls)).await??;

    // Create signed JWT with a short lifetime.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| AppError::Config(format!("clock error: {err}")))?;
    let iat = now.as_secs();
    let exp = iat + state.config.token_ttl_secs;

    let claims = AttestationClaims {
        iss: state.config.issuer.clone(),
        sub: "enclave-attestation".to_string(),
        iat,
        exp,
        enclave_url: request.enclave_url,
        enclave_public_key: enclave_public_key.clone(),
        policy: PolicyClaims {
            mrenclave: state.config.expected_mrenclave.clone(),
            mrsigner: state.config.expected_mrsigner.clone(),
            isv_prod_id: state.config.expected_isv_prod_id.clone(),
            isv_svn: state.config.expected_isv_svn.clone(),
        },
        nonce: request.nonce,
    };

    let token = encode(&Header::new(Algorithm::ES256), &claims, &state.encoding_key)?;

    Ok(Json(AttestResponse {
        token,
        enclave_public_key,
        expires_at: exp,
    }))
}

// Allowlist helper: match exact host or host:port.
fn is_host_allowed(host: &str, port: Option<u16>, allowlist: &[String]) -> bool {
    let host_only = host.to_string();
    let host_with_port = port.map(|value| format!("{host}:{value}"));
    allowlist.iter().any(|allowed| {
        if allowed == &host_only {
            return true;
        }
        if let Some(host_port) = &host_with_port {
            if allowed == host_port {
                return true;
            }
        }
        false
    })
}

fn fetch_enclave_public_key(
    url: Url,
    ratls: Arc<std::sync::Mutex<RaTlsVerifier>>,
) -> Result<Jwk, AppError> {
    // Fetch the enclave's public encryption key over the RA-TLS channel.
    // Uses OpenSSL to access the raw certificate for RA-TLS verification.
    let host = url
        .host_str()
        .ok_or_else(|| AppError::EnclaveResponse("enclave_url host missing".to_string()))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| AppError::EnclaveResponse("enclave_url port missing".to_string()))?;
    let path = url.path().to_string();
    let host_header = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };

    let address = format!("{host}:{port}");
    let stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(15)))?;

    // Configure OpenSSL client and attach the RA-TLS verifier callback.
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_verify(SslVerifyMode::PEER);

    let ratls_clone = ratls.clone();
    builder.set_verify_callback(SslVerifyMode::PEER, move |_preverify_ok, x509_ctx| {
        if x509_ctx.error_depth() != 0 {
            return true;
        }
        let cert = match x509_ctx.current_cert() {
            Some(cert) => cert,
            None => return false,
        };
        let der = match cert.to_der() {
            Ok(der) => der,
            Err(_) => return false,
        };
        let guard = match ratls_clone.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        match guard.verify_der(&der) {
            Ok(_) => true,
            Err(err) => {
                warn!(error = %err, "RA-TLS verification failed");
                false
            }
        }
    });

    let connector = builder.build();
    // Perform the TLS handshake (RA-TLS verification happens above).
    let mut tls_stream = connector
        .connect(&host, stream)
        .map_err(|err| AppError::EnclaveResponse(format!("TLS handshake failed: {err}")))?;

    // Minimal HTTP/1.1 request to avoid extra client dependencies.
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    tls_stream.write_all(request.as_bytes())?;
    tls_stream.flush()?;

    let mut response_bytes = Vec::new();
    tls_stream.read_to_end(&mut response_bytes)?;

    // Parse HTTP response to locate the JSON body.
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    let status = response.parse(&response_bytes)?;
    let header_len = match status {
        httparse::Status::Complete(len) => len,
        httparse::Status::Partial => {
            return Err(AppError::EnclaveResponse("incomplete HTTP response".to_string()))
        }
    };

    let status_code = response.code.unwrap_or(0);
    if status_code != 200 {
        return Err(AppError::EnclaveResponse(format!(
            "enclave returned status {status_code}"
        )));
    }

    let body = &response_bytes[header_len..];
    let jwk: Jwk = serde_json::from_slice(body)?;
    Ok(jwk)
}

// Build a JWK from a P-256 public key; kid = SHA-256 over the uncompressed point.
fn jwk_for_public_key(public_key: &p256::PublicKey, use_: &'static str, alg: &'static str) -> Jwk {
    let encoded = public_key.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[1..33]);
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[33..65]);
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

// OpenAPI registry for Swagger UI.
#[derive(OpenApi)]
#[openapi(
    paths(health, jwks, attest),
    components(schemas(Jwk, JwkSet, AttestRequest, AttestResponse, PolicyClaims, AttestationClaims))
)]
struct ApiDoc;
