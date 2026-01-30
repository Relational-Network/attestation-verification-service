# Attestation Verification Service (AVS)

Non-browser service that verifies SGX RA-TLS (DCAP) and issues browser-verifiable JWTs
binding user identity, role, and enclave public key to the attested enclave.

## What it does

1. Receives attestation requests from browser/API clients
2. Connects to enclave using RA-TLS (verifies SGX quote via DCAP)
3. Fetches the enclave's public encryption key from `/attestation/public-key`
4. Signs a short-lived JWT containing user identity, role, enclave key, and policy
5. Publishes its signing public key at `/.well-known/jwks.json` for verification

## JWT Token Structure

### Claims

| Claim | Description |
|-------|-------------|
| `iss` | Issuer: `attestation-verification-service` |
| `sub` | Subject: user identifier (from request or `anonymous`) |
| `aud` | Audience: `relational-sdk` |
| `iat` | Issued at timestamp |
| `exp` | Expiration timestamp |
| `role` | User role: `admin`, `user`, or `read_only` |
| `enclave_url` | URL of the attested enclave |
| `enclave_public_key` | JWK of enclave's P-256 encryption key |
| `policy` | Enclave identity policy (MRENCLAVE, MRSIGNER, ISV) |
| `nonce` | Optional replay protection nonce |

### Example Token Payload

```json
{
  "iss": "attestation-verification-service",
  "sub": "alice@example.com",
  "aud": "relational-sdk",
  "iat": 1700000000,
  "exp": 1700000300,
  "role": "admin",
  "enclave_url": "https://127.0.0.1:8080",
  "enclave_public_key": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "...",
    "use": "enc",
    "alg": "ECDH-ES",
    "kid": "..."
  },
  "policy": {
    "mrenclave": "69a1cdc6...",
    "mrsigner": "777d23b7...",
    "isv_prod_id": "0",
    "isv_svn": "0"
  }
}
```

### Verifying Tokens

Clients should verify tokens using the JWKS endpoint:

```javascript
// JavaScript example using jose library
import * as jose from 'jose';

const jwks = jose.createRemoteJWKSet(
  new URL('http://avs-host:9100/.well-known/jwks.json')
);

const { payload } = await jose.jwtVerify(token, jwks, {
  issuer: 'attestation-verification-service',
  audience: 'relational-sdk',
});

// Use payload.enclave_public_key for encryption
// Use payload.role for authorization decisions
```

## Required environment

| Variable | Description |
|----------|-------------|
| `AVS_SIGNING_KEY_PATH` | EC P-256 private key in PEM (PKCS8) |
| `AVS_EXPECTED_MRSIGNER` | Expected MRSIGNER (hex) or `any` |
| `AVS_EXPECTED_MRENCLAVE` | Expected MRENCLAVE (hex) or `any` |

Note: At least one of `AVS_EXPECTED_MRSIGNER` or `AVS_EXPECTED_MRENCLAVE` must be set (not `any`).

## Optional environment

| Variable | Default | Description |
|----------|---------|-------------|
| `AVS_BIND_ADDR` | `0.0.0.0:9100` | Listen address |
| `AVS_ISSUER` | `attestation-verification-service` | JWT issuer claim |
| `AVS_TOKEN_TTL_SECS` | `300` | Token lifetime in seconds |
| `AVS_RATLS_VERIFY_LIB` | `libra_tls_verify_dcap.so` | RA-TLS verifier library |
| `AVS_EXPECTED_ISV_PROD_ID` | `any` | Expected ISV Product ID |
| `AVS_EXPECTED_ISV_SVN` | `any` | Expected ISV Security Version |
| `AVS_ALLOWED_ENCLAVE_HOSTS` | (none) | Comma-separated allowlist |
| `AVS_ALLOW_DEBUG_ENCLAVE` | `0` | Set to `1` for debug enclaves |
| `AVS_ALLOW_OUTDATED_TCB` | `0` | Set to `1` to allow outdated TCB |
| `AVS_ALLOW_HW_CONFIG_NEEDED` | `0` | Set to `1` to allow HW config needed |
| `AVS_ALLOW_SW_HARDENING_NEEDED` | `0` | Set to `1` to allow SW hardening needed |
| `AVS_TLS_CERT_PATH` | (none) | Path to TLS certificate (PEM) - enables HTTPS |
| `AVS_TLS_KEY_PATH` | (none) | Path to TLS private key (PEM) - enables HTTPS |

## Development

### Run locally (HTTP)

```bash
# Generate signing key (first time only)
cd secrets && ./generate-keys.sh

# Run service (HTTP mode)
export AVS_SIGNING_KEY_PATH=./secrets/avs-signing-key.pem
export AVS_EXPECTED_MRSIGNER=<hex>
export AVS_ALLOW_DEBUG_ENCLAVE=1  # for development only
cargo run
```

### Run locally (HTTPS)

```bash
# Generate TLS certificate (self-signed for development)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout secrets/avs-tls.key -out secrets/avs-tls.crt -days 365 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Run service (HTTPS mode)
export AVS_SIGNING_KEY_PATH=./secrets/avs-signing-key.pem
export AVS_TLS_CERT_PATH=./secrets/avs-tls.crt
export AVS_TLS_KEY_PATH=./secrets/avs-tls.key
export AVS_EXPECTED_MRSIGNER=<hex>
export AVS_ALLOW_DEBUG_ENCLAVE=1
cargo run

# Test with curl (-k for self-signed cert)
curl -sk https://127.0.0.1:9100/health
```

### Docker (HTTP)

> **Note:** The Docker image is based on Ubuntu 20.04 (focal) because `az-dcap-client`
> requires this specific version for Azure DCsv3 SGX VMs.

```bash
# Build
docker build -t avs .

# Run (HTTP mode, host network for localhost enclave access)
docker run -d \
  --name avs \
  --network host \
  -v ./secrets:/secrets:ro \
  -e AVS_SIGNING_KEY_PATH=/secrets/avs-signing-key.pem \
  -e AVS_EXPECTED_MRSIGNER=<hex> \
  -e AVS_ALLOW_DEBUG_ENCLAVE=1 \
  -e AVS_ALLOW_OUTDATED_TCB=1 \
  avs
```

### Docker (HTTPS)

```bash
# Generate TLS certificate first (see above)

# Run (HTTPS mode)
docker run -d \
  --name avs \
  --network host \
  -v ./secrets:/secrets:ro \
  -e AVS_SIGNING_KEY_PATH=/secrets/avs-signing-key.pem \
  -e AVS_TLS_CERT_PATH=/secrets/avs-tls.crt \
  -e AVS_TLS_KEY_PATH=/secrets/avs-tls.key \
  -e AVS_EXPECTED_MRSIGNER=<hex> \
  -e AVS_ALLOW_DEBUG_ENCLAVE=1 \
  -e AVS_ALLOW_OUTDATED_TCB=1 \
  avs

# Test
curl -sk https://127.0.0.1:9100/health
```

### Quick E2E Test (HTTPS)

```bash
# 1. Generate keys (if not exists)
mkdir -p secrets
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out secrets/avs-signing-key.pem
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout secrets/avs-tls.key -out secrets/avs-tls.crt -days 365 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# 2. Start AVS container (HTTPS)
docker run --rm -d --name avs --network host \
  -v $(pwd)/secrets:/secrets:ro \
  -e AVS_SIGNING_KEY_PATH=/secrets/avs-signing-key.pem \
  -e AVS_TLS_CERT_PATH=/secrets/avs-tls.crt \
  -e AVS_TLS_KEY_PATH=/secrets/avs-tls.key \
  -e AVS_EXPECTED_MRSIGNER=777d23b75d3974a2a67224e49e78a45f65537861605cc0b86cb92e8d79a8d243 \
  -e AVS_ALLOW_DEBUG_ENCLAVE=1 \
  -e AVS_ALLOW_OUTDATED_TCB=1 \
  avs

# 3. Test health
curl http://127.0.0.1:9100/health

# 4. Test attestation (requires enclave running on port 8080)
curl -s -X POST http://127.0.0.1:9100/v1/attest \
  -H 'Content-Type: application/json' \
  -d '{"enclave_url":"https://127.0.0.1:8080"}' | jq
```

### Generate a signing key

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out avs-signing-key.pem
```

## CI/CD

This repo uses GitHub Actions:

- **CI** (`.github/workflows/ci.yml`): Runs on push/PR to main/staging
  - Lint (rustfmt, clippy)
  - Test
  - Build Docker image
  - Security audit

- **CD** (`.github/workflows/cd-staging.yml`): Runs on push to staging
  - Build and push Docker image to GHCR
  - Deploy to staging environment

### Required Secrets

| Secret | Description |
|--------|-------------|
| `GITHUB_TOKEN` | Automatic, for GHCR |
| `STAGING_SSH_HOST` | (optional) SSH host for deployment |

## API

All API endpoints are versioned with `/v1/` prefix. Well-known endpoints remain unversioned per RFC standards.

### POST /v1/attest

Request attestation token for an enclave.

**Request:**
```json
{
  "enclave_url": "https://127.0.0.1:8080",
  "user_id": "alice@example.com",
  "role": "admin",
  "nonce": "random-string"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "enclave_public_key": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  },
  "expires_at": 1700000300
}
```

**Fields:**
- `user_id` (optional): User identifier, defaults to `anonymous`
- `role` (optional): User role, defaults to `user`
- `nonce` (optional): Client-provided nonce for replay protection

### GET /.well-known/jwks.json

Returns the AVS public key in JWK format for token verification.

### GET /docs

Serves Swagger UI (OpenAPI at `/api-doc/openapi.json`).

## Notes

- The AVS performs RA-TLS verification using Gramine's DCAP verifier library (DCAP only, EPID not supported).
- The enclave must expose `GET /v1/attestation/public-key` over RA-TLS.
- Tokens include user identity and role for RBAC in the enclave.
- All API endpoints use `/v1/` prefix for versioning.

## Module Structure

The codebase is organized into logical modules:

| Module | Description |
|--------|-------------|
| `main.rs` | Application entry point, router setup |
| `config.rs` | Environment configuration |
| `error.rs` | Error types and HTTP responses |
| `handlers.rs` | HTTP request handlers |
| `jwk.rs` | JWK types and key utilities |
| `ratls.rs` | RA-TLS verifier FFI wrapper |

## End-to-end verification (manual)

1. Build and run the enclave server with RA-TLS enabled:

   ```bash
   cd .../relational-sdk
   make SGX=1 RA_TYPE=dcap
   gramine-sgx relational-sdk
   ```

2. Extract measurements from the enclave SIGSTRUCT:

   ```bash
   gramine-sgx-sigstruct-view relational-sdk.sig
   ```

3. Run the AVS with expected measurements:

   ```bash
   cd .../attestation-verification-service
   export AVS_SIGNING_KEY_PATH=/path/to/avs-signing-key.pem
   export AVS_EXPECTED_MRSIGNER=<hex>
   export AVS_EXPECTED_ISV_PROD_ID=<decimal>
   export AVS_EXPECTED_ISV_SVN=<decimal>
   cargo run
   ```

4. Request attestation:

   ```bash
   curl -s -X POST http://127.0.0.1:9100/v1/attest \
     -H 'Content-Type: application/json' \
     -d '{"enclave_url":"https://127.0.0.1:8080"}' | jq
   ```

5. Use the token to call protected enclave endpoints:

   ```bash
   TOKEN=$(curl -s -X POST http://127.0.0.1:9100/v1/attest \
     -H 'Content-Type: application/json' \
     -d '{"enclave_url":"https://127.0.0.1:8080"}' | jq -r '.token')

   curl -sk https://127.0.0.1:8080/v1/data/query \
     -H "Authorization: Bearer $TOKEN" | jq
   ```

## License

This project is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later), see LICENSE for details.