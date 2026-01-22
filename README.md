# Attestation Verification Service (AVS)

Non-browser service that verifies SGX RA-TLS (DCAP) and issues a browser-verifiable JWT
binding an enclave public key to the attested enclave identity policy.

## What it does
- Connects to an enclave RA-TLS endpoint.
- Verifies the SGX quote via `libra_tls_verify_dcap.so`.
- Fetches the enclave's public encryption key from `/attestation/public-key`.
- Signs a short-lived JWT containing the key + policy.
- Publishes its signing public key at `/.well-known/jwks.json`.

## Required environment

- `AVS_SIGNING_KEY_PATH` (required): EC P-256 private key in PEM (PKCS8).
- `AVS_EXPECTED_MRSIGNER` or `AVS_EXPECTED_MRENCLAVE`: hex string, or `any`.
- `AVS_EXPECTED_ISV_PROD_ID` (default `any`), `AVS_EXPECTED_ISV_SVN` (default `any`).

## Optional environment

- `AVS_BIND_ADDR` (default `0.0.0.0:9100`)
- `AVS_ISSUER` (default `attestation-verification-service`)
- `AVS_TOKEN_TTL_SECS` (default `300`)
- `AVS_RATLS_VERIFY_LIB` (default `libra_tls_verify_dcap.so`)
- `AVS_ALLOWED_ENCLAVE_HOSTS` (comma-separated allowlist, optional)
- `AVS_ALLOW_DEBUG_ENCLAVE` (`1` to allow debug enclaves)
- `AVS_ALLOW_OUTDATED_TCB` (`1` to allow outdated TCB)
- `AVS_ALLOW_HW_CONFIG_NEEDED` (`1` to allow HW_CONFIG_NEEDED)
- `AVS_ALLOW_SW_HARDENING_NEEDED` (`1` to allow SW_HARDENING_NEEDED)

## Run

```bash
export AVS_SIGNING_KEY_PATH=/path/to/avs-signing-key.pem
export AVS_EXPECTED_MRSIGNER=<hex>
export AVS_EXPECTED_ISV_PROD_ID=1
export AVS_EXPECTED_ISV_SVN=1

cargo run
```

## Generate a signing key (dev)

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out avs-signing-key.pem
```

## API

- `POST /attest`
  - Request: `{ "enclave_url": "https://127.0.0.1:8443", "nonce": "..." }`
  - Response: `{ "token": "...", "enclave_public_key": { ...JWK... }, "expires_at": 1234567890 }`

- `GET /.well-known/jwks.json` returns the AVS public key in JWK format.
- `GET /docs` serves Swagger UI (OpenAPI at `/api-doc/openapi.json`).

## Notes

- The AVS performs RA-TLS verification using Gramine's DCAP verifier library.
- The enclave must expose `GET /attestation/public-key` over RA-TLS.

## End-to-end verification (manual)

1. Build and run the enclave server with RA-TLS enabled:

   ```bash
   cd /home/binglekruger/development/iob-micres/relational-sdk
   make SGX=1 RA_TYPE=dcap
   gramine-sgx relational-sdk
   ```

2. Extract measurements from the enclave SIGSTRUCT:

   ```bash
   gramine-sgx-sigstruct-view relational-sdk.sig
   ```

3. Run the AVS with expected measurements:

   ```bash
   cd /home/binglekruger/development/iob-micres/attestation-verification-service
   export AVS_SIGNING_KEY_PATH=/path/to/avs-signing-key.pem
   export AVS_EXPECTED_MRSIGNER=<hex>
   export AVS_EXPECTED_ISV_PROD_ID=<decimal>
   export AVS_EXPECTED_ISV_SVN=<decimal>
   cargo run
   ```

4. Request attestation:

   ```bash
   curl -s -X POST http://127.0.0.1:9100/attest \
     -H 'content-type: application/json' \
     -d '{"enclave_url":"https://127.0.0.1:8080"}'
   ```

## License

This project is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later), see LICENSE for details.