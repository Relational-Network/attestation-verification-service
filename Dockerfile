# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Multi-stage build for AVS (Attestation Verification Service)
# Uses Ubuntu 20.04 for compatibility with az-dcap-client

# === Build Stage ===
FROM ubuntu:20.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /build

# Install Rust and build dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock* ./

# Create dummy src to build dependencies
RUN mkdir src && \
    echo 'fn main() { println!("placeholder"); }' > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source code
COPY src ./src

# Build the actual binary (touch to invalidate cache)
RUN touch src/main.rs && cargo build --release

# === Runtime Stage ===
FROM ubuntu:20.04 AS runtime

# Install runtime dependencies and Gramine RA-TLS DCAP library
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl1.1 \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Add Gramine repository
RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg \
    https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ focal main" \
    > /etc/apt/sources.list.d/gramine.list

# Add Intel SGX repository for DCAP libraries
RUN curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc \
    https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" \
    > /etc/apt/sources.list.d/intel-sgx.list

# Add Microsoft repository for Azure DCAP client
RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor \
    > /usr/share/keyrings/microsoft-prod.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/20.04/prod focal main" \
    > /etc/apt/sources.list.d/microsoft-prod.list

# Install Gramine RA-TLS and DCAP libraries (including Azure DCAP client)
RUN apt-get update && apt-get install -y \
    gramine-ratls-dcap \
    libsgx-dcap-quote-verify \
    az-dcap-client \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -r -s /bin/false -u 1000 avs

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/attestation-verification-service /app/avs

# Create directories for secrets and TLS certs
RUN mkdir -p /secrets /tls && chown -R avs:avs /app /secrets /tls

# Switch to non-root user
USER avs

# Expose default port (9100 for both HTTP and HTTPS)
EXPOSE 9100

# Health check - supports both HTTP and HTTPS
# Uses HTTP by default; override CMD if using HTTPS
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsk http://localhost:9100/health || curl -fsk https://localhost:9100/health || exit 1

# Environment variables (override at runtime)
ENV AVS_BIND_ADDR=0.0.0.0:9100
ENV RUST_LOG=info
# TLS is optional - set these to enable HTTPS:
# ENV AVS_TLS_CERT_PATH=/tls/avs.crt
# ENV AVS_TLS_KEY_PATH=/tls/avs.key

# Run the service
ENTRYPOINT ["/app/avs"]
