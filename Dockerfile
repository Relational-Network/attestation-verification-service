# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Multi-stage Dockerfile for AVS (Attestation Verification Service)
# Stage 1: Build the binary in Ubuntu 20.04 to ensure library compatibility
# Stage 2: Create minimal runtime image

# =============================================================================
# BUILD STAGE
# =============================================================================
FROM ubuntu:20.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    clang \
    cmake \
    pkg-config \
    libssl-dev \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.92.0
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Copy source code
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

# Build the binary
RUN CC=clang CXX=clang++ cargo build --release

# =============================================================================
# RUNTIME STAGE
# =============================================================================
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
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

# Create non-root user for security with home directory for az-dcap-client cache
RUN useradd -r -s /bin/false -u 1000 -m avs

WORKDIR /app

# Copy binary from build stage
COPY --from=builder /build/target/release/attestation-verification-service /app/avs

# Create directories for secrets and TLS certs
RUN mkdir -p /secrets /tls && chown -R avs:avs /app /secrets /tls /home/avs

# Make binary executable
RUN chmod +x /app/avs

# Switch to non-root user
USER avs

# Expose AVS HTTP port and secret provisioning TLS port
EXPOSE 9100
EXPOSE 4433

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsk http://localhost:9100/health || curl -fsk https://localhost:9100/health || exit 1

# Environment variables
ENV AVS_BIND_ADDR=0.0.0.0:9100
ENV RUST_LOG=info
# Default cert paths point to the /secrets mount (overridden for native dev via env)
ENV SECRET_PROV_CERT=/secrets/avs-tls.crt
ENV SECRET_PROV_KEY=/secrets/avs-tls.key

ENTRYPOINT ["/app/avs"]