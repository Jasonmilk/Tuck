# Tuck — Helix ecosystem immune system
# Multi-stage build: Rust builder → minimal runtime

# ============================================================================
# Stage 1: Build
# ============================================================================
FROM rust:1.75-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifest files first (layer caching)
COPY Cargo.toml Cargo.lock ./
COPY crates/tuck-core/Cargo.toml crates/tuck-core/
COPY crates/tuck/Cargo.toml crates/tuck/

# Create dummy source files to cache dependencies
RUN mkdir -p crates/tuck-core/src crates/tuck/src \
    && echo "fn main() {}" > crates/tuck/src/main.rs \
    && echo "" > crates/tuck-core/src/lib.rs \
    && cargo build --release --workspace 2>/dev/null || true

# Copy actual source code
COPY crates/ crates/
COPY config.example.toml ./

# Build in release mode
RUN cargo build --release --workspace

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --system tuck \
    && useradd --system --gid tuck --home-dir /var/lib/tuck --shell /usr/sbin/nologin tuck

# Create directories
RUN mkdir -p /etc/tuck /var/log/tuck /var/lib/tuck \
    && chown -R tuck:tuck /etc/tuck /var/log/tuck /var/lib/tuck

# Copy binary from builder
COPY --from=builder /build/target/release/tuck /usr/local/bin/tuck

# Copy example config
COPY --from=builder /build/config.example.toml /etc/tuck/config.example.toml

# Expose ports
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD tuck --version || exit 1

# Run as non-root user
USER tuck

# Default command
CMD ["tuck", "--config", "/etc/tuck/config.toml"]
