# Build stage
FROM rust:latest as builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build for release
RUN cargo build --release

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /app/target/release/selinux-rust-manager /usr/local/bin/

# Create a non-root user
RUN useradd -m -u 1000 selinux-manager

# Switch to non-root user
USER selinux-manager

# Set working directory
WORKDIR /home/selinux-manager

# Expose port
EXPOSE 3000

# Set environment variables
ENV RUST_LOG=info
ENV PORT=3000
ENV BIND_ADDR=0.0.0.0

# Run the binary
CMD ["selinux-rust-manager"]