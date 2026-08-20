# Fixed Go Dockerfile with proper permissions
FROM golang:1.26.2-bookworm AS build

# Install dependencies and update debian packages
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get dist-upgrade -y && \
    apt-get install -y --no-install-recommends git curl build-essential wget pkg-config libssl-dev make && \
    apt-get clean

# Create app directory
RUN mkdir -p /app
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire project
COPY . .

# Build the Go application and compile the circuits
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o last_build/executables/server ./cmd/server/main.go
RUN go run cmd/setup/setup_r1cs.go

# Ensure proper permissions for all built files
RUN chmod -R 755 /app

# Production stage
FROM debian:13.2-slim

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install runtime dependencies
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends curl make && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create app directory with proper ownership
RUN mkdir -p /app && chown -R appuser:appuser /app
WORKDIR /app

# Copy files with proper ownership
COPY --from=build --chown=appuser:appuser /app/last_build ./last_build
COPY --from=build --chown=appuser:appuser /app/pkg ./pkg
COPY --from=build --chown=appuser:appuser /app/config ./config
COPY --from=build --chown=appuser:appuser /app/primitives ./primitives
COPY --from=build --chown=appuser:appuser /app/poseidon ./poseidon

# Copy your startup script with proper ownership and permissions
COPY --chown=appuser:appuser run_gnark_server.sh ./run_gnark_server.sh
RUN chmod +x ./run_gnark_server.sh

# Ensure all directories have proper permissions
RUN chown -R appuser:appuser /app && \
    chmod -R 755 /app

# Create any directories that might be needed at runtime
RUN mkdir -p /app/tmp /app/logs && \
    chown -R appuser:appuser /app/tmp /app/logs && \
    chmod -R 775 /app/tmp /app/logs

# Switch to non-root user
USER appuser

# Expose the necessary port
EXPOSE 3003

# Run your bash script
CMD ["./run_gnark_server.sh"]