# ── Stage 1: Build ────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Install git and ca-certificates (needed by some deps)
RUN apk add --no-cache git ca-certificates

# Copy dependency manifests first → cache layer
COPY go.mod go.sum ./
RUN go mod download

# Copy full source
COPY . .

# Build a statically-linked, fully-stripped binary
# CGO_ENABLED=0 is needed because ncruces/go-sqlite3 ships its own
# WASM-based SQLite engine (no CGO required).
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /vulnscan ./cmd/vulnscanner

# ── Stage 2: Runtime ─────────────────────────────────────────────────
FROM alpine:3.19

# Minimal runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create a non-root user
RUN addgroup -S vulnscan && adduser -S -G vulnscan vulnscan

WORKDIR /app

# Copy the compiled binary
COPY --from=builder /vulnscan /app/vulnscan

# The DB file will live here; persist it with a volume
RUN touch /app/vulnscan.db && chown -R vulnscan:vulnscan /app

USER vulnscan

EXPOSE 8080

VOLUME ["/app"]

ENTRYPOINT ["/app/vulnscan"]
CMD ["serve", "--addr", ":8080", "--db", "/app/vulnscan.db"]
