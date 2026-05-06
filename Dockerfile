# Step 1: Build the binary
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Copy go mod and sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application
COPY . .

# Build the WAF server and the SecLang compiler
RUN CGO_ENABLED=0 GOOS=linux go build -o go-waf-server ./cmd/server/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o seclang-compiler ./cmd/seclang-compiler/main.go

# Step 2: Runtime image
FROM alpine:latest

# Security: Add a non-root user
RUN adduser -D -u 1000 wafuser

WORKDIR /home/wafuser

# Copy binaries from builder
COPY --from=builder /app/go-waf-server .
COPY --from=builder /app/seclang-compiler .

# Copy default configurations and rules
COPY --from=builder /app/configs ./configs
COPY --from=builder /app/tmp/crs/rules ./tmp/crs/rules

# Create logs directory and set permissions
RUN mkdir -p /home/wafuser/logs && \
    chown -R wafuser:wafuser /home/wafuser

USER wafuser

# Expose WAF proxy port (8080) and Admin API port (8081 - assumed)
EXPOSE 8080
EXPOSE 8081

# Set production environment defaults
ENV WAF_SERVER_MODE=release
ENV WAF_LOG_LEVEL=info

ENTRYPOINT ["./go-waf-server"]