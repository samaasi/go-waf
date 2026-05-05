FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=${VERSION:-dev}" \
    -trimpath \
    -o /waf-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="go-waf" \
      org.opencontainers.image.description="Enterprise Web Application Firewall" \
      org.opencontainers.image.vendor="samaasi"
WORKDIR /
COPY --from=builder --chmod=0555 /waf-server /waf-server
COPY --from=builder --chmod=0444 /app/configs/ /configs/
USER 65532:65532
ENV WAF_CONFIG_DIR=/configs
EXPOSE 8080
ENTRYPOINT ["/waf-server"]