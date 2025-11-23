FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /waf-server ./cmd/waf-server

FROM gcr.io/distroless/base-debian12
WORKDIR /
COPY --from=builder /waf-server /waf-server
COPY configs/ /configs/
USER 65532:65532
ENV WAF_CONFIG_DIR=/configs
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://localhost:8080/health || exit 1
ENTRYPOINT ["/waf-server"]