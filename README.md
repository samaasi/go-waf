# go-waf

An enterprise-ready Web Application Firewall (WAF) written in Go. It provides a modular analysis pipeline with multiple detection engines, a Gin middleware for enforcement, Redis-backed rate limiting, and production-focused safeguards.

## Features

- Multi-engine inspection: regex signatures, fast keyword scanning (Aho‑Corasick), statistical heuristics
- Centralized scoring with configurable block thresholds
- Safe request handling: body size caps, double-read safe buffering, content-type awareness
- Sliding-window rate limiting with headers and per-route keys
- GeoIP enforcement with allow/block country lists (MaxMind)
- Structured logging with Zap; request correlation via `X-Request-ID`
- Admin API for stats and runtime controls
- Configurable via file and environment variables with sensible defaults
- Docker build (multi-stage) and example configs

## Architecture

- `internal/analysis/engines`: detection engines
  - `regex_engine.go`: JSON-loaded signature rules under `configs/rules/regex_rules.json`
  - `aho_corasick.go`: fast keyword scanning loaded from `configs/rules/keywords.json`
  - `ml_model.go`: statistical heuristics (entropy, special-char ratio)
- `internal/analysis/pipeline.go`: coordinates engines and uses `Scorer` for threat scoring
- `internal/middleware/gin_waf.go`: Gin middleware that rate-limits, buffers request body safely, runs pipeline, and enforces block/allow
- `internal/ratelimit/redis_limiter.go`: sliding-window rate limiter using Redis ZSETs
- `internal/platform/geoip/maxmind.go`: GeoIP lookup via MaxMind DB
- `internal/admin`: admin service and REST endpoints (`/admin/*`)
- `pkg/utils`: utilities such as normalization for evasion resistance

## Quickstart

```sh
go build ./cmd/waf-server
./waf-server
```

Or run directly:

```sh
go run ./cmd/waf-server/main.go
```

Health check:

```sh
curl http://localhost:8080/health
```

## Configuration

- Config file name: `app-config.yaml`
- Default search paths: current directory (`.`), `./configs`, and `WAF_CONFIG_DIR` env var
- Environment overrides use prefix `WAF_` and dot-to-underscore mapping (e.g., `WAF_SECURITY_BLOCK_THRESHOLD`)

Example `configs/app-config.yaml`:

```yaml
server:
  port: "8080"
  mode: "debug" # or "release"
  read_timeout: 30
  write_timeout: 30
  max_body_mb: 10
  trusted_proxies: []

redis:
  host: "127.0.0.1"
  port: 6379
  password: ""
  db: 0

security:
  block_threshold: 50
  rate_limit: 100
  rate_limit_window_seconds: 1
  rate_limit_fail_open: true
  enable_geoip: false
  allow_countries: []
  block_countries: []

log:
  level: "info"
```

Rule packs:

- `configs/rules/regex_rules.json`: regex signatures
- `configs/rules/keywords.json`: keywords for fast scanner
- `configs/rules/GeoLite2-Country.mmdb`: MaxMind database for GeoIP (optional)

## Admin API

- Routes mounted under `/admin`
- `GET /admin/stats`: returns runtime stats (mode, thresholds, rate-limit window, engines count, counters)
- `POST /admin/config/threshold`: update block threshold

## Rate Limiting

- Sliding window with Redis ZSET timestamps
- Per-route keys (`ip:path`) to reduce false positives
- Emits `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `Retry-After` on 429

## Evasion Resistance

- Normalization before matching: URL decode (multi-pass), HTML entity unescape, Unicode NFKC, removal of zero-width/control chars, limited homoglyph mapping
- Applied in both regex and keyword engines

## Testing

- Unit tests:
  - Normalization: `test/normalize_test.go`
  - Engine normalization and matching: `test/engines_test.go`
  - Attack replay harness against local server: `test/server_attack_test.go`
- Attack sample payloads under `test/attack_samples` for replay and benchmarking

Run:

```sh
go test ./...
```

Makefile targets:

```sh
make build
make run
make test
make race
make bench
make lint
```

## Docker

- Multi-stage build in `Dockerfile` produces a distroless image with non-root user

Build and run:

```sh
docker build -t go-waf .
docker run -p 8080:8080 -e WAF_CONFIG_DIR=/configs go-waf
```

## Security Notes

- Block responses are generic; rule details are not exposed to clients
- Secrets (e.g., Redis password) are never logged
- Trusted proxy list should be configured in production for accurate client IP

## Roadmap

- [] Prometheus metrics and OpenTelemetry traces
- [] Rule hot-reload and richer admin controls
- [] Kubernetes manifests (Deployment/Service/ConfigMap/Secret, health probes, HPA)
- [] Programmable WAF engine (JSON DSL/CEL/OPA)
- [] Additional evasions and normalization strategies