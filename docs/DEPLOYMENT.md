# Deployment Guide: Go-WAF Production Orchestration

This guide covers the deployment of Go-WAF across various environments, from local development to large-scale Kubernetes clusters.

## 1. Local Development (Docker Compose)
The easiest way to get started with the full stack (WAF + Redis + Prometheus + Dashboard).

```bash
docker-compose up -d
```

## 2. Kubernetes Deployment

### Helm Chart
Deploy Go-WAF as a centralized gateway or as a sidecar for specific namespaces.

```bash
helm install go-waf ./deployments/helm/go-waf
```

### K8s Operator
For automated policy reconciliation and zero-touch protection.
1. Install the CRDs: `kubectl apply -f deployments/operator/crd.yaml`
2. Define a Security Policy:
```yaml
apiVersion: waf.samaasi.com/v1
kind: SecurityPolicy
metadata:
  name: api-protection
spec:
  mode: blocking
  dlp: enabled
  ml_anomaly: high_fidelity
```

## 3. Envoy / Service Mesh Integration (WASM)
Go-WAF provides a high-performance WASM filter compiled with TinyGo.

1. Build the filter: `tinygo build -o waf.wasm -target=wasi internal/wasm/main.go`
2. Configure Envoy:
```yaml
http_filters:
- name: envoy.filters.http.wasm
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
    config:
      name: "go-waf-filter"
      vm_config:
        runtime: "envoy.wasm.runtime.v8"
        code:
          local:
            filename: "/etc/envoy/waf.wasm"
```

## 4. Nginx Integration

### Option A: Nginx `auth_request` (High Performance)
Use Go-WAF as a "Security Decider." Nginx will call Go-WAF for a pre-check before allowing traffic to the upstream.

```nginx
location / {
    auth_request /waf-check;
    proxy_pass http://my_app;
}

location = /waf-check {
    internal;
    proxy_pass http://waf-internal:8081/admin/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}
```

### Option B: Nginx Proxy Pass
Nginx handles TLS/SSL and forwards the decrypted traffic to Go-WAF.

```nginx
location / {
    proxy_pass http://go-waf-proxy:9090;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

## 5. Standalone Reverse Proxy
Run Go-WAF as a standalone binary to protect upstream services.

```bash
WAF_MODE=blocking \
UPSTREAM_URL=http://localhost:8080 \
./go-waf-proxy
```

## 5. Serverless / Lambda Middleware
Go-WAF can be integrated as a "Lambda Layer" or middleware to protect serverless functions.

```go
func main() {
    h := http.HandlerFunc(MyHandler)
    lambda.Start(waf.Middleware(h))
}
```

---

## Performance Tuning
- **Max Body Sample**: Adjust `WAF_MAX_BODY_SAMPLE` (default 1MB) for deep inspection vs performance.
- **Worker Pool**: Set `WAF_WORKER_POOL` for parallel engine execution.
- **L1 Cache**: Configure `WAF_L1_CACHE_SIZE` (default 10k) for local rate-limit decisions.
