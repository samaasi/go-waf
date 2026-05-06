# Production Deployment & Hardening Guide

This document provides professional-grade instructions for deploying Go-WAF in mission-critical environments. It assumes familiarity with Go toolchains, Linux security modules, and advanced Nginx orchestration.

## 1. High-Performance Build Process

To achieve maximum throughput, use the following build flags for a stripped, optimized binary.

```bash
# Build with symbol stripping and aggressive optimization
export CGO_ENABLED=1
go build -v -ldflags="-s -w" -o go-waf-prod cmd/proxy/main.go
```

### Profile-Guided Optimization (PGO)
For an additional 2-7% performance boost, collect a profile from a running staging instance and rebuild:
```bash
go build -pgo=default.pgo -o go-waf-prod cmd/proxy/main.go
```

## 2. Systemd Service Hardening
Deploy Go-WAF using a hardened Systemd unit. This configuration restricts the process's ability to escalate privileges or access sensitive filesystem paths.

```ini
[Unit]
Description=Go-WAF Security Gateway
After=network.target redis.service

[Service]
Type=simple
User=gowaf
Group=gowaf
Environment="WAF_HTTP_PORT=9090"
Environment="WAF_ADMIN_PORT=9091"
Environment="WAF_MODE=blocking"
ExecStart=/usr/local/bin/go-waf-prod
Restart=always

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
DeviceAllow=/dev/null rw
ProtectSystem=full
ProtectHome=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

## 3. Professional Nginx Orchestration

### High-Availability Upstream Pool
Configure Nginx to load balance across a Go-WAF cluster with keep-alive connections to minimize TLS handshake overhead.

```nginx
upstream waf_cluster {
    server 10.0.0.10:9090;
    server 10.0.0.11:9090;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    
    location / {
        proxy_pass http://waf_cluster;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## 4. Redis Cluster & State Persistence
In production, ensure Redis is configured for high availability (Sentinel or Cluster). Go-WAF uses the `WAF_REDIS_ADDR` environment variable to connect.

- **Pool Tuning**: Adjust `WAF_REDIS_POOL_SIZE` to match your core count.
- **Circuit Breaking**: Enable `WAF_REDIS_FAIL_OPEN=true` if you prefer to allow traffic during a Redis outage.

## 5. Audit Log Rotation
Go-WAF's audit logs can grow rapidly. Use `logrotate` to manage the high-volume JSON streams.

```text
/var/log/go-waf/audit.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /bin/systemctl kill -s HUP go-waf.service
    endscript
}
```
