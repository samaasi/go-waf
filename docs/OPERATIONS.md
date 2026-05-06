# Operations & Admin Guide: Managing Go-WAF

Go-WAF provides real-time visibility and control through its Admin API and Security Dashboard.

## 1. Security Dashboard
The visual command center for your WAF.
- **Access**: `http://<admin-host>:8081/admin/dashboard`
- **Features**:
    - Real-time Allowed/Blocked traffic counters.
    - Attack trend visualization.
    - Hot-toggle rule switch (Enable/Disable rules instantly).

## 2. Admin API Reference

### List Active Rules
Retrieve the current rule inventory and their state across all engines.
`GET /admin/rules`

### Toggle Rule State
Enable or disable a specific rule at runtime.
`POST /admin/rules/:id/toggle`
```json
{ "enabled": false }
```

### Metrics Endpoint
Scrape multi-dimensional metrics for Prometheus/Grafana.
`GET /admin/metrics`

## 3. Observability Signals

### Prometheus Metrics
- `waf_requests_total`: Counter of all processed requests.
- `waf_blocked_total`: Counter of blocked requests by engine.
- `waf_inspection_latency_seconds`: Histogram of analysis time.
- `waf_rule_match_total`: Counter of matches per rule ID.

### Audit Logging
Audit logs are streamed asynchronously to avoid request latency.
- **Log Format**: JSON with correlation ID.
- **Variables**: Captures matched data, remote IP, path, and engine ID.

## 4. Emergency Procedures

### Bypass Mode
If the WAF is causing an outage, switch to `passthrough` mode via environment variable or API.
```bash
WAF_MODE=passthrough
```

### Force Reload Rules
Force a complete reload of the CRSLang and Regex engines.
`POST /admin/reload`
