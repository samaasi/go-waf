# Security Operations: Live Control & Virtual Patching

Go-WAF is built for real-time security operations. This guide explains how to use the Admin API and Dashboard to mitigate emerging threats instantly.

## 1. The Virtual Patching Workflow

When a new high-profile vulnerability (like a 0-day) is discovered, you need to protect your servers *before* your developers can patch the underlying code. This is **Virtual Patching**.

### Step 1: Create a Mitigation Rule
Define a lightweight CRSLang or Regex rule to block the specific exploit pattern.
```yaml
id: "VIRTUAL-PATCH-LOG4J"
name: "Mitigation for CVE-2021-44228"
patterns:
  - "${jndi:ldap://"
action: "BLOCK"
```

### Step 2: Deploy Instantly
Push the rule to your Go-WAF cluster via the Admin API or the `/admin/reload` endpoint. The WAF will hot-reload its rules in milliseconds without dropping any traffic.

---

## 2. Admin API Reference

### Real-Time Rule Toggling
You can enable or disable any security rule instantly.
`POST /admin/rules/:id/toggle`
```json
{ "enabled": false }
```
*Useful for quickly disabling a noisy rule that is causing False Positives.*

### System Health & Metrics
Monitor your WAF's performance in real-time.
`GET /admin/metrics` (Prometheus Format)

**Key Metrics to Watch:**
- `waf_blocked_total`: Are you seeing a spike in attacks?
- `waf_inspection_latency_seconds`: Is the WAF adding too much delay? (Should be < 0.001s).

---

## 3. Real-Time Dashboard
Access the glassmorphism Dashboard at `http://<admin-host>:9091/admin/dashboard`.

- **Visual Traffic Feed**: Watch attacks as they happen.
- **Rule Inventory**: Search through all active rules across all engines (ML, Regex, CRS).
- **One-Click Toggles**: Quickly flip rules between `Enabled` and `Disabled` states from the UI.

---

## 4. Tuning for Zero-False Positives
If Go-WAF is blocking legitimate users:
1. **Check the Audit Log**: Look for the `MatchedData` field to see exactly what triggered the block.
2. **Adjust ML Thresholds**: In `config.yaml`, you can raise the `entropy_threshold` or the `kl_divergence_threshold` to be less aggressive.
3. **Engine Bypass**: You can disable specific engines (like the ML engine) for trusted internal IP ranges using the `Pipeline` configuration.
