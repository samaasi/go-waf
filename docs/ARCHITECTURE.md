# Go-WAF Architecture: Parallel Security Orchestration

Go-WAF is architected for the modern cloud-native era, where latency is a top-tier security metric. This document details the internal mechanics of our analysis pipeline and detection engines.

## 1. High-Performance Analysis Pipeline

Traditional WAFs (like ModSecurity) use a sequential "Rule Loop" which increases latency as more rules are added. Go-WAF uses a **Parallel Engine Dispatcher**.

### Parallel Execution Flow
1. **Request Intake**: Headers and Body (sampled) are buffered in a zero-allocation pool.
2. **Phase 1 (Headers)**: Parallel execution of GeoIP, ML-Client Fingerprinting, and Schema validation.
3. **Phase 2 (Body)**: Parallel dispatch to CRSLang, Regex, Libinjection, and ML-Statistical engines.
4. **Early Exit**: If any "High Confidence" engine returns a `BLOCK` action, all other active engines are canceled immediately to save CPU cycles.
5. **Score Aggregation**: If no engine blocks, individual anomaly scores are summed and compared against the global threshold.

## 2. Advanced Detection Engines

### ML-Lite: High-Dimensional Fingerprinting
Our most advanced engine, designed for **Zero-Day Protection**.
- **KL-Divergence**: We compare the byte distribution of the request against a pre-computed "Normal Traffic" model. Large statistical distances (KL > 10.0) indicate machine-generated or obfuscated payloads.
- **N-gram Anomaly**: Scans for character transition probabilities. This is highly effective at catching "Living off the Land" attacks and Log4j bypasses that use unusual character sequences.
- **Entropy Shield**: Detects high-entropy payloads (encrypted/compressed) which are often used for data exfiltration or C2 communication.

### CRSLang: Modern Ruleset Engine
A YAML-native implementation of the OWASP CRS logic.
- **Stateful Persistence**: Uses Redis to track variables across multiple requests (e.g., `TX.anomaly_score`, `IP.reputation`).
- **GitOps Compatible**: Rules are defined in human-readable YAML, making them easy to version control and audit.

### DLP: Response-Phase Data Protection
The DLP engine operates in the response phase to prevent data leaks.
- **Sensitive Data Detection**: Pre-built patterns for Credit Cards (validated via Luhn), PII, and Cloud Provider secrets.
- **Automatic Masking**: Go-WAF can be configured to "mask" sensitive data (e.g., `XXXX-XXXX-XXXX-1234`) instead of blocking the entire response, maintaining application availability.

## 3. Protocol Awareness (gRPC & HTTP/2)
Go-WAF includes a native **gRPC/Protobuf Parser**. 
- It understands binary Protobuf frames and extracts individual field values.
- These fields are then mapped back to the standard WAF `ARGS` collection, allowing you to use existing security rules against binary gRPC traffic without any modifications.

## 4. Distributed State Architecture
Go-WAF implements a two-tier state management system:
- **L1 Cache (Local)**: High-speed in-memory LRU cache for millisecond rate-limiting and session decisions.
- **L2 Store (Redis)**: Distributed state for cluster-wide reputation, session persistence, and global anomaly scoring.
