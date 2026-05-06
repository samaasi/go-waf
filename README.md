# Go-WAF: Enterprise WAAP & API Security Platform

Go-WAF is a high-performance Web Application and API Protection (WAAP) platform architected for sub-millisecond execution and modern cloud-native environments. It provides deep security for gRPC, HTTP/2, and REST APIs using a multi-layered detection strategy.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/samaasi/go-waf)](https://goreportcard.com/report/github.com/samaasi/go-waf)

## 🛡️ The High-Fidelity Security Strategy

Go-WAF moves beyond legacy signature matching by implementing a **Three-Layer Defense Shield**:

### 1. Statistical Shield (Zero-Day Protection)
Our **ML-Lite Engine** uses high-dimensional fingerprinting (KL-Divergence & N-gram Analysis) to identify anomalous traffic patterns. It detects attacks that have no known signatures—like the next *Log4Shell*—by measuring how much the request's byte distribution deviates from "normal" human traffic.

### 2. Structural Shield (Positive Security Model)
Using native **OpenAPI Schema Enforcement**, Go-WAF ensures that your APIs only receive exactly what they expect. Any request containing unexpected fields, invalid data types, or fuzzed parameters is rejected before it even reaches your application logic.

### 3. Signature & Semantic Shield
We combine the battle-tested **OWASP Core Rule Set (CRS)** with **libinjection** for high-confidence SQLi/XSS detection. Our parallel pipeline executes these checks simultaneously, maintaining sub-millisecond latency even under heavy rule loads.

---

## 🌟 Why Go-WAF?

| Feature | Coraza | Go-WAF |
| :--- | :--- | :--- |
| **Philosophy** | SecLang Parity | **Performance & Modernity** |
| **Pipeline** | Sequential | **Parallel with Short-Circuiting** |
| **Rule Format** | SecLang (Legacy) | **CRSLang (YAML/GitOps Ready)** |
| **Zero-Day** | Basic Signatures | **Statistical KL-Divergence** |
| **L7 Security** | Plugins Required | **Native gRPC/Protobuf Support** |
| **DLP** | Static Patterns | **Dynamic Masking & Secret Detection** |

---

## 🗺️ Development Roadmap

We are committed to making Go-WAF the gold standard for high-performance security. Our current focus areas for the next releases include:

- `[ ]` **Rule Persistence**: Move Admin API rule toggles from in-memory to persistent Redis storage.
- `[ ]` **Enterprise Test Coverage**: Increase statement coverage to **>80%**, targeting the Admin and gRPC layers.
- `[ ]` **Zero-Allocation Audit**: Optimization of the hot-path to ensure absolute zero-allocation per request.
- `[ ]` **Full CRS Parity**: Implementation of complex ModSecurity-style variables (e.g. `MATCHED_VARS_NAMES`).
- `[ ]` **Automated Threat Intel**: Integration with remote rule repositories for real-time signature updates.
- `[ ]` **Integration Hardening**: Restoring full compatibility with the FTW (Framework for Testing WAFs) suite.

## 📚 Documentation Suite

- **[Quickstart Guide](docs/QUICKSTART.md)**: Get running in 5 minutes (for beginners).
- **[Architecture Deep-Dive](docs/ARCHITECTURE.md)**: How our Parallel Pipeline and ML-Lite engine work.
- **[Deployment Patterns](docs/DEPLOYMENT.md)**: Nginx, Docker, Sidecar, and Envoy WASM.
- **[Production Hardening](docs/PRODUCTION.md)**: Expert-level security, scaling, and PGO builds.
- **[Operations & Admin](docs/OPERATIONS.md)**: Real-time dashboard and **Virtual Patching** via API.

---

## 🛠️ Installation

```bash
docker-compose up -d
```
Visit `http://localhost:9091/admin/dashboard` to see your security operations center.

## 🤝 Contributing & Security
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md) for our dev process.
- **Security**: For vulnerability reporting, see [SECURITY.md](SECURITY.md).

## 📄 License
Go-WAF is released under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See [LICENSE](LICENSE) for more information.