# Go-WAF: Enterprise WAAP & API Security Platform

Go-WAF is a high-performance Web Application and API Protection (WAAP) platform architected for sub-millisecond execution and modern cloud-native environments.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/samaasi/go-waf)](https://goreportcard.com/report/github.com/samaasi/go-waf)

## 🌟 Why Go-WAF?

Go-WAF was built to address the limitations of legacy WAF architectures in high-traffic, low-latency environments.

### Go-WAF vs. Coraza
| Feature | Coraza | Go-WAF |
| :--- | :--- | :--- |
| **Philosophy** | SecLang Parity | **Performance & Modernity** |
| **Pipeline** | Sequential | **Parallel with Short-Circuiting** |
| **Rule Format** | SecLang (Legacy) | **CRSLang (YAML/GitOps Ready)** |
| **Statistical Depth**| Basic | **Native KL-Divergence & Entropy** |
| **L7 Security** | Plugins Required | **Native gRPC/Protobuf/H2 Support** |
| **DLP** | Static Patterns | **Dynamic Masking & Secret Detection** |

### Performance-Validated Security (OWASP CRS)
Go-WAF is designed for **OWASP CRS Compatibility**, but we take a "Performance-First" approach:
- **Curated Core-180**: We ship with 180+ mission-critical rules that provide 95% protection against the OWASP Top 10. This avoids the "False Positive" noise and CPU lag of the full 3000+ rule set.
- **Sub-Millisecond Goal**: By curating the rules, we ensure the WAF adds **less than 1ms** of delay to your requests.
- **Full Depth Available**: You can still load all 3000+ legacy rules if your environment requires extreme security depth over raw performance.

## 🚀 Key Features

- **Sub-Millisecond Latency**: Optimized for high-throughput with <1ms overhead.
- **Multi-Engine Defense**: Combines signature matching, semantic analysis (libinjection), and statistical ML.
- **Data Loss Prevention (DLP)**: Real-time masking of PII, Credit Cards, and Cloud Secrets.
- **Cloud Native**: Native K8s Operator, Prometheus metrics, and Envoy WASM support.

## 📚 Documentation

Get started quickly with our structured documentation:

- **[Quickstart Guide](docs/QUICKSTART.md)**: For beginners and first-time server setups.
- **[Standard Deployment](docs/DEPLOYMENT.md)**: Nginx, Docker, and Sidecar integrations.
- **[Production Hardening](docs/PRODUCTION.md)**: For expert DevOps and mission-critical environments.
- **[Operations & API](docs/OPERATIONS.md)**: Managing the dashboard and live rule toggling.

## 🛠️ Installation

```bash
docker-compose up -d
```
Visit `http://localhost:9091/admin/dashboard` to see your security posture.

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

Go-WAF is released under the **Apache 2.0 License**. See [LICENSE](LICENSE) for more information.