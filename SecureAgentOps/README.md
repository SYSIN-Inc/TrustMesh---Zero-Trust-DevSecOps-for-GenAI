# SecureAgentOps
## Zero-Trust DevSecOps for GenAI Agents at Scale

**Architecture Overview:**

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐     ┌──────────────┐     ┌─────────────┐
│  Developer  │────▶│   CI/CD      │────▶│ Security Gate   │────▶│  Deployment  │────▶│ Monitoring  │
│   (GitHub)  │     │  Pipeline    │     │   (Gatekeeper)  │     │  (Kubernetes)│     │ (Prometheus)│
└─────────────┘     └──────────────┘     └─────────────────┘     └──────────────┘     └─────────────┘
                            │                       │                       │
                            │                       ▼                       │
                            │              ┌─────────────────┐              │
                            │              │  Trivy Scanner  │              │
                            │              │  Code Analyzer  │              │
                            │              │ Policy Engine   │              │
                            │              └─────────────────┘              │
                            │                                              │
                            └──────────────────────────────────────────────┘
                                           Continuous Security
```

#### ��️ Core Components

**1. Security Gatekeeper Service**
- **Technology:** FastAPI (Python 3.11+)
- **Features:**
  - RESTful API for security scanning
  - Multi-scanner architecture (Code, Dependency, Prompt, Trivy)
  - Policy evaluation engine
  - Prometheus metrics integration
- **Location:** `gatekeeper/`

**2. Security Scanners**
- **Static Code Analysis:** Detects hardcoded secrets, dangerous functions, injection risks
- **Dependency Scanner:** Identifies vulnerable packages in requirements.txt
- **Prompt Security Scanner:** Detects prompt injection patterns and unsafe prompts
- **Trivy Integration:** Comprehensive vulnerability scanning for:
  - Container images
  - Filesystem vulnerabilities
  - Dependency CVEs
  - Kubernetes resources

**3. Zero-Trust Policy Engine**
- **Policy-as-Code:** YAML-based policy configuration
- **Automated Decisions:** ALLOW/BLOCK/WARN based on security findings
- **Configurable Rules:** 8+ default policies, extensible for custom requirements
- **Integration:** Works seamlessly with CI/CD pipelines


**4. Kubernetes Deployment**
- **Infrastructure:** AWS EKS (Elastic Kubernetes Service)
- **Container Registry:** AWS ECR (Elastic Container Registry)
- **Monitoring Stack:**
  - Prometheus for metrics collection
  - Grafana for visualization
  - Custom dashboards for security metrics

**5. CI/CD Pipeline Integration**
- **GitHub Actions:** Complete workflow with security scanning, SBOM generation, and deployment
- **GitLab CI:** Multi-stage pipeline with automated security validation
- **Jenkins:** Declarative pipeline with security gates and deployment automation
- **Deployment Scripts:** Automated build, test, and deploy scripts
- **Image Management:** Automated Docker image building and ECR push
- **Kubernetes Manifests:** Infrastructure-as-code for all components

#### 💻 Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **API Framework** | FastAPI | High-performance REST API |
| **Language** | Python 3.11+ | Core security logic |
| **Container Platform** | Kubernetes (EKS) | Scalable deployment |
| **Vulnerability Scanner** | Trivy | CVE and dependency scanning |
| **Monitoring** | Prometheus + Grafana | Metrics and visualization |
| **Cloud Provider** | AWS (EKS, ECR) | Production-ready infrastructure |
| **Infrastructure as Code** | Kubernetes Manifests | Reproducible deployments |

#### 🔧 Working Demo

**Live Demo Available:**
```bash
./scripts/demo.sh
```

The demo demonstrates:
1. ✅ **Zero-Trust Security Scanning** - Real-time agent code analysis
2. ✅ **Trivy Vulnerability Detection** - Container and dependency scanning
3. ✅ **Policy-Based Deployment Gates** - Automated policy evaluation
4. ✅ **Real-time Monitoring** - Prometheus metrics and Grafana dashboards
5. ✅ **Agent Security Validation** - End-to-end security checks

---


## 🚀 Quick Start

### Prerequisites

- AWS Account with EKS cluster
- `kubectl` configured
- `docker` installed
- `eksctl` (for cluster creation)
- `jq` (for JSON processing)

### Deploy to AWS EKS

```bash
# 1. Clone repository
git clone <repository-url>
cd SecureAgentOps

# 2. Configure AWS credentials
export AWS_REGION=us-east-1
export ECR_ACCOUNT_ID=<your-aws-account-id>

# 3. Deploy to EKS
./scripts/deploy-to-aws-eks.sh

# 4. Run demo
./scripts/demo.sh
```

### Local Development

```bash
# 1. Build gatekeeper image
cd gatekeeper
docker build -t secureagentops-gatekeeper:latest .

# 2. Run locally
docker run -p 8080:8080 secureagentops-gatekeeper:latest

# 3. Test API
curl http://localhost:8080/health
```

---

## 📁 Project Structure

```
---

### Zero-Trust Policies

- **zt-001:** No Critical Security Issues (BLOCK)
- **zt-002:** Limited High Security Issues (WARN)
- **zt-003:** Agent Identity Verification (BLOCK)
- **zt-004:** Dependency Security (BLOCK)
- **zt-005:** Prompt Injection Protection (BLOCK)
- **zt-006:** Resource Limits (WARN)
- **zt-007:** Network Security (WARN)
- **zt-008:** Data Privacy (BLOCK)

---

## 📊 Monitoring & Metrics

### Prometheus Metrics

- `secureagentops_security_scans_total{status}`
- `secureagentops_security_findings_total{severity, category}`
- `secureagentops_policy_evaluations_total{result}`

### Grafana Dashboards

- Security scan trends
- Policy evaluation statistics
- Vulnerability distribution
- Agent deployment timeline
