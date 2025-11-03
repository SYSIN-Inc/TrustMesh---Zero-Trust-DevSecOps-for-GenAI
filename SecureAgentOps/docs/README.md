# SecureAgentOps Documentation

## Overview

SecureAgentOps is a comprehensive zero-trust DevSecOps framework specifically designed for GenAI agents. It provides automated security scanning, policy enforcement, identity verification, and continuous monitoring for AI agents deployed at scale.

## Architecture

The framework consists of several key components:

### 1. Security Gatekeeper Agent
- **Purpose**: Central security validation and policy enforcement
- **Components**:
  - Security Scanner: Scans agent code, prompts, and dependencies
  - Agent Identity Manager: Handles cryptographic signing and verification
  - Policy Engine: Evaluates agents against zero-trust policies
  - Agent Deployer: Manages secure deployment to Kubernetes

### 2. Monitoring & Telemetry
- **Prometheus**: Metrics collection and storage
- **Grafana**: Security dashboards and visualization
- **Telemetry Collector**: Real-time security event collection

### 3. CI/CD Pipeline
- **GitHub Actions**: Automated security validation and deployment
- **Multi-stage validation**: Security scan → Identity verification → Policy evaluation → Deployment

## Quick Start

### Prerequisites
- Kubernetes cluster (v1.20+)
- kubectl configured
- Docker installed
- Python 3.11+

### Installation

1. **Clone and Setup**
```bash
git clone <repository>
cd SecureAgentOps
chmod +x scripts/setup.sh
./scripts/setup.sh
```

2. **Deploy Sample Agent**
```bash
./scripts/deploy-sample-agent.sh
```

3. **Access Dashboards**
- Grafana: http://localhost:3000 (admin/admin)
- Prometheus: http://localhost:9090
- Security Gatekeeper: http://localhost:8080

## Security Features

### Automated Security Scanning
- **Code Analysis**: Static analysis for vulnerabilities, dangerous functions, hardcoded secrets
- **Prompt Security**: Injection attack detection and sanitization
- **Dependency Scanning**: Known vulnerability detection
- **Configuration Validation**: Security policy compliance

### Agent Identity Verification
- **Cryptographic Signing**: RSA-based manifest signing
- **Integrity Verification**: Checksum validation
- **Dependency Verification**: Secure dependency validation
- **Tamper Detection**: Signature verification

### Zero-Trust Policies
- **No Critical Issues**: Block deployment with critical security findings
- **Limited High Issues**: Allow maximum 2 high-severity issues
- **Identity Verification**: Require valid signed manifests
- **Resource Limits**: Enforce resource constraints
- **Network Security**: Require network policies

### Continuous Monitoring
- **Real-time Metrics**: Security events, policy violations, agent health
- **Automated Alerting**: Critical security event notifications
- **Compliance Reporting**: SOC2, GDPR compliance tracking
- **Performance Monitoring**: Agent performance and reliability metrics

## Usage Examples

### Deploying a New Agent

1. **Prepare Agent Code**
```bash
# Create agent directory structure
mkdir -p agents/my-agent
cd agents/my-agent

# Create main.py, requirements.txt, Dockerfile, agent_config.yaml
```

2. **Run Security Validation**
```bash
# Security scan
python3 gatekeeper/security_scanner.py agents/my-agent --output security_report.json

# Create signed manifest
python3 gatekeeper/agent_identity.py create \
    --agent-path agents/my-agent \
    --agent-id my-agent \
    --version 1.0.0 \
    --created-by developer \
    --signing-key keys/agent_signing_key.pem

# Policy evaluation
python3 gatekeeper/policy_engine.py \
    --security-scan security_report.json \
    --identity-verification my-agent_manifest.json \
    --agent-config agents/my-agent/agent_config.yaml
```

3. **Deploy via CI/CD**
```bash
# Push to repository triggers automated pipeline
git add .
git commit -m "Add new agent"
git push origin main
```

### Customizing Security Policies

1. **Create Custom Policy File**
```yaml
# policies/custom-policies.yaml
policies:
  - id: "custom-001"
    name: "Custom Security Rule"
    description: "Custom security validation"
    severity: "high"
    action: "block"
    conditions:
      custom_condition: true
    remediation: "Fix custom issue"
```

2. **Apply Custom Policies**
```bash
python3 gatekeeper/policy_engine.py \
    --policy-file policies/custom-policies.yaml \
    --security-scan security_report.json \
    --identity-verification manifest.json \
    --agent-config config.yaml
```

## API Reference

### Security Gatekeeper API

#### POST /api/v1/validate
Validate agent security and policies.

**Request Body:**
```json
{
    "agent_id": "my-agent",
    "agent_path": "agents/my-agent",
    "version": "1.0.0"
}
```

**Response:**
```json
{
    "overall_decision": "ALLOW",
    "summary": {
        "total_policies": 8,
        "passed": 8,
        "failed": 0,
        "warnings": 0
    },
    "policy_results": [...]
}
```

#### GET /api/v1/health
Health check endpoint.

### Agent Deployer API

#### POST /api/v1/deploy
Deploy a validated agent.

**Request Body:**
```json
{
    "agent_id": "my-agent",
    "agent_version": "1.0.0",
    "agent_path": "agents/my-agent",
    "namespace": "secureagentops",
    "replicas": 2,
    "resources": {
        "limits": {
            "memory": "512Mi",
            "cpu": "500m"
        }
    }
}
```

## Monitoring & Observability

### Prometheus Metrics

- `secureagentops_security_findings_total`: Security findings by severity
- `secureagentops_policy_violations_total`: Policy violations by policy
- `secureagentops_agent_deployments_total`: Deployment status
- `secureagentops_agent_runtime_health`: Agent health scores
- `secureagentops_security_scan_duration_seconds`: Scan duration

### Grafana Dashboards

- **Security Overview**: High-level security metrics
- **Agent Health**: Individual agent performance
- **Policy Compliance**: Policy violation trends
- **Deployment Status**: Deployment success/failure rates

### Alerting Rules

- Critical security findings detected
- High security findings threshold exceeded
- Agent health score below threshold
- Policy violations detected

## Best Practices

### Agent Development
1. **Security First**: Implement security controls from the start
2. **Input Validation**: Validate and sanitize all inputs
3. **Output Sanitization**: Sanitize AI model outputs
4. **Resource Limits**: Set appropriate resource constraints
5. **Network Policies**: Implement least-privilege network access

### Deployment
1. **Staged Deployment**: Use staging environment for testing
2. **Gradual Rollout**: Deploy with limited replicas initially
3. **Monitoring**: Enable comprehensive monitoring
4. **Rollback Plan**: Prepare rollback procedures
5. **Documentation**: Document agent behavior and policies

### Security
1. **Regular Scanning**: Run security scans regularly
2. **Policy Updates**: Keep security policies updated
3. **Key Rotation**: Rotate cryptographic keys regularly
4. **Access Control**: Implement proper RBAC
5. **Audit Logging**: Enable comprehensive audit logging

## Troubleshooting

### Common Issues

1. **Security Scan Failures**
   - Check for hardcoded secrets
   - Review dangerous function usage
   - Validate input sanitization

2. **Policy Violations**
   - Review policy conditions
   - Check agent configuration
   - Verify resource limits

3. **Deployment Failures**
   - Check Kubernetes cluster status
   - Verify image availability
   - Review resource constraints

4. **Monitoring Issues**
   - Check Prometheus connectivity
   - Verify Grafana configuration
   - Review telemetry collector logs

### Debug Commands

```bash
# Check security gatekeeper logs
kubectl logs -l app=security-gatekeeper -n secureagentops

# Check agent deployment status
kubectl get pods -l app=my-agent -n secureagentops

# Check Prometheus targets
kubectl port-forward service/prometheus 9090:9090 -n secureagentops

# Check Grafana logs
kubectl logs -l app=grafana -n secureagentops
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Run security scans
5. Submit pull request

## License

MIT License - see LICENSE file for details.

## Support

- Documentation: [docs/](docs/)
- Issues: GitHub Issues
- Discussions: GitHub Discussions
- Security: security@secureagentops.com
