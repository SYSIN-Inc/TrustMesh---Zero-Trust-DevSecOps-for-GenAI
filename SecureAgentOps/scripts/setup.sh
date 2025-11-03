#!/bin/bash
# SecureAgentOps Setup Script
# Sets up the complete zero-trust DevSecOps framework for GenAI agents

set -e

echo "🚀 Setting up SecureAgentOps Framework..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl is not installed. Please install kubectl first."
        exit 1
    fi
    
    # Check if docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if python3 is installed
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed. Please install Python 3 first."
        exit 1
    fi
    
    print_success "All prerequisites are installed"
}

# Install Python dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."
    
    # Install dependencies for gatekeeper
    pip3 install -r gatekeeper/requirements.txt
    
    # Install dependencies for agents
    pip3 install -r agents/customer-support-agent/requirements.txt
    
    print_success "Python dependencies installed"
}

# Generate cryptographic keys
generate_keys() {
    print_status "Generating cryptographic keys..."
    
    # Create keys directory
    mkdir -p keys
    
    # Generate signing keys
    python3 gatekeeper/agent_identity.py generate-keys --output-dir ./keys
    
    print_success "Cryptographic keys generated"
}

# Deploy Kubernetes infrastructure
deploy_infrastructure() {
    print_status "Deploying Kubernetes infrastructure..."
    
    # Create namespace
    kubectl apply -f k8s/namespace.yaml
    
    # Deploy gatekeeper
    kubectl apply -f k8s/gatekeeper.yaml
    
    # Deploy monitoring stack
    kubectl apply -f k8s/monitoring.yaml
    
    # Wait for deployments to be ready
    print_status "Waiting for deployments to be ready..."
    kubectl wait --for=condition=ready pod -l app=security-gatekeeper -n secureagentops --timeout=300s
    kubectl wait --for=condition=ready pod -l app=prometheus -n secureagentops --timeout=300s
    kubectl wait --for=condition=ready pod -l app=grafana -n secureagentops --timeout=300s
    
    print_success "Kubernetes infrastructure deployed"
}

# Configure policies
configure_policies() {
    print_status "Configuring zero-trust policies..."
    
    # Create policy configuration
    cat > policies/zero-trust-policies.yaml << EOF
policies:
  - id: "zt-001"
    name: "No Critical Security Issues"
    description: "Block deployment if critical security issues are found"
    severity: "critical"
    action: "block"
    conditions:
      max_critical_findings: 0
    remediation: "Fix all critical security issues before deployment"
  
  - id: "zt-002"
    name: "Limited High Security Issues"
    description: "Allow maximum 2 high-severity security issues"
    severity: "high"
    action: "warn"
    conditions:
      max_high_findings: 2
    remediation: "Review and fix high-severity issues"
  
  - id: "zt-003"
    name: "Agent Identity Verification"
    description: "Agent must have valid signed manifest"
    severity: "critical"
    action: "block"
    conditions:
      require_signed_manifest: true
    remediation: "Ensure agent has valid signed manifest"
EOF
    
    print_success "Zero-trust policies configured"
}

# Build and push container images
build_images() {
    print_status "Building container images..."
    
    # Build gatekeeper image
    docker build -t secureagentops/gatekeeper:latest -f gatekeeper/Dockerfile .
    
    # Build customer support agent image
    docker build -t secureagentops/customer-support-agent:latest -f agents/customer-support-agent/Dockerfile agents/customer-support-agent/
    
    # Build risk detection agent image
    docker build -t secureagentops/risk-detection-agent:latest -f agents/risk-detection-agent/Dockerfile agents/risk-detection-agent/
    
    print_success "Container images built"
}

# Deploy sample agents
deploy_sample_agents() {
    print_status "Deploying sample agents..."
    
    # Deploy customer support agent
    kubectl apply -f k8s/agent-deployment.yaml
    
    # Wait for agent to be ready
    kubectl wait --for=condition=ready pod -l app=customer-support-agent -n secureagentops --timeout=300s
    
    print_success "Sample agents deployed"
}

# Run security tests
run_security_tests() {
    print_status "Running security tests..."
    
    # Test security scanner
    python3 gatekeeper/security_scanner.py agents/customer-support-agent --output security_test_report.json
    
    # Test agent identity verification
    python3 gatekeeper/agent_identity.py create \
        --agent-path agents/customer-support-agent \
        --agent-id customer-support-agent \
        --version 1.0.0 \
        --created-by test-user \
        --signing-key keys/agent_signing_key.pem \
        --output customer-support-agent_manifest.json
    
    # Test policy evaluation
    python3 gatekeeper/policy_engine.py \
        --security-scan security_test_report.json \
        --identity-verification customer-support-agent_manifest.json \
        --agent-config agents/customer-support-agent/agent_config.yaml \
        --output policy_test_report.json
    
    print_success "Security tests completed"
}

# Setup monitoring
setup_monitoring() {
    print_status "Setting up monitoring..."
    
    # Generate Grafana dashboard
    python3 monitoring/telemetry_collector.py --generate-dashboard --dashboard-output grafana_dashboard.json
    
    # Start telemetry collector
    python3 monitoring/telemetry_collector.py --port 8000 &
    TELEMETRY_PID=$!
    
    print_success "Monitoring setup completed (PID: $TELEMETRY_PID)"
}

# Display access information
display_access_info() {
    print_success "SecureAgentOps Framework setup completed!"
    echo ""
    echo "🔗 Access Information:"
    echo "  Grafana Dashboard: http://localhost:3000 (admin/admin)"
    echo "  Prometheus: http://localhost:9090"
    echo "  Security Gatekeeper API: http://localhost:8080"
    echo "  Customer Support Agent: http://localhost:8080"
    echo ""
    echo "📊 Monitoring:"
    echo "  Telemetry Collector: http://localhost:8000/metrics"
    echo ""
    echo "🔐 Security:"
    echo "  Signing Keys: ./keys/"
    echo "  Policy Reports: *.json"
    echo ""
    echo "🚀 Next Steps:"
    echo "  1. Configure your OpenAI API key in Kubernetes secrets"
    echo "  2. Deploy your own agents using the CI/CD pipeline"
    echo "  3. Monitor security metrics in Grafana"
    echo "  4. Review and customize zero-trust policies"
    echo ""
    echo "📚 Documentation:"
    echo "  README.md - Framework overview"
    echo "  docs/ - Detailed documentation"
    echo "  policies/ - Security policies"
    echo ""
}

# Main setup function
main() {
    echo "SecureAgentOps: Zero-Trust DevSecOps Framework for GenAI Agents"
    echo "=================================================================="
    echo ""
    
    check_prerequisites
    install_dependencies
    generate_keys
    deploy_infrastructure
    configure_policies
    build_images
    deploy_sample_agents
    run_security_tests
    setup_monitoring
    display_access_info
    
    print_success "Setup completed successfully! 🎉"
}

# Run main function
main "$@"
