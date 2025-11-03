#!/bin/bash
# Deploy Sample Agent Script
# Demonstrates the complete SecureAgentOps deployment process

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Default values
AGENT_PATH="agents/customer-support-agent"
AGENT_ID="customer-support-agent"
VERSION="1.0.0"
NAMESPACE="secureagentops"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --agent-path)
            AGENT_PATH="$2"
            shift 2
            ;;
        --agent-id)
            AGENT_ID="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --agent-path PATH    Path to agent code (default: agents/customer-support-agent)"
            echo "  --agent-id ID        Agent identifier (default: customer-support-agent)"
            echo "  --version VERSION    Agent version (default: 1.0.0)"
            echo "  --namespace NS        Kubernetes namespace (default: secureagentops)"
            echo "  -h, --help           Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

print_status "Deploying agent: $AGENT_ID (version: $VERSION)"
print_status "Agent path: $AGENT_PATH"
print_status "Namespace: $NAMESPACE"

# Step 1: Security Scan
print_status "Step 1: Running security scan..."
python3 gatekeeper/security_scanner.py "$AGENT_PATH" --output "security_report_${AGENT_ID}.json" --verbose

if [ $? -eq 0 ]; then
    print_success "Security scan passed"
elif [ $? -eq 2 ]; then
    print_warning "Security scan passed with warnings"
else
    print_error "Security scan failed"
    exit 1
fi

# Step 2: Agent Identity Verification
print_status "Step 2: Creating signed manifest..."
python3 gatekeeper/agent_identity.py create \
    --agent-path "$AGENT_PATH" \
    --agent-id "$AGENT_ID" \
    --version "$VERSION" \
    --created-by "$(whoami)" \
    --signing-key keys/agent_signing_key.pem \
    --output "${AGENT_ID}_manifest.json"

if [ $? -eq 0 ]; then
    print_success "Agent manifest created and signed"
else
    print_error "Failed to create agent manifest"
    exit 1
fi

# Step 3: Policy Evaluation
print_status "Step 3: Running policy evaluation..."
python3 gatekeeper/policy_engine.py \
    --security-scan "security_report_${AGENT_ID}.json" \
    --identity-verification "${AGENT_ID}_manifest.json" \
    --agent-config "$AGENT_PATH/agent_config.yaml" \
    --output "policy_evaluation_${AGENT_ID}.json"

if [ $? -eq 0 ]; then
    print_success "Policy evaluation passed"
elif [ $? -eq 2 ]; then
    print_warning "Policy evaluation passed with warnings"
else
    print_error "Policy evaluation failed"
    exit 1
fi

# Step 4: Build Container Image
print_status "Step 4: Building container image..."
docker build -t "secureagentops/${AGENT_ID}:${VERSION}" -f "$AGENT_PATH/Dockerfile" "$AGENT_PATH"

if [ $? -eq 0 ]; then
    print_success "Container image built successfully"
else
    print_error "Failed to build container image"
    exit 1
fi

# Step 5: Deploy to Kubernetes
print_status "Step 5: Deploying to Kubernetes..."

# Create deployment manifest
cat > "k8s/${AGENT_ID}-deployment.yaml" << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${AGENT_ID}
  namespace: ${NAMESPACE}
  labels:
    app: ${AGENT_ID}
    version: "${VERSION}"
    managed-by: secureagentops
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ${AGENT_ID}
  template:
    metadata:
      labels:
        app: ${AGENT_ID}
        version: "${VERSION}"
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8000"
        prometheus.io/path: "/metrics"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
      containers:
      - name: ${AGENT_ID}
        image: secureagentops/${AGENT_ID}:${VERSION}
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 8000
          name: metrics
        env:
        - name: AGENT_ID
          value: "${AGENT_ID}"
        - name: AGENT_VERSION
          value: "${VERSION}"
        - name: SECURITY_MODE
          value: "enabled"
        resources:
          requests:
            memory: "256Mi"
            cpu: "200m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL

---
apiVersion: v1
kind: Service
metadata:
  name: ${AGENT_ID}-service
  namespace: ${NAMESPACE}
  labels:
    app: ${AGENT_ID}
    managed-by: secureagentops
spec:
  selector:
    app: ${AGENT_ID}
  ports:
  - name: http
    port: 8080
    targetPort: 8080
    protocol: TCP
  - name: metrics
    port: 8000
    targetPort: 8000
    protocol: TCP
  type: ClusterIP

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ${AGENT_ID}-network-policy
  namespace: ${NAMESPACE}
spec:
  podSelector:
    matchLabels:
      app: ${AGENT_ID}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: secureagentops
    - podSelector:
        matchLabels:
          app: security-gatekeeper
    ports:
    - protocol: TCP
      port: 8080
    - protocol: TCP
      port: 8000
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
EOF

# Apply the deployment
kubectl apply -f "k8s/${AGENT_ID}-deployment.yaml"

# Wait for deployment to be ready
print_status "Waiting for deployment to be ready..."
kubectl wait --for=condition=ready pod -l app="$AGENT_ID" -n "$NAMESPACE" --timeout=300s

if [ $? -eq 0 ]; then
    print_success "Agent deployed successfully"
else
    print_error "Failed to deploy agent"
    exit 1
fi

# Step 6: Verify Deployment
print_status "Step 6: Verifying deployment..."

# Get service URL
SERVICE_URL=$(kubectl get service "${AGENT_ID}-service" -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')

# Test health endpoint
kubectl run test-pod --image=curlimages/curl --rm -i --restart=Never -- \
    curl -f "http://${SERVICE_URL}:8080/health"

if [ $? -eq 0 ]; then
    print_success "Health check passed"
else
    print_warning "Health check failed"
fi

# Test metrics endpoint
kubectl run test-pod --image=curlimages/curl --rm -i --restart=Never -- \
    curl -f "http://${SERVICE_URL}:8000/metrics"

if [ $? -eq 0 ]; then
    print_success "Metrics endpoint accessible"
else
    print_warning "Metrics endpoint not accessible"
fi

# Step 7: Display Results
print_success "Agent deployment completed successfully!"
echo ""
echo "📊 Deployment Summary:"
echo "  Agent ID: $AGENT_ID"
echo "  Version: $VERSION"
echo "  Namespace: $NAMESPACE"
echo "  Service: ${AGENT_ID}-service"
echo ""
echo "🔗 Access Information:"
echo "  Health Check: http://${SERVICE_URL}:8080/health"
echo "  Metrics: http://${SERVICE_URL}:8000/metrics"
echo "  API: http://${SERVICE_URL}:8080/api/v1/"
echo ""
echo "📋 Security Reports:"
echo "  Security Scan: security_report_${AGENT_ID}.json"
echo "  Agent Manifest: ${AGENT_ID}_manifest.json"
echo "  Policy Evaluation: policy_evaluation_${AGENT_ID}.json"
echo ""
echo "🚀 Next Steps:"
echo "  1. Monitor the agent in Grafana dashboard"
echo "  2. Check Prometheus metrics"
echo "  3. Test the agent API endpoints"
echo "  4. Review security reports"
echo ""

# Cleanup temporary files
rm -f "k8s/${AGENT_ID}-deployment.yaml"

print_success "Deployment process completed! 🎉"
