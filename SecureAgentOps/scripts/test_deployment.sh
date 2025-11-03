#!/usr/bin/env bash
set -euo pipefail

NAMESPACE=${NAMESPACE:-secureagentops}

echo "=== SecureAgentOps Deployment Test ==="
echo ""

# 1. Check all pods are running
echo "1. Checking pod status..."
kubectl -n $NAMESPACE get pods
echo ""

# 2. Test gatekeeper health endpoints
echo "2. Testing Security Gatekeeper health endpoints..."
GATEKEEPER_POD=$(kubectl -n $NAMESPACE get pod -l app=security-gatekeeper -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [[ -n "$GATEKEEPER_POD" ]]; then
  echo "   Gatekeeper pod: $GATEKEEPER_POD"
  
  # Port-forward to test endpoints
  echo "   Testing /health endpoint..."
  kubectl -n $NAMESPACE port-forward $GATEKEEPER_POD 8080:8080 > /dev/null 2>&1 &
  PF_PID=$!
  sleep 2
  
  if curl -s http://localhost:8080/health > /dev/null; then
    echo "   ✅ Health endpoint working"
    curl -s http://localhost:8080/health | jq . || curl -s http://localhost:8080/health
  else
    echo "   ❌ Health endpoint failed"
  fi
  
  echo ""
  echo "   Testing /ready endpoint..."
  if curl -s http://localhost:8080/ready > /dev/null; then
    echo "   ✅ Ready endpoint working"
    curl -s http://localhost:8080/ready | jq . || curl -s http://localhost:8080/ready
  else
    echo "   ❌ Ready endpoint failed"
  fi
  
  echo ""
  echo "   Testing /metrics endpoint..."
  if curl -s http://localhost:8080/metrics > /dev/null; then
    echo "   ✅ Metrics endpoint working"
    curl -s http://localhost:8080/metrics | head -20
  else
    echo "   ❌ Metrics endpoint failed"
  fi
  
  kill $PF_PID 2>/dev/null || true
else
  echo "   ❌ No gatekeeper pod found"
fi

echo ""
echo "3. Testing Customer Support Agent..."
AGENT_POD=$(kubectl -n $NAMESPACE get pod -l app=customer-support-agent -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [[ -n "$AGENT_POD" ]]; then
  echo "   Agent pod: $AGENT_POD"
  
  # Port-forward to test endpoints
  kubectl -n $NAMESPACE port-forward $AGENT_POD 8080:8080 > /dev/null 2>&1 &
  AGENT_PF_PID=$!
  sleep 2
  
  echo "   Testing /health endpoint..."
  if curl -s http://localhost:8080/health > /dev/null; then
    echo "   ✅ Agent health endpoint working"
    curl -s http://localhost:8080/health | jq . || curl -s http://localhost:8080/health
  else
    echo "   ❌ Agent health endpoint failed"
  fi
  
  kill $AGENT_PF_PID 2>/dev/null || true
else
  echo "   ❌ No customer-support-agent pod found"
fi

echo ""
echo "4. Testing Security Scanning API..."
GATEKEEPER_SVC="security-gatekeeper.$NAMESPACE.svc.cluster.local"

# Create a test scan request
cat > /tmp/scan-test.json <<EOF
{
  "agent_path": "/tmp",
  "agent_id": "test-agent",
  "agent_version": "1.0.0"
}
EOF

echo "   Sending scan request..."
# Note: This will fail if agent_path doesn't exist in container, but tests API
kubectl run test-scanner --image=curlimages/curl:latest --rm -i --restart=Never -n $NAMESPACE -- \
  curl -s -X POST http://security-gatekeeper:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"agent_path": "/tmp", "agent_id": "test-agent", "agent_version": "1.0.0"}' || \
  echo "   ⚠️  Scan test requires agent code to be accessible"

echo ""
echo "5. Checking Prometheus metrics..."
PROMETHEUS_POD=$(kubectl -n $NAMESPACE get pod -l app=prometheus -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [[ -n "$PROMETHEUS_POD" ]]; then
  echo "   Prometheus pod: $PROMETHEUS_POD"
  echo "   ✅ Prometheus is running"
else
  echo "   ⚠️  Prometheus not running (optional component)"
fi

echo ""
echo "6. Checking Grafana..."
GRAFANA_POD=$(kubectl -n $NAMESPACE get pod -l app=grafana -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [[ -n "$GRAFANA_POD" ]]; then
  echo "   Grafana pod: $GRAFANA_POD"
  echo "   Access Grafana via port-forward:"
  echo "   kubectl -n $NAMESPACE port-forward $GRAFANA_POD 3000:3000"
  echo "   Then open http://localhost:3000 (login: admin/admin)"
else
  echo "   ⚠️  Grafana not running (optional component)"
fi

echo ""
echo "=== Test Summary ==="
kubectl -n $NAMESPACE get pods -o wide


