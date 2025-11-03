#!/usr/bin/env bash
set -euo pipefail

NAMESPACE=${NAMESPACE:-secureagentops}

echo "=== Testing Security Scanning Functionality ==="
echo ""

# Port-forward gatekeeper service
GATEKEEPER_POD=$(kubectl -n $NAMESPACE get pod -l app=security-gatekeeper -o jsonpath='{.items[0].metadata.name}')
if [[ -z "$GATEKEEPER_POD" ]]; then
  echo "❌ Security Gatekeeper pod not found"
  exit 1
fi

echo "Port-forwarding gatekeeper service (Ctrl+C to stop)..."
kubectl -n $NAMESPACE port-forward $GATEKEEPER_POD 8080:8080 &
PF_PID=$!
sleep 3

echo ""
echo "1. Testing /health endpoint:"
curl -s http://localhost:8080/health | jq . || curl -s http://localhost:8080/health
echo ""

echo "2. Testing /ready endpoint:"
curl -s http://localhost:8080/ready | jq . || curl -s http://localhost:8080/ready
echo ""

echo "3. Testing /metrics endpoint:"
curl -s http://localhost:8080/metrics | grep secureagentops | head -10
echo ""

echo "4. Testing security scan API:"
# This tests the scan endpoint (will return error if path doesn't exist, but validates API)
SCAN_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "agent_path": "/app",
    "agent_id": "test-agent-001",
    "agent_version": "1.0.0"
  }')

echo "$SCAN_RESPONSE" | jq . || echo "$SCAN_RESPONSE"
echo ""

echo "5. Testing policy evaluation API:"
POLICY_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/policy/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test-agent-001",
    "scan_results": {
      "summary": {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 0,
        "total_findings": 3
      }
    }
  }')

echo "$POLICY_RESPONSE" | jq . || echo "$POLICY_RESPONSE"
echo ""

# Cleanup
kill $PF_PID 2>/dev/null || true
echo "✅ Testing complete"


