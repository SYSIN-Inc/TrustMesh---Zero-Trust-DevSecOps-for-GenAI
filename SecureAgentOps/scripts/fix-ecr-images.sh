#!/usr/bin/env bash
set -euo pipefail

# Get ECR details
AWS_REGION=${AWS_REGION:-us-east-1}
ECR_ACCOUNT_ID=${ECR_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}
ECR_URI="${ECR_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

# Get tag (use git SHA or provided TAG)
TAG=${TAG:-$(git rev-parse --short HEAD 2>/dev/null || echo "")}

if [[ -z "${TAG}" ]]; then
  # Try to find the latest tag in ECR
  LATEST_TAG=$(aws ecr describe-images --repository-name customer-support-agent --region "${AWS_REGION}" \
    --query 'sort_by(imageDetails,&imagePushedAt)[-1].imageTags[0]' --output text 2>/dev/null || echo "")
  
  if [[ -n "${LATEST_TAG}" && "${LATEST_TAG}" != "None" ]]; then
    TAG="${LATEST_TAG}"
    echo "Using latest tag from ECR: ${TAG}"
  else
    echo "Error: Could not determine tag. Please set TAG environment variable."
    echo "Example: export TAG=4b5e777"
    exit 1
  fi
fi

echo "Updating images to use ECR: ${ECR_URI} with tag: ${TAG}"
echo ""

# Update security-gatekeeper
if kubectl -n secureagentops get deploy/security-gatekeeper &>/dev/null; then
  echo "Updating security-gatekeeper..."
  kubectl -n secureagentops set image deploy/security-gatekeeper \
    security-gatekeeper="${ECR_URI}/gatekeeper:${TAG}"
  echo "✅ Updated security-gatekeeper"
else
  echo "⚠️  security-gatekeeper deployment not found"
fi

# Update customer-support-agent
if kubectl -n secureagentops get deploy/customer-support-agent &>/dev/null; then
  echo "Updating customer-support-agent..."
  kubectl -n secureagentops set image deploy/customer-support-agent \
    customer-support-agent="${ECR_URI}/customer-support-agent:${TAG}"
  echo "✅ Updated customer-support-agent"
else
  echo "⚠️  customer-support-agent deployment not found"
fi

echo ""
echo "Waiting for rollout..."
kubectl -n secureagentops rollout status deploy/customer-support-agent --timeout=60s || true
kubectl -n secureagentops rollout status deploy/security-gatekeeper --timeout=60s || true

echo ""
echo "Current pod status:"
kubectl -n secureagentops get pods -l app=customer-support-agent
kubectl -n secureagentops get pods -l app=security-gatekeeper


