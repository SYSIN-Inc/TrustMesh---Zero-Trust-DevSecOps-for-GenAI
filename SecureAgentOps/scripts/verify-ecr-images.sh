#!/usr/bin/env bash
set -euo pipefail

# Get ECR details
AWS_REGION=${AWS_REGION:-us-east-1}
ECR_ACCOUNT_ID=${ECR_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}
ECR_URI="${ECR_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

echo "=== ECR Image Verification ==="
echo "Account ID: ${ECR_ACCOUNT_ID}"
echo "Region: ${AWS_REGION}"
echo "ECR URI: ${ECR_URI}"
echo ""

# Check what tags exist in ECR
echo "=== Checking ECR repositories ==="
for repo in gatekeeper customer-support-agent; do
  echo "Repository: ${repo}"
  if aws ecr describe-repositories --repository-names "${repo}" --region "${AWS_REGION}" &>/dev/null; then
    echo "  ✅ Repository exists"
    IMAGES=$(aws ecr describe-images --repository-name "${repo}" --region "${AWS_REGION}" --query 'imageDetails[].imageTags' --output json 2>/dev/null || echo "[]")
    if echo "${IMAGES}" | grep -q 'null\|\[\]'; then
      echo "  ⚠️  No images found in repository"
    else
      echo "  Images:"
      aws ecr describe-images --repository-name "${repo}" --region "${AWS_REGION}" \
        --query 'imageDetails[*].[imageTags[0],imagePushedAt]' --output table 2>/dev/null || echo "    Error retrieving images"
    fi
  else
    echo "  ❌ Repository does not exist"
  fi
  echo ""
done

# Check current deployment images
echo "=== Current Deployment Images ==="
kubectl -n secureagentops get deploy -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.template.spec.containers[0].image}{"\n"}{end}' 2>/dev/null || echo "Error getting deployments"
echo ""

# Suggest fix
echo "=== Suggested Fix ==="
LATEST_TAG=$(aws ecr describe-images --repository-name customer-support-agent --region "${AWS_REGION}" \
  --query 'sort_by(imageDetails,&imagePushedAt)[-1].imageTags[0]' --output text 2>/dev/null || echo "")

if [[ -n "${LATEST_TAG}" && "${LATEST_TAG}" != "None" ]]; then
  echo "Latest tag in ECR: ${LATEST_TAG}"
  echo ""
  echo "To update deployments, run:"
  echo "  kubectl -n secureagentops set image deploy/customer-support-agent \\"
  echo "    customer-support-agent=${ECR_URI}/customer-support-agent:${LATEST_TAG}"
  echo ""
  echo "  kubectl -n secureagentops set image deploy/security-gatekeeper \\"
  echo "    security-gatekeeper=${ECR_URI}/gatekeeper:${LATEST_TAG}"
else
  echo "⚠️  No images found. You may need to rebuild and push images."
  echo "  Run: ./scripts/deploy-to-aws-eks.sh"
fi


