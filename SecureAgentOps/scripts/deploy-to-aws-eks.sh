#!/usr/bin/env bash
set -euo pipefail

# Configurable variables
AWS_REGION=${AWS_REGION:-us-east-1}
ECR_ACCOUNT_ID=${ECR_ACCOUNT_ID:-}
EKS_CLUSTER_NAME=${EKS_CLUSTER_NAME:-secure-agent-ops}
K8S_DIR=${K8S_DIR:-"$(cd "$(dirname "$0")"/.. && pwd)/k8s"}
PROJECT_ROOT=${PROJECT_ROOT:-"$(cd "$(dirname "$0")"/.. && pwd)"}

if [[ -z "${ECR_ACCOUNT_ID}" ]]; then
  echo "ECR_ACCOUNT_ID is required. Export ECR_ACCOUNT_ID=<your_account_id>." >&2
  exit 1
fi

ECR_URI="${ECR_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

# Images to build and push: map of name:context
# name must match k8s image name references you will set
IMAGES=(
  "gatekeeper:${PROJECT_ROOT}/gatekeeper"
  "customer-support-agent:${PROJECT_ROOT}/agents/customer-support-agent"
)

# Ensure repos exist
aws ecr describe-repositories --repository-names gatekeeper customer-support-agent --region "${AWS_REGION}" >/dev/null 2>&1 || \
aws ecr create-repository --repository-name gatekeeper --region "${AWS_REGION}" >/dev/null 2>&1 || true
aws ecr describe-repositories --repository-names gatekeeper customer-support-agent --region "${AWS_REGION}" >/dev/null 2>&1 || \
aws ecr create-repository --repository-name customer-support-agent --region "${AWS_REGION}" >/dev/null 2>&1 || true

# Login to ECR
aws ecr get-login-password --region "${AWS_REGION}" | docker login --username AWS --password-stdin "${ECR_URI}"

GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "local")
TAG=${TAG:-${GIT_SHA}}

for entry in "${IMAGES[@]}"; do
  NAME="${entry%%:*}"
  CONTEXT="${entry#*:}"
  IMAGE="${ECR_URI}/${NAME}:${TAG}"
  echo "Building ${IMAGE} from ${CONTEXT}"
  docker build -t "${IMAGE}" "${CONTEXT}"
  docker push "${IMAGE}"

done

# Update manifests in-memory with images and apply
# Requires yq; fallback to kubectl set image if not available
apply_manifests() {
  # Check if yq is available and executable
  if command -v yq >/dev/null 2>&1 && [ -x "$(command -v yq)" ]; then
    # Set images in deployment files if they match known names
    tmpdir=$(mktemp -d)
    cp -R "${K8S_DIR}"/* "$tmpdir"/
    for file in "$tmpdir"/*.yaml; do
      if grep -q "image:" "$file"; then
        for entry in "${IMAGES[@]}"; do
          NAME="${entry%%:*}"
          yq -i \
            '(.spec.template.spec.containers[] | select(.name == "'"${NAME}"'").image) = "'"${ECR_URI}/${NAME}:${TAG}"'"' \
            "$file" || true
        done
      fi
    done
    kubectl apply -f "$tmpdir"
    rm -rf "$tmpdir"
  else
    echo "yq not found or not executable. Applying manifests and updating images via kubectl..."
    kubectl apply -f "${K8S_DIR}"
    # Update images using kubectl set image as fallback
    for entry in "${IMAGES[@]}"; do
      NAME="${entry%%:*}"
      IMAGE="${ECR_URI}/${NAME}:${TAG}"
      if kubectl -n secureagentops get deploy/"${NAME}" &>/dev/null; then
        kubectl -n secureagentops set image deploy/"${NAME}" \
          "${NAME}"="${IMAGE}" || echo "Warning: Could not update deploy/${NAME}"
      fi
    done
  fi
}

# Ensure cluster context
aws eks update-kubeconfig --region "${AWS_REGION}" --name "${EKS_CLUSTER_NAME}"

apply_manifests

echo "Deployment complete. Namespace resources:"
kubectl get all --all-namespaces | grep -E "gatekeeper|customer-support-agent" || true
