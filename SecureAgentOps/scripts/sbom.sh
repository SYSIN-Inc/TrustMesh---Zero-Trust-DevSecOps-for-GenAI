#!/usr/bin/env bash
set -euo pipefail

# Generate Software Bill of Materials (SBOM) locally for an agent
# Usage: ./scripts/generate-sbom.sh <agent_path> [output_file.json]

AGENT_PATH=${1:-""}
OUTPUT_FILE=${2:-""}

if [[ -z "$AGENT_PATH" ]]; then
  echo "Usage: $0 <agent_path> [output_file.json]"
  echo ""
  echo "Example:"
  echo "  $0 agents/customer-support-agent sbom.json"
  echo "  $0 /path/to/agent"
  exit 1
fi

if [[ ! -d "$AGENT_PATH" ]]; then
  echo "❌ Error: Agent path does not exist: $AGENT_PATH"
  exit 1
fi

echo "=========================================="
echo "  SecureAgentOps - SBOM Generator"
echo "=========================================="
echo ""
echo "Generating Software Bill of Materials (SBOM)..."
echo "  Agent Path: $AGENT_PATH"
echo ""

# Check if Trivy is available
if ! command -v trivy >/dev/null 2>&1; then
  echo "⚠️  Trivy not found. Installing Trivy..."
  
  # Try to install Trivy
  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    echo "Downloading Trivy v${TRIVY_VERSION}..."
    wget -qO /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
    tar -xzf /tmp/trivy.tar.gz -C /tmp
    export PATH="/tmp:$PATH"
    chmod +x /tmp/trivy
    TRIVY_CMD="/tmp/trivy"
  elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Please install Trivy: brew install trivy"
    exit 1
  else
    echo "Please install Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    exit 1
  fi
else
  TRIVY_CMD="trivy"
fi

echo "✅ Trivy found: $($TRIVY_CMD --version 2>/dev/null | head -1 || echo "unknown version")"
echo ""

# Generate SBOM using Trivy
echo "🔍 Scanning filesystem and generating SBOM..."
SBOM_OUTPUT=$(mktemp)

if $TRIVY_CMD fs --format cyclonedx --output "$SBOM_OUTPUT" --quiet "$AGENT_PATH" 2>/dev/null; then
  echo "✅ SBOM generated successfully"
  
  # Add agent metadata
  AGENT_NAME=$(basename "$AGENT_PATH")
  AGENT_VERSION="1.0.0"
  
  # Enhance SBOM with metadata
  if command -v jq >/dev/null 2>&1; then
    ENHANCED_SBOM=$(jq \
      --arg name "$AGENT_NAME" \
      --arg version "$AGENT_VERSION" \
      --arg path "$AGENT_PATH" \
      '.metadata.component.name = $name |
       .metadata.component.version = $version |
       .metadata.component.properties = [
         {"name": "agent_path", "value": $path},
         {"name": "generated_by", "value": "SecureAgentOps"},
         {"name": "generated_locally", "value": "true"}
       ]' \
      "$SBOM_OUTPUT" 2>/dev/null || cat "$SBOM_OUTPUT")
  else
    ENHANCED_SBOM=$(cat "$SBOM_OUTPUT")
  fi
  
  # Save to output file or display
  if [[ -n "$OUTPUT_FILE" ]]; then
    echo "$ENHANCED_SBOM" > "$OUTPUT_FILE"
    echo ""
    echo "�� SBOM saved to: $OUTPUT_FILE"
  else
    echo ""
    echo "📄 SBOM (JSON):"
    echo "$ENHANCED_SBOM" | jq . 2>/dev/null || echo "$ENHANCED_SBOM"
  fi
  
  # Display summary
  if command -v jq >/dev/null 2>&1; then
    COMPONENT_COUNT=$(echo "$ENHANCED_SBOM" | jq '.components | length' 2>/dev/null || echo "0")
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "SBOM Summary:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Format: CycloneDX"
    echo "  Components: $COMPONENT_COUNT"
    echo "  Agent: $AGENT_NAME"
    echo "  Version: $AGENT_VERSION"
    echo ""
    
    if [[ "$COMPONENT_COUNT" -gt 0 ]]; then
      echo "Sample Components:"
      echo "$ENHANCED_SBOM" | jq -r '.components[0:5] | .[] | "  • \(.name) (\(.version // "unknown")) - \(.type)"' 2>/dev/null || echo "  (See full SBOM)"
    fi
  fi
  
  rm -f "$SBOM_OUTPUT"
else
  echo "❌ Error: Failed to generate SBOM"
  rm -f "$SBOM_OUTPUT"
  exit 1
fi

echo ""
echo "✅ SBOM generation complete!"
