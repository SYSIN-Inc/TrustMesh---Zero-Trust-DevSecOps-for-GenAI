#!/usr/bin/env python3
"""
Security Gatekeeper Service
FastAPI service for security scanning and policy evaluation
"""

import os
import logging
import subprocess
import json
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from prometheus_client import generate_latest, Counter, Histogram
from prometheus_client.exposition import CONTENT_TYPE_LATEST
from starlette.responses import Response
import uvicorn

from security_scanner import SecurityGatekeeper, SecurityFinding
from policy_engine import ZeroTrustPolicyEngine, PolicyResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Prometheus metrics
security_scans_total = Counter(
    'secureagentops_security_scans_total',
    'Total number of security scans performed',
    ['status']
)

security_findings_total = Counter(
    'secureagentops_security_findings_total',
    'Total number of security findings',
    ['severity', 'category']
)

policy_evaluations_total = Counter(
    'secureagentops_policy_evaluations_total',
    'Total number of policy evaluations',
    ['result']
)

# FastAPI app
app = FastAPI(title="Security Gatekeeper", version="1.0.0")

# Initialize components (with Trivy enabled)
scanner = SecurityGatekeeper(enable_trivy=True)
policy_engine = ZeroTrustPolicyEngine()

# Load policies from config if available
POLICIES_CONFIG_PATH = os.getenv('POLICIES_CONFIG_PATH', '/etc/gatekeeper/policies.yaml')

try:
    if os.path.exists(POLICIES_CONFIG_PATH):
        policy_engine.load_policies(POLICIES_CONFIG_PATH)
        logger.info(f"Loaded policies from {POLICIES_CONFIG_PATH}")
    else:
        logger.info("Using default policies (config file not found)")
except Exception as e:
    logger.warning(f"Failed to load policies from {POLICIES_CONFIG_PATH}: {e}. Using defaults.")

class ScanRequest(BaseModel):
    agent_path: str
    agent_id: str = "unknown"
    agent_version: str = "1.0.0"
    enable_trivy: bool = True

class ScanResponse(BaseModel):
    passed: bool
    findings: List[Dict[str, Any]]
    summary: Dict[str, Any]

class ScanPodsRequest(BaseModel):
    namespace: str = "secureagentops"
    scan_images: bool = True

class ScanContainersRequest(BaseModel):
    image: str
    scan_image: bool = True

class PolicyEvaluationRequest(BaseModel):
    agent_id: str
    scan_results: Dict[str, Any]

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint"""
    return {"status": "ready"}

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_agent(request: ScanRequest):
    """Scan an agent for security issues"""
    try:
        logger.info(f"Scanning agent: {request.agent_id} at {request.agent_path} (Trivy: {request.enable_trivy})")
        
        # Create scanner with Trivy enabled/disabled based on request
        scan_scanner = SecurityGatekeeper(enable_trivy=request.enable_trivy)
        
        # Perform security scan (returns a dict with findings and summary)
        scan_results = scan_scanner.scan_agent(request.agent_path)
        
        # Extract findings and summary from scan results
        findings_dict = scan_results.get('findings', [])
        summary = scan_results.get('summary', {})
        
        # Add Trivy scan indicator
        summary['trivy_enabled'] = request.enable_trivy
        summary['trivy_findings'] = len([f for f in findings_dict if 'Trivy' in f.get('description', '')])
        
        # Determine if scan passed (no critical findings)
        passed = summary.get('critical', 0) == 0
        
        # Update metrics
        security_scans_total.labels(status="passed" if passed else "failed").inc()
        for finding in findings_dict:
            severity = finding.get('severity', 'UNKNOWN')
            category = finding.get('category', 'UNKNOWN')
            security_findings_total.labels(
                severity=severity,
                category=category
            ).inc()
        
        return ScanResponse(
            passed=passed,
            findings=findings_dict,
            summary=summary
        )
    except Exception as e:
        logger.error(f"Error scanning agent: {e}", exc_info=True)
        security_scans_total.labels(status="error").inc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/scan/pods", response_model=ScanResponse)
async def scan_pods(request: ScanPodsRequest):
    """Scan all pods in a namespace using Trivy"""
    try:
        logger.info(f"Scanning pods in namespace: {request.namespace}")
        
        if not scanner.trivy_scanner:
            raise HTTPException(status_code=400, detail="Trivy scanner not available")
        
        all_findings = []
        unique_images = set()
        images_scanned = 0
        
        # Get pod images first (skip Kubernetes cluster scan - it's slow and may not work in all environments)
        try:
            import subprocess
            logger.info("Fetching pod information...")
            result = subprocess.run(
                ["kubectl", "get", "pods", "-n", request.namespace, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                import json as json_lib
                pods_data = json_lib.loads(result.stdout)
                
                for pod in pods_data.get("items", []):
                    for container in pod.get("spec", {}).get("containers", []):
                        image = container.get("image")
                        if image and image not in unique_images:
                            unique_images.add(image)
                
                logger.info(f"Found {len(unique_images)} unique container images to scan")
            else:
                logger.warning(f"Failed to get pods: {result.stderr}")
                raise HTTPException(status_code=500, detail=f"Failed to fetch pods: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error("Timeout fetching pod information")
            raise HTTPException(status_code=504, detail="Timeout fetching pod information")
        except Exception as e:
            logger.error(f"Error fetching pods: {e}")
            raise HTTPException(status_code=500, detail=f"Error fetching pods: {str(e)}")
        
        # Scan each image with timeout per image
        if request.scan_images and unique_images:
            logger.info(f"Starting to scan {len(unique_images)} container images...")
            for idx, image in enumerate(unique_images, 1):
                try:
                    logger.info(f"Scanning image {idx}/{len(unique_images)}: {image}")
                    # Use shorter timeout per image (2 minutes max per image)
                    image_findings = scanner.trivy_scanner.scan_container_image(image, timeout=120)
                    all_findings.extend(image_findings)
                    images_scanned += 1
                    logger.info(f"✓ Scanned {image}: found {len(image_findings)} issues")
                except Exception as e:
                    logger.warning(f"Failed to scan image {image}: {e}")
                    # Continue with next image instead of failing completely
                    from security_scanner import SecurityFinding
                    all_findings.append(SecurityFinding(
                        severity="MEDIUM",
                        category="DEPENDENCY",
                        description=f"Failed to scan image: {image} - {str(e)[:100]}",
                        file_path=image,
                        remediation="Check image accessibility and Trivy configuration"
                    ))
        else:
            logger.info("Skipping image scans (scan_images=false or no images found)")
        
        # Convert findings to dict format
        findings_dict = [
            {
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "remediation": f.remediation
            }
            for f in all_findings
        ]
        
        # Calculate summary
        summary = {
            "total_findings": len(all_findings),
            "critical": len([f for f in all_findings if f.severity == "CRITICAL"]),
            "high": len([f for f in all_findings if f.severity == "HIGH"]),
            "medium": len([f for f in all_findings if f.severity == "MEDIUM"]),
            "low": len([f for f in all_findings if f.severity == "LOW"]),
            "trivy_enabled": True,
            "trivy_findings": len(all_findings),
            "pods_scanned": len(unique_images),
            "images_scanned": images_scanned
        }
        
        passed = summary["critical"] == 0
        
        # Update metrics
        security_scans_total.labels(status="passed" if passed else "failed").inc()
        for finding in all_findings:
            security_findings_total.labels(
                severity=finding.severity,
                category=finding.category
            ).inc()
        
        return ScanResponse(
            passed=passed,
            findings=findings_dict,
            summary=summary
        )
    except Exception as e:
        logger.error(f"Error scanning pods: {e}", exc_info=True)
        security_scans_total.labels(status="error").inc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/scan/container", response_model=ScanResponse)
async def scan_container(request: ScanContainersRequest):
    """Scan a specific container image using Trivy"""
    try:
        logger.info(f"Scanning container image: {request.image}")
        
        if not scanner.trivy_scanner:
            raise HTTPException(status_code=400, detail="Trivy scanner not available")
        
        if not request.scan_image:
            raise HTTPException(status_code=400, detail="Container image scanning must be enabled")
        
        # Scan the container image
        findings = scanner.trivy_scanner.scan_container_image(request.image)
        
        # Convert findings to dict format
        findings_dict = [
            {
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "remediation": f.remediation
            }
            for f in findings
        ]
        
        # Calculate summary
        summary = {
            "total_findings": len(findings),
            "critical": len([f for f in findings if f.severity == "CRITICAL"]),
            "high": len([f for f in findings if f.severity == "HIGH"]),
            "medium": len([f for f in findings if f.severity == "MEDIUM"]),
            "low": len([f for f in findings if f.severity == "LOW"]),
            "trivy_enabled": True,
            "trivy_findings": len(findings),
            "image": request.image
        }
        
        passed = summary["critical"] == 0
        
        # Update metrics
        security_scans_total.labels(status="passed" if passed else "failed").inc()
        for finding in findings:
            security_findings_total.labels(
                severity=finding.severity,
                category=finding.category
            ).inc()
        
        return ScanResponse(
            passed=passed,
            findings=findings_dict,
            summary=summary
        )
    except Exception as e:
        logger.error(f"Error scanning container: {e}", exc_info=True)
        security_scans_total.labels(status="error").inc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/policy/evaluate")
async def evaluate_policy(request: PolicyEvaluationRequest):
    """Evaluate policies for an agent"""
    try:
        logger.info(f"Evaluating policies for agent: {request.agent_id}")
        
        # Prepare evaluation inputs - policy engine expects specific structure
        security_scan = request.scan_results if isinstance(request.scan_results, dict) else {}
        identity_verification = {"agent_id": request.agent_id, "verified": True, "overall_valid": True}  # Simplified for API
        agent_config = {"agent_id": request.agent_id}  # Minimal config
        
        # Evaluate policies (returns a dict with policy_results)
        evaluation_result = policy_engine.evaluate_agent(security_scan, identity_verification, agent_config)
        
        # Extract policy results from evaluation_result
        # The policy engine returns a dict with 'policy_results' containing the results
        policy_results = evaluation_result.get('policy_results', [])
        
        # Also extract from self.results if available (backup)
        if hasattr(policy_engine, 'results') and policy_engine.results:
            results_dict = [
                {
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "passed": r.passed,
                    "severity": r.severity.value,
                    "action": r.action.value,
                    "message": r.message,
                    "details": r.details
                }
                for r in policy_engine.results
            ]
        else:
            # Use policy_results from evaluation_result
            results_dict = policy_results
        
        # Update metrics
        for result_data in results_dict:
            if isinstance(result_data, dict):
                passed = result_data.get('passed', False)
            else:
                passed = getattr(result_data, 'passed', False)
            policy_evaluations_total.labels(
                result="passed" if passed else "failed"
            ).inc()
        
        return {"results": results_dict}
    except Exception as e:
        logger.error(f"Error evaluating policies: {e}", exc_info=True)
        policy_evaluations_total.labels(result="error").inc()
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    port = int(os.getenv("API_PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
