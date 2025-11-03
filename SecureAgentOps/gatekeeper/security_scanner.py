#!/usr/bin/env python3
"""
Security Gatekeeper Agent - Core Security Scanner
Scans GenAI agent code, prompts, and dependencies for security vulnerabilities
"""

import os
import json
import hashlib
import re
import ast
import yaml
import subprocess
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SecurityFinding:
    """Represents a security finding"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # CODE, PROMPT, DEPENDENCY, CONFIG
    description: str
    file_path: str
    line_number: Optional[int] = None
    remediation: Optional[str] = None

@dataclass
class AgentManifest:
    """Agent manifest for identity verification"""
    agent_id: str
    version: str
    checksum: str
    dependencies: List[str]
    prompts: List[str]
    signature: str
    created_at: datetime

class PromptSecurityScanner:
    """Scans prompts for injection vulnerabilities"""
    
    INJECTION_PATTERNS = [
        r'ignore\s+previous\s+instructions',
        r'forget\s+everything',
        r'you\s+are\s+now\s+a\s+different\s+ai',
        r'system\s+prompt',
        r'jailbreak',
        r'roleplay',
        r'pretend\s+to\s+be',
        r'act\s+as\s+if',
        r'override\s+safety',
        r'bypass\s+security',
        r'ignore\s+safety\s+guidelines',
        r'act\s+as\s+a\s+developer',
        r'give\s+me\s+admin\s+access',
        r'extract\s+sensitive\s+data',
        r'reveal\s+internal\s+information'
    ]
    
    def scan_prompt(self, prompt: str, file_path: str) -> List[SecurityFinding]:
        """Scan a prompt for injection vulnerabilities"""
        findings = []
        
        for pattern in self.INJECTION_PATTERNS:
            matches = re.finditer(pattern, prompt, re.IGNORECASE)
            for match in matches:
                findings.append(SecurityFinding(
                    severity="HIGH",
                    category="PROMPT",
                    description=f"Potential prompt injection detected: '{match.group()}'",
                    file_path=file_path,
                    line_number=self._get_line_number(prompt, match.start()),
                    remediation="Review prompt for injection attempts and add input validation"
                ))
        
        # Check for suspicious patterns
        if re.search(r'\{.*\}', prompt):
            findings.append(SecurityFinding(
                severity="MEDIUM",
                category="PROMPT",
                description="Prompt contains template variables - ensure proper sanitization",
                file_path=file_path,
                remediation="Validate and sanitize all template variables"
            ))
        
        return findings
    
    def _get_line_number(self, text: str, position: int) -> int:
        """Get line number from character position"""
        return text[:position].count('\n') + 1

class CodeSecurityScanner:
    """Scans Python code for security vulnerabilities"""
    
    DANGEROUS_FUNCTIONS = [
        'eval', 'exec', 'compile', '__import__',
        'os.system', 'subprocess.run', 'subprocess.call',
        'pickle.loads', 'pickle.load',
        'yaml.load', 'yaml.unsafe_load'
    ]
    
    SENSITIVE_PATTERNS = [
        r'password\s*=\s*["\'][^"\']+["\']',
        r'api_key\s*=\s*["\'][^"\']+["\']',
        r'secret\s*=\s*["\'][^"\']+["\']',
        r'token\s*=\s*["\'][^"\']+["\']',
        r'private_key\s*=\s*["\'][^"\']+["\']'
    ]
    
    def scan_file(self, file_path: str) -> List[SecurityFinding]:
        """Scan a Python file for security issues"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST
            tree = ast.parse(content)
            
            # Check for dangerous functions
            findings.extend(self._check_dangerous_functions(tree, file_path))
            
            # Check for hardcoded secrets
            findings.extend(self._check_hardcoded_secrets(content, file_path))
            
            # Check for unsafe imports
            findings.extend(self._check_unsafe_imports(tree, file_path))
            
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            findings.append(SecurityFinding(
                severity="MEDIUM",
                category="CODE",
                description=f"Failed to parse file: {e}",
                file_path=file_path
            ))
        
        return findings
    
    def _check_dangerous_functions(self, tree: ast.AST, file_path: str) -> List[SecurityFinding]:
        """Check for dangerous function calls"""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in self.DANGEROUS_FUNCTIONS:
                        findings.append(SecurityFinding(
                            severity="HIGH",
                            category="CODE",
                            description=f"Dangerous function '{node.func.id}' detected",
                            file_path=file_path,
                            line_number=node.lineno,
                            remediation="Use safer alternatives or add proper validation"
                        ))
                elif isinstance(node.func, ast.Attribute):
                    func_name = f"{node.func.value.id}.{node.func.attr}"
                    if func_name in self.DANGEROUS_FUNCTIONS:
                        findings.append(SecurityFinding(
                            severity="HIGH",
                            category="CODE",
                            description=f"Dangerous function '{func_name}' detected",
                            file_path=file_path,
                            line_number=node.lineno,
                            remediation="Use safer alternatives or add proper validation"
                        ))
        
        return findings
    
    def _check_hardcoded_secrets(self, content: str, file_path: str) -> List[SecurityFinding]:
        """Check for hardcoded secrets"""
        findings = []
        
        for pattern in self.SENSITIVE_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append(SecurityFinding(
                    severity="CRITICAL",
                    category="CODE",
                    description=f"Hardcoded secret detected: {match.group()}",
                    file_path=file_path,
                    line_number=content[:match.start()].count('\n') + 1,
                    remediation="Use environment variables or secure secret management"
                ))
        
        return findings
    
    def _check_unsafe_imports(self, tree: ast.AST, file_path: str) -> List[SecurityFinding]:
        """Check for unsafe imports"""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ['pickle', 'marshal', 'shelve']:
                        findings.append(SecurityFinding(
                            severity="MEDIUM",
                            category="CODE",
                            description=f"Unsafe import '{alias.name}' detected",
                            file_path=file_path,
                            line_number=node.lineno,
                            remediation="Consider using safer serialization methods"
                        ))
        
        return findings

class DependencyScanner:
    """Scans dependencies for known vulnerabilities"""
    
    def scan_requirements(self, requirements_file: str) -> List[SecurityFinding]:
        """Scan requirements.txt for vulnerable packages"""
        findings = []
        
        try:
            with open(requirements_file, 'r') as f:
                requirements = f.readlines()
            
            for line_num, line in enumerate(requirements, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    package = line.split('==')[0].split('>=')[0].split('<=')[0]
                    
                    # Check for known vulnerable packages
                    if package in self._get_vulnerable_packages():
                        findings.append(SecurityFinding(
                            severity="HIGH",
                            category="DEPENDENCY",
                            description=f"Known vulnerable package: {package}",
                            file_path=requirements_file,
                            line_number=line_num,
                            remediation="Update to latest secure version"
                        ))
        
        except Exception as e:
            logger.error(f"Error scanning {requirements_file}: {e}")
        
        return findings
    
    def _get_vulnerable_packages(self) -> List[str]:
        """Get list of known vulnerable packages"""
        # In production, this would query a vulnerability database
        return [
            'requests==2.25.0',  # Example vulnerable version
            'urllib3==1.24.0',   # Example vulnerable version
        ]

class TrivyScanner:
    """Scans using Trivy for comprehensive security analysis"""
    
    def __init__(self):
        self.trivy_cmd = "trivy"
        self._check_trivy_installed()
    
    def _check_trivy_installed(self) -> bool:
        """Check if Trivy is installed and accessible"""
        try:
            result = subprocess.run(
                [self.trivy_cmd, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"Trivy detected: {result.stdout.strip()}")
                return True
            else:
                logger.warning("Trivy not available")
                return False
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning(f"Trivy not found or not accessible: {e}")
            return False
    
    def scan_filesystem(self, target_path: str, severity: str = "CRITICAL,HIGH,MEDIUM,LOW") -> List[SecurityFinding]:
        """Scan filesystem using Trivy"""
        findings = []
        
        if not self._check_trivy_installed():
            return findings
        
        try:
            logger.info(f"Running Trivy filesystem scan on: {target_path}")
            
            # Run Trivy filesystem scan
            cmd = [
                self.trivy_cmd,
                "fs",
                "--quiet",
                "--severity", severity,
                "--format", "json",
                "--no-progress",
                target_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd="/tmp"  # Set working directory
            )
            
            if result.returncode == 0 or result.stdout:
                # Parse Trivy JSON output
                try:
                    trivy_data = json.loads(result.stdout)
                    findings.extend(self._parse_trivy_results(trivy_data, target_path))
                except json.JSONDecodeError:
                    # If JSON parsing fails, try to extract from stderr or text output
                    logger.warning("Could not parse Trivy JSON output, checking text output")
                    if result.stderr:
                        findings.extend(self._parse_trivy_text(result.stderr, target_path))
            
            logger.info(f"Trivy scan completed: found {len(findings)} issues")
            
        except subprocess.TimeoutExpired:
            logger.error("Trivy scan timed out")
            findings.append(SecurityFinding(
                severity="MEDIUM",
                category="DEPENDENCY",
                description="Trivy scan timed out - scan may be incomplete",
                file_path=target_path,
                remediation="Try scanning smaller directories or increase timeout"
            ))
        except Exception as e:
            logger.error(f"Error running Trivy scan: {e}")
            findings.append(SecurityFinding(
                severity="MEDIUM",
                category="DEPENDENCY",
                description=f"Trivy scan error: {str(e)}",
                file_path=target_path,
                remediation="Check Trivy installation and permissions"
            ))
        
        return findings
    
    def scan_requirements_with_trivy(self, requirements_file: str) -> List[SecurityFinding]:
        """Scan requirements.txt using Trivy"""
        findings = []
        
        if not self._check_trivy_installed():
            return findings
        
        try:
            logger.info(f"Running Trivy on requirements file: {requirements_file}")
            
            # Trivy can scan requirements.txt directly
            cmd = [
                self.trivy_cmd,
                "fs",
                "--quiet",
                "--severity", "CRITICAL,HIGH,MEDIUM",
                "--format", "json",
                "--no-progress",
                requirements_file
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.stdout:
                try:
                    trivy_data = json.loads(result.stdout)
                    findings.extend(self._parse_trivy_results(trivy_data, requirements_file))
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            logger.error(f"Error running Trivy on requirements: {e}")
        
        return findings
    
    def _parse_trivy_results(self, trivy_data: Dict[str, Any], target_path: str) -> List[SecurityFinding]:
        """Parse Trivy JSON output into SecurityFinding objects"""
        findings = []
        
        if "Results" not in trivy_data:
            return findings
        
        for result in trivy_data.get("Results", []):
            target = result.get("Target", target_path)
            
            for vuln in result.get("Vulnerabilities", []):
                severity = self._map_trivy_severity(vuln.get("Severity", "UNKNOWN"))
                
                finding = SecurityFinding(
                    severity=severity,
                    category="DEPENDENCY",
                    description=f"{vuln.get('Title', 'Vulnerability')} - {vuln.get('Description', '')[:200]}",
                    file_path=target,
                    remediation=vuln.get("FixedVersion", "Update package to secure version")
                )
                findings.append(finding)
        
        return findings
    
    def _parse_trivy_text(self, text_output: str, target_path: str) -> List[SecurityFinding]:
        """Parse Trivy text output (fallback)"""
        findings = []
        # Simple text parsing as fallback
        lines = text_output.split('\n')
        for line in lines:
            if any(keyword in line.lower() for keyword in ['critical', 'high', 'vulnerability', 'cve']):
                findings.append(SecurityFinding(
                    severity="HIGH",
                    category="DEPENDENCY",
                    description=f"Trivy finding: {line.strip()}",
                    file_path=target_path,
                    remediation="Review Trivy output for details"
                ))
        return findings
    
    def _map_trivy_severity(self, trivy_severity: str) -> str:
        """Map Trivy severity to our severity levels"""
        mapping = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "UNKNOWN": "MEDIUM"
        }
        return mapping.get(trivy_severity.upper(), "MEDIUM")
    
    def scan_container_image(self, image: str, timeout: int = 180) -> List[SecurityFinding]:
        """Scan a container image using Trivy"""
        findings = []
        
        if not self._check_trivy_installed():
            return findings
        
        try:
            logger.info(f"Running Trivy container image scan on: {image} (timeout: {timeout}s)")
            
            cmd = [
                self.trivy_cmd,
                "image",
                "--quiet",
                "--severity", "CRITICAL,HIGH,MEDIUM",
                "--format", "json",
                "--no-progress",
                "--skip-db-update",  # Skip DB update to speed up
                image
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,  # 3 minute timeout per image (default)
            )
            
            if result.stdout:
                try:
                    trivy_data = json.loads(result.stdout)
                    findings.extend(self._parse_trivy_results(trivy_data, image))
                except json.JSONDecodeError as e:
                    logger.warning(f"Could not parse Trivy JSON output for image scan: {e}")
                    # Try to extract some info from stderr or text
                    if result.stderr:
                        logger.debug(f"Trivy stderr: {result.stderr[:200]}")
            
            if result.returncode != 0 and result.stderr:
                logger.warning(f"Trivy scan returned non-zero: {result.stderr[:200]}")
            
            logger.info(f"Trivy image scan completed: found {len(findings)} issues")
            
        except subprocess.TimeoutExpired:
            logger.error(f"Trivy image scan timed out after {timeout}s for {image}")
            findings.append(SecurityFinding(
                severity="MEDIUM",
                category="DEPENDENCY",
                description=f"Trivy image scan timed out for {image}",
                file_path=image,
                remediation="Image may be large or inaccessible. Try scanning smaller images or increase timeout."
            ))
        except Exception as e:
            logger.error(f"Error running Trivy image scan: {e}")
            findings.append(SecurityFinding(
                severity="MEDIUM",
                category="DEPENDENCY",
                description=f"Trivy image scan error: {str(e)[:200]}",
                file_path=image,
                remediation="Check image accessibility and Trivy installation"
            ))
        
        return findings
    
    def scan_kubernetes_cluster(self, namespace: Optional[str] = None, timeout: int = 300) -> List[SecurityFinding]:
        """Scan Kubernetes cluster for vulnerabilities"""
        findings = []
        
        if not self._check_trivy_installed():
            return findings
        
        try:
            logger.info(f"Running Trivy Kubernetes cluster scan (namespace: {namespace or 'all'}) - timeout: {timeout}s")
            
            cmd = [
                self.trivy_cmd,
                "k8s",
                "cluster",
                "--quiet",
                "--severity", "CRITICAL,HIGH,MEDIUM",
                "--format", "json",
                "--no-progress",
                "--skip-db-update"  # Skip DB update to speed up
            ]
            
            if namespace:
                cmd.extend(["--namespace", namespace])
            
            # Trivy k8s needs kubectl access - use in-cluster config
            k8s_env = dict(os.environ)
            # Use in-cluster config if available, otherwise try default locations
            if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount"):
                # In-cluster - Trivy will auto-detect
                pass
            else:
                # Try common kubeconfig locations
                kubeconfig_paths = [
                    os.path.expanduser("~/.kube/config"),
                    "/etc/kubernetes/admin.conf",
                    "/root/.kube/config"
                ]
                for kubeconfig in kubeconfig_paths:
                    if os.path.exists(kubeconfig):
                        k8s_env["KUBECONFIG"] = kubeconfig
                        break
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,  # Default 5 minute timeout for cluster scan
                env=k8s_env
            )
            
            if result.stdout:
                try:
                    trivy_data = json.loads(result.stdout)
                    # Trivy k8s output has different structure
                    findings.extend(self._parse_trivy_k8s_results(trivy_data))
                except json.JSONDecodeError as e:
                    logger.warning(f"Could not parse Trivy Kubernetes JSON output: {e}")
            
            if result.returncode != 0:
                logger.warning(f"Trivy k8s scan returned non-zero: {result.stderr[:200]}")
            
            logger.info(f"Trivy Kubernetes scan completed: found {len(findings)} issues")
            
        except subprocess.TimeoutExpired:
            logger.error(f"Trivy Kubernetes scan timed out after {timeout}s")
        except Exception as e:
            logger.error(f"Error running Trivy Kubernetes scan: {e}")
        
        return findings
    
    def _parse_trivy_k8s_results(self, trivy_data: Dict[str, Any]) -> List[SecurityFinding]:
        """Parse Trivy Kubernetes scan results"""
        findings = []
        
        # Trivy k8s output structure varies, handle multiple formats
        if "Results" in trivy_data:
            for result in trivy_data.get("Results", []):
                target = result.get("Target", "unknown")
                
                for vuln in result.get("Vulnerabilities", []):
                    severity = self._map_trivy_severity(vuln.get("Severity", "UNKNOWN"))
                    
                    finding = SecurityFinding(
                        severity=severity,
                        category="DEPENDENCY",
                        description=f"{vuln.get('Title', 'Vulnerability')} - {vuln.get('Description', '')[:200]}",
                        file_path=target,
                        remediation=vuln.get("FixedVersion", "Update to secure version")
                    )
                    findings.append(finding)
        
        return findings

class SecurityGatekeeper:
    """Main security gatekeeper agent"""
    
    def __init__(self, enable_trivy: bool = True):
        self.prompt_scanner = PromptSecurityScanner()
        self.code_scanner = CodeSecurityScanner()
        self.dependency_scanner = DependencyScanner()
        self.trivy_scanner = TrivyScanner() if enable_trivy else None
        self.findings: List[SecurityFinding] = []
    
    def scan_agent(self, agent_path: str) -> Dict[str, Any]:
        """Perform comprehensive security scan of an agent"""
        logger.info(f"Starting security scan for agent: {agent_path}")
        
        self.findings = []
        scan_results = {
            'agent_path': agent_path,
            'scan_timestamp': datetime.now().isoformat(),
            'findings': [],
            'summary': {
                'total_findings': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        # Scan all Python files
        for py_file in Path(agent_path).rglob('*.py'):
            if py_file.is_file():
                self.findings.extend(self.code_scanner.scan_file(str(py_file)))
        
        # Scan prompt files
        for prompt_file in Path(agent_path).rglob('*.prompt'):
            if prompt_file.is_file():
                with open(prompt_file, 'r') as f:
                    prompt_content = f.read()
                self.findings.extend(self.prompt_scanner.scan_prompt(prompt_content, str(prompt_file)))
        
        # Scan requirements files
        for req_file in Path(agent_path).rglob('requirements*.txt'):
            if req_file.is_file():
                self.findings.extend(self.dependency_scanner.scan_requirements(str(req_file)))
                
                # Also scan with Trivy for comprehensive dependency analysis
                if self.trivy_scanner:
                    self.findings.extend(self.trivy_scanner.scan_requirements_with_trivy(str(req_file)))
        
        # Run Trivy filesystem scan for comprehensive analysis
        if self.trivy_scanner:
            logger.info("Running Trivy filesystem scan...")
            trivy_findings = self.trivy_scanner.scan_filesystem(agent_path)
            self.findings.extend(trivy_findings)
            logger.info(f"Trivy found {len(trivy_findings)} additional issues")
        
        # Generate summary
        for finding in self.findings:
            scan_results['summary'][finding.severity.lower()] += 1
            scan_results['summary']['total_findings'] += 1
        
        scan_results['findings'] = [
            {
                'severity': f.severity,
                'category': f.category,
                'description': f.description,
                'file_path': f.file_path,
                'line_number': f.line_number,
                'remediation': f.remediation
            }
            for f in self.findings
        ]
        
        logger.info(f"Security scan completed. Found {scan_results['summary']['total_findings']} issues")
        return scan_results
    
    def generate_report(self, scan_results: Dict[str, Any], output_file: str):
        """Generate security scan report"""
        report = {
            'scan_results': scan_results,
            'recommendations': self._generate_recommendations(scan_results),
            'compliance_status': self._check_compliance(scan_results)
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Security report generated: {output_file}")
    
    def _generate_recommendations(self, scan_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if scan_results['summary']['critical'] > 0:
            recommendations.append("CRITICAL: Address all critical findings before deployment")
        
        if scan_results['summary']['high'] > 0:
            recommendations.append("HIGH: Review and fix high-severity issues")
        
        if scan_results['summary']['medium'] > 0:
            recommendations.append("MEDIUM: Consider addressing medium-severity issues")
        
        return recommendations
    
    def _check_compliance(self, scan_results: Dict[str, Any]) -> Dict[str, bool]:
        """Check compliance with security policies"""
        return {
            'zero_trust_policy': scan_results['summary']['critical'] == 0 and scan_results['summary']['high'] == 0,
            'deployment_ready': scan_results['summary']['critical'] == 0,
            'production_ready': scan_results['summary']['critical'] == 0 and scan_results['summary']['high'] <= 2
        }

def main():
    """Main entry point for security scanning"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Gatekeeper Agent')
    parser.add_argument('agent_path', help='Path to agent code')
    parser.add_argument('--output', '-o', default='security_report.json', help='Output report file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    gatekeeper = SecurityGatekeeper()
    scan_results = gatekeeper.scan_agent(args.agent_path)
    gatekeeper.generate_report(scan_results, args.output)
    
    # Exit with error code if critical issues found
    if scan_results['summary']['critical'] > 0:
        logger.error("Critical security issues found. Deployment blocked.")
        exit(1)
    elif scan_results['summary']['high'] > 0:
        logger.warning("High-severity security issues found.")
        exit(2)
    else:
        logger.info("Security scan passed.")
        exit(0)

if __name__ == '__main__':
    main()
