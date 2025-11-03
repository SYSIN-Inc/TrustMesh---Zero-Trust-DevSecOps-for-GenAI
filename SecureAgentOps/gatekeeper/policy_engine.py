#!/usr/bin/env python3
"""
Policy-Based Deployment Gates
Implements zero-trust policies for GenAI agent deployment
"""

import json
import yaml
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class PolicySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class PolicyAction(Enum):
    BLOCK = "block"
    WARN = "warn"
    ALLOW = "allow"

@dataclass
class PolicyRule:
    """Individual policy rule"""
    id: str
    name: str
    description: str
    severity: PolicySeverity
    action: PolicyAction
    conditions: Dict[str, Any]
    remediation: str

@dataclass
class PolicyResult:
    """Result of policy evaluation"""
    rule_id: str
    rule_name: str
    passed: bool
    severity: PolicySeverity
    action: PolicyAction
    message: str
    details: Dict[str, Any]

class ZeroTrustPolicyEngine:
    """Zero-trust policy engine for agent deployment"""
    
    def __init__(self, policy_file: Optional[str] = None):
        self.policies: List[PolicyRule] = []
        self.results: List[PolicyResult] = []
        
        if policy_file:
            self.load_policies(policy_file)
        else:
            self._load_default_policies()
    
    def _load_default_policies(self):
        """Load default zero-trust policies"""
        default_policies = [
            PolicyRule(
                id="zt-001",
                name="No Critical Security Issues",
                description="Block deployment if critical security issues are found",
                severity=PolicySeverity.CRITICAL,
                action=PolicyAction.BLOCK,
                conditions={"max_critical_findings": 0},
                remediation="Fix all critical security issues before deployment"
            ),
            PolicyRule(
                id="zt-002",
                name="Limited High Security Issues",
                description="Allow maximum 2 high-severity security issues",
                severity=PolicySeverity.HIGH,
                action=PolicyAction.WARN,
                conditions={"max_high_findings": 2},
                remediation="Review and fix high-severity issues"
            ),
            PolicyRule(
                id="zt-003",
                name="Agent Identity Verification",
                description="Agent must have valid signed manifest",
                severity=PolicySeverity.CRITICAL,
                action=PolicyAction.BLOCK,
                conditions={"require_signed_manifest": True},
                remediation="Ensure agent has valid signed manifest"
            ),
            PolicyRule(
                id="zt-004",
                name="Dependency Security",
                description="All dependencies must be vulnerability-free",
                severity=PolicySeverity.HIGH,
                action=PolicyAction.BLOCK,
                conditions={"no_vulnerable_dependencies": True},
                remediation="Update vulnerable dependencies"
            ),
            PolicyRule(
                id="zt-005",
                name="Prompt Injection Protection",
                description="Prompts must be free of injection patterns",
                severity=PolicySeverity.HIGH,
                action=PolicyAction.BLOCK,
                conditions={"no_prompt_injections": True},
                remediation="Review and sanitize prompts"
            ),
            PolicyRule(
                id="zt-006",
                name="Resource Limits",
                description="Agent must specify resource limits",
                severity=PolicySeverity.MEDIUM,
                action=PolicyAction.WARN,
                conditions={"require_resource_limits": True},
                remediation="Add resource limits to agent configuration"
            ),
            PolicyRule(
                id="zt-007",
                name="Network Security",
                description="Agent must use secure network policies",
                severity=PolicySeverity.MEDIUM,
                action=PolicyAction.WARN,
                conditions={"require_network_policies": True},
                remediation="Configure network security policies"
            ),
            PolicyRule(
                id="zt-008",
                name="Data Privacy",
                description="Agent must handle data according to privacy policies",
                severity=PolicySeverity.HIGH,
                action=PolicyAction.BLOCK,
                conditions={"comply_with_privacy": True},
                remediation="Ensure data handling complies with privacy policies"
            )
        ]
        
        self.policies = default_policies
        logger.info(f"Loaded {len(default_policies)} default policies")
    
    def load_policies(self, policy_file: str):
        """Load policies from YAML file"""
        try:
            with open(policy_file, 'r') as f:
                policy_data = yaml.safe_load(f)
            
            self.policies = []
            for rule_data in policy_data.get('policies', []):
                rule = PolicyRule(
                    id=rule_data['id'],
                    name=rule_data['name'],
                    description=rule_data['description'],
                    severity=PolicySeverity(rule_data['severity']),
                    action=PolicyAction(rule_data['action']),
                    conditions=rule_data['conditions'],
                    remediation=rule_data['remediation']
                )
                self.policies.append(rule)
            
            logger.info(f"Loaded {len(self.policies)} policies from {policy_file}")
            
        except Exception as e:
            logger.error(f"Failed to load policies from {policy_file}: {e}")
            self._load_default_policies()
    
    def evaluate_agent(self, security_scan: Dict[str, Any], 
                     identity_verification: Dict[str, Any],
                     agent_config: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate agent against all policies"""
        logger.info("Starting policy evaluation")
        
        self.results = []
        evaluation_result = {
            'timestamp': datetime.now().isoformat(),
            'overall_decision': 'ALLOW',
            'blocking_issues': [],
            'warnings': [],
            'policy_results': [],
            'summary': {
                'total_policies': len(self.policies),
                'passed': 0,
                'failed': 0,
                'warnings': 0
            }
        }
        
        # Evaluate each policy
        for policy in self.policies:
            result = self._evaluate_policy(policy, security_scan, identity_verification, agent_config)
            self.results.append(result)
            evaluation_result['policy_results'].append({
                'rule_id': result.rule_id,
                'rule_name': result.rule_name,
                'passed': result.passed,
                'severity': result.severity.value,
                'action': result.action.value,
                'message': result.message,
                'details': result.details
            })
            
            if result.passed:
                evaluation_result['summary']['passed'] += 1
            else:
                evaluation_result['summary']['failed'] += 1
                
                if result.action == PolicyAction.BLOCK:
                    evaluation_result['blocking_issues'].append({
                        'rule_id': result.rule_id,
                        'message': result.message,
                        'remediation': policy.remediation
                    })
                elif result.action == PolicyAction.WARN:
                    evaluation_result['warnings'].append({
                        'rule_id': result.rule_id,
                        'message': result.message,
                        'remediation': policy.remediation
                    })
                    evaluation_result['summary']['warnings'] += 1
        
        # Determine overall decision
        if evaluation_result['blocking_issues']:
            evaluation_result['overall_decision'] = 'BLOCK'
        elif evaluation_result['warnings']:
            evaluation_result['overall_decision'] = 'WARN'
        
        logger.info(f"Policy evaluation completed. Decision: {evaluation_result['overall_decision']}")
        return evaluation_result
    
    def _evaluate_policy(self, policy: PolicyRule, security_scan: Dict[str, Any],
                        identity_verification: Dict[str, Any], agent_config: Dict[str, Any]) -> PolicyResult:
        """Evaluate a single policy rule"""
        
        if policy.id == "zt-001":  # No Critical Security Issues
            critical_count = security_scan.get('summary', {}).get('critical', 0)
            passed = critical_count <= policy.conditions['max_critical_findings']
            message = f"Found {critical_count} critical security issues"
            
        elif policy.id == "zt-002":  # Limited High Security Issues
            high_count = security_scan.get('summary', {}).get('high', 0)
            passed = high_count <= policy.conditions['max_high_findings']
            message = f"Found {high_count} high-severity security issues"
            
        elif policy.id == "zt-003":  # Agent Identity Verification
            passed = identity_verification.get('overall_valid', False)
            message = "Agent identity verification" + ("passed" if passed else "failed")
            
        elif policy.id == "zt-004":  # Dependency Security
            passed = identity_verification.get('dependencies_valid', False)
            message = "Dependency security check" + ("passed" if passed else "failed")
            
        elif policy.id == "zt-005":  # Prompt Injection Protection
            prompt_findings = [f for f in security_scan.get('findings', []) 
                             if f.get('category') == 'PROMPT' and f.get('severity') == 'HIGH']
            passed = len(prompt_findings) == 0
            message = f"Found {len(prompt_findings)} prompt injection issues"
            
        elif policy.id == "zt-006":  # Resource Limits
            has_limits = bool(agent_config.get('resources', {}).get('limits'))
            passed = has_limits
            message = "Resource limits" + ("configured" if passed else "not configured")
            
        elif policy.id == "zt-007":  # Network Security
            has_network_policy = bool(agent_config.get('network_policy'))
            passed = has_network_policy
            message = "Network security policy" + ("configured" if passed else "not configured")
            
        elif policy.id == "zt-008":  # Data Privacy
            privacy_compliant = agent_config.get('privacy', {}).get('compliant', False)
            passed = privacy_compliant
            message = "Data privacy compliance" + ("verified" if passed else "not verified")
            
        else:
            # Unknown policy
            passed = True
            message = "Unknown policy rule"
        
        return PolicyResult(
            rule_id=policy.id,
            rule_name=policy.name,
            passed=passed,
            severity=policy.severity,
            action=policy.action,
            message=message,
            details={'policy_conditions': policy.conditions}
        )
    
    def generate_policy_report(self, evaluation_result: Dict[str, Any], output_file: str):
        """Generate policy evaluation report"""
        report = {
            'evaluation_result': evaluation_result,
            'recommendations': self._generate_recommendations(evaluation_result),
            'next_steps': self._generate_next_steps(evaluation_result)
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Policy report generated: {output_file}")
    
    def _generate_recommendations(self, evaluation_result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on policy results"""
        recommendations = []
        
        if evaluation_result['overall_decision'] == 'BLOCK':
            recommendations.append("CRITICAL: Address all blocking issues before deployment")
            for issue in evaluation_result['blocking_issues']:
                recommendations.append(f"- {issue['message']}: {issue['remediation']}")
        
        if evaluation_result['warnings']:
            recommendations.append("WARNING: Consider addressing warnings before production deployment")
            for warning in evaluation_result['warnings']:
                recommendations.append(f"- {warning['message']}: {warning['remediation']}")
        
        if evaluation_result['overall_decision'] == 'ALLOW':
            recommendations.append("SUCCESS: Agent meets all security policies")
            recommendations.append("Consider implementing additional monitoring in production")
        
        return recommendations
    
    def _generate_next_steps(self, evaluation_result: Dict[str, Any]) -> List[str]:
        """Generate next steps based on evaluation result"""
        next_steps = []
        
        if evaluation_result['overall_decision'] == 'BLOCK':
            next_steps.append("Fix all blocking issues")
            next_steps.append("Re-run security scan and policy evaluation")
            next_steps.append("Request security review if needed")
        
        elif evaluation_result['overall_decision'] == 'WARN':
            next_steps.append("Review warnings and decide on action")
            next_steps.append("Deploy with enhanced monitoring")
            next_steps.append("Schedule follow-up review")
        
        else:  # ALLOW
            next_steps.append("Proceed with deployment")
            next_steps.append("Enable production monitoring")
            next_steps.append("Schedule regular security reviews")
        
        return next_steps

def main():
    """Main entry point for policy evaluation"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Zero-Trust Policy Engine')
    parser.add_argument('--security-scan', required=True, help='Security scan results file')
    parser.add_argument('--identity-verification', required=True, help='Identity verification results file')
    parser.add_argument('--agent-config', required=True, help='Agent configuration file')
    parser.add_argument('--policy-file', help='Custom policy file')
    parser.add_argument('--output', default='policy_evaluation.json', help='Output report file')
    
    args = parser.parse_args()
    
    # Load input data
    with open(args.security_scan, 'r') as f:
        security_scan = json.load(f)
    
    with open(args.identity_verification, 'r') as f:
        identity_verification = json.load(f)
    
    with open(args.agent_config, 'r') as f:
        agent_config = json.load(f)
    
    # Initialize policy engine
    policy_engine = ZeroTrustPolicyEngine(args.policy_file)
    
    # Evaluate agent
    evaluation_result = policy_engine.evaluate_agent(
        security_scan, identity_verification, agent_config
    )
    
    # Generate report
    policy_engine.generate_policy_report(evaluation_result, args.output)
    
    # Exit with appropriate code
    if evaluation_result['overall_decision'] == 'BLOCK':
        logger.error("Deployment blocked by policy evaluation")
        exit(1)
    elif evaluation_result['overall_decision'] == 'WARN':
        logger.warning("Deployment allowed with warnings")
        exit(2)
    else:
        logger.info("Deployment approved by policy evaluation")
        exit(0)

if __name__ == '__main__':
    main()
