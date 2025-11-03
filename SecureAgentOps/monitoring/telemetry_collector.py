#!/usr/bin/env python3
"""
Security Telemetry Collector
Collects security metrics and events for monitoring GenAI agents
"""

import json
import time
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import threading
import queue

logger = logging.getLogger(__name__)

# Prometheus metrics
security_findings_total = Counter(
    'secureagentops_security_findings_total',
    'Total number of security findings',
    ['agent_id', 'severity', 'category']
)

policy_violations_total = Counter(
    'secureagentops_policy_violations_total',
    'Total number of policy violations',
    ['agent_id', 'policy_id', 'severity']
)

agent_deployments_total = Counter(
    'secureagentops_agent_deployments_total',
    'Total number of agent deployments',
    ['agent_id', 'status']
)

agent_runtime_health = Gauge(
    'secureagentops_agent_runtime_health',
    'Agent runtime health score',
    ['agent_id']
)

security_scan_duration = Histogram(
    'secureagentops_security_scan_duration_seconds',
    'Time spent on security scans',
    ['agent_id']
)

policy_evaluation_duration = Histogram(
    'secureagentops_policy_evaluation_duration_seconds',
    'Time spent on policy evaluations',
    ['agent_id']
)

@dataclass
class SecurityEvent:
    """Security event for telemetry"""
    event_id: str
    agent_id: str
    event_type: str
    severity: str
    timestamp: str
    details: Dict[str, Any]
    source: str

@dataclass
class AgentMetrics:
    """Agent performance and security metrics"""
    agent_id: str
    timestamp: str
    health_score: float
    security_score: float
    performance_score: float
    compliance_score: float
    total_requests: int
    error_rate: float
    response_time_p95: float
    memory_usage: float
    cpu_usage: float

class SecurityTelemetryCollector:
    """Collects and processes security telemetry data"""
    
    def __init__(self, prometheus_port: int = 8000):
        self.prometheus_port = prometheus_port
        self.events_queue = queue.Queue()
        self.metrics_buffer: Dict[str, AgentMetrics] = {}
        self.running = False
        self.collector_thread = None
        
        # Start Prometheus metrics server
        start_http_server(self.prometheus_port)
        logger.info(f"Prometheus metrics server started on port {self.prometheus_port}")
    
    def start(self):
        """Start the telemetry collector"""
        self.running = True
        self.collector_thread = threading.Thread(target=self._collect_loop)
        self.collector_thread.start()
        logger.info("Security telemetry collector started")
    
    def stop(self):
        """Stop the telemetry collector"""
        self.running = False
        if self.collector_thread:
            self.collector_thread.join()
        logger.info("Security telemetry collector stopped")
    
    def record_security_finding(self, agent_id: str, severity: str, category: str):
        """Record a security finding"""
        security_findings_total.labels(
            agent_id=agent_id,
            severity=severity,
            category=category
        ).inc()
        
        event = SecurityEvent(
            event_id=f"sec_{int(time.time())}",
            agent_id=agent_id,
            event_type="security_finding",
            severity=severity,
            timestamp=datetime.now().isoformat(),
            details={"category": category},
            source="security_scanner"
        )
        
        self.events_queue.put(event)
        logger.info(f"Recorded security finding for agent {agent_id}: {severity}/{category}")
    
    def record_policy_violation(self, agent_id: str, policy_id: str, severity: str):
        """Record a policy violation"""
        policy_violations_total.labels(
            agent_id=agent_id,
            policy_id=policy_id,
            severity=severity
        ).inc()
        
        event = SecurityEvent(
            event_id=f"pol_{int(time.time())}",
            agent_id=agent_id,
            event_type="policy_violation",
            severity=severity,
            timestamp=datetime.now().isoformat(),
            details={"policy_id": policy_id},
            source="policy_engine"
        )
        
        self.events_queue.put(event)
        logger.info(f"Recorded policy violation for agent {agent_id}: {policy_id}")
    
    def record_deployment(self, agent_id: str, status: str):
        """Record an agent deployment"""
        agent_deployments_total.labels(
            agent_id=agent_id,
            status=status
        ).inc()
        
        event = SecurityEvent(
            event_id=f"dep_{int(time.time())}",
            agent_id=agent_id,
            event_type="deployment",
            severity="INFO",
            timestamp=datetime.now().isoformat(),
            details={"status": status},
            source="deployment_engine"
        )
        
        self.events_queue.put(event)
        logger.info(f"Recorded deployment for agent {agent_id}: {status}")
    
    def record_security_scan_duration(self, agent_id: str, duration: float):
        """Record security scan duration"""
        security_scan_duration.labels(agent_id=agent_id).observe(duration)
    
    def record_policy_evaluation_duration(self, agent_id: str, duration: float):
        """Record policy evaluation duration"""
        policy_evaluation_duration.labels(agent_id=agent_id).observe(duration)
    
    def update_agent_metrics(self, metrics: AgentMetrics):
        """Update agent runtime metrics"""
        self.metrics_buffer[metrics.agent_id] = metrics
        
        # Update Prometheus gauges
        agent_runtime_health.labels(agent_id=metrics.agent_id).set(metrics.health_score)
        
        logger.debug(f"Updated metrics for agent {metrics.agent_id}")
    
    def _collect_loop(self):
        """Main collection loop"""
        while self.running:
            try:
                # Process events from queue
                while not self.events_queue.empty():
                    event = self.events_queue.get_nowait()
                    self._process_event(event)
                
                # Update metrics
                self._update_metrics()
                
                time.sleep(1)  # Collect every second
                
            except Exception as e:
                logger.error(f"Error in collection loop: {e}")
                time.sleep(5)
    
    def _process_event(self, event: SecurityEvent):
        """Process a security event"""
        # In production, this would send to external monitoring systems
        logger.info(f"Processing event: {event.event_type} for agent {event.agent_id}")
        
        # Store event for later analysis
        self._store_event(event)
    
    def _store_event(self, event: SecurityEvent):
        """Store event for persistence"""
        # In production, this would store in a database or send to external systems
        pass
    
    def _update_metrics(self):
        """Update aggregated metrics"""
        # Calculate aggregate metrics from buffered data
        for agent_id, metrics in self.metrics_buffer.items():
            # Update health score based on various factors
            health_score = self._calculate_health_score(metrics)
            agent_runtime_health.labels(agent_id=agent_id).set(health_score)
    
    def _calculate_health_score(self, metrics: AgentMetrics) -> float:
        """Calculate overall health score for an agent"""
        # Weighted combination of different scores
        weights = {
            'security': 0.4,
            'performance': 0.3,
            'compliance': 0.2,
            'reliability': 0.1
        }
        
        reliability_score = 1.0 - metrics.error_rate
        
        health_score = (
            weights['security'] * metrics.security_score +
            weights['performance'] * metrics.performance_score +
            weights['compliance'] * metrics.compliance_score +
            weights['reliability'] * reliability_score
        )
        
        return min(1.0, max(0.0, health_score))
    
    def get_agent_health_summary(self, agent_id: str) -> Dict[str, Any]:
        """Get health summary for an agent"""
        if agent_id not in self.metrics_buffer:
            return {"error": "Agent not found"}
        
        metrics = self.metrics_buffer[agent_id]
        health_score = self._calculate_health_score(metrics)
        
        return {
            'agent_id': agent_id,
            'timestamp': metrics.timestamp,
            'overall_health': health_score,
            'security_score': metrics.security_score,
            'performance_score': metrics.performance_score,
            'compliance_score': metrics.compliance_score,
            'total_requests': metrics.total_requests,
            'error_rate': metrics.error_rate,
            'response_time_p95': metrics.response_time_p95,
            'memory_usage': metrics.memory_usage,
            'cpu_usage': metrics.cpu_usage
        }
    
    def get_security_dashboard_data(self) -> Dict[str, Any]:
        """Get data for security dashboard"""
        return {
            'timestamp': datetime.now().isoformat(),
            'total_agents': len(self.metrics_buffer),
            'healthy_agents': len([m for m in self.metrics_buffer.values() 
                                 if self._calculate_health_score(m) > 0.8]),
            'unhealthy_agents': len([m for m in self.metrics_buffer.values() 
                                   if self._calculate_health_score(m) <= 0.8]),
            'agents': [
                {
                    'agent_id': agent_id,
                    'health_score': self._calculate_health_score(metrics),
                    'security_score': metrics.security_score,
                    'last_update': metrics.timestamp
                }
                for agent_id, metrics in self.metrics_buffer.items()
            ]
        }

class GrafanaDashboardGenerator:
    """Generates Grafana dashboard configurations"""
    
    @staticmethod
    def generate_security_dashboard() -> Dict[str, Any]:
        """Generate Grafana dashboard configuration for security monitoring"""
        dashboard = {
            "dashboard": {
                "id": None,
                "title": "SecureAgentOps Security Dashboard",
                "tags": ["secureagentops", "security", "genai"],
                "timezone": "browser",
                "panels": [
                    {
                        "id": 1,
                        "title": "Security Findings by Severity",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "sum(rate(secureagentops_security_findings_total[5m])) by (severity)",
                                "legendFormat": "{{severity}}"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "color": {
                                    "mode": "thresholds"
                                },
                                "thresholds": {
                                    "steps": [
                                        {"color": "green", "value": 0},
                                        {"color": "yellow", "value": 1},
                                        {"color": "red", "value": 5}
                                    ]
                                }
                            }
                        }
                    },
                    {
                        "id": 2,
                        "title": "Policy Violations",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "sum(rate(secureagentops_policy_violations_total[5m])) by (policy_id)",
                                "legendFormat": "{{policy_id}}"
                            }
                        ]
                    },
                    {
                        "id": 3,
                        "title": "Agent Health Scores",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "secureagentops_agent_runtime_health",
                                "legendFormat": "{{agent_id}}"
                            }
                        ]
                    },
                    {
                        "id": 4,
                        "title": "Deployment Status",
                        "type": "piechart",
                        "targets": [
                            {
                                "expr": "sum(secureagentops_agent_deployments_total) by (status)",
                                "legendFormat": "{{status}}"
                            }
                        ]
                    },
                    {
                        "id": 5,
                        "title": "Security Scan Duration",
                        "type": "histogram",
                        "targets": [
                            {
                                "expr": "histogram_quantile(0.95, rate(secureagentops_security_scan_duration_seconds_bucket[5m]))",
                                "legendFormat": "95th percentile"
                            }
                        ]
                    }
                ],
                "time": {
                    "from": "now-1h",
                    "to": "now"
                },
                "refresh": "5s"
            }
        }
        
        return dashboard
    
    @staticmethod
    def save_dashboard_config(dashboard: Dict[str, Any], output_file: str):
        """Save dashboard configuration to file"""
        with open(output_file, 'w') as f:
            json.dump(dashboard, f, indent=2)
        
        logger.info(f"Grafana dashboard configuration saved: {output_file}")

def main():
    """Main entry point for telemetry collector"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Telemetry Collector')
    parser.add_argument('--port', type=int, default=8000, help='Prometheus metrics port')
    parser.add_argument('--generate-dashboard', action='store_true', help='Generate Grafana dashboard')
    parser.add_argument('--dashboard-output', default='grafana_dashboard.json', help='Dashboard output file')
    
    args = parser.parse_args()
    
    if args.generate_dashboard:
        dashboard_generator = GrafanaDashboardGenerator()
        dashboard = dashboard_generator.generate_security_dashboard()
        dashboard_generator.save_dashboard_config(dashboard, args.dashboard_output)
        print(f"Grafana dashboard configuration generated: {args.dashboard_output}")
        return
    
    # Start telemetry collector
    collector = SecurityTelemetryCollector(args.port)
    
    try:
        collector.start()
        
        # Simulate some metrics for demonstration
        collector.update_agent_metrics(AgentMetrics(
            agent_id="customer-support-agent",
            timestamp=datetime.now().isoformat(),
            health_score=0.95,
            security_score=0.98,
            performance_score=0.92,
            compliance_score=0.96,
            total_requests=1000,
            error_rate=0.02,
            response_time_p95=150.0,
            memory_usage=0.75,
            cpu_usage=0.45
        ))
        
        collector.record_security_finding("customer-support-agent", "LOW", "CODE")
        collector.record_deployment("customer-support-agent", "SUCCESS")
        
        print(f"Telemetry collector running on port {args.port}")
        print("Press Ctrl+C to stop")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping telemetry collector...")
        collector.stop()

if __name__ == '__main__':
    main()
