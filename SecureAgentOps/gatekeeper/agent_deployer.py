#!/usr/bin/env python3
"""
Agent Deployer Service
Handles secure deployment of GenAI agents after security validation
"""

import json
import yaml
import logging
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import kubernetes
from kubernetes import client, config
import requests

logger = logging.getLogger(__name__)

class DeploymentRequest(BaseModel):
    agent_id: str
    agent_version: str
    agent_path: str
    namespace: str = "default"
    replicas: int = 1
    resources: Dict[str, Any] = {}
    environment_vars: Dict[str, str] = {}

class DeploymentStatus(BaseModel):
    agent_id: str
    status: str  # PENDING, DEPLOYING, DEPLOYED, FAILED
    timestamp: str
    details: Dict[str, Any]

@dataclass
class AgentDeployment:
    """Represents an agent deployment"""
    agent_id: str
    version: str
    namespace: str
    status: str
    created_at: datetime
    manifest: Dict[str, Any]

class AgentDeployer:
    """Handles secure deployment of GenAI agents"""
    
    def __init__(self, gatekeeper_url: str = "http://security-gatekeeper:8080"):
        self.gatekeeper_url = gatekeeper_url
        self.deployments: Dict[str, AgentDeployment] = {}
        
        # Initialize Kubernetes client
        try:
            config.load_incluster_config()
        except:
            config.load_kube_config()
        
        self.k8s_client = client.ApiClient()
        self.apps_v1 = client.AppsV1Api(self.k8s_client)
        self.core_v1 = client.CoreV1Api(self.k8s_client)
        self.networking_v1 = client.NetworkingV1Api(self.k8s_client)
        
        logger.info("Agent deployer initialized")
    
    async def deploy_agent(self, request: DeploymentRequest) -> DeploymentStatus:
        """Deploy an agent after security validation"""
        logger.info(f"Starting deployment for agent {request.agent_id}")
        
        # Step 1: Security validation
        security_result = await self._validate_security(request)
        if not security_result['approved']:
            raise HTTPException(
                status_code=400,
                detail=f"Security validation failed: {security_result['reason']}"
            )
        
        # Step 2: Create deployment manifest
        manifest = await self._create_deployment_manifest(request)
        
        # Step 3: Deploy to Kubernetes
        deployment_result = await self._deploy_to_k8s(manifest, request.namespace)
        
        # Step 4: Create network policies
        await self._create_network_policies(request)
        
        # Step 5: Update deployment status
        deployment = AgentDeployment(
            agent_id=request.agent_id,
            version=request.agent_version,
            namespace=request.namespace,
            status="DEPLOYED",
            created_at=datetime.now(),
            manifest=manifest
        )
        
        self.deployments[request.agent_id] = deployment
        
        return DeploymentStatus(
            agent_id=request.agent_id,
            status="DEPLOYED",
            timestamp=datetime.now().isoformat(),
            details={
                "security_validation": security_result,
                "deployment_result": deployment_result,
                "namespace": request.namespace
            }
        )
    
    async def _validate_security(self, request: DeploymentRequest) -> Dict[str, Any]:
        """Validate agent security through gatekeeper"""
        try:
            # Call security gatekeeper API
            validation_request = {
                "agent_id": request.agent_id,
                "agent_path": request.agent_path,
                "version": request.agent_version
            }
            
            response = requests.post(
                f"{self.gatekeeper_url}/api/v1/validate",
                json=validation_request,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "approved": result.get("overall_decision") != "BLOCK",
                    "reason": result.get("summary", {}),
                    "details": result
                }
            else:
                return {
                    "approved": False,
                    "reason": f"Gatekeeper validation failed: {response.status_code}"
                }
                
        except Exception as e:
            logger.error(f"Security validation error: {e}")
            return {
                "approved": False,
                "reason": f"Security validation error: {str(e)}"
            }
    
    async def _create_deployment_manifest(self, request: DeploymentRequest) -> Dict[str, Any]:
        """Create Kubernetes deployment manifest"""
        
        # Default resource limits
        default_resources = {
            "requests": {
                "memory": "256Mi",
                "cpu": "200m"
            },
            "limits": {
                "memory": "512Mi",
                "cpu": "500m"
            }
        }
        
        # Merge with provided resources
        resources = {**default_resources, **request.resources}
        
        # Create environment variables
        env_vars = []
        for key, value in request.environment_vars.items():
            env_vars.append({
                "name": key,
                "value": value
            })
        
        # Add security-related environment variables
        env_vars.extend([
            {"name": "AGENT_ID", "value": request.agent_id},
            {"name": "AGENT_VERSION", "value": request.agent_version},
            {"name": "SECURITY_MODE", "value": "enabled"}
        ])
        
        manifest = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": f"{request.agent_id}-deployment",
                "namespace": request.namespace,
                "labels": {
                    "app": request.agent_id,
                    "version": request.agent_version,
                    "managed-by": "secureagentops"
                }
            },
            "spec": {
                "replicas": request.replicas,
                "selector": {
                    "matchLabels": {
                        "app": request.agent_id
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": request.agent_id,
                            "version": request.agent_version
                        },
                        "annotations": {
                            "prometheus.io/scrape": "true",
                            "prometheus.io/port": "8000",
                            "prometheus.io/path": "/metrics"
                        }
                    },
                    "spec": {
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 1000,
                            "fsGroup": 2000
                        },
                        "containers": [
                            {
                                "name": request.agent_id,
                                "image": f"secureagentops/{request.agent_id}:{request.agent_version}",
                                "ports": [
                                    {
                                        "containerPort": 8080,
                                        "name": "http"
                                    },
                                    {
                                        "containerPort": 8000,
                                        "name": "metrics"
                                    }
                                ],
                                "env": env_vars,
                                "resources": resources,
                                "livenessProbe": {
                                    "httpGet": {
                                        "path": "/health",
                                        "port": 8080
                                    },
                                    "initialDelaySeconds": 30,
                                    "periodSeconds": 10
                                },
                                "readinessProbe": {
                                    "httpGet": {
                                        "path": "/ready",
                                        "port": 8080
                                    },
                                    "initialDelaySeconds": 5,
                                    "periodSeconds": 5
                                },
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {
                                        "drop": ["ALL"]
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
        
        return manifest
    
    async def _deploy_to_k8s(self, manifest: Dict[str, Any], namespace: str) -> Dict[str, Any]:
        """Deploy manifest to Kubernetes"""
        try:
            # Create deployment
            deployment = self.apps_v1.create_namespaced_deployment(
                namespace=namespace,
                body=manifest
            )
            
            # Create service
            service_manifest = self._create_service_manifest(manifest)
            service = self.core_v1.create_namespaced_service(
                namespace=namespace,
                body=service_manifest
            )
            
            logger.info(f"Deployment created: {deployment.metadata.name}")
            
            return {
                "deployment_name": deployment.metadata.name,
                "service_name": service.metadata.name,
                "status": "success"
            }
            
        except Exception as e:
            logger.error(f"Kubernetes deployment failed: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Deployment failed: {str(e)}"
            )
    
    def _create_service_manifest(self, deployment_manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Create service manifest for deployment"""
        app_name = deployment_manifest["metadata"]["labels"]["app"]
        
        return {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": f"{app_name}-service",
                "namespace": deployment_manifest["metadata"]["namespace"],
                "labels": {
                    "app": app_name,
                    "managed-by": "secureagentops"
                }
            },
            "spec": {
                "selector": {
                    "app": app_name
                },
                "ports": [
                    {
                        "name": "http",
                        "port": 8080,
                        "targetPort": 8080
                    },
                    {
                        "name": "metrics",
                        "port": 8000,
                        "targetPort": 8000
                    }
                ],
                "type": "ClusterIP"
            }
        }
    
    async def _create_network_policies(self, request: DeploymentRequest):
        """Create network policies for agent"""
        try:
            network_policy = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": f"{request.agent_id}-network-policy",
                    "namespace": request.namespace
                },
                "spec": {
                    "podSelector": {
                        "matchLabels": {
                            "app": request.agent_id
                        }
                    },
                    "policyTypes": ["Ingress", "Egress"],
                    "ingress": [
                        {
                            "from": [
                                {
                                    "namespaceSelector": {
                                        "matchLabels": {
                                            "name": "secureagentops"
                                        }
                                    }
                                }
                            ],
                            "ports": [
                                {"protocol": "TCP", "port": 8080},
                                {"protocol": "TCP", "port": 8000}
                            ]
                        }
                    ],
                    "egress": [
                        {
                            "to": [],
                            "ports": [
                                {"protocol": "TCP", "port": 443},
                                {"protocol": "TCP", "port": 53},
                                {"protocol": "UDP", "port": 53}
                            ]
                        }
                    ]
                }
            }
            
            self.networking_v1.create_namespaced_network_policy(
                namespace=request.namespace,
                body=network_policy
            )
            
            logger.info(f"Network policy created for {request.agent_id}")
            
        except Exception as e:
            logger.warning(f"Failed to create network policy: {e}")
    
    def get_deployment_status(self, agent_id: str) -> Optional[DeploymentStatus]:
        """Get deployment status for an agent"""
        if agent_id not in self.deployments:
            return None
        
        deployment = self.deployments[agent_id]
        
        return DeploymentStatus(
            agent_id=agent_id,
            status=deployment.status,
            timestamp=deployment.created_at.isoformat(),
            details={
                "namespace": deployment.namespace,
                "version": deployment.version
            }
        )
    
    def list_deployments(self) -> List[DeploymentStatus]:
        """List all deployments"""
        return [
            DeploymentStatus(
                agent_id=deployment.agent_id,
                status=deployment.status,
                timestamp=deployment.created_at.isoformat(),
                details={
                    "namespace": deployment.namespace,
                    "version": deployment.version
                }
            )
            for deployment in self.deployments.values()
        ]

# FastAPI application
app = FastAPI(title="Agent Deployer", version="1.0.0")
deployer = AgentDeployer()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint"""
    return {"status": "ready", "timestamp": datetime.now().isoformat()}

@app.post("/api/v1/deploy", response_model=DeploymentStatus)
async def deploy_agent(request: DeploymentRequest, background_tasks: BackgroundTasks):
    """Deploy a new agent"""
    try:
        result = await deployer.deploy_agent(request)
        return result
    except Exception as e:
        logger.error(f"Deployment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/deployments/{agent_id}", response_model=DeploymentStatus)
async def get_deployment_status(agent_id: str):
    """Get deployment status for an agent"""
    status = deployer.get_deployment_status(agent_id)
    if not status:
        raise HTTPException(status_code=404, detail="Deployment not found")
    return status

@app.get("/api/v1/deployments", response_model=List[DeploymentStatus])
async def list_deployments():
    """List all deployments"""
    return deployer.list_deployments()

@app.delete("/api/v1/deployments/{agent_id}")
async def delete_deployment(agent_id: str):
    """Delete an agent deployment"""
    try:
        if agent_id not in deployer.deployments:
            raise HTTPException(status_code=404, detail="Deployment not found")
        
        deployment = deployer.deployments[agent_id]
        
        # Delete Kubernetes resources
        self.apps_v1.delete_namespaced_deployment(
            name=f"{agent_id}-deployment",
            namespace=deployment.namespace
        )
        
        self.core_v1.delete_namespaced_service(
            name=f"{agent_id}-service",
            namespace=deployment.namespace
        )
        
        # Remove from local tracking
        del deployer.deployments[agent_id]
        
        return {"message": f"Deployment {agent_id} deleted successfully"}
        
    except Exception as e:
        logger.error(f"Deletion failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
