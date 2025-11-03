#!/usr/bin/env python3
"""
Risk Detection Agent - Example GenAI Agent
A secure agent that analyzes data for risk patterns and anomalies
"""

import os
import json
import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
import numpy as np
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Prometheus metrics
risk_analysis_count = Counter('risk_detection_analyses_total', 'Total risk analyses performed', ['risk_level'])
anomaly_detection_time = Histogram('risk_detection_analysis_duration_seconds', 'Time spent on risk analysis')
active_risk_sessions = Gauge('risk_detection_active_sessions', 'Number of active risk analysis sessions')

class RiskData(BaseModel):
    """Risk analysis data model"""
    transaction_id: str = Field(..., description="Unique transaction identifier")
    amount: float = Field(..., description="Transaction amount")
    timestamp: str = Field(..., description="Transaction timestamp")
    user_id: str = Field(..., description="User identifier")
    transaction_type: str = Field(..., description="Type of transaction")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

class RiskAnalysis(BaseModel):
    """Risk analysis result model"""
    analysis_id: str
    transaction_id: str
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Risk score between 0 and 1")
    risk_level: str = Field(..., description="Risk level: LOW, MEDIUM, HIGH, CRITICAL")
    anomalies: List[str] = Field(default_factory=list, description="Detected anomalies")
    recommendations: List[str] = Field(default_factory=list, description="Risk mitigation recommendations")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Analysis confidence")
    timestamp: str
    agent_id: str = "risk-detection-agent"

class RiskDetectionAgent:
    """Secure risk detection agent"""
    
    def __init__(self):
        self.agent_id = "risk-detection-agent"
        self.version = os.getenv("AGENT_VERSION", "1.0.0")
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        
        # Risk detection models (simplified for demo)
        self.risk_models = self._initialize_risk_models()
        
        # Security policies
        self.security_policies = self._load_security_policies()
        
        logger.info(f"Risk Detection Agent {self.version} initialized")
    
    def _initialize_risk_models(self) -> Dict[str, Any]:
        """Initialize risk detection models"""
        return {
            "amount_threshold": 10000.0,  # High amount threshold
            "velocity_threshold": 5,      # Transactions per hour
            "geographic_anomaly": True,   # Geographic anomaly detection
            "time_anomaly": True,         # Time-based anomaly detection
            "pattern_anomaly": True       # Pattern-based anomaly detection
        }
    
    def _load_security_policies(self) -> Dict[str, Any]:
        """Load security policies for the agent"""
        return {
            "max_analysis_time": 30,  # seconds
            "data_retention": "24h",
            "privacy_mode": True,
            "audit_logging": True,
            "rate_limits": {
                "analyses_per_minute": 100,
                "analyses_per_hour": 1000
            }
        }
    
    async def analyze_risk(self, data: RiskData) -> RiskAnalysis:
        """Analyze transaction data for risk patterns"""
        logger.info(f"Analyzing risk for transaction {data.transaction_id}")
        
        # Security validation
        if not self._validate_data(data):
            raise HTTPException(status_code=400, detail="Invalid data provided")
        
        # Rate limiting
        if not self._check_rate_limit(data.user_id):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        # Start session tracking
        session_id = f"{data.user_id}_{int(datetime.now().timestamp())}"
        self.active_sessions[session_id] = {
            "user_id": data.user_id,
            "start_time": datetime.now(),
            "analysis_count": 1
        }
        active_risk_sessions.set(len(self.active_sessions))
        
        try:
            # Perform risk analysis
            analysis = await self._perform_risk_analysis(data)
            
            # Log successful analysis
            risk_analysis_count.labels(risk_level=analysis.risk_level).inc()
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error in risk analysis: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")
        
        finally:
            # Clean up session
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
                active_risk_sessions.set(len(self.active_sessions))
    
    def _validate_data(self, data: RiskData) -> bool:
        """Validate input data for security"""
        
        # Check required fields
        if not all([data.transaction_id, data.user_id, data.timestamp]):
            return False
        
        # Check amount range
        if data.amount < 0 or data.amount > 1000000:  # Max $1M
            return False
        
        # Check timestamp format
        try:
            datetime.fromisoformat(data.timestamp.replace('Z', '+00:00'))
        except ValueError:
            return False
        
        return True
    
    def _check_rate_limit(self, user_id: str) -> bool:
        """Check rate limits for user"""
        current_time = datetime.now()
        
        # Count analyses in the last minute
        recent_analyses = sum(1 for session in self.active_sessions.values() 
                            if (current_time - session["start_time"]).seconds < 60)
        
        return recent_analyses < self.security_policies["rate_limits"]["analyses_per_minute"]
    
    async def _perform_risk_analysis(self, data: RiskData) -> RiskAnalysis:
        """Perform comprehensive risk analysis"""
        start_time = datetime.now()
        
        # Initialize analysis
        risk_score = 0.0
        anomalies = []
        recommendations = []
        
        # Amount-based risk
        amount_risk = self._analyze_amount_risk(data.amount)
        risk_score += amount_risk["score"]
        if amount_risk["anomaly"]:
            anomalies.append(amount_risk["description"])
            recommendations.append(amount_risk["recommendation"])
        
        # Velocity-based risk
        velocity_risk = await self._analyze_velocity_risk(data)
        risk_score += velocity_risk["score"]
        if velocity_risk["anomaly"]:
            anomalies.append(velocity_risk["description"])
            recommendations.append(velocity_risk["recommendation"])
        
        # Time-based risk
        time_risk = self._analyze_time_risk(data.timestamp)
        risk_score += time_risk["score"]
        if time_risk["anomaly"]:
            anomalies.append(time_risk["description"])
            recommendations.append(time_risk["recommendation"])
        
        # Pattern-based risk
        pattern_risk = await self._analyze_pattern_risk(data)
        risk_score += pattern_risk["score"]
        if pattern_risk["anomaly"]:
            anomalies.append(pattern_risk["description"])
            recommendations.append(pattern_risk["recommendation"])
        
        # Normalize risk score
        risk_score = min(1.0, risk_score)
        
        # Determine risk level
        risk_level = self._determine_risk_level(risk_score)
        
        # Calculate confidence
        confidence = self._calculate_confidence(anomalies, risk_score)
        
        # Record analysis time
        analysis_time = (datetime.now() - start_time).total_seconds()
        anomaly_detection_time.observe(analysis_time)
        
        return RiskAnalysis(
            analysis_id=f"risk_{int(datetime.now().timestamp())}",
            transaction_id=data.transaction_id,
            risk_score=risk_score,
            risk_level=risk_level,
            anomalies=anomalies,
            recommendations=recommendations,
            confidence=confidence,
            timestamp=datetime.now().isoformat(),
            agent_id=self.agent_id
        )
    
    def _analyze_amount_risk(self, amount: float) -> Dict[str, Any]:
        """Analyze amount-based risk"""
        threshold = self.risk_models["amount_threshold"]
        
        if amount > threshold:
            return {
                "score": 0.3,
                "anomaly": True,
                "description": f"High amount transaction: ${amount:,.2f}",
                "recommendation": "Manual review required for high-value transaction"
            }
        elif amount > threshold * 0.5:
            return {
                "score": 0.1,
                "anomaly": False,
                "description": "Moderate amount transaction",
                "recommendation": "Monitor for additional high-value transactions"
            }
        else:
            return {
                "score": 0.0,
                "anomaly": False,
                "description": "Normal amount transaction",
                "recommendation": "No action required"
            }
    
    async def _analyze_velocity_risk(self, data: RiskData) -> Dict[str, Any]:
        """Analyze transaction velocity risk"""
        # Simulate velocity analysis
        velocity_threshold = self.risk_models["velocity_threshold"]
        
        # Mock velocity calculation
        mock_velocity = np.random.randint(1, 10)
        
        if mock_velocity > velocity_threshold:
            return {
                "score": 0.4,
                "anomaly": True,
                "description": f"High transaction velocity: {mock_velocity} transactions/hour",
                "recommendation": "Temporary velocity limit recommended"
            }
        else:
            return {
                "score": 0.0,
                "anomaly": False,
                "description": "Normal transaction velocity",
                "recommendation": "No action required"
            }
    
    def _analyze_time_risk(self, timestamp: str) -> Dict[str, Any]:
        """Analyze time-based risk patterns"""
        try:
            transaction_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            hour = transaction_time.hour
            
            # Unusual hours (2 AM - 6 AM)
            if 2 <= hour <= 6:
                return {
                    "score": 0.2,
                    "anomaly": True,
                    "description": f"Transaction during unusual hours: {hour}:00",
                    "recommendation": "Verify transaction legitimacy"
                }
            else:
                return {
                    "score": 0.0,
                    "anomaly": False,
                    "description": "Normal transaction time",
                    "recommendation": "No action required"
                }
        except:
            return {
                "score": 0.1,
                "anomaly": True,
                "description": "Invalid timestamp format",
                "recommendation": "Verify transaction data integrity"
            }
    
    async def _analyze_pattern_risk(self, data: RiskData) -> Dict[str, Any]:
        """Analyze pattern-based risk"""
        # Simulate pattern analysis
        pattern_score = np.random.random() * 0.3
        
        if pattern_score > 0.2:
            return {
                "score": pattern_score,
                "anomaly": True,
                "description": "Unusual transaction pattern detected",
                "recommendation": "Enhanced monitoring recommended"
            }
        else:
            return {
                "score": 0.0,
                "anomaly": False,
                "description": "Normal transaction pattern",
                "recommendation": "No action required"
            }
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score"""
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.3:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_confidence(self, anomalies: List[str], risk_score: float) -> float:
        """Calculate analysis confidence"""
        base_confidence = 0.8
        
        # Adjust confidence based on number of anomalies
        anomaly_factor = min(0.2, len(anomalies) * 0.05)
        
        # Adjust confidence based on risk score
        risk_factor = risk_score * 0.1
        
        confidence = base_confidence + anomaly_factor - risk_factor
        return max(0.5, min(1.0, confidence))
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get agent health status"""
        return {
            "agent_id": self.agent_id,
            "version": self.version,
            "status": "healthy",
            "active_sessions": len(self.active_sessions),
            "uptime": datetime.now().isoformat(),
            "risk_models": {
                "enabled": True,
                "version": "1.0"
            }
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get agent metrics"""
        return {
            "total_analyses": risk_analysis_count._value.sum(),
            "active_sessions": len(self.active_sessions),
            "average_analysis_time": anomaly_detection_time._sum / max(anomaly_detection_time._count, 1),
            "risk_distribution": {
                "low": risk_analysis_count.labels(risk_level="LOW")._value.sum(),
                "medium": risk_analysis_count.labels(risk_level="MEDIUM")._value.sum(),
                "high": risk_analysis_count.labels(risk_level="HIGH")._value.sum(),
                "critical": risk_analysis_count.labels(risk_level="CRITICAL")._value.sum()
            }
        }

# Initialize agent
agent = RiskDetectionAgent()

# FastAPI application
app = FastAPI(
    title="Risk Detection Agent",
    description="Secure GenAI risk detection agent",
    version=agent.version
)

@app.on_event("startup")
async def startup_event():
    """Startup event"""
    # Start Prometheus metrics server
    start_http_server(8000)
    logger.info("Prometheus metrics server started on port 8000")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return agent.get_health_status()

@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint"""
    return {"status": "ready", "timestamp": datetime.now().isoformat()}

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    pass

@app.post("/api/v1/analyze", response_model=RiskAnalysis)
async def analyze_risk(data: RiskData, request: Request):
    """Analyze transaction data for risk"""
    try:
        analysis = await agent.analyze_risk(data)
        return analysis
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/v1/metrics")
async def get_metrics():
    """Get agent metrics"""
    return agent.get_metrics()

@app.get("/api/v1/status")
async def get_status():
    """Get agent status"""
    return {
        "agent_id": agent.agent_id,
        "version": agent.version,
        "status": "running",
        "active_sessions": len(agent.active_sessions),
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
