#!/usr/bin/env python3
"""
Customer Support Agent - Example GenAI Agent
A secure customer support agent that handles inquiries and provides assistance
"""

import os
import json
import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
import openai
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Prometheus metrics
request_count = Counter('customer_support_requests_total', 'Total customer support requests', ['status'])
response_time = Histogram('customer_support_response_time_seconds', 'Response time for customer support')
active_sessions = Gauge('customer_support_active_sessions', 'Number of active customer support sessions')

class CustomerInquiry(BaseModel):
    """Customer inquiry model"""
    customer_id: str = Field(..., description="Unique customer identifier")
    inquiry_type: str = Field(..., description="Type of inquiry")
    message: str = Field(..., description="Customer message")
    priority: str = Field(default="normal", description="Priority level")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

class SupportResponse(BaseModel):
    """Support response model"""
    response_id: str
    customer_id: str
    message: str
    confidence: float
    suggested_actions: List[str]
    timestamp: str
    agent_id: str = "customer-support-agent"

class CustomerSupportAgent:
    """Secure customer support agent"""
    
    def __init__(self):
        self.agent_id = "customer-support-agent"
        self.version = os.getenv("AGENT_VERSION", "1.0.0")
        self.openai_client = None
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        
        # Initialize OpenAI client securely
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.warning("OpenAI API key not found. Agent will run in mock mode.")
        else:
            self.openai_client = openai.OpenAI(api_key=api_key)
        
        # Load security policies
        self.security_policies = self._load_security_policies()
        
        logger.info(f"Customer Support Agent {self.version} initialized")
    
    def _load_security_policies(self) -> Dict[str, Any]:
        """Load security policies for the agent"""
        return {
            "max_response_length": 2000,
            "allowed_inquiry_types": [
                "billing", "technical", "general", "complaint", "refund"
            ],
            "blocked_patterns": [
                "password", "credit card", "ssn", "social security"
            ],
            "rate_limits": {
                "requests_per_minute": 60,
                "requests_per_hour": 1000
            }
        }
    
    async def process_inquiry(self, inquiry: CustomerInquiry) -> SupportResponse:
        """Process a customer inquiry securely"""
        logger.info(f"Processing inquiry from customer {inquiry.customer_id}")
        
        # Security validation
        if not self._validate_inquiry(inquiry):
            raise HTTPException(status_code=400, detail="Invalid inquiry")
        
        # Rate limiting
        if not self._check_rate_limit(inquiry.customer_id):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        # Start session tracking
        session_id = f"{inquiry.customer_id}_{int(datetime.now().timestamp())}"
        self.active_sessions[session_id] = {
            "customer_id": inquiry.customer_id,
            "start_time": datetime.now(),
            "inquiry_count": 1
        }
        active_sessions.set(len(self.active_sessions))
        
        try:
            # Generate response
            response = await self._generate_response(inquiry)
            
            # Log successful request
            request_count.labels(status="success").inc()
            
            return response
            
        except Exception as e:
            logger.error(f"Error processing inquiry: {e}")
            request_count.labels(status="error").inc()
            raise HTTPException(status_code=500, detail="Internal server error")
        
        finally:
            # Clean up session
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
                active_sessions.set(len(self.active_sessions))
    
    def _validate_inquiry(self, inquiry: CustomerInquiry) -> bool:
        """Validate customer inquiry for security"""
        
        # Check inquiry type
        if inquiry.inquiry_type not in self.security_policies["allowed_inquiry_types"]:
            logger.warning(f"Invalid inquiry type: {inquiry.inquiry_type}")
            return False
        
        # Check for blocked patterns
        message_lower = inquiry.message.lower()
        for pattern in self.security_policies["blocked_patterns"]:
            if pattern in message_lower:
                logger.warning(f"Blocked pattern detected: {pattern}")
                return False
        
        # Check message length
        if len(inquiry.message) > self.security_policies["max_response_length"]:
            logger.warning("Message too long")
            return False
        
        return True
    
    def _check_rate_limit(self, customer_id: str) -> bool:
        """Check rate limits for customer"""
        # Simple rate limiting implementation
        # In production, use Redis or similar for distributed rate limiting
        current_time = datetime.now()
        
        # Count requests in the last minute
        recent_requests = sum(1 for session in self.active_sessions.values() 
                            if (current_time - session["start_time"]).seconds < 60)
        
        return recent_requests < self.security_policies["rate_limits"]["requests_per_minute"]
    
    async def _generate_response(self, inquiry: CustomerInquiry) -> SupportResponse:
        """Generate response using AI model"""
        
        # Create secure prompt
        prompt = self._create_secure_prompt(inquiry)
        
        if self.openai_client:
            # Use OpenAI API
            response = await self._call_openai_api(prompt)
        else:
            # Mock response for testing
            response = self._generate_mock_response(inquiry)
        
        return SupportResponse(
            response_id=f"resp_{int(datetime.now().timestamp())}",
            customer_id=inquiry.customer_id,
            message=response["message"],
            confidence=response["confidence"],
            suggested_actions=response["suggested_actions"],
            timestamp=datetime.now().isoformat(),
            agent_id=self.agent_id
        )
    
    def _create_secure_prompt(self, inquiry: CustomerInquiry) -> str:
        """Create a secure prompt for the AI model"""
        
        system_prompt = """You are a helpful customer support agent. 
        You must:
        - Be polite and professional
        - Provide accurate information
        - Never ask for sensitive information like passwords or credit card numbers
        - Escalate complex issues to human agents
        - Follow company policies and procedures
        
        Do not:
        - Provide personal opinions
        - Share internal company information
        - Make promises you cannot keep
        - Ask for sensitive customer information"""
        
        user_prompt = f"""Customer inquiry:
        Type: {inquiry.inquiry_type}
        Priority: {inquiry.priority}
        Message: {inquiry.message}
        
        Please provide a helpful response."""
        
        return f"{system_prompt}\n\n{user_prompt}"
    
    async def _call_openai_api(self, prompt: str) -> Dict[str, Any]:
        """Call OpenAI API securely"""
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.7,
                timeout=30
            )
            
            message = response.choices[0].message.content
            
            return {
                "message": message,
                "confidence": 0.9,
                "suggested_actions": self._extract_suggested_actions(message)
            }
            
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise
    
    def _generate_mock_response(self, inquiry: CustomerInquiry) -> Dict[str, Any]:
        """Generate mock response for testing"""
        
        mock_responses = {
            "billing": "I understand you have a billing inquiry. Let me help you with that. Please provide your account number and I'll look into your billing details.",
            "technical": "I can help you with technical support. Could you please describe the specific issue you're experiencing?",
            "general": "Thank you for contacting us. How can I assist you today?",
            "complaint": "I'm sorry to hear about your concern. Let me help resolve this issue for you.",
            "refund": "I can help you with your refund request. Please provide your order number and reason for the refund."
        }
        
        message = mock_responses.get(inquiry.inquiry_type, "Thank you for your inquiry. How can I help you?")
        
        return {
            "message": message,
            "confidence": 0.8,
            "suggested_actions": ["Follow up in 24 hours", "Escalate if needed"]
        }
    
    def _extract_suggested_actions(self, message: str) -> List[str]:
        """Extract suggested actions from response"""
        actions = []
        
        if "escalate" in message.lower():
            actions.append("Escalate to human agent")
        
        if "follow up" in message.lower():
            actions.append("Schedule follow-up")
        
        if "refund" in message.lower():
            actions.append("Process refund request")
        
        return actions or ["Monitor customer satisfaction"]
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get agent health status"""
        return {
            "agent_id": self.agent_id,
            "version": self.version,
            "status": "healthy",
            "active_sessions": len(self.active_sessions),
            "uptime": datetime.now().isoformat(),
            "security_policies": {
                "enabled": True,
                "version": "1.0"
            }
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get agent metrics"""
        return {
            "total_requests": request_count._value.sum(),
            "active_sessions": len(self.active_sessions),
            "average_response_time": response_time._sum / max(response_time._count, 1),
            "error_rate": request_count.labels(status="error")._value.sum() / max(request_count._value.sum(), 1)
        }

# Initialize agent
agent = CustomerSupportAgent()

# FastAPI application
app = FastAPI(
    title="Customer Support Agent",
    description="Secure GenAI customer support agent",
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
    # This is handled by prometheus_client
    pass

@app.post("/api/v1/inquiry", response_model=SupportResponse)
async def process_customer_inquiry(inquiry: CustomerInquiry, request: Request):
    """Process customer inquiry"""
    start_time = datetime.now()
    
    try:
        response = await agent.process_inquiry(inquiry)
        
        # Record response time
        response_time.observe((datetime.now() - start_time).total_seconds())
        
        return response
        
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
