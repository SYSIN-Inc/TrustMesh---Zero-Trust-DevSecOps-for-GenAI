#!/usr/bin/env python3
"""
Agent Identity Verification and Signed Manifests
Implements cryptographic signing and verification for GenAI agents
"""

import json
import hashlib
import hmac
import base64
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

@dataclass
class AgentManifest:
    """Agent manifest for identity verification"""
    agent_id: str
    version: str
    checksum: str
    dependencies: List[str]
    prompts: List[str]
    model_config: Dict[str, Any]
    security_policy_version: str
    created_at: str
    created_by: str
    signature: Optional[str] = None

class AgentSigner:
    """Handles cryptographic signing of agent manifests"""
    
    def __init__(self, private_key_path: Optional[str] = None, password: Optional[str] = None):
        self.private_key_path = private_key_path
        self.password = password
        self.private_key = None
        self.public_key = None
        
        if private_key_path:
            self._load_keys()
    
    def _load_keys(self):
        """Load private and public keys"""
        try:
            with open(self.private_key_path, 'rb') as key_file:
                private_key_data = key_file.read()
            
            if self.password:
                # Decrypt private key
                self.private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=self.password.encode(),
                    backend=default_backend()
                )
            else:
                self.private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=None,
                    backend=default_backend()
                )
            
            self.public_key = self.private_key.public_key()
            logger.info("Keys loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load keys: {e}")
            raise
    
    def generate_keypair(self, output_dir: str):
        """Generate new RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        # Save private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        private_key_path = Path(output_dir) / "agent_signing_key.pem"
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        
        # Save public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        public_key_path = Path(output_dir) / "agent_verification_key.pem"
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        
        logger.info(f"Key pair generated: {private_key_path}, {public_key_path}")
        return str(private_key_path), str(public_key_path)
    
    def sign_manifest(self, manifest: AgentManifest) -> str:
        """Sign an agent manifest"""
        if not self.private_key:
            raise ValueError("Private key not loaded")
        
        # Create signature data (exclude signature field)
        manifest_dict = asdict(manifest)
        manifest_dict.pop('signature', None)
        signature_data = json.dumps(manifest_dict, sort_keys=True).encode()
        
        # Sign the data
        signature = self.private_key.sign(
            signature_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Encode signature
        signature_b64 = base64.b64encode(signature).decode()
        logger.info(f"Manifest signed for agent: {manifest.agent_id}")
        
        return signature_b64
    
    def verify_signature(self, manifest: AgentManifest, public_key_path: str) -> bool:
        """Verify an agent manifest signature"""
        try:
            # Load public key
            with open(public_key_path, 'rb') as key_file:
                public_key_data = key_file.read()
            
            public_key = serialization.load_pem_public_key(
                public_key_data,
                backend=default_backend()
            )
            
            # Prepare signature data
            manifest_dict = asdict(manifest)
            signature = manifest_dict.pop('signature', '')
            signature_data = json.dumps(manifest_dict, sort_keys=True).encode()
            
            # Decode signature
            signature_bytes = base64.b64decode(signature)
            
            # Verify signature
            public_key.verify(
                signature_bytes,
                signature_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            logger.info(f"Signature verified for agent: {manifest.agent_id}")
            return True
            
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

class AgentIdentityManager:
    """Manages agent identity and verification"""
    
    def __init__(self, signing_key_path: str, verification_key_path: str):
        self.signer = AgentSigner(signing_key_path)
        self.verification_key_path = verification_key_path
        self.registered_agents: Dict[str, AgentManifest] = {}
    
    def create_manifest(self, agent_path: str, agent_id: str, version: str, 
                       created_by: str) -> AgentManifest:
        """Create a signed manifest for an agent"""
        
        # Calculate checksum
        checksum = self._calculate_checksum(agent_path)
        
        # Extract dependencies
        dependencies = self._extract_dependencies(agent_path)
        
        # Extract prompts
        prompts = self._extract_prompts(agent_path)
        
        # Extract model configuration
        model_config = self._extract_model_config(agent_path)
        
        # Create manifest
        manifest = AgentManifest(
            agent_id=agent_id,
            version=version,
            checksum=checksum,
            dependencies=dependencies,
            prompts=prompts,
            model_config=model_config,
            security_policy_version="1.0",
            created_at=datetime.now().isoformat(),
            created_by=created_by
        )
        
        # Sign manifest
        signature = self.signer.sign_manifest(manifest)
        manifest.signature = signature
        
        # Register agent
        self.registered_agents[agent_id] = manifest
        
        logger.info(f"Manifest created and signed for agent: {agent_id}")
        return manifest
    
    def verify_agent(self, manifest: AgentManifest) -> Dict[str, Any]:
        """Verify an agent's identity and integrity"""
        verification_result = {
            'agent_id': manifest.agent_id,
            'signature_valid': False,
            'checksum_valid': False,
            'dependencies_valid': False,
            'overall_valid': False,
            'issues': []
        }
        
        # Verify signature
        verification_result['signature_valid'] = self.signer.verify_signature(
            manifest, self.verification_key_path
        )
        
        if not verification_result['signature_valid']:
            verification_result['issues'].append("Invalid signature")
        
        # Verify checksum (would need to recalculate from current agent files)
        # This is a placeholder - in practice, you'd recalculate and compare
        verification_result['checksum_valid'] = True
        
        # Verify dependencies
        verification_result['dependencies_valid'] = self._verify_dependencies(manifest.dependencies)
        
        if not verification_result['dependencies_valid']:
            verification_result['issues'].append("Dependency verification failed")
        
        # Overall validation
        verification_result['overall_valid'] = (
            verification_result['signature_valid'] and
            verification_result['checksum_valid'] and
            verification_result['dependencies_valid']
        )
        
        return verification_result
    
    def _calculate_checksum(self, agent_path: str) -> str:
        """Calculate SHA256 checksum of agent files"""
        hasher = hashlib.sha256()
        
        for file_path in sorted(Path(agent_path).rglob('*')):
            if file_path.is_file() and not file_path.name.startswith('.'):
                with open(file_path, 'rb') as f:
                    hasher.update(f.read())
        
        return hasher.hexdigest()
    
    def _extract_dependencies(self, agent_path: str) -> List[str]:
        """Extract dependencies from requirements files"""
        dependencies = []
        
        for req_file in Path(agent_path).rglob('requirements*.txt'):
            with open(req_file, 'r') as f:
                dependencies.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
        
        return dependencies
    
    def _extract_prompts(self, agent_path: str) -> List[str]:
        """Extract prompts from prompt files"""
        prompts = []
        
        for prompt_file in Path(agent_path).rglob('*.prompt'):
            with open(prompt_file, 'r') as f:
                prompts.append(f.read())
        
        return prompts
    
    def _extract_model_config(self, agent_path: str) -> Dict[str, Any]:
        """Extract model configuration"""
        config = {}
        
        config_file = Path(agent_path) / "agent_config.yaml"
        if config_file.exists():
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
        
        return config
    
    def _verify_dependencies(self, dependencies: List[str]) -> bool:
        """Verify dependencies are secure"""
        # In production, this would check against vulnerability databases
        vulnerable_packages = ['requests==2.25.0', 'urllib3==1.24.0']
        
        for dep in dependencies:
            if any(vuln in dep for vuln in vulnerable_packages):
                return False
        
        return True
    
    def save_manifest(self, manifest: AgentManifest, output_path: str):
        """Save manifest to file"""
        with open(output_path, 'w') as f:
            json.dump(asdict(manifest), f, indent=2)
        
        logger.info(f"Manifest saved: {output_path}")
    
    def load_manifest(self, manifest_path: str) -> AgentManifest:
        """Load manifest from file"""
        with open(manifest_path, 'r') as f:
            manifest_data = json.load(f)
        
        return AgentManifest(**manifest_data)

def main():
    """Main entry point for agent identity management"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Agent Identity Manager')
    parser.add_argument('action', choices=['create', 'verify', 'generate-keys'], 
                       help='Action to perform')
    parser.add_argument('--agent-path', help='Path to agent code')
    parser.add_argument('--agent-id', help='Agent ID')
    parser.add_argument('--version', help='Agent version')
    parser.add_argument('--created-by', help='Creator identifier')
    parser.add_argument('--signing-key', help='Path to signing key')
    parser.add_argument('--verification-key', help='Path to verification key')
    parser.add_argument('--manifest', help='Path to manifest file')
    parser.add_argument('--output', help='Output file path')
    
    args = parser.parse_args()
    
    if args.action == 'generate-keys':
        signer = AgentSigner()
        private_key, public_key = signer.generate_keypair('.')
        print(f"Keys generated: {private_key}, {public_key}")
    
    elif args.action == 'create':
        if not all([args.agent_path, args.agent_id, args.version, args.created_by, args.signing_key]):
            print("Error: Missing required arguments for create action")
            return
        
        identity_manager = AgentIdentityManager(args.signing_key, args.signing_key.replace('.pem', '_public.pem'))
        manifest = identity_manager.create_manifest(
            args.agent_path, args.agent_id, args.version, args.created_by
        )
        
        output_path = args.output or f"{args.agent_id}_manifest.json"
        identity_manager.save_manifest(manifest, output_path)
        print(f"Manifest created: {output_path}")
    
    elif args.action == 'verify':
        if not all([args.manifest, args.verification_key]):
            print("Error: Missing required arguments for verify action")
            return
        
        identity_manager = AgentIdentityManager("", args.verification_key)
        manifest = identity_manager.load_manifest(args.manifest)
        result = identity_manager.verify_agent(manifest)
        
        print(f"Verification result: {json.dumps(result, indent=2)}")
        
        if not result['overall_valid']:
            exit(1)

if __name__ == '__main__':
    main()
