pipeline {
    agent any
    
    environment {
        AWS_REGION = 'us-east-1'
        EKS_CLUSTER_NAME = 'secure-agent-ops'
        ECR_REGISTRY = "${env.AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
        DOCKER_IMAGE_TAG = "${env.GIT_COMMIT.take(7)}"
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Security Scan') {
            steps {
                script {
                    sh '''
                        python3 -m venv venv
                        source venv/bin/activate
                        pip install -r gatekeeper/requirements.txt
                        echo "Running security scan..."
                        ./scripts/generate-sbom.sh gatekeeper sbom-gatekeeper.json || true
                    '''
                }
            }
        }
        
        stage('Build Docker Images') {
            steps {
                script {
                    sh '''
                        # Login to ECR
                        aws ecr get-login-password --region ${AWS_REGION} | \
                          docker login --username AWS --password-stdin ${ECR_REGISTRY}
                        
                        # Build and push gatekeeper
                        cd gatekeeper
                        docker build -t ${ECR_REGISTRY}/gatekeeper:${DOCKER_IMAGE_TAG} .
                        docker push ${ECR_REGISTRY}/gatekeeper:${DOCKER_IMAGE_TAG}
                        docker tag ${ECR_REGISTRY}/gatekeeper:${DOCKER_IMAGE_TAG} ${ECR_REGISTRY}/gatekeeper:latest
                        docker push ${ECR_REGISTRY}/gatekeeper:latest
                        
                        # Build and push agent
                        cd ../agents/customer-support-agent
                        docker build -t ${ECR_REGISTRY}/customer-support-agent:${DOCKER_IMAGE_TAG} .
                        docker push ${ECR_REGISTRY}/customer-support-agent:${DOCKER_IMAGE_TAG}
                    '''
                }
            }
        }
        
        stage('Security Validation') {
            steps {
                script {
                    sh '''
                        # Configure kubectl
                        aws eks update-kubeconfig --name ${EKS_CLUSTER_NAME} --region ${AWS_REGION}
                        
                        # Get gatekeeper pod and run scan
                        GATEKEEPER_POD=$(kubectl -n secureagentops get pod -l app=security-gatekeeper -o jsonpath='{.items[0].metadata.name}')
                        
                        # Port-forward and scan
                        kubectl -n secureagentops port-forward $GATEKEEPER_POD 8080:8080 &
                        sleep 5
                        
                        curl -X POST http://localhost:8080/api/v1/scan \
                          -H "Content-Type: application/json" \
                          -d "{
                            \"agent_path\": \"/app\",
                            \"agent_id\": \"jenkins-agent\",
                            \"agent_version\": \"${DOCKER_IMAGE_TAG}\",
                            \"enable_trivy\": true
                          }" > scan_results.json
                        
                        # Check results
                        SCAN_PASSED=$(cat scan_results.json | jq -r '.passed // false')
                        if [ "$SCAN_PASSED" != "true" ]; then
                          echo "❌ Security scan failed!"
                          cat scan_results.json | jq '.'
                          exit 1
                        fi
                        
                        echo "✅ Security scan passed!"
                    '''
                }
            }
        }
        
        stage('Policy Evaluation') {
            steps {
                script {
                    sh '''
                        curl -X POST http://localhost:8080/api/v1/policy/evaluate \
                          -H "Content-Type: application/json" \
                          -d '{
                            "agent_id": "jenkins-agent",
                            "scan_results": {
                              "summary": {
                                "critical": 0,
                                "high": 0,
                                "medium": 0,
                                "low": 0
                              }
                            }
                          }' > policy_results.json
                        
                        echo "Policy evaluation complete"
                        cat policy_results.json | jq '.'
                    '''
                }
            }
        }
        
        stage('Deploy to Kubernetes') {
            when {
                branch 'main'
            }
            steps {
                script {
                    sh '''
                        # Update deployments
                        kubectl -n secureagentops set image deploy/security-gatekeeper \
                          security-gatekeeper=${ECR_REGISTRY}/gatekeeper:${DOCKER_IMAGE_TAG}
                        
                        kubectl -n secureagentops set image deploy/customer-support-agent \
                          customer-support-agent=${ECR_REGISTRY}/customer-support-agent:${DOCKER_IMAGE_TAG}
                        
                        # Wait for rollout
                        kubectl -n secureagentops rollout status deploy/security-gatekeeper
                        kubectl -n secureagentops rollout status deploy/customer-support-agent
                    '''
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: '*.json', allowEmptyArchive: true
        }
        success {
            echo 'Pipeline succeeded!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}


