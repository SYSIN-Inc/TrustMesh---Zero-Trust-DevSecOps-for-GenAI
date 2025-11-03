FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies and kubectl (for Trivy k8s scanning)
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    ca-certificates \
    && curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/kubectl \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy binary (more reliable than apt repo)
RUN TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && wget -qO /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    && tar -xzf /tmp/trivy.tar.gz -C /tmp \
    && mv /tmp/trivy /usr/local/bin/trivy \
    && chmod +x /usr/local/bin/trivy \
    && rm -rf /tmp/trivy.tar.gz /tmp/LICENSE /tmp/contrib \
    && trivy --version

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user (but keep trivy accessible)
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
# Note: Trivy needs cache directory accessible
RUN mkdir -p /tmp/.trivy && chown -R appuser:appuser /tmp/.trivy
USER appuser

# Expose ports
EXPOSE 8080 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["python", "main.py"]

