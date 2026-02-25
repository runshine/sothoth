"""
Dockerfile for SecFlow Workflow Service
"""
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY config.yaml .

# Expose port (configurable via config.yaml, default is 8080)
EXPOSE 8080

# Set environment variables
ENV PYTHONPATH=/app
ENV CONFIG_PATH=/app/config.yaml

# Run the application (host and port are read from config file)
CMD ["python", "-m", "app.main"]
