#!/bin/bash
set -e

# Copy all patch files
cp /tmp/sa_patch/tasks.py          ~/sa_build/app_src/app/api/tasks.py
cp /tmp/sa_patch/config.py         ~/sa_build/app_src/app/api/config.py
cp /tmp/sa_patch/task_service.py   ~/sa_build/app_src/app/service/task_service.py
cp /tmp/sa_patch/config_service.py ~/sa_build/app_src/app/service/config_service.py
cp /tmp/sa_patch/server.py         ~/sa_build/app_src/app/server.py
cp /tmp/sa_patch/models.py         ~/sa_build/app_src/app/db/models.py

# Write Dockerfile
cat > ~/sa_build/Dockerfile.patch << 'DOCKERFILE'
FROM 172.31.30.52:5000/secflow-app-system-analyse:latest
COPY app_src/app/api/tasks.py /app/app/api/tasks.py
COPY app_src/app/api/config.py /app/app/api/config.py
COPY app_src/app/service/task_service.py /app/app/service/task_service.py
COPY app_src/app/service/config_service.py /app/app/service/config_service.py
COPY app_src/app/server.py /app/app/server.py
COPY app_src/app/db/models.py /app/app/db/models.py
DOCKERFILE

echo "=== Dockerfile.patch ==="
cat ~/sa_build/Dockerfile.patch

# Build
cd ~/sa_build
docker build -f Dockerfile.patch -t 172.31.30.52:5000/secflow-app-system-analyse:latest .
echo "=== BUILD DONE ==="

# Push
docker push 172.31.30.52:5000/secflow-app-system-analyse:latest
echo "=== PUSH DONE ==="

# Rollout restart
kubectl rollout restart deployment/secflow-app-system-analyse -n secflow-ns
kubectl rollout status deployment/secflow-app-system-analyse -n secflow-ns --timeout=120s
echo "=== ROLLOUT DONE ==="
