#!/bin/bash

kubectl rollout restart deployment/secflow-app-code-server
kubectl rollout restart deployment/secflow-app-secmate-ng
kubectl rollout restart deployment/secflow-platform-agent
kubectl rollout restart deployment/secflow-platform-auth
kubectl rollout restart deployment/secflow-platform-deploy-script
kubectl rollout restart deployment/secflow-platform-frontend
kubectl rollout restart deployment/secflow-platform-k8s
kubectl rollout restart deployment/secflow-platform-menu
kubectl rollout restart deployment/secflow-platform-project
kubectl rollout restart deployment/secflow-platform-resource
kubectl rollout restart deployment/secflow-platform-static-binary
kubectl rollout restart deployment/secflow-platform-workflow