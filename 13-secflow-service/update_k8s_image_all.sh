#!/bin/bash

kubectl rollout restart deployment/secflow-app-code-server -n secflow-ns
kubectl rollout restart deployment/secflow-app-secmate-ng -n secflow-ns
kubectl rollout restart deployment/secflow-app-binary-to-source-manager -n secflow-ns
kubectl rollout restart deployment/secflow-app-binary-to-source-worker -n secflow-ns
kubectl rollout restart deployment/secflow-platform-agent -n secflow-ns
kubectl rollout restart deployment/secflow-platform-auth -n secflow-ns
kubectl rollout restart deployment/secflow-platform-deploy-script -n secflow-ns
kubectl rollout restart deployment/secflow-platform-frontend -n secflow-ns
kubectl rollout restart deployment/secflow-platform-k8s -n secflow-ns
kubectl rollout restart deployment/secflow-platform-menu -n secflow-ns
kubectl rollout restart deployment/secflow-platform-fileserver -n secflow-ns
kubectl rollout restart deployment/secflow-platform-project -n secflow-ns
kubectl rollout restart deployment/secflow-platform-resource -n secflow-ns
kubectl rollout restart deployment/secflow-platform-static-binary -n secflow-ns
kubectl rollout restart deployment/secflow-platform-system-analysis -n secflow-ns
kubectl rollout restart deployment/secflow-platform-workflow -n secflow-ns
