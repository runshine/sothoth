# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sothoth v2 is a Kubernetes-based security testing platform called "SecFlow". The project consists of multiple microservices deployed to Kubernetes, with numbered directory prefixes indicating deployment order.

## Development Commands

### Python Microservices

Use the `sothoth` conda environment for all Python services:

```bash
# Activate environment
source /home/runshine/miniconda3/etc/profile.d/conda.sh && conda activate sothoth

# Install dependencies for a service
cd 13-secflow-service/image_build/<service-name>
pip install -r requirements.txt

# Run a service (example for secflow-platform-agent)
python app.py -c config.json
```

Most Python services follow this pattern:
- Entry point: `app.py` with optional `-c config.json` argument
- Configuration: `config.json` file with database, Redis, Nacos settings
- Dependencies: `requirements.txt` with Flask, PyJWT, Redis, PyMySQL, etc.

### Frontend (secflow-frontend)

```bash
cd 13-secflow-service/image_build/secflow-frontend

npm install        # Install dependencies
npm run dev        # Development server (Vite)
npm run build      # Production build
npm run lint       # TypeScript type checking (tsc --noEmit)
```

### Kubernetes Deployment

Each service directory contains deployment scripts:

```bash
./deploy.sh        # Apply all *.yaml files with kubectl apply
./cleanup.sh       # Delete all *.yaml files in reverse order
./update_k8s_image_all.sh   # Rollout restart for all deployments
```

## Architecture

### Microservices Structure

The main SecFlow platform resides in `13-secflow-service/` with these core services:

| Service | Port | Purpose |
|---------|------|---------|
| secflow-platform-menu | 10002 | Menu/navigation service |
| secflow-platform-auth | 10003 | Authentication service |
| secflow-platform-project | 10004 | Project management |
| secflow-platform-resource | 10005 | Resource management |
| secflow-platform-agent | 10008 | Agent management with Docker Compose |
| secflow-platform-workflow | 10009 | Workflow management |

All services connect to:
- **MySQL** (172.31.30.100:3306) - Primary database
- **Redis** (172.31.30.100:6379) - Caching and pub/sub
- **Nacos** (172.31.30.100:8848) - Service registry

### Supporting Services

- `00-pre-init/`: Kubernetes cluster setup (Flannel CNI, MetalLB, NGINX Ingress, cert-manager, storage classes)
- `01-mysql-service/`: MySQL with CloudBeaver GUI
- `02-vpn-access-service/`: OpenVPN server
- `03-elk-service/`: ELK Stack using ECK operator
- `06-nacos-registry-service/`: Service registry
- `09-redis-service/`: Redis cache
- `11-new-api-service/`: API gateway
- `12-harbor-service/`: Harbor container registry
- `100-agent-service-image/`: Agent services (remote debugging, Tetragon security monitoring)
- `mcp_service/`: MCP services for SSH
- `99-external-service/`: Ingress and TLS configurations

### Ingress Routing

All services are exposed via NGINX Ingress with domain `secflow.ai.icsl.huawei.com`:

```
/api/menu      -> secflow-platform-menu:80
/api/auth      -> secflow-platform-auth:80
/api/project   -> secflow-platform-project:80
/api/resource  -> secflow-platform-resource:80
/api/agent     -> secflow-platform-agent:80
/api/workflow  -> secflow-platform-workflow:80
```

## Naming Conventions

- **Directories**: Numbered prefix for deployment order (`00-`, `01-`, `02-`, etc.)
- **Kubernetes manifests**: `{order}-{service}-{component}.yaml`
  - Example: `00-secflow-01-00-platform-frontend-deployment.yaml`
- **Namespaces**: `secflow-ns` (main), `sothothv2-ns` (legacy)
- **Docker images**: `secflow-{service-name}` format
- **Service health endpoints**: `/api/{service}/health`

## Kubernetes Patterns

- **StatefulSets**: For stateful services (MySQL, Redis, Nacos, OpenVPN)
- **Deployments**: For stateless services
- **ConfigMaps**: Configuration mounted as JSON/YAML files
- **PVCs**: Persistent storage for stateful services
- **ServiceAccounts**: Specific permissions for K8s API access (e.g., for secflow-platform-k8s service)
- **Security contexts**: Non-root users where possible (appuser, debuguser)

## CI/CD Pipeline

GitHub Actions automatically build and push Docker images:

- **Trigger**: Push to `v2.*` branches
- **Workflows**: Each service has `.github/workflows/build-{service}-image.yaml`
- **Architectures**: Multi-arch builds for `linux/amd64` and `linux/arm64`
- **Registries**: Dual push to Docker Hub (`runshine0819/*`) and GHCR (`ghcr.io/runshine/*`)
- **Tags**: `latest` and date-based `YYYYMMDD` format

## Configuration Files

Service configurations follow this pattern:
- `config.json`: Main service configuration (ports, database connections, timeouts)
- `requirements.txt`: Python dependencies
- `Dockerfile`: Container build instructions
- Kubernetes YAMLs in the same directory for deployment

Key configuration values typically include:
- Port bindings
- Database connection strings (MySQL, Redis)
- Nacos service registry URL
- Timeout settings for agent API calls
- JWT secret keys
- Log file paths

## Special Services

### Agent Helper (100-agent-service-image/01-secflow-agent-service-agent-helper)

Remote debugging container with:
- Flask API (port 20001) for command execution
- ttyd web terminal (port 20002)
- code-server VS Code Web IDE (port 20003)
- Privileged container with host namespace access
- Comprehensive debugging tools (gdb, lldb, strace, etc.)

### SecFlow Platform K8s Service

Manages Kubernetes resources directly via K8s API:
- Requires ServiceAccount with appropriate RBAC permissions
- Handles pod/exec for terminal sessions
- Manages deployments and services

## Important Notes

- When running services locally for development, use the `sothoth` conda environment
- Most services require MySQL, Redis, and Nacos to be running (172.31.30.100)
- Frontend builds are served via Nginx reverse proxy
- Large file uploads supported up to 10GB via Ingress configuration
- Extended timeouts (300s) configured for long-running operations
