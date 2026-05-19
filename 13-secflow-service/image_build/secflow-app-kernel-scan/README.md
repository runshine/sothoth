# SecFlow Kernel Scan Service

FastAPI microservice for kernel attack-entry discovery, vulnerability audit, and PoC verification. The service wraps the existing scripts:

- `ask_claude_entry.py`
- `ask_claude_kernaudit_v2.py`
- `ask_claude_poc.py`

The workers run those scripts as subprocesses, stream logs, keep task heartbeats alive, and persist stage artifacts under `/workspace`.

## Quick Facts

- API base path: `/api/app/kernel-scan`
- Container port: `8080`
- Default compose port: `18081`
- Kernel source path in container: `/workspace/kernel`
- State root: `/var/lib/secflow-kernel-scan`
- Stage artifact root: `/workspace`
- Database: SQLite

## Pipeline Modes

| Mode | Stages | Required Inputs |
|---|---|---|
| `entry_only` | entry | optional `kernel_dir` |
| `audit_only` | audit | `entrylist`, optional `kernel_dir` |
| `poc_only` | poc | `kernel_dir`, `report_dir`; ADB server from `~/.bashrc` |
| `entry_audit_poc` | entry -> audit -> poc | optional `kernel_dir`; PoC uses ADB server from `~/.bashrc` |

## Run With Docker Compose

Prepare required host variables:

```bash
export KERNEL_HOST_PATH=/path/to/kernel/source
export ANTHROPIC_API_KEY=sk-ant-...
```

Android platform-tools and Android NDK are cached under `./tools`. Build with
the helper script when you want the cache populated automatically:

```bash
./build-image.sh
```

The helper reuses these files if present, and downloads them from Google only
when missing:

```text
./tools/android-platform-tools.zip
./tools/android-ndk-r29.zip
```

The Dockerfile also uses those cached files during image build. The zip files
are ignored by Git.

Start the service:

```bash
docker compose up -d --build
docker compose logs -f secflow-app-kernel-scan
```

If you use `docker compose up --build` directly, run the cache step once first:

```bash
./scripts/prepare-android-tools.sh
docker compose up -d --build
```

Health check:

```bash
curl http://localhost:18081/api/app/kernel-scan/health
```

## Deploy To Kubernetes

Build and push the service image first:

```bash
IMAGE=ghcr.io/runshine/secflow-app-kernel-scan:latest ./build-image.sh
docker push ghcr.io/runshine/secflow-app-kernel-scan:latest
```

GitHub Actions can also build and push this image automatically with
`.github/workflows/build-secflow-app-kernel-scan-image.yaml`. After the image is
available, create the Claude API secret:

```bash
kubectl -n secflow-ns create secret generic secflow-app-kernel-scan-secret \
  --from-literal=ANTHROPIC_API_KEY='sk-...' \
  --from-literal=ANTHROPIC_BASE_URL=''
```

Apply the manifests:

```bash
kubectl apply -k .
kubectl -n secflow-ns get pods,svc,pvc -l name=secflow-app-kernel-scan
```

The deployment is intentionally single-replica because it uses SQLite and a
local scheduler state directory.

## ADB Device Setup

PoC tasks no longer accept ADB IP in `/tasks`. Configure the fixed remote ADB server first:

```bash
curl -X POST http://localhost:18081/api/app/kernel-scan/devices/adb/connect \
  -H 'Content-Type: application/json' \
  -d '{}'
```

The endpoint:

- accepts an empty request body and always uses `ADB_SERVER_SOCKET=tcp:172.31.30.81:15037`
- runs `adb devices`
- verifies that `adb shell true` works on an online device
- writes `export ADB_SERVER_SOCKET=...` into `~/.bashrc`
- returns only the `adb devices` command result

During PoC stage, the worker sources `~/.bashrc`, captures the sourced environment, ensures `/opt/android-tools` is in `PATH`, runs `adb devices`, chooses the first `device` status serial, and passes `ANDROID_SERIAL` to `ask_claude_poc.py`.

## Create Tasks

### Full Pipeline

```bash
curl -X POST http://localhost:18081/api/app/kernel-scan/tasks \
  -H 'Content-Type: application/json' \
  -d '{
    "title": "kernel full scan",
    "pipeline_mode": "entry_audit_poc",
    "kernel_dir": "/workspace/kernel",
    "entry_threads": 4,
    "audit_threads": 4,
    "poc_threads": 2
  }'
```

### Entry Only

```bash
curl -X POST http://localhost:18081/api/app/kernel-scan/tasks \
  -H 'Content-Type: application/json' \
  -d '{
    "title": "entry scan",
    "pipeline_mode": "entry_only",
    "kernel_dir": "/workspace/kernel"
  }'
```

### Audit Only

```bash
curl -X POST http://localhost:18081/api/app/kernel-scan/tasks \
  -H 'Content-Type: application/json' \
  -d '{
    "title": "audit from entry list",
    "pipeline_mode": "audit_only",
    "kernel_dir": "/workspace/kernel",
    "entrylist": "/workspace/entry/kscan-task-xxx/entry_scan_results.txt"
  }'
```

### PoC Only

Run `/devices/adb/connect` first, then:

```bash
curl -X POST http://localhost:18081/api/app/kernel-scan/tasks \
  -H 'Content-Type: application/json' \
  -d '{
    "title": "verify audit reports",
    "pipeline_mode": "poc_only",
    "kernel_dir": "/workspace/kernel",
    "report_dir": "/workspace/audit/kscan-task-xxx"
  }'
```

## Inspect Tasks

```bash
curl 'http://localhost:18081/api/app/kernel-scan/tasks?page=1&per_page=20'
curl http://localhost:18081/api/app/kernel-scan/tasks/<task_id>
curl 'http://localhost:18081/api/app/kernel-scan/tasks/<task_id>/events?after_seq=0'
```

Cancel or delete:

```bash
curl -X POST http://localhost:18081/api/app/kernel-scan/tasks/<task_id>/cancel
curl -X DELETE http://localhost:18081/api/app/kernel-scan/tasks/<task_id>
```

Only terminal tasks can be deleted.

## Artifacts

All stage outputs are written under `workspace_root`, default `/workspace`.

| Stage | Directory | Key Files |
|---|---|---|
| entry | `/workspace/entry/{task_id}/` | `entry.log`, `entry_scan_results.json`, `entry_scan_results.txt`, `entry_scan_progress.json` |
| audit | `/workspace/audit/{task_id}/` | `audit.log`, generated `*.md` reports, optional generated `entrylist` |
| poc | `/workspace/poc/{task_id}/` | `poc.log`, `vullist`, `poc_results.json`, `vul_results/{report}/{VUL-N}/` |

PoC per-vulnerability directories contain:

- `vulnerability.md`
- `claude_response.md`
- Claude-generated PoC files, logs, and verification reports

## Workspace Browser

The frontend can browse and preview files through:

```bash
curl 'http://localhost:18081/api/app/kernel-scan/workspace/browse?path=/workspace'
curl 'http://localhost:18081/api/app/kernel-scan/workspace/read?path=/workspace/poc/<task_id>/poc.log'
```

Paths must be absolute and under `/workspace`.

## Configuration

Common environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `KERNEL_SCAN_DATABASE_URL` | `sqlite:////var/lib/secflow-kernel-scan/kernel-scan.db` | SQLite DB |
| `KERNEL_SCAN_STATE_ROOT` | `/var/lib/secflow-kernel-scan` | scheduler/task state |
| `KERNEL_SCAN_KERNEL_DIR` | `/workspace/kernel` | default kernel source |
| `KERNEL_SCAN_WORKSPACE_ROOT` | `/workspace` | stage artifact root |
| `KERNEL_SCAN_CLAUDE_MODEL` | `zai-org/GLM-5` | default Claude model |
| `KERNEL_SCAN_MAX_PARALLEL_TASKS` | `1` | concurrent tasks |
| `KERNEL_SCAN_ENTRY_THREADS` | `4` | entry stage threads |
| `KERNEL_SCAN_AUDIT_THREADS` | `4` | audit stage threads |
| `KERNEL_SCAN_POC_THREADS` | `2` | poc stage threads |
| `ANTHROPIC_API_KEY` | empty | Claude API key |
| `ANTHROPIC_BASE_URL` | empty | optional custom base URL |

See `config.example.yaml` and `API.md` for the full reference.

## Troubleshooting

### `ADB_SERVER_SOCKET is not set after sourcing ~/.bashrc`

Run `/devices/adb/connect` first. It writes the remote ADB server into `~/.bashrc` only after `adb devices` and `adb shell true` succeed.

### `adb executable not found after sourcing ~/.bashrc`

The PoC worker adds `/opt/android-tools` back into the sourced environment, and
the image should already contain `adb`. Check:

```bash
docker compose exec secflow-app-kernel-scan adb version
```

### `no online adb device found after sourcing ~/.bashrc`

Check the remote ADB server:

```bash
adb devices
adb -s <serial> shell true
```

Then call `/devices/adb/connect` again.

### Task failed with `attempt lost (lease expired)`

This usually means the worker stopped heartbeating. Current stage workers use `run_logged_command` heartbeat pumping; inspect `poc.log`, `audit.log`, or container logs for the actual subprocess failure.

## More Docs

- `API.md`: endpoint-level API reference
- `CLAUDE.md`: implementation notes and maintenance context
