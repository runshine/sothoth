# Helper Docker Service Checklist

## Build
- [ ] `Dockerfile` can build successfully on target architectures.
- [ ] AI CLI entrypoints exist and are executable: `claude`, `claude-a2a`, `codex`, `opencode`.
- [ ] Python dependencies from `requirements.txt` install successfully.
- [ ] `entrypoint.sh` passes `bash -n`.

## Runtime Layout
- [ ] Container starts `agent_ai_service` on `REST_PORT`.
- [ ] Container starts `process_monitor_service` on `PROCESS_MONITOR_PORT`.
- [ ] Container starts `ttyd` on `TTYD_PORT`.
- [ ] Container starts `code-server` on `CODE_SERVER_PORT`.
- [ ] `/host` is mounted and readable.
- [ ] `/host/proc` is available for process inspection.
- [ ] State directory exists: `${AGENT_HELPER_STATE_DIR}`.

## Port Safety
- [ ] `REST_PORT` is not occupied before startup.
- [ ] `TTYD_PORT` is not occupied before startup.
- [ ] `CODE_SERVER_PORT` is not occupied before startup.
- [ ] `PROCESS_MONITOR_PORT` is not occupied before startup.
- [ ] Container restart does not leave orphan helper processes on host.

## Health
- [ ] `GET /health` on `agent_ai_service` returns `healthy`.
- [ ] `GET /api/ai-agents` returns all expected agents.
- [ ] `GET /health` on `process_monitor_service` returns `healthy`.
- [ ] `GET /ready` on `process_monitor_service` returns `ready`.

## AI Agent Management
- [ ] `claude` installed state is correct.
- [ ] `claude-a2a` installed state is correct.
- [ ] `codex` installed state is correct.
- [ ] `opencode` installed state is correct.
- [ ] activate/start/stop APIs work for one agent.
- [ ] session creation works.
- [ ] multi-round message sending works.

## Process Monitor
- [ ] `GET /api/processes` returns process list.
- [ ] `GET /api/processes/{pid}` returns stable process details.
- [ ] signal API can terminate a test process.
- [ ] sync `path_files` works.
- [ ] sync `pid_files` works.
- [ ] invisible PID is skipped without breaking task.
- [ ] sync task progress, events, results, retry all work.

## Deployment Integration
- [ ] Template compose matches image runtime requirements.
- [ ] Service carries `AI_AGENT_HELPER` tag.
- [ ] Platform can discover helper from aggregated services.
- [ ] Service status and real container status are consistent.
- [ ] Ingress and direct port access are both healthy where configured.
