# SecFlow Binary Security Go

This is a deliberately small streaming-only successor to `secflow-app-binary-security`.

## Scope

It supports these pipelines: `binary` (`firmware_unpack -> system_analysis -> binary_to_source -> entry_analysis -> dataflow_vuln_scan`), `binary_module`, `source/default`, and `source/kg_source_vuln_scan`.

SQLite is the state authority. An item has a unique `(task_id, stage, item_key)` identity, so replaying a completion cannot create duplicated descendants. A successful upstream item immediately materializes its descendants; in particular, every entry success creates dataflow work without waiting for the entire entry stage. Item completion, child creation, and parent stage projection are one SQLite transaction. Task terminal state is computed only after every materialized item is terminal.

The service intentionally excludes owner leases, archive jobs, workspace JSON state, automatic retry histories, manual selection, and full-task reconciliation. The worker claims pending rows with a conditional update, calls the stage-specific downstream API, and polls its terminal state. Transport failures are retried three times; cancellation is propagated to bound downstream tasks. The knowledge-graph flow reads audit sources directly and then materializes dataflow items.

## API

The API prefix remains `/api/app/binary-security`. It exposes health/ready, task create/start/get, stage-item listing, item completion, and cancel endpoints. Run locally with `DATABASE_PATH=/tmp/binary.db go run ./cmd/secflow-app-binary-security-go --role=api`.

The Kubernetes manifest runs one API and one worker container in the same Pod. This is intentional: they share the SQLite database on the mounted volume, while no cross-Pod SQLite locking or owner election is required. Configure `DOWNSTREAM_TOKEN` when downstream APIs require bearer authentication. Base URLs are configured with `DOWNSTREAM_<STAGE>_BASE_URL`; the knowledge graph uses `KNOWLEDGE_GRAPH_AUDIT_BASE_URL`.
