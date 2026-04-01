# SecFlow System Analysis API

## Base

- Prefix: `/api/system-analysis`

## Endpoints

1. `GET /api/system-analysis/health`
2. `GET /api/system-analysis/capabilities/nodes?project_id={project_id}`
3. `GET /api/system-analysis/overview?project_id={project_id}`
4. `GET /api/system-analysis/prompts`
5. `POST /api/system-analysis/prompts`
6. `GET /api/system-analysis/prompts/{prompt_id}`
7. `PUT /api/system-analysis/prompts/{prompt_id}`
8. `DELETE /api/system-analysis/prompts/{prompt_id}`
9. `POST /api/system-analysis/prompts/{prompt_id}/clone`
10. `POST /api/system-analysis/tasks`
11. `GET /api/system-analysis/tasks`
12. `GET /api/system-analysis/tasks/{task_id}`
13. `GET /api/system-analysis/tasks/{task_id}/nodes`
14. `GET /api/system-analysis/tasks/{task_id}/nodes/{agent_key}`
15. `POST /api/system-analysis/tasks/{task_id}/rerun`
16. `POST /api/system-analysis/tasks/{task_id}/cancel`
17. `POST /api/system-analysis/tasks/{task_id}/retry-node`
18. `GET /api/system-analysis/tasks/{task_id}/report`

## Status Enums

- Task: `pending`, `preparing`, `running`, `partial_success`, `success`, `failed`, `cancelled`
- Node: `pending`, `session_creating`, `session_created`, `analyzing`, `success`, `failed`, `cancelled`
- Risk: `unknown`, `low`, `medium`, `high`, `critical`

