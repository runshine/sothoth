# Tests

## Install

```bash
cd 13-secflow-service/image_build/secflow-app-code-server
python -m pip install -r requirements-dev.txt
```

## Run

```bash
cd 13-secflow-service/image_build/secflow-app-code-server
PYTHONPATH=. python -m pytest -q tests/test_task_manager_llm_binding.py
```

## Coverage

`tests/test_task_manager_llm_binding.py` covers:

- create flow without `llm_provider_key`
- create flow with `llm_provider_key` and env override precedence
- create flow with `file_bindings` + ConfigMap mounting parameters
- delete flow cleanup for `llm_configmap_name`
