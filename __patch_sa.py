#!/usr/bin/env python3
"""Patch SA backend: use row.output_path in build_task_config."""

config_path = '/home/icsl/sa_build/app_src/app/config.py'
ts_path = '/home/icsl/sa_build/app_src/app/service/task_service.py'

# ── config.py ──────────────────────────────────────────────────────────────
with open(config_path) as f:
    c = f.read()

c = c.replace(
    'def build_task_config(svc: ServiceConfig, prompt: str, cwd: str = "") -> TaskConfig:',
    'def build_task_config(svc: ServiceConfig, prompt: str, cwd: str = "", output_dir: str = "") -> TaskConfig:'
)
c = c.replace(
    '    effective_cwd = cwd or TARGET_DIR\n    cfg = TaskConfig(',
    '    effective_cwd = cwd or TARGET_DIR\n    effective_output = output_dir or svc.output_dir\n    cfg = TaskConfig('
)
c = c.replace(
    '        output_dir=svc.output_dir,\n        archive_dir=svc.archive_dir,\n        result_dir=svc.result_dir,',
    '        output_dir=effective_output,\n        archive_dir=effective_output,\n        result_dir=effective_output,'
)

with open(config_path, 'w') as f:
    f.write(c)
print('config.py patched, effective_output occurrences:', c.count('effective_output'))

# ── task_service.py ────────────────────────────────────────────────────────
with open(ts_path) as f:
    ts = f.read()

ts = ts.replace(
    'cfg = build_task_config(svc, row.prompt_content, cwd=row.input_path)',
    'cfg = build_task_config(svc, row.prompt_content, cwd=row.input_path, output_dir=row.output_path or "")'
)

with open(ts_path, 'w') as f:
    f.write(ts)
print('task_service.py patched, output_dir occurrences:', ts.count('output_dir=row.output_path'))
