Generate or improve the firmware unpacking Python tool for this evolution round.

Firmware input:
$input

Evolution output directory:
$output

Tools directory:
$tools

Main unpack task run directory:
$main_run

Current evolution job run directory:
$evolution_run

Working Python tool file path:
$working_tool

Round context file:
$round_context

Rules:
1. Read `$round_context` first. Treat it as the primary context for this round.
2. Do not read full session transcripts by default. Only if `$round_context`, the current working tool, and the referenced summary/reason/feedback files are insufficient, read `sessions/index.json` first and then open only one or two targeted session files.
3. If `$working_tool` already exists, read the current working Python tool file at `$working_tool`. If it does not exist yet, generate the first real tool instead of treating the missing file as an error.
4. Read `$output/summary.md` and `$output/reason.md` only when they exist and are relevant to the current round.
5. Follow the round-specific instruction appended after this context:
   - if no tool exists, generate the first real Python tool
   - if a tool exists, inspect and improve the working tool if needed
   - if review failed, improve the working tool according to reason files
6. Keep your investigation minimal and targeted. Do not spend tokens re-deriving the full firmware structure if the current round context already identifies the failure point.
7. Do not execute unpacking commands manually as a substitute for fixing the tool. Any new extraction logic must be written into the Python tool first.
8. You may either modify `$working_tool` directly, or create a brand-new `.py` tool file anywhere under the current evolution job sandbox directory `$evolution_run`.
9. Do not write tools directly into the formal tools repository path. Only write inside the current evolution job sandbox directory `$evolution_run`; the backend will normalize the accepted tool into `working_tool/`.
10. The Python tool must include matcher-readable metadata as leading `# key: value` comments immediately after an optional shebang. Required keys:
   - `# name: <short tool name>`
   - `# format_id: <narrow firmware family id>`
   - `# description: <firmware family and extraction scope>`
   - `# extensions: [.<ext>]` or actual supported extensions for the current family
   - `# magic_hex: <first 4-8 hex chars>` based on the current family
   - `# keywords: [vendor, family, firmware, ...]` adjusted to the current family
   - `# binwalk_sigs: [sig1, sig2, ...]` adjusted to observed signatures
11. Metadata must be compatible with `app/tool_store.py`: `extensions`, `keywords`, and `binwalk_sigs` are comma-separated lists; `magic_hex` is plain lowercase/uppercase hex without spaces.
12. The tool must support the runtime interface used by matched tool execution:
   - It will be invoked as `python tool.py <task_manifest_path>`.
   - The manifest JSON contains `input_path`, `output_path`, `run_path`, `log_path`, and `log_file_path`.
   - `run_path` is a directory for task runtime artifacts.
   - `log_file_path` is the preferred concrete file path for this tool's own log, usually `<run_path>/tool.log`.
   - `log_path` is kept for compatibility and should be treated as a file path when present.
   - It may also receive `SECFLOW_TOOL_INPUT_PATH`, `SECFLOW_TOOL_OUTPUT_PATH`, `SECFLOW_TOOL_RUN_PATH`, `SECFLOW_TOOL_LOG_PATH`, `SECFLOW_TOOL_LOG_FILE_PATH`, and `SECFLOW_TOOL_MANIFEST_PATH`.
   - It must resolve input/output/log paths from manifest/env at runtime and must not hard-code any specific task path.
13. The tool must create the output directory, write `summary.txt` and `summary.md`, and exit with code `0` only when the tool execution completed successfully enough for review.
14. The tool must be generic for the current firmware format family, not case-by-case for this one task:
   - Do not hard-code project IDs, task IDs, absolute firmware paths, output paths, exact file sizes, or a single firmware version as required conditions.
   - Derive or validate offsets/sizes at runtime from the firmware header/table, uImage headers, SquashFS superblocks, and/or bounded binwalk results.
   - Known offsets are allowed only as a validated fast path with magic/size checks and a fallback parser for nearby same-family variants.
15. The tool must be efficient on large firmware:
   - Do not use full-file byte-by-byte gzip/signature scanning as the primary extraction strategy.
   - Prefer `binwalk` output, fixed offset tables, or bounded targeted signature checks.
   - If the tool uses `binwalk` only for identification, prefer `binwalk -B`; if it uses `binwalk` for extraction, use `binwalk -e` or `binwalk -eM` with `--run-as=root`.
   - Do not load a large firmware entirely with `f.read()`; use `seek()` and bounded `read(size)` for each section.
   - If a broad scan is necessary, make it a bounded fallback with explicit size/time limits.
16. Prefer a format-family fast path when the current family exposes a stable header, table, magic, container layout, or validated known offsets. Keep heuristic scanning as a fallback, not the primary strategy.
17. Extract the major components that are actually present for the current firmware family, such as kernels, initrd/ramdisk images, filesystems, signatures/certificates, or other family-specific containers.
18. For fixed-offset extraction, use Python `seek/read` or large-block copy helpers. Do not use `dd bs=1`; if shell `dd` is used, use a large block size and avoid byte-at-a-time copying.

19. Do not execute the tool yourself. The backend will validate and execute the returned tool path.
20. Your final response must be exactly one line containing only the final absolute tool path.
21. Do not include any explanation, markdown, code fences, labels, quotes, backticks, or trailing text.
22. Do not translate or rewrite path segments. In particular, `/data/...` must stay `/data/...`; never output localized variants such as `/数据/...`.
23. The returned line must start with `/` and end with `.py`.
24. If you modified the existing working tool in place, return that same path exactly as given. If you created a new tool elsewhere under `$evolution_run`, return that absolute path exactly.

Valid final response example:
/data/files/.../working_tool/huawei-cc-00000002-v1-20260526164526.py
/data/files/.../round_002/tmp/huawei-cc-00000002-v1-20260526164526.py

Invalid final response examples:
- The updated tool is `/data/files/.../working_tool/tool.py`
- `/数据/files/.../working_tool/tool.py`
- `/data/files/.../working_tool/tool.py` updated
- `/tmp/tool.py`
