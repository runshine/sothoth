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

Rules:
1. Read the main unpack task sessions under `$main_run/sessions`.
2. Read the evolution-job sessions under `$evolution_run/sessions`.
3. Read the current working Python tool file at `$working_tool`.
4. Read `$output/summary.md` and `$output/reason.md` if present.
5. Follow the round-specific instruction appended after this context:
   - if no tool exists, generate the first real Python tool
   - if a tool exists, inspect and improve the working tool if needed
   - if review failed, improve the working tool according to reason files
6. Do not execute unpacking commands manually as a substitute for fixing the tool. Any new extraction logic must be written into the Python tool first.
7. You may either modify `$working_tool` directly, or create a brand-new `.py` tool file under the same `working_tool/` directory.
8. Do not write tools directly into the formal tools repository path. Only write inside the current evolution job's `working_tool/` directory.
9. The Python tool must include matcher-readable metadata as leading `# key: value` comments immediately after an optional shebang. Required keys:
   - `# name: <short tool name>`
   - `# format_id: <narrow firmware family id>`
   - `# description: <firmware family and extraction scope>`
   - `# extensions: [.cc]` or actual supported extensions
   - `# magic_hex: <first 4-8 hex chars>`; for the current Huawei `.cc` family this is usually `00000002`
   - `# keywords: [huawei, ne20e, v800r022, cc]` adjusted to the current family
   - `# binwalk_sigs: [object signature in der format, squashfs filesystem, uimage header]` adjusted to observed signatures
10. Metadata must be compatible with `app/tool_store.py`: `extensions`, `keywords`, and `binwalk_sigs` are comma-separated lists; `magic_hex` is plain lowercase/uppercase hex without spaces.
11. The tool must support the runtime interface used by matched tool execution:
   - It will be invoked as `python tool.py <task_manifest_path>`.
   - The manifest JSON contains `input_path`, `output_path`, `run_path`, `log_path`, and `log_file_path`.
   - `run_path` is a directory for task runtime artifacts.
   - `log_file_path` is the preferred concrete file path for this tool's own log, usually `<run_path>/tool.log`.
   - `log_path` is kept for compatibility and should be treated as a file path when present.
   - It may also receive `SECFLOW_TOOL_INPUT_PATH`, `SECFLOW_TOOL_OUTPUT_PATH`, `SECFLOW_TOOL_RUN_PATH`, `SECFLOW_TOOL_LOG_PATH`, `SECFLOW_TOOL_LOG_FILE_PATH`, and `SECFLOW_TOOL_MANIFEST_PATH`.
   - It must resolve input/output/log paths from manifest/env at runtime and must not hard-code any specific task path.
12. The tool must create the output directory, write `summary.txt` and `summary.md`, and exit with code `0` only when the tool execution completed successfully enough for review.
13. The tool must be generic for the current firmware format family, not case-by-case for this one task:
   - Do not hard-code project IDs, task IDs, absolute firmware paths, output paths, exact file sizes, or a single firmware version as required conditions.
   - Derive or validate offsets/sizes at runtime from the firmware header/table, uImage headers, SquashFS superblocks, and/or bounded binwalk results.
   - Known offsets are allowed only as a validated fast path with magic/size checks and a fallback parser for nearby same-family variants.
14. The tool must be efficient on large firmware:
   - Do not use full-file byte-by-byte gzip/signature scanning as the primary extraction strategy.
   - Prefer `binwalk` output, fixed offset tables, or bounded targeted signature checks.
   - Do not load a large firmware entirely with `f.read()`; use `seek()` and bounded `read(size)` for each section.
   - If a broad scan is necessary, make it a bounded fallback with explicit size/time limits.
15. For Huawei NE20E `.cc` firmware with `magic_hex: 00000002`, implement a format-family fast path based on validated header/table parsing or checked known offsets before heuristic scanning. Extract at least:
   - kernel/uImage
   - ramdisk/initrd
   - main SquashFS
   - secondary SquashFS
   - certificate/signature block
16. For fixed-offset extraction, use Python `seek/read` or large-block copy helpers. Do not use `dd bs=1`; if shell `dd` is used, use a large block size and avoid byte-at-a-time copying.

17. Do not execute the tool yourself. The backend will validate and execute the returned tool path.

Your final response must contain only the absolute path of the generated or updated tool file.
