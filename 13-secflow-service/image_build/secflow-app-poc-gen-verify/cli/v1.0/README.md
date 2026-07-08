# PoC_V1 — automated PoC generation & GDB-verification CLI

`poc` is a command-line wrapper around the `claude` (Claude Code) CLI. Given a
**data-flow entry function**, a **vulnerability report**, and the **unpacked
firmware binary directory**, it constructs the `/goal` task prompt and drives
`claude -p` (headless) to perform the full workflow:

1. build a C PoC-verification harness that enters via the data-flow entry
   function (not the vulnerable function directly), resolving every symbol/
   dependency on the way (real firmware `.so` where present, empty stubs where
   genuinely missing, recursively);
2. analyze the report, generate a PoC, and trigger the vulnerability for real;
3. drive **gdb via the tmux-mcp server**, observe+correct in a loop until the
   vuln truly triggers;
4. save the trigger-time memory state, the final PoC, and all artifacts to
   `<output>/output/` (the prompt tells claude to save under `{输出目录}/output`).
   The `/goal` Stop-hook releases on **either** of two evidence-backed paths:
   **Path A — confirmed trigger** (harness compiles+links; gdb backtrace proves
   entry→vuln call chain; an observable trigger signal — crash/loop-count/ASAN —
   at the vulnerable function; required artifacts present), **or Path B —
   false-positive/unreachable** (gdb-advanced along the call chain, multiple
   inputs/paths tried, a concrete blocker located — unreachable call chain /
   unpassable check / unsatisfiable precondition — with gdb register/memory
   evidence at the blocker, plus a 简体中文 false-positive report). Fabricating
   evidence (fake gdb output/crash, stubbing out the vuln check to fake a
   trigger) is explicitly forbidden and fails the task.

This is the same task done manually for `VULN-001` (see
`/home/icsl/ipsec-fangzheng/binary_full_claude_code_glm5.2/output/`).

## Prerequisites (already satisfied in this environment)

- `claude` CLI on PATH (Claude Code 2.1.x).
- `tmux-mcp` MCP server configured at user level (`~/.claude.json` → `mcpServers`).
- The built-in `/goal` command (sets a Stop-hook that keeps claude working until
  the task condition is met).
- `permissions.defaultMode = "auto"` + `skipDangerousModePermissionPrompt = true`
  (so `--dangerously-skip-permissions` runs without an interactive prompt).
- Model `glm-5.2` (set in `~/.claude/settings.json`).

If any of these are missing in a different environment, configure them first.

## Install

No build step — pure Python 3 (stdlib only). Either call the wrapper directly:

```bash
git clone <this-repo> /home/icsl/PoC_V1   # or just use the dir in place
/home/icsl/PoC_V1/poc --help
```

or put it on PATH:

```bash
ln -sf /home/icsl/PoC_V1/poc /usr/local/bin/poc   # then: poc --help
```

## Usage

```bash
poc -e <entry-func> -r <vuln-report.md> -b <firmware-bin-dir> [-o <output-dir>] [options]
```

### Required

| flag | meaning |
|---|---|
| `-e, --entry` | Data-flow entry function name (e.g. `IPSEC_SOCKI_PipeMsg`). |
| `-r, --report` | Path to the vulnerability report file. |
| `-b, --bindir` | Full unpacked firmware binary directory (searched for real `.so`). |

### Optional

| flag | default | meaning |
|---|---|---|
| `-o, --output` | auto | Output dir for all artifacts (substituted as `{输出目录}`). If omitted, a dir named `<entry>_<bindir-basename>_<timestamp>` is created under the cwd. |
| `-w, --workdir` | `<output>` | Where claude runs (cwd). |
| `--model` | settings (`glm-5.2`) | Model override (passed to `claude --model`). |
| `--effort` | settings (`xhigh`) | Effort level: `low`/`medium`/`high`/`xhigh`/`max` (passed to `claude --effort`). |
| `--session-name` | none | Session display name (passed to `claude -n`; shown in the `/resume` picker). |
| `--session-id` | none | Session UUID (passed to `claude --session-id`; transcript stored as `<id>.jsonl`). |
| `--session-dir` | `<workdir>/.claude` | Sets `CLAUDE_CONFIG_DIR` for the claude subprocess — session transcripts + claude config are stored under this dir. The baked `~/.claude.json` + `~/.claude/settings.json` are copied in on first use so the GLM/MCP/permissions config travels with the session. Default isolates each run's sessions under its own workdir. |
| `--output-format` | `stream-json` | `text` or `stream-json` (live progress). |
| `--timeout` | `7200` | Hard cap in seconds (kills claude if exceeded). |
| `--log` | `<workdir>/poc_cli_<ts>.log` | Log file path. |
| `--no-skip-permissions` | off | Do not pass `--dangerously-skip-permissions`. |
| `--dry-run` | off | Print the exact claude command + prompt and exit. |
| `--claude-bin` | `claude` | Path to the claude executable. |

## Example (VULN-001)

```bash
poc -e IPSEC_SOCKI_PipeMsg \
    -r /home/icsl/ipsec-fangzheng/binary_full_claude_code_glm5.2/result_001.md \
    -b /home/icsl/ipsec-fangzheng/binary_full_claude_code_glm5.2 \
    -o /home/icsl/ipsec-fangzheng/binary_full_claude_code_glm5.2/output
```

`-o` is optional — omit it and a dir like
`./IPSEC_SOCKI_PipeMsg_binary_full_claude_code_glm5.2_20260701_055832` is created
under the cwd (named `<entry>_<bindir-basename>_<timestamp>`):

```bash
poc -e IPSEC_SOCKI_PipeMsg -r .../result_001.md -b .../firmware   # -o auto-generated
```

What happens:
- Validates the 3 required inputs (4th, `-o`, defaults if omitted).
- Substitutes them into the `/goal` prompt template (saved to
  `<workdir>/poc_prompt.txt` for reproducibility).
- Runs `claude -p <prompt> --output-format stream-json --dangerously-skip-permissions
  --add-dir <bindir> --add-dir <output>` with `cwd=<workdir>` (default `<output>`).
- Streams live progress (assistant text + tool names) to the terminal and the
  log file.
- On exit, lists the artifacts produced under `<output>/output/`.

Inspect without running claude:

```bash
poc --dry-run -e IPSEC_SOCKI_PipeMsg -r .../result_001.md -b .../firmware -o .../output
```

## How it works

`poc_cli.py` does **not** implement the PoC logic itself — it orchestrates
`claude -p`, which does the real work (RE, harness build, symbol resolution, PoC
generation, gdb-via-tmux-mcp verification). The tool's job is: input validation,
prompt construction, a robust headless invocation with streaming + timeout +
logging, and a post-run artifact check. The `/goal` Stop-hook makes claude keep
working until the task condition is satisfied (or the `--timeout` kills it).

## Notes

- **Permissions**: the workflow compiles C, runs gdb, and writes files, so the
  default uses `--dangerously-skip-permissions` (consistent with this env's
  `auto` mode). Drop it with `--no-skip-permissions` if you want interactive
  prompts.
- **Timeout**: PoC generation is long (tens of minutes at `xhigh` effort). The
  2h default is a safety net; tune with `--timeout`.
- **Output**: artifacts go to `<output>/output/` (claude writes there per the
  prompt; `post_run_check` scans that subdir). `<workdir>/poc_prompt.txt` (the
  exact prompt) and a log file also live under `<workdir>` (default `<output>`).
- **Reproducibility**: `poc_prompt.txt` + the log's `# cmd=` line let you re-run
  the exact `claude` invocation by hand if needed.
- **Session storage**: Claude Code has no `--session-folder` CLI flag, but the
  **base dir** is controllable via the `CLAUDE_CONFIG_DIR` env var (confirmed in
  the compiled `claude` binary: `configDir = CLAUDE_CONFIG_DIR || ~/.claude`,
  `projectsDir = configDir/projects`). `--session-dir` sets that env var and
  **defaults to `<workdir>/.claude`**, so each run's sessions are isolated under
  its own workdir (the baked `~/.claude.json` + `~/.claude/settings.json` are
  copied in on first use). The full session path is
  `<session-dir>/projects/<encoded-cwd>/<session-id>.jsonl`: the **project
  subfolder** comes from the cwd (`--workdir`), the **filename** from
  `--session-id`, the **display name** from `--session-name`.
- **Headless caveat**: `claude -p` (stream-json) emits one JSON event per line;
  the tool renders assistant text and tool names live. If the model/endpoint
  is briefly unavailable, claude may emit a permission/classifier notice —
  retry after a short wait.
