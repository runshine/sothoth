# poc CLI — automated PoC generation & GDB-verification CLI (v2.0, two-stage)

`poc` is a command-line wrapper around the `claude` (Claude Code) CLI. Given a
**data-flow entry function**, a **vulnerability report**, and the **unpacked
firmware binary directory**, it drives `claude -p` (headless) through a
**two-stage, two-session** pipeline:

| stage | session | job | success criterion |
|---|---|---|---|
| **Stage 1** | `<base>-stage1` | construct a harness that enters via the data-flow entry function + a **benign reachability driver**, and GDB-prove entry→vuln-point reachability | harness compiles+links; gdb backtrace hits entry & vuln-point; vuln code runs real/unmodified; `harness_report.md` written |
| **Gate** | — (deterministic, CLI-side) | verify Stage-1 artifacts exist + reachability transcript hits both functions | all 5 files present + report markers + transcript mentions |
| **Stage 2** | `<base>-stage2` (**fresh context**) | read Stage-1 artifacts (no re-RE; `reach_driver.bin` is reference-only, not reused), freely analyze the entry→vuln call chain (not limited to Stage 1's path) and generate a malicious PoC, loop-debug-trigger via tmux-mcp/gdb | trigger evidence (crash / loop≥1e7 / gdb-observed OOB) + memory state + PoC + `poc_report.md`; or false-positive report |

**Why two sessions (not one session + two `/goal`):** the split's value is
context-budget reset, a reviewable Stage-1 checkpoint, and independent Stage-2
retry against a frozen harness — all of which require Stage 2 to start fresh.
Same-session `--resume` would carry Stage 1's 70k-token RE history into Stage 2,
which is the very pressure the split is meant to relieve. The handoff is the
on-disk artifacts: the harness **source code** is the durable carrier of Stage
1's hard knowledge; `harness_report.md` covers the rest; Stage 2 may grep Stage
1's transcript file on disk without loading it into context.

The `/goal` Stop-hook in each stage keeps claude working until that stage's
condition is met. Fabricating evidence (fake gdb output/crash, stubbing out the
vuln check to fake a trigger) is explicitly forbidden and fails the task.

## Prerequisites (already satisfied in this environment)

- `claude` CLI on PATH (Claude Code 2.1.x).
- `tmux-mcp` MCP server configured at user level (`~/.claude.json` → `mcpServers`).
- The built-in `/goal` command.
- `permissions.defaultMode = "auto"` + `skipDangerousModePermissionPrompt = true`.
- Model `glm-5.2` (in `~/.claude/settings.json`).
- `gdb`, `tmux`, a C toolchain on PATH.

## Install

No build step — pure Python 3 (stdlib only). Put it on PATH:

```bash
ln -sf /home/icsl/sothoth/13-secflow-service/image_build/secflow-app-poc-gen-verify/cli/poc /usr/local/bin/poc
poc --help
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
| `-o, --output` | auto | Output dir (`{输出目录}` in prompts). If omitted, `<entry>_<bindir-basename>_<ts>` under cwd. |
| `-w, --workdir` | `<output>` | Where claude runs (cwd). |
| `--model` | settings (`glm-5.2`) | Model override (`claude --model`). |
| `--effort` | settings (`xhigh`) | `low`/`medium`/`high`/`xhigh`/`max` (`claude --effort`). |
| `--session-name` | `poc` | Base session display name; stage suffixes `-stage1`/`-stage2` appended (two-stage); verbatim with `--single`. |
| `--session-id` | auto UUID | Stage-1 session UUID (two-stage: stage1 uses this if given, stage2 auto-generates a fresh UUID; verbatim with `--single`). |
| `--session-dir` | `<workdir>/.claude` | `CLAUDE_CONFIG_DIR` — both stages share it so Stage 2 can grep Stage 1's transcript on disk. |
| `--output-format` | `stream-json` | `text` or `stream-json`. |
| `--log` | auto | Log path (`<workdir>/poc_cli_<ts>[_stageN].log`). |
| `--no-skip-permissions` | off | Do not pass `--dangerously-skip-permissions`. |
| `--dry-run` | off | Print the cmds + prompts + gate plan and exit. |
| `--claude-bin` | `claude` | Path to claude executable. |

### Stage-selection flags (mutually exclusive)

| flag | behavior |
|---|---|
| *(none)* | **two-stage** (v2.0 default): Stage 1 → gate → Stage 2. |
| `--single` | v1.0 monolithic single-`/goal` prompt, one session. Escape hatch for the degenerate case where the vuln-point function is only reachable via the buggy path (reachability == trigger). |
| `--stage1-only` | two-stage but run only Stage 1 (+ gate); don't proceed to Stage 2. Build+prove a harness in isolation. |
| `--stage2-only` | skip Stage 1 (its artifacts must already exist in `<output>/output/`); gate on them, then run Stage 2 only. Retry Stage 2 against a frozen harness. |

## Stage-1 gate (deterministic, CLI-side)

Between the two stages, the CLI (not the LLM) checks `<output>/output/`:

- required files: `harness.c`, `harness`, `reach_driver.bin`, `gdb_reachability.log`, `harness_report.md`
- `harness_report.md` contains `漏洞点函数: <name>` and a `可达性结论:` line
- (only when `可达性结论: 已确认`) `gdb_reachability.log` mentions the entry function AND the reported vuln-point function, with a backtrace

Three outcomes:

| outcome | condition | exit code | Stage 2? |
|---|---|---|---|
| **pass** | all files present + `可达性结论: 已确认` + transcript hits entry & vuln-point + backtrace | 0 (→Stage 2 rc) | yes |
| **blocked** | all files present + `可达性结论: 未确认` (Stage 1 honestly couldn't prove reachability — the reachability analog of Path B); the blocker explanation is extracted from the report and printed | **3** | no |
| **fail** | contract violation: missing files, missing/ambiguous marker, or transcript inconsistent with the claimed `已确认` | **2** | no |

`未确认` is a first-class negative result: the gate surfaces the blocker text
and uses exit 3 (distinct from exit 2) so scripts can tell "Stage 1 reachability
blocked" from "Stage 1 didn't comply with the artifact contract". Transcript
cross-check is skipped for `未确认` (the vuln-point function not being hit is
the expected outcome there, not a failure).

## Stage-2 required artifacts

`poc_input.bin`, `gdb_trigger.log`, `trigger_memory.txt`, `poc_report.md`.

## Example

```bash
poc -e IPSEC_SOCKI_PipeMsg \
    -r /home/icsl/ipsec-fangzheng/result_001.md \
    -b /home/icsl/ipsec-fangzheng/binary_full \
    -o /home/icsl/ipsec-fangzheng/output
```

Inspect without running claude:

```bash
poc --dry-run -e IPSEC_SOCKI_PipeMsg -r .../result_001.md -b .../firmware
```

Iterate on the harness alone, then retry the trigger against the frozen harness:

```bash
poc --stage1-only -e ... -r ... -b ... -o /work/out       # build + prove harness
poc --stage2-only -e ... -r ... -b ... -o /work/out       # retry trigger only
```

## How it works

`poc_cli.py` does **not** implement the PoC logic itself — it orchestrates
`claude -p`, which does the real work (RE, harness build, symbol resolution,
reachability proof, PoC generation, gdb-via-tmux-mcp verification). The CLI's
job is: input validation, prompt construction (per-stage), a robust headless
invocation with streaming + logging, the **deterministic Stage-1 gate**, and a
post-run artifact check. The `/goal` Stop-hook makes claude keep working until
the stage condition is satisfied.

## Notes

- **Two sessions**: Stage 1 and Stage 2 run as separate `claude -p` invocations
  with separate `--session-id` (both transcripts under the shared `--session-dir`
  so Stage 2 can grep Stage 1's transcript on demand). Stage 2 starts with a
  fresh context.
- **Handoff = on-disk artifacts**: Stage 2 reads `harness_report.md` + the
  harness source (not Stage 1's thinking history). The harness source is the
  durable carrier of Stage 1's hard knowledge (call chain, stub strategy,
  struct layouts). `harness_report.md`'s required fields are pinned in the
  Stage-1 prompt and enforced by the gate.
- **tmux/gdb process management**: the prompt (both stages) forbids
  `pkill -f`/`killall` for cleaning gdb — the claude process's own command line
  contains the full prompt (with "gdb"/"harness" in it), so `pkill -f 'gdb.*…'`
  would match and SIGKILL claude itself (this is what killed the v1.0 runs
  063033/063110). gdb cleanup must use `tmux kill-session -t <name>`,
  `tmux send-keys 'quit'`, or a precisely-PID'd `kill`. Each task must use a
  per-task tmux session name and clean it up at exit.
- **Web/skill lockdown**: the session settings get `permissions.deny =
  [WebSearch, WebFetch, Skill]` so the PoC must be self-derived from the
  binary + vuln report only (set `POC_ALLOW_WEB=1` to disable).
- **Log files (two per stage run):** each stage writes a sibling pair under
  `<workdir>/`:
  - `poc_cli_<ts>[_stageN].log` — **rendered, human-readable** mirror of the
    terminal (the `[system] init` / assistant text / `-> tool:` / `-> result:` /
    `[result]` lines you see live), plus a `# cmd= / # entry= / ...` header. This
    is what you read to review a run.
  - `poc_cli_<ts>[_stageN].jsonl` — the **raw stream-json** (one event per line,
    incl. `thinking_tokens`), for programmatic grep/analysis (e.g. extracting
    `stop_reason`, `result` events, `usage` tokens). Only written in
    `stream-json` mode (the default).
  The terminal output and the `.log` are identical (the CLI tees every rendered
  line to both). The raw stream that used to be in the `.log` moved to the
  `.jsonl` so the `.log` is readable.
- **Reproducibility**: `poc_prompt_stage1.txt` + `poc_prompt_stage2.txt` (or
  `poc_prompt.txt` for `--single`) + the logs' `# cmd=` lines let you re-run
  either stage by hand.
- **v1.0 backup**: the monolithic single-`/goal` script + prompt are backed up
  in `cli/v1.0/` (`poc_cli.py`, `poc`, `README.md`, `prompt_v1.0.md`). The v1.0
  prompt is also kept live as `PROMPT_SINGLE` in `poc_cli.py`, reachable via
  `--single`.
