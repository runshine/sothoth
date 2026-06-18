---
name: skill-recall-onboard
namespace: bootstrap
description: |
  Bring local Claude Code skills under skill-recall management. Scans
  <skills-dir>/, for each skill that is not yet git-managed locally and not
  yet registered on skill-recall, creates a Gitea repo under namespace `demo`
  and pushes it. Skips this skill and any other skill declaring
  `namespace: bootstrap` in its frontmatter. Triggers on: "onboard skills",
  "纳管 skill", "把本地 skill 推到 skill-recall".
tags: [skill-recall, onboarding, infra, bootstrap]
---

# skill-recall-onboard

## What this skill does

For every directory under `<skills-dir>/<name>/` containing `SKILL.md`:

| Local state | Platform state | Action |
|-------------|----------------|--------|
| `namespace: bootstrap` in frontmatter | (any) | **skip** — bootstrap skills are managed separately |
| has `.git` with remote pointing at our Gitea, clean + up-to-date | (any) | **skip** — nothing to push |
| has `.git` with remote pointing at our Gitea, unpushed commits/tags | (any) | **push** unpushed commits + tags → trigger recall sync |
| has `.git` with remote pointing at our Gitea, dirty tree | (any) | **skip + warn** — user has in-flight edits; refuse to auto-commit |
| has `.git` with remote elsewhere (GitHub etc.) | (any) | **skip + report** — foreign remote, leave it alone |
| no `.git` | skill-recall already has `{org}/{slug}` | **skip** — platform already has it |
| no `.git` | skill-recall does NOT have it | **onboard**: create Gitea repo → `git init` in skill dir → commit → tag `v1.0.0` → push → trigger recall sync |

### Project-level skill auto-discovery

By default the script also scans for **project-level skills** by walking up from
the current working directory looking for `.opencode/skills/` or
`.claude/skills/`. Skills found there are merged with the global skills
directory for scanning.

**Deduplication**: when a skill with the same slug exists in both global and
project directories, the **project-level version takes precedence** (it
overwrites the global entry).

Use `--no-project` to disable project-level auto-discovery and only scan the
global skills directory.

After every successful push, the script calls
`POST {SKILL_RECALL_URL}/admin/sync/{org}/{slug}` so the new skill is searchable
in `/recall` immediately (don't need to wait for the next webhook).

The script is **idempotent**: re-running it does nothing for skills that are
already in MANAGED_LOCAL / PLATFORM_HAS_IT state.

## When to invoke this skill

这是默认 post-task 生命周期的一环。

它在每次任务结束后都必须执行一次，用于：
- 把新的本地 skill 纳入 skill-recall 管理
- 或把已纳管 skill 的未推送 commits/tags 同步到 Gitea
- 如果没有可同步内容，则脚本应返回明确的 skipped 状态

也可在用户显式要求时单独运行，例如：
## How to invoke

## 配置约束

Gitea 和 skill-recall 服务地址必须来自环境变量 `GITEA_URL`、`SKILL_RECALL_URL`，认证来自 `GITEA_TOKEN`。执行命令时应先加载 `~/.config/secocto/.env`；除非用户显式要求临时覆盖，否则不要在命令参数中写死服务端地址。

Required env (or use the `--gitea-url` / `--gitea-token` / `--recall-url` flags):

| Variable | Default | Required? |
|----------|---------|-----------|
| `GITEA_URL` | from env / `~/.config/secocto/.env` | no |
| `GITEA_TOKEN` | — | **yes** |
| `SKILL_RECALL_URL` | from env / `~/.config/secocto/.env` | no |

Commands:

```bash
# Apply (default behavior — no confirmation prompt):
python <skills-dir>/skill-recall-onboard/scripts/onboard.py

# Preview only (no writes):
python <skills-dir>/skill-recall-onboard/scripts/onboard.py --dry-run

# Only one specific skill (debugging):
python <skills-dir>/skill-recall-onboard/scripts/onboard.py --skill cao-reflect

# Skip project-level skills, only scan global:
python <skills-dir>/skill-recall-onboard/scripts/onboard.py --no-project

# Use a different Gitea org:
python <skills-dir>/skill-recall-onboard/scripts/onboard.py --org my-team

# Machine-readable JSON output (for chaining in scripts):
python <skills-dir>/skill-recall-onboard/scripts/onboard.py --json
```

Exit codes:

- `0` — success: all NEW skills onboarded, no foreign remotes
- `1` — partial: some NEW skills failed to push, or some skills had foreign remotes (review the report)
- `2` — pre-flight failed: Gitea or skill-recall unreachable, missing token, or bad skills dir

## Dependencies

- Python 3.10+
- `httpx`, `pyyaml` (most envs already have them; if not: `pip install httpx pyyaml`)
- `git` CLI

## Self-skip mechanism

This skill's own `SKILL.md` has `namespace: bootstrap` in its frontmatter, so
`onboard.py` will skip it during scanning — preventing the obvious recursion
of trying to onboard itself. Any other infra-level skill that should not be
pushed to the regular `demo` namespace can mark itself the same way.
