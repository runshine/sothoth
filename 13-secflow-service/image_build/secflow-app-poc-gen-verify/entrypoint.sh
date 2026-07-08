#!/usr/bin/env bash
# entrypoint.sh - install ~/.claude.json + ~/.claude/settings.json templates on
# first start, resolve the tmux-mcp absolute path, mark onboarding done, then exec.
# (Adapted from secflow-app-kernel-scan/entrypoint.sh; mcpServers is preserved so
#  tmux-mcp stays registered for the project path the `poc` CLI runs in.)
set -euo pipefail

HOME_DIR="${HOME:-/home/scanner}"
CLAUDE_JSON="$HOME_DIR/.claude.json"
SETTINGS_JSON="$HOME_DIR/.claude/settings.json"
mkdir -p "$HOME_DIR/.claude"

# 1. install templates on first start
if [ -f /app/.claude.json.template ] && [ ! -f "$CLAUDE_JSON" ]; then
  cp /app/.claude.json.template "$CLAUDE_JSON"
fi
if [ -f /app/settings.json.template ] && [ ! -f "$SETTINGS_JSON" ]; then
  cp /app/settings.json.template "$SETTINGS_JSON"
fi

# 2. resolve tmux-mcp absolute path into .claude.json (claude spawns it directly)
if [ -f "$CLAUDE_JSON" ] && command -v jq >/dev/null && command -v tmux-mcp >/dev/null; then
  TMUX_MCP_PATH="$(command -v tmux-mcp)"
  tmp="$(mktemp)"
  jq --arg p "$TMUX_MCP_PATH" '.mcpServers["tmux-mcp"].command = $p' "$CLAUDE_JSON" > "$tmp"
  mv "$tmp" "$CLAUDE_JSON"
fi

# 3. mark onboarding complete (idempotent)
if [ -f "$CLAUDE_JSON" ] && command -v jq >/dev/null; then
  CLAUDE_VER="$(claude --version 2>/dev/null | awk '{print $1}')"
  tmp="$(mktemp)"
  jq --arg v "$CLAUDE_VER" '.hasCompletedOnboarding=true | .lastOnboardingVersion=$v' "$CLAUDE_JSON" > "$tmp"
  mv "$tmp" "$CLAUDE_JSON"
fi

echo "[entrypoint] claude=$(command -v claude 2>/dev/null || echo MISSING) tmux=$(command -v tmux 2>/dev/null || echo MISSING) gdb=$(command -v gdb 2>/dev/null || echo MISSING) tmux-mcp=$(command -v tmux-mcp 2>/dev/null || echo MISSING) poc=$(command -v poc 2>/dev/null || echo MISSING) HOME=$HOME_DIR"

exec "$@"
