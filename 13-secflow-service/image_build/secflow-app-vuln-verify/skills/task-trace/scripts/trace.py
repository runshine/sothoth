#!/usr/bin/env python3
"""定位 agent transcript → 本地缓存，并按需上传到 MinIO HTTP bucket。

OpenCode/KiloCode 场景会尽量导出完整任务轨迹：dispatcher session + 所有
subagent session，按消息时间全局排序后写入 trace-{sid}.jsonl。每条 record 会
附带 _trace_session_id 和 _trace_agent，便于后续定位消息来源。

同时保留既有契约：可选 MinIO 上传、输出 trace_url、写入
~/.cache/task-trace/<agent>/trace-<session_id>.json metadata，供
vuln-report/task-collect/skill-recall-propose 继续消费。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from pathlib import Path
from typing import Any

# Load centralized config (setdefault semantics)
_env_file = Path.home() / ".config" / "secocto" / ".env"
if _env_file.is_file():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if not _line or _line.startswith("#"):
            continue
        _k, _, _v = _line.partition("=")
        _v = _v.strip().strip("\"'")
        if _k and _k not in os.environ:
            os.environ[_k] = _v

CACHE_DIR = Path.home() / ".cache" / "task-trace"


def env_enabled(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _get_opencode_db(agent: str = "opencode") -> Path:
    """返回 OpenCode/KiloCode DB 路径。"""
    if agent == "kilo":
        return Path(os.environ.get("KILO_DATA_DIR", "~/.local/share/kilo")).expanduser() / "kilo.db"
    return Path(os.environ.get("OPENCODE_DATA_DIR", "~/.local/share/opencode")).expanduser() / "opencode.db"


def _detect_agent_type(explicit_agent: str | None = None) -> str:
    """检测 agent 类型（不强依赖 session ID）。

    优先级：显式指定 > 当前 session env > 数据目录 env > 当前 cwd 的 DB root session
    > 本地 DB/配置目录。这样可避免机器上同时存在多个 agent DB 时误选。
    """
    if explicit_agent:
        return explicit_agent

    if os.environ.get("KILO_SESSION_ID"):
        return "kilo"
    if os.environ.get("OPENCODE_SESSION_ID"):
        return "opencode"
    if os.environ.get("CLAUDE_CODE_SESSION_ID"):
        return "claude"

    if os.environ.get("KILO_DATA_DIR"):
        return "kilo"
    if os.environ.get("OPENCODE_DATA_DIR"):
        return "opencode"

    cwd_agent = _detect_agent_type_from_current_cwd_db()
    if cwd_agent:
        return cwd_agent

    if _get_opencode_db("kilo").exists():
        return "kilo"
    if _get_opencode_db("opencode").exists():
        return "opencode"

    config_dir = os.environ.get("CLAUDE_CONFIG_DIR", str(Path.home() / ".claude"))
    if Path(config_dir).exists():
        return "claude"
    print("ERROR: 无法检测 agent 类型（未找到 OpenCode/KiloCode DB、session env 或 Claude 配置目录）", file=sys.stderr)
    sys.exit(2)


def _env_session_id(agent: str) -> str | None:
    if agent == "kilo":
        return os.environ.get("KILO_SESSION_ID")
    if agent == "opencode":
        return os.environ.get("OPENCODE_SESSION_ID")
    if agent == "claude":
        return os.environ.get("CLAUDE_CODE_SESSION_ID")
    return None


def _session_agent(conn: sqlite3.Connection, session_id: str, default: str = "unknown") -> str:
    row = conn.execute("SELECT agent FROM session WHERE id = ?", (session_id,)).fetchone()
    return row[0] if row and row[0] else default


def _preferred_dispatcher_agents() -> list[str]:
    """读取偏好的 dispatcher agent 名称。

    兼容特定部署里使用的 nazhua-audit，同时不把它作为唯一条件：如果没有匹配，
    会回退到当前 cwd 下最新的 root session。
    """
    raw = os.environ.get("TASK_TRACE_DISPATCHER_AGENT", "nazhua-audit")
    return [x.strip() for x in raw.split(",") if x.strip()]


def _sort_key(value: Any) -> tuple[int, float | str]:
    """Normalize DB/JSON timestamps for stable global ordering.

    SQLite-backed agents may store time_created as ISO strings or numeric epochs. Avoid
    converting numbers to strings before sorting, otherwise values like 10 and 2 sort
    incorrectly.
    """
    if value is None:
        return (2, "")
    if isinstance(value, (int, float)):
        return (0, float(value))
    text = str(value)
    try:
        return (0, float(text))
    except ValueError:
        return (1, text)


def _detect_agent_type_from_current_cwd_db() -> str | None:
    """Infer OpenCode/KiloCode by checking which DB has a root session for cwd.

    This is only used when no explicit agent/session/data-dir env is present. If both
    DBs have matching cwd sessions, choose the one with the newest root session.
    """
    cwd = os.getcwd()
    matches: list[tuple[tuple[int, float | str], str]] = []
    for agent in ("kilo", "opencode"):
        info = find_dispatcher_session_info(_get_opencode_db(agent), cwd)
        if info:
            _sid, time_created = info
            matches.append((_sort_key(time_created), agent))
    if not matches:
        return None
    matches.sort(key=lambda item: item[0], reverse=True)
    return matches[0][1]


def find_dispatcher_session_info(db_path: Path, cwd: str) -> tuple[str, Any] | None:
    """从 DB 查找当前项目最近的 dispatcher/root session，返回 (sid, time_created)。"""
    if not db_path.exists():
        return None
    try:
        conn = sqlite3.connect(str(db_path))
        rows = conn.execute(
            "SELECT id, agent, time_created FROM session "
            "WHERE parent_id IS NULL AND directory = ? "
            "ORDER BY time_created DESC LIMIT 50",
            (cwd,),
        ).fetchall()
        conn.close()
    except Exception as e:
        print(f"WARN: DB 查询 dispatcher session 失败: {e}", file=sys.stderr)
        return None

    if not rows:
        return None

    rows = sorted(rows, key=lambda row: _sort_key(row[2]), reverse=True)

    preferred = set(_preferred_dispatcher_agents())
    if preferred:
        for sid, agent, time_created in rows:
            if agent in preferred:
                return (sid, time_created)
    sid, _agent, time_created = rows[0]
    return (sid, time_created)


def find_dispatcher_session(db_path: Path, cwd: str) -> str | None:
    """从 DB 查找当前项目最近的 dispatcher/root session。

    优先选择 TASK_TRACE_DISPATCHER_AGENT 指定的 agent 名称；如果没有匹配，
    回退到 directory=cwd 且 parent_id IS NULL 的最新 root session。
    """
    info = find_dispatcher_session_info(db_path, cwd)
    return info[0] if info else None


def find_all_subagent_sessions(conn: sqlite3.Connection, dispatcher_session_id: str) -> list[str]:
    """查找 dispatcher session 下所有 descendant subagent session。

    使用 parent_id 递归发现，不只包含直接子 session。返回顺序大致按创建时间。
    """
    result: list[str] = []
    seen = {dispatcher_session_id}
    queue: deque[str] = deque([dispatcher_session_id])
    while queue:
        parent = queue.popleft()
        rows = conn.execute(
            "SELECT id FROM session WHERE parent_id = ? ORDER BY time_created",
            (parent,),
        ).fetchall()
        for (sid,) in rows:
            if sid in seen:
                continue
            seen.add(sid)
            result.append(sid)
            queue.append(sid)
    return result


def walk_to_root(db_path: Path, session_id: str) -> str | None:
    """沿 parent_id 递归查找 root session（parent_id IS NULL）。"""
    if not db_path.exists():
        return None
    try:
        conn = sqlite3.connect(str(db_path))
        current = session_id
        seen: set[str] = set()
        max_depth = 50
        while current and max_depth > 0:
            if current in seen:
                conn.close()
                return None
            seen.add(current)
            row = conn.execute("SELECT parent_id FROM session WHERE id = ?", (current,)).fetchone()
            if row is None:
                conn.close()
                return None
            if row[0] is None:
                conn.close()
                return current
            current = row[0]
            max_depth -= 1
        conn.close()
        return None
    except Exception as e:
        print(f"WARN: DB walk_to_root 失败: {e}", file=sys.stderr)
        return None


def discover_session_id(cli_session_id: str | None, explicit_agent: str | None = None) -> tuple[str, str]:
    """返回 (agent_type, real_session_id)。

    优先级：
    1. --session-id 显式传入；
    2. session env var + DB parent_id 递归到 root（修复 subagent env var 场景）；
    3. 当前 cwd 下最新 root/dispatcher session（修复缺少 env var 场景）；
    4. env var 直接使用；
    5. 全失败则退出。
    """
    agent = _detect_agent_type(explicit_agent)

    if cli_session_id:
        print(f"INFO: session ID 来自 CLI 参数: {cli_session_id}", file=sys.stderr)
        return (agent, cli_session_id)

    env_sid = _env_session_id(agent)
    if env_sid and agent in ("opencode", "kilo"):
        db_path = _get_opencode_db(agent)
        root_sid = walk_to_root(db_path, env_sid)
        if root_sid:
            if root_sid != env_sid:
                print(f"INFO: session ID 来自 env var + parent_id 递归: {env_sid} → {root_sid}", file=sys.stderr)
            else:
                print(f"INFO: session ID 来自 env var root session: {root_sid}", file=sys.stderr)
            return (agent, root_sid)

    if agent in ("opencode", "kilo"):
        cwd = os.getcwd()
        db_path = _get_opencode_db(agent)
        dispatcher_sid = find_dispatcher_session(db_path, cwd)
        if dispatcher_sid:
            print(f"INFO: session ID 来自 DB 查询 (dispatcher/root, cwd={cwd}): {dispatcher_sid}", file=sys.stderr)
            return (agent, dispatcher_sid)

    if env_sid:
        print(f"INFO: session ID 来自 env var (直接): {env_sid}", file=sys.stderr)
        return (agent, env_sid)

    print("ERROR: 无法获取真实 session ID（所有发现机制均失败）", file=sys.stderr)
    print("  - CLI --session-id: 未提供", file=sys.stderr)
    print("  - Env var: OPENCODE_SESSION_ID / KILO_SESSION_ID / CLAUDE_CODE_SESSION_ID 均为空或无法解析", file=sys.stderr)
    print("  - DB 查询: 未找到当前 cwd 的 dispatcher/root session", file=sys.stderr)
    sys.exit(2)


def get_claude_jsonl(session_id: str) -> Path:
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR", str(Path.home() / ".claude"))
    cwd_escaped = "-" + os.getcwd().replace("/", "-").lstrip("-")
    jsonl = Path(config_dir) / "projects" / cwd_escaped / f"{session_id}.jsonl"
    if not jsonl.exists():
        print(f"ERROR: transcript 不存在: {jsonl}", file=sys.stderr)
        sys.exit(2)
    return jsonl


def _loads_json(data: str, context: str) -> dict[str, Any]:
    try:
        obj = json.loads(data)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"invalid JSON in {context}: {e}") from e
    if not isinstance(obj, dict):
        raise RuntimeError(f"unexpected non-object JSON in {context}")
    return obj


def _export_session_records(
    conn: sqlite3.Connection,
    session_id: str,
    agent_name: str,
) -> list[tuple[tuple[int, float | str], dict[str, Any]]]:
    """导出单条 session 的所有消息，附加 trace 溯源字段。"""
    msgs = conn.execute(
        "SELECT m.id, m.data, m.time_created FROM message m WHERE m.session_id = ? ORDER BY m.time_created",
        (session_id,),
    ).fetchall()
    parts = conn.execute(
        "SELECT p.message_id, p.data FROM part p WHERE p.session_id = ? ORDER BY p.time_created",
        (session_id,),
    ).fetchall()

    if not msgs:
        print(f"WARN: session {session_id} 无消息记录，跳过", file=sys.stderr)
        return []

    parts_by_msg: dict[str, list[dict[str, Any]]] = {}
    for msg_id, data in parts:
        parts_by_msg.setdefault(msg_id, []).append(_loads_json(data, f"part {msg_id}"))

    records: list[tuple[tuple[int, float | str], dict[str, Any]]] = []
    for msg_id, data, time_created in msgs:
        record = _loads_json(data, f"message {msg_id}")
        if msg_id in parts_by_msg:
            record["parts"] = parts_by_msg[msg_id]
        record["_trace_session_id"] = session_id
        record["_trace_agent"] = agent_name
        records.append((_sort_key(time_created if time_created is not None else record.get("time_created")), record))
    return records


def export_opencode_jsonl(session_id: str, dest: Path, agent: str = "opencode") -> Path:
    """从 OpenCode/KiloCode DB 导出单条 session transcript，直接写入 dest。"""
    db_path = _get_opencode_db(agent)
    if not db_path.exists():
        print(f"ERROR: {agent} DB 不存在: {db_path}", file=sys.stderr)
        sys.exit(2)
    conn = sqlite3.connect(str(db_path))
    agent_name = _session_agent(conn, session_id)
    records = _export_session_records(conn, session_id, agent_name)
    conn.close()

    if not records:
        print(f"ERROR: session {session_id} 无消息记录", file=sys.stderr)
        sys.exit(2)

    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as f:
        for _time_created, record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return dest


def export_full_trajectory(db_path: Path, dispatcher_session_id: str, dest: Path, agent: str = "opencode") -> tuple[Path, int]:
    """导出 dispatcher + 所有 subagent 的完整轨迹，按 time_created 全局排序写入 dest。"""
    if not db_path.exists():
        print(f"ERROR: {agent} DB 不存在: {db_path}", file=sys.stderr)
        sys.exit(2)

    conn = sqlite3.connect(str(db_path))
    dispatcher_agent_name = _session_agent(conn, dispatcher_session_id, default="dispatcher")
    records = _export_session_records(conn, dispatcher_session_id, dispatcher_agent_name)
    if not records:
        conn.close()
        print(f"ERROR: dispatcher session {dispatcher_session_id} 无消息记录", file=sys.stderr)
        sys.exit(2)

    subagent_ids = find_all_subagent_sessions(conn, dispatcher_session_id)
    for sid in subagent_ids:
        agent_name = _session_agent(conn, sid)
        records.extend(_export_session_records(conn, sid, agent_name))
    conn.close()

    records.sort(key=lambda item: item[0])

    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as f:
        for _time_created, record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return (dest, len(subagent_ids))


def cache_locally(source: Path, agent: str, session_id: str) -> Path:
    dest_dir = CACHE_DIR / agent
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"trace-{session_id}.jsonl"
    shutil.copy2(source, dest)
    return dest


def trace_object_key(agent: str, session_id: str) -> str:
    prefix = os.environ.get("TASK_TRACE_PREFIX", "traces").strip().strip("/")
    key = f"{agent}/trace-{session_id}.jsonl"
    return f"{prefix}/{key}" if prefix else key


def build_trace_url(base_url: str, bucket: str, key: str) -> str:
    base = base_url.rstrip("/")
    quoted_bucket = urllib.parse.quote(bucket.strip("/"), safe="")
    quoted_key = urllib.parse.quote(key, safe="/")
    return f"{base}/{quoted_bucket}/{quoted_key}"


def upload_http_put(path: Path, agent: str, session_id: str) -> str | None:
    if not env_enabled("TASK_TRACE_UPLOAD_ENABLED"):
        return None

    endpoint = os.environ.get("TASK_TRACE_HTTP_ENDPOINT", "http://localhost:9000").strip()
    public_base = os.environ.get("TASK_TRACE_PUBLIC_BASE_URL", endpoint).strip()
    bucket = os.environ.get("TASK_TRACE_BUCKET", "task-traces").strip()
    timeout = float(os.environ.get("TASK_TRACE_UPLOAD_TIMEOUT", "15"))

    if not endpoint or not public_base or not bucket:
        raise RuntimeError("TASK_TRACE_HTTP_ENDPOINT / TASK_TRACE_PUBLIC_BASE_URL / TASK_TRACE_BUCKET must be set")

    key = trace_object_key(agent, session_id)
    upload_url = build_trace_url(endpoint, bucket, key)
    trace_url = build_trace_url(public_base, bucket, key)
    data = path.read_bytes()

    req = urllib.request.Request(
        upload_url,
        data=data,
        method="PUT",
        headers={
            "Content-Type": "application/x-ndjson",
            "Content-Length": str(len(data)),
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status not in (200, 201, 204):
            raise RuntimeError(f"MinIO returned HTTP {resp.status}")
    return trace_url


def write_metadata(agent: str, session_id: str, result: dict[str, Any]) -> None:
    path = CACHE_DIR / agent / f"trace-{session_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="定位 agent transcript → 本地缓存，并按需上传到 MinIO")
    parser.add_argument("--session-id", default=None, help="显式传入 session ID；优先级最高")
    parser.add_argument("--agent", choices=("claude", "opencode", "kilo"), default=None, help="显式指定 agent 类型")
    args = parser.parse_args()

    agent, session_id = discover_session_id(args.session_id, args.agent)

    subagent_count = 0
    if agent == "claude":
        source = get_claude_jsonl(session_id)
        cached = cache_locally(source, agent, session_id)
    else:
        db_path = _get_opencode_db(agent)
        cached, subagent_count = export_full_trajectory(
            db_path,
            session_id,
            CACHE_DIR / agent / f"trace-{session_id}.jsonl",
            agent,
        )

    result: dict[str, Any] = {
        "agent": agent,
        "session_id": session_id,
        "local_path": str(cached),
        "subagent_count": subagent_count,
    }

    try:
        trace_url = upload_http_put(cached, agent, session_id)
        if trace_url:
            result["trace_url"] = trace_url
    except (OSError, RuntimeError, urllib.error.URLError) as e:
        result["upload_error"] = str(e)

    write_metadata(agent, session_id, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
