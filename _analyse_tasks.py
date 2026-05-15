import json, datetime, collections
from pathlib import Path

TASKS = [
    ("sat_fd3270625f5c490c", "/data/files/66a98a8e5f647259/app/secflow-app-system-analyse", "passed"),
    ("sat_a52a61bcd5284b09",  "/data/files/66a98a8e5f647259/app/secflow-app-system-analyse", "passed"),
    ("sat_343ce32fe2c54bab", "/data/files/44f9029d00650a10/app/secflow-app-system-analyse", "passed"),
    ("sat_2295258a983e468d", "/data/files/44f9029d00650a10/app/secflow-app-system-analyse", "passed"),
    ("sat_775256ba66b04232", "/data/files/44f9029d00650a10/app/secflow-app-system-analyse", "passed"),
    ("sat_9e3daeef0a92477a", "/data/files/44f9029d00650a10/app/secflow-app-system-analyse", "failed"),
]

def read_jsonl(p):
    out = []
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return out

def fmt(sec):
    if sec is None:
        return "---"
    h, r = divmod(int(sec), 3600)
    m, s = divmod(r, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"

def ts2t(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "--:--:--"

W = print

for tid, base, status in TASKS:
    run_dir = Path(base) / tid / "run"
    epath   = run_dir / "events.jsonl"
    rows    = read_jsonl(epath)

    cfg_lines = {}
    stage_info = {}
    model_rows = []
    errors = []
    fails = []
    t_start = t_end = None
    total_in = total_out = 0
    run_breaks = []
    prev_ts = 0

    for row in rows:
        if row.get("__final__"):
            continue
        ts  = row.get("ts", 0)
        typ = row.get("type", "")
        dat = row.get("data") or {}

        if t_start is None or ts < t_start:
            t_start = ts
        if t_end is None or ts > t_end:
            t_end = ts
        if prev_ts > 0 and ts < prev_ts - 5:
            run_breaks.append(ts)
        prev_ts = ts

        if typ == "task_config_print":
            for l in (dat.get("lines") or []):
                if "=" in l:
                    k, _, v = l.partition("=")
                    cfg_lines[k.strip()] = v.strip()

        elif typ == "stage":
            stage = dat.get("stage", "?")
            mod   = dat.get("module", "")
            hb    = dat.get("heartbeat", 0)
            key   = f"{stage}/{mod}" if mod else str(stage)
            si    = stage_info.setdefault(key, {"t_first": ts, "t_last": ts, "hb_max": 0, "judge_id": None})
            if ts < si["t_first"]:
                si["t_first"] = ts
            if ts > si["t_last"]:
                si["t_last"] = ts
            si["hb_max"] = max(si["hb_max"], hb)
            if dat.get("judge_id"):
                si["judge_id"] = dat["judge_id"]

        elif typ == "stage_result":
            stage = dat.get("stage", "?")
            mod   = dat.get("module", "")
            key   = f"{stage}/{mod}" if mod else str(stage)
            si    = stage_info.setdefault(key, {"t_first": ts, "t_last": ts, "hb_max": 0})
            si["done_ts"] = ts

        elif typ == "stage_fail":
            stage  = dat.get("stage", "?")
            mod    = dat.get("module", "")
            reason = dat.get("reason") or dat.get("error") or dat.get("msg") or str(dat)[:80]
            fails.append(f"{stage}/{mod}: {reason[:120]}")

        elif typ == "model":
            u      = dat.get("usage") or {}
            pi_in  = u.get("prompt_tokens", 0)
            pi_out = u.get("completion_tokens", 0)
            total_in  += pi_in
            total_out += pi_out
            model_rows.append({"ts": ts, "stage": dat.get("stage", "?"),
                                "model": (dat.get("model") or "?")[:30],
                                "in": pi_in, "out": pi_out})

        elif typ == "log":
            msg = dat.get("msg") or dat.get("message") or ""
            if any(k in msg for k in ("ERROR", "Error", "exception", "Traceback", "timeout", "超时", "失败")):
                errors.append(msg[:160])

        elif typ == "task_end":
            err = dat.get("error", "")
            if err:
                errors.append(f"task_end: {err[:120]}")

    dur = (t_end - t_start) if (t_start and t_end) else None

    # session tokens
    sess_tokens = collections.defaultdict(lambda: {"in": 0, "out": 0, "calls": 0})
    sess_dir = run_dir / "sessions"
    if sess_dir.exists():
        for jf in sorted(sess_dir.rglob("*.jsonl")):
            rel   = str(jf.relative_to(sess_dir))
            sdata = read_jsonl(jf)
            s_in = s_out = s_calls = 0
            for r2 in sdata:
                if r2.get("type") == "llm_response":
                    u = r2.get("data", {}).get("usage", {}) or {}
                    s_in   += u.get("prompt_tokens", 0)
                    s_out  += u.get("completion_tokens", 0)
                    s_calls += 1
            if s_in or s_out:
                sk = rel.split("/")[0]
                sess_tokens[sk]["in"]    += s_in
                sess_tokens[sk]["out"]   += s_out
                sess_tokens[sk]["calls"] += s_calls

    # result.json
    result = {}
    rpath  = run_dir / "result.json"
    if rpath.exists():
        try:
            result = json.loads(rpath.read_text(errors="replace"))
        except Exception:
            pass

    # evaluation_summary.json
    esum = {}
    esum_path = run_dir / "evaluation_summary.json"
    if esum_path.exists():
        try:
            esum = json.loads(esum_path.read_text(errors="replace"))
        except Exception:
            pass

    W()
    W("=" * 80)
    W(f"  任务: {tid}  状态: {status.upper()}")
    W("=" * 80)
    W(f"  开始: {ts2t(t_start)}   结束: {ts2t(t_end)}   总耗时: {fmt(dur)}")
    if run_breaks:
        W(f"  ** 含 {len(run_breaks)} 次 resume 续跑边界")
    W(f"  粒度: {cfg_lines.get('module_granularity', '?')}   并行: {cfg_lines.get('parallel_modules', '?')}   目标: {cfg_lines.get('target_dir', '?')}")

    W()
    W("  -- Token 消耗 (model事件) --")
    W(f"     输入: {total_in:>8,}   输出: {total_out:>8,}   合计: {total_in + total_out:>8,}")
    if model_rows:
        by_stage = collections.defaultdict(lambda: [0, 0, 0])
        for m in model_rows:
            by_stage[m["stage"]][0] += m["in"]
            by_stage[m["stage"]][1] += m["out"]
            by_stage[m["stage"]][2] += 1
        for sn, (i, o, c) in sorted(by_stage.items()):
            W(f"     {sn:<24} in={i:>8,}  out={o:>8,}  calls={c}")

    if sess_tokens:
        W()
        W("  -- Token 消耗 (session files) --")
        tot_si = tot_so = 0
        for sn, sv in sorted(sess_tokens.items()):
            tot_si += sv["in"]
            tot_so += sv["out"]
            W(f"     {sn:<28} in={sv['in']:>8,}  out={sv['out']:>8,}  calls={sv['calls']}")
        W(f"     {'[合计]':<28} in={tot_si:>8,}  out={tot_so:>8,}")

    W()
    W("  -- Stage 耗时 --")
    stage_groups = collections.defaultdict(list)
    for key, si in stage_info.items():
        stage_groups[key.split("/")[0]].append((key, si))

    ORDER = ["explore", "0", "1", "2", "3", "4", "5",
             "classify", "refine", "analyse", "security_filter",
             "final_report", "completeness"]
    seen = set()
    for sname in ORDER:
        if sname not in stage_groups:
            continue
        seen.add(sname)
        items  = stage_groups[sname]
        durs   = [(si["t_last"] - si["t_first"]) for _, si in items if si["t_last"] > si["t_first"]]
        total_s = sum(durs)
        mx = max(durs) if durs else 0
        mn = min(durs) if durs else 0
        n    = len(items)
        done = sum(1 for _, si in items if "done_ts" in si)
        W(f"     {sname:<22} 模块={n:<3} 完成={done:<3} 累计={fmt(total_s):<12} max={fmt(mx):<12} min={fmt(mn)}")
    for sname, items in stage_groups.items():
        if sname in seen:
            continue
        durs    = [(si["t_last"] - si["t_first"]) for _, si in items if si["t_last"] > si["t_first"]]
        total_s = sum(durs)
        mx = max(durs) if durs else 0
        n    = len(items)
        done = sum(1 for _, si in items if "done_ts" in si)
        W(f"     {sname:<22} 模块={n:<3} 完成={done:<3} 累计={fmt(total_s):<12} max={fmt(mx)}")

    long_mod = [(k, si["t_last"] - si["t_first"])
                for k, si in stage_info.items()
                if si["t_last"] - si["t_first"] > 1200]
    if long_mod:
        W()
        W("  ** 超长模块(>20min):")
        for km, d in sorted(long_mod, key=lambda x: -x[1]):
            W(f"     ! {km:<46} {fmt(d)}")

    redo_mods = [(k, stage_info[k]["hb_max"])
                 for k in stage_info
                 if "analyse" in k.lower() and stage_info[k]["hb_max"] > 1]
    if redo_mods:
        W()
        W("  ** S3 redo 模块 (heartbeat>1):")
        for k, h in sorted(redo_mods, key=lambda x: -x[1])[:15]:
            W(f"     [redo] {k:<44} hb={h}")

    if fails:
        W()
        W("  ** stage_fail:")
        for f2 in fails:
            W(f"     x {f2}")
    if errors:
        W()
        W("  ** 错误/告警 (前10):")
        for e in errors[:10]:
            W(f"     ! {e[:150]}")

    if result:
        modules = result.get("modules") or []
        rc = sum(1 for m in modules
                 if (m.get("risk_level") or "").upper() in ("HIGH", "CRITICAL", "MEDIUM", "HIGH_RISK", "CRITICAL_RISK"))
        W()
        W(f"  >> result: {len(modules)} 模块  高/中风险={rc}")
        tops = sorted(
            [m for m in modules if (m.get("risk_level") or "").upper() in ("HIGH", "CRITICAL", "MEDIUM")],
            key=lambda m: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get((m.get("risk_level") or "").upper(), 9)
        )[:10]
        for m in tops:
            W(f"     {(m.get('risk_level') or '?'):<10} {m.get('name') or m.get('module_name') or '?'}")

    if esum:
        W()
        W(f"  >> eval_summary: {str(esum)[:200]}")

print()
print("ANALYSIS COMPLETE")
