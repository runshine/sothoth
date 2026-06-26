#!/usr/bin/env python3
"""
V3 端到端 6 场景测试（并发模式，4 workers 并行派发）。

每个场景独立插入任务 + 写 cancel/restart 命令，6 场景可并发跑：
  场景 1: 新任务正常执行
  场景 2: 任务 cancel + 归档
  场景 3: 任务 restart 正常
  场景 4: 先 cancel 然后 restart
  场景 5: rollout 场景（旧任务执行正常）
  场景 6: 任务正常/异常结束 调度正常

6 场景不依赖前序场景状态：各自 insert 新任务，依赖 cancel/restart 命令
由 _cmd_cancel / _cmd_restart 处理，V3 scheduler DONE-driven 派发。
"""
import json
import os
import re
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import pymysql

DB = dict(host='10.100.51.130', user='secflow', password='Huawei12#$',
          database='secflow', connect_timeout=8, autocommit=False)

PROJECT = '2abc83006a7ca7a4'
TEST_MODULE = 'urpc'
PASSED_TIMEOUT = 900  # 15 min（V3 super_fast R1 ~8-10min + 余量）


def conn():
    return pymysql.connect(**DB)


def new_task_id(scenario_tag):
    return f"eat_v3_{scenario_tag}_{datetime.now().strftime('%H%M%S')}_{uuid.uuid4().hex[:6]}"


def get_passed_config_template():
    with conn() as c:
        with c.cursor() as cur:
            cur.execute(
                "SELECT task_config_json FROM secflow_app_ea_tasks "
                "WHERE status='passed' AND is_deleted=0 "
                "AND task_config_json LIKE %s "
                "AND module_name=%s "
                "ORDER BY finished_at DESC LIMIT 1",
                ("%input_contract%", TEST_MODULE),
            )
            row = cur.fetchone()
            if not row:
                raise RuntimeError("找不到已 passed 任务的 config 模板")
            return json.loads(row[0])


def get_passed_output_path():
    with conn() as c:
        with c.cursor() as cur:
            cur.execute(
                "SELECT output_path FROM secflow_app_ea_tasks "
                "WHERE status='passed' AND is_deleted=0 AND output_path IS NOT NULL "
                "AND module_name=%s "
                "ORDER BY finished_at DESC LIMIT 1",
                (TEST_MODULE,),
            )
            row = cur.fetchone()
            return row[0] if row else f"/data/files/{PROJECT}/app/secflow-app-entry-analyse"


def insert_task(task_id, task_name, cfg, real_input, real_source_path, real_output, module_name):
    sql = ("INSERT INTO secflow_app_ea_tasks "
           "(task_id, project_id, task_name, task_description, input_path, source_path, "
           " module_name, output_path, prompt_content, status, owner_pod, owner_pod_ip, "
           " lease_expires_at, cancel_requested, cancel_acknowledged, cancel_process_cleanup_done, "
           " cancel_finalized, task_origin_type, task_config_json, is_deleted, created_by) "
           "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', NULL, NULL, NULL, "
           " 0, 0, 0, 0, 'manual', %s, 0, 'v3_e2e_concurrent')")
    with conn() as c:
        with c.cursor() as cur:
            cur.execute(sql, (
                task_id, PROJECT, task_name, f"V3 concurrent test {task_name}",
                real_input, real_source_path, module_name, real_output,
                f"分析 {module_name} 模块的外部入口",
                json.dumps(cfg),
            ))
            c.commit()
    return task_id


def write_cmd(task_id, command, requested_by="v3_e2e_concurrent"):
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("INSERT INTO secflow_app_ea_task_commands (task_id, project_id, command, status, requested_by, created_at) "
                        "VALUES (%s, %s, %s, 'pending', %s, NOW())",
                        (task_id, PROJECT, command, requested_by))
            c.commit()


def get_task(task_id):
    with conn() as c:
        with c.cursor() as cur:
            cur.execute(
                "SELECT task_id, status, owner_pod, error, "
                "started_at, finished_at FROM secflow_app_ea_tasks WHERE task_id=%s",
                (task_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            cur.execute(
                "SELECT COUNT(*) FROM secflow_app_ea_task_event "
                "WHERE task_id=%s AND event_type='task_retried'",
                (task_id,),
            )
            retry_events = cur.fetchone()[0]
            return row + (retry_events,)


def wait_status(task_id, target_status, timeout, poll=10):
    if isinstance(target_status, str):
        target_status = [target_status]
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        t = get_task(task_id)
        last = t
        if t and t[1] in target_status:
            return t
        time.sleep(poll)
    return last


def artifact_exists(task_id):
    out = f"/data/files/{PROJECT}/app/secflow-app-entry-analyse/{task_id}/output"
    has_flag = os.path.exists(f"{out}/flag")
    return has_flag, f"flag={has_flag} out={out}"


# ═══════════════════════════════════════════════════════════════════════════════
# 场景 1：新任务正常执行（pending → running → passed）
# ═══════════════════════════════════════════════════════════════════════════════
def scenario_1(cfg, paths):
    print("\n═══ 场景 1: 新任务正常执行 ═══")
    tid = new_task_id("s1")
    insert_task(tid, "scenario1_basic", cfg, *paths)
    print(f"  [inserted] {tid}")
    final = wait_status(tid, 'passed', timeout=PASSED_TIMEOUT)
    ok, info = artifact_exists(tid)
    print(f"  [result] {final}")
    print(f"  [archive] {ok} {info}")
    return tid, final and final[1] == 'passed'


# ═══════════════════════════════════════════════════════════════════════════════
# 场景 2：任务 cancel + 归档
# 在 running 中途写 cancel 命令（V3 scheduler 收到 → socket TERMINATE → worker killpg+归档）
# ═══════════════════════════════════════════════════════════════════════════════
def scenario_2(cfg, paths):
    print("\n═══ 场景 2: 任务 cancel + 归档 ═══")
    tid = new_task_id("s2")
    insert_task(tid, "scenario2_cancel", cfg, *paths)
    print(f"  [inserted] {tid}")
    # 等任务到 running 然后立即 cancel
    t0 = time.time()
    while time.time() - t0 < 600:  # 等最多 10min 到 running
        t = get_task(tid)
        if t and t[1] == 'running':
            print(f"  [t={int(time.time()-t0)}s] running, 下发 cancel")
            write_cmd(tid, 'cancel', 'v3_s2')
            break
        if t and t[1] in ('passed', 'cancelled', 'failed'):
            print(f"  [warning] 任务已完成 {t[1]}, 仍下发 cancel")
            write_cmd(tid, 'cancel', 'v3_s2')
            break
        time.sleep(5)
    final = wait_status(tid, 'cancelled', timeout=120, poll=3)
    ok, info = artifact_exists(tid)
    print(f"  [result] {final}")
    print(f"  [archive] {ok} {info}")
    return tid, final and final[1] == 'cancelled'


# ═══════════════════════════════════════════════════════════════════════════════
# 场景 3：任务 restart 正常
# 插入任务 → 写 restart 命令（V3 _cmd_restart reset pending + 立即派发）
# 关键：先不直接 set_pending，让 _cmd_restart 走 reset 路径
# ═══════════════════════════════════════════════════════════════════════════════
def scenario_3(cfg, paths):
    print("\n═══ 场景 3: 任务 restart ═══")
    tid = new_task_id("s3")
    insert_task(tid, "scenario3_restart", cfg, *paths)
    print(f"  [inserted] {tid}")
    # 等任务到 running 然后写 restart
    t0 = time.time()
    while time.time() - t0 < 600:
        t = get_task(tid)
        if t and t[1] == 'running':
            print(f"  [t={int(time.time()-t0)}s] running, 下发 restart")
            write_cmd(tid, 'restart', 'v3_s3')
            break
        time.sleep(5)
    # restart 后任务 cancel → set pending → 重派发 → passed
    # 但 _cmd_restart 内部处理可能让 task 直接重启而不 cancel
    final = wait_status(tid, 'passed', timeout=PASSED_TIMEOUT)
    retry_events = final[6] if final else 0
    print(f"  [result] {final} retry_events={retry_events}")
    return tid, final and final[1] == 'passed' and retry_events > 0


# ═══════════════════════════════════════════════════════════════════════════════
# 场景 4：先 cancel 再 restart
# 插入任务 → 等到 running → cancel → 等 cancelled → restart → 等 passed
# ═══════════════════════════════════════════════════════════════════════════════
def scenario_4(cfg, paths):
    print("\n═══ 场景 4: 先 cancel 再 restart ═══")
    tid = new_task_id("s4")
    insert_task(tid, "scenario4_cancel_restart", cfg, *paths)
    print(f"  [inserted] {tid}")
    # 等 running
    t0 = time.time()
    while time.time() - t0 < 600:
        t = get_task(tid)
        if t and t[1] == 'running':
            print(f"  [t={int(time.time()-t0)}s] running, 下发 cancel")
            write_cmd(tid, 'cancel', 'v3_s4_cancel')
            break
        time.sleep(5)
    # 等 cancelled
    cancel_final = wait_status(tid, 'cancelled', timeout=120, poll=3)
    print(f"  [cancel] {cancel_final}")
    # 下发 restart
    time.sleep(2)  # 让 _cmd_cancel 完成
    write_cmd(tid, 'restart', 'v3_s4_restart')
    # 等 passed
    final = wait_status(tid, 'passed', timeout=PASSED_TIMEOUT)
    retry_events = final[6] if final else 0
    print(f"  [restart result] {final} retry_events={retry_events}")
    return tid, (cancel_final and cancel_final[1] == 'cancelled') and (final and final[1] == 'passed' and retry_events > 0)


# ═══════════════════════════════════════════════════════════════════════════════
# 场景 5：rollout 场景（scheduler reclaim 失败 worker 的任务）
# 插入任务 → 等到 running → 强制 owner_pod=NULL 模拟 worker 死亡 → 等 reclaim 重派
# ═══════════════════════════════════════════════════════════════════════════════
def scenario_5(cfg, paths):
    print("\n═══ 场景 5: rollout 场景（worker 死亡 → scheduler reclaim）═══")
    tid = new_task_id("s5")
    insert_task(tid, "scenario5_rollout", cfg, *paths)
    print(f"  [inserted] {tid}")
    # 等 running
    t0 = time.time()
    while time.time() - t0 < 600:
        t = get_task(tid)
        if t and t[1] == 'running':
            print(f"  [t={int(time.time()-t0)}s] running owner={t[2]}")
            break
        time.sleep(5)
    # 模拟 worker 死亡：清 owner_pod（但 task.status 仍 running；reclaim 30s 后认 worker 死亡）
    # 实际上更直接：把 task 改回 pending（模拟 reclaim 后状态）
    print(f"  [模拟 worker 死亡] 强制 owner_pod=NULL, 触发 reclaim")
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("UPDATE secflow_app_ea_tasks SET owner_pod=NULL WHERE task_id=%s", (tid,))
            c.commit()
    # 等 passed（scheduler reclaim 30s 后会重派发）
    final = wait_status(tid, 'passed', timeout=PASSED_TIMEOUT)
    print(f"  [result] {final}")
    return tid, final and final[1] == 'passed'


# ═══════════════════════════════════════════════════════════════════════════════
# 场景 6：任务正常/异常结束 调度正常
# 任务 A：正常 passed；任务 B：module 不存在 → 任务失败但 scheduler 继续派发
# ═══════════════════════════════════════════════════════════════════════════════
def scenario_6(cfg, paths):
    print("\n═══ 场景 6: 正常/异常结束后调度正常 ═══")
    # 任务 A: 正常
    tid_a = new_task_id("s6a")
    insert_task(tid_a, "scenario6_normal", cfg, *paths)
    # 任务 B: 用不存在 module 触发失败（但要保证 task_config 含 input_contract 让 load_module 不立即报错）
    tid_b = new_task_id("s6b")
    bad_cfg = dict(cfg)
    bad_cfg["input_contract"] = dict(cfg.get("input_contract", {}))
    # 用一个明显不存在的 module 路径
    insert_task(tid_b, "scenario6_abnormal", bad_cfg, *paths[:-1],
                paths[-1].rsplit('/', 1)[0] + "/__nonexistent_v3test__")
    print(f"  [inserted A] {tid_a}")
    print(f"  [inserted B] {tid_b}")
    a = wait_status(tid_a, 'passed', timeout=PASSED_TIMEOUT)
    b = wait_status(tid_b, ['failed', 'cancelled', 'error'], timeout=PASSED_TIMEOUT)
    print(f"  [A result] {a}")
    print(f"  [B result] {b}")
    return (tid_a, tid_b), (a and a[1] == 'passed', b and b[1] in ('failed', 'cancelled', 'error'))


# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    print("=" * 70)
    print("V3 端到端 6 场景测试（并发模式）")
    print("=" * 70)
    print(f"  DB: {DB['host']}:3306/{DB['database']}")
    print(f"  module: {TEST_MODULE} (复用 passed 任务 input_contract)")
    print(f"  时间: {datetime.now().isoformat(timespec='seconds')}")
    print()

    # ── 准备 config 模板 ─────────────────────────────────────
    print("─── 准备 config + 路径")
    cfg = get_passed_config_template()
    ic = cfg.get("input_contract", {})
    real_source_dir = ic.get("source_dir") or ic.get("module_dir")
    real_input = ic.get("source_root") or ic.get("source_root_path")
    real_output = get_passed_output_path()
    m = re.search(r'/modules/([^/]+)/?$', real_source_dir or '')
    module_name = m.group(1) if m else TEST_MODULE
    paths = (real_input, real_source_dir, real_output, module_name)
    print(f"  input_path  = {real_input}")
    print(f"  source_path = {real_source_dir}")
    print(f"  module_name = {module_name}")
    print(f"  output_path = {real_output}")
    print()

    # ── 6 场景并发跑 ─────────────────────────────────────
    print("─── 6 场景并发跑（4 workers 并行）")
    t0 = time.time()
    scenarios = [
        ('1', scenario_1, (cfg, paths)),
        ('2', scenario_2, (cfg, paths)),
        ('3', scenario_3, (cfg, paths)),
        ('4', scenario_4, (cfg, paths)),
        ('5', scenario_5, (cfg, paths)),
        ('6', scenario_6, (cfg, paths)),
    ]
    results = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(s, *args): name for name, s, args in scenarios}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                tid, ok = fut.result()
            except Exception as e:
                print(f"\n  场景 {name} 异常: {e}")
                tid, ok = None, False
            results[name] = (tid, ok)
            elapsed = int(time.time() - t0)
            mark = '✅' if ok else '❌'
            if name == '6':
                ids, (okA, okB) = (tid if tid else (None, None), (ok, False) if not isinstance(ok, tuple) else ok)
                # scenario_6 returns ((tid_a, tid_b), (okA, okB))
                pass
            print(f"  [{elapsed}s] 场景 {name}: {mark}")
    t1 = time.time()
    total = int(t1 - t0)

    # ── 总结 ─────────────────────────────────────────
    print("\n" + "=" * 70)
    print("V3 6 场景并发测试总结")
    print("=" * 70)
    print(f"  总耗时: {total}s ({total/60:.1f}min)")
    pass_count = 0
    for name in ['1', '2', '3', '4', '5', '6']:
        tid, ok = results.get(name, (None, False))
        if name == '6':
            ids, oks = (tid if isinstance(tid, tuple) else (None, None),
                        ok if isinstance(ok, tuple) else (False, False))
            mark = '✅' if all(oks) else '❌'
            print(f"  场景 {name}: {mark} A={oks[0]} B={oks[1]}  ids={ids}")
            if all(oks):
                pass_count += 1
        else:
            mark = '✅' if ok else '❌'
            print(f"  场景 {name}: {mark}  {tid}")
            if ok:
                pass_count += 1
    print(f"\n  通过: {pass_count}/6")
    if pass_count == 6:
        print("✅ 全部 6 场景通过")
        sys.exit(0)
    else:
        print(f"⚠️  {6-pass_count} 场景失败")
        sys.exit(1)
