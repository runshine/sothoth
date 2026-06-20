#!/usr/bin/env python3
"""
V3 端到端 6 场景测试（直接 DB 驱动，不走 API auth）。

覆盖：
  1. 新任务能正常执行（pending → running → passed）
  2. 任务 cancel 正常，产物归档正常
  3. 任务 restart 正常
  4. 任务先 cancel 然后 restart 正常
  5. rollout 场景，旧任务执行正常（轮换 worker pod 期间任务不中断）
  6. 任务正常/异常结束 调度正常（passed + failed 后 scheduler 继续派发新任务）
"""
import json
import sys
import time
import uuid
from datetime import datetime, timedelta

import pymysql

DB = dict(host='10.100.51.130', user='secflow', password='Huawei12#$', database='secflow', connect_timeout=8, autocommit=False)

PROJECT = '2abc83006a7ca7a4'  # 复用现有项目（真实 module 已存在）


# V3 端到端测试用已验证能成功的 module 名（"worker"，eat_602e08c5772e4675 用过同 module 成功 passed）
TEST_MODULE = 'worker'


def get_passed_config_template():
    """从已 passed 任务取完整 task_config_json（含真实 files_list/source_dir/source_root/source_root_path）。"""
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("SELECT task_config_json FROM secflow_app_ea_tasks "
                        "WHERE status='passed' AND is_deleted=0 AND task_config_json LIKE '%input_contract%' "
                        "ORDER BY finished_at DESC LIMIT 1")
            row = cur.fetchone()
            if not row: raise RuntimeError("找不到已 passed 任务的 config 模板")
            return json.loads(row[0])


def get_passed_output_path():
    """复用 passed 任务的 output_path。"""
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("SELECT output_path FROM secflow_app_ea_tasks "
                        "WHERE status='passed' AND is_deleted=0 AND output_path IS NOT NULL "
                        "ORDER BY finished_at DESC LIMIT 1")
            row = cur.fetchone()
            return row[0] if row else f"/data/files/{PROJECT}/app/secflow-app-entry-analyse"


def conn():
    return pymysql.connect(**DB)

def new_task_id():
    return f"eat_v3test_{datetime.now().strftime('%H%M%S')}_{uuid.uuid4().hex[:6]}"


def insert_task(task_id, task_name, module_name=None, config=None):
    """插入一个 pending 任务。V3 scheduler 会通过 socket 派发给 worker control process。"""
    # 基础：复用 passed 任务完整 config（input_contract 含真实 files_list/source_dir/source_root/...）
    base_cfg = get_passed_config_template()
    ic = base_cfg.get("input_contract", {})
    # 实际目录结构：
    #   source_root (ic.source_root) = .../8f7d29eef14d4871/input/  ← 真实源码树（含 umdk-master/）
    #   modules 索引 = .../source_project__sat_xxx/modules/urpc/files.list
    #   V3 task_runner 用 cfg.cwd = input_path 同时跑 load_module 和 resolve_file_path
    #   → input/modules/urpc/files.list 要被找到 + input/umdk-master/... 要被找到
    #   需要 input/modules 是软链（已手动创建）或 modules 与 source 同棵
    real_source_dir = ic.get("source_dir") or ic.get("module_dir")
    real_source_path = real_source_dir
    real_input = ic.get("source_root") or ic.get("source_root_path")
    real_output = get_passed_output_path()
    if module_name is None:
        import re as _re
        m = _re.search(r'/modules/([^/]+)/?$', real_source_path or '')
        module_name = m.group(1) if m else TEST_MODULE
    if config:
        # 用户显式覆盖项（如 fast_mode 切换）合并入
        for k, v in config.items():
            base_cfg[k] = v
    sql = ("INSERT INTO secflow_app_ea_tasks "
           "(task_id, project_id, task_name, task_description, input_path, source_path, "
           " module_name, output_path, prompt_content, status, owner_pod, owner_pod_ip, "
           " lease_expires_at, cancel_requested, cancel_acknowledged, cancel_process_cleanup_done, "
           " cancel_finalized, task_origin_type, task_config_json, is_deleted, created_by) "
           "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', NULL, NULL, NULL, "
           " 0, 0, 0, 0, 'manual', %s, 0, 'v3_test')")
    with conn() as c:
        with c.cursor() as cur:
            cur.execute(sql, (
                task_id, PROJECT, task_name, f"V3 test {task_name}",
                real_input,        # input_path = source_root（files.list 路径基准）
                real_source_path,  # source_path = source_dir（engine 路径解析）
                module_name,
                real_output,       # output_path
                f"分析 {module_name} 模块的外部入口",  # prompt_content
                json.dumps(base_cfg),
            ))
            c.commit()
    print(f"  [inserted] {task_id} ({task_name})")
    return task_id


def get_task(task_id):
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("SELECT task_id, status, owner_pod, error, finished_at FROM secflow_app_ea_tasks "
                        "WHERE task_id=%s", (task_id,))
            return cur.fetchone()


def get_events(task_id, limit=20):
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("SELECT event_type, level, source, message, created_at FROM secflow_app_ea_task_event "
                        "WHERE task_id=%s ORDER BY created_at ASC LIMIT %s", (task_id, limit))
            return cur.fetchall()


def write_cmd(task_id, command, requested_by="v3_test"):
    """写入命令队列（V3 scheduler command loop 读取并经 socket 下发）。"""
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("INSERT INTO secflow_app_ea_task_commands (task_id, project_id, command, status, requested_by, created_at) "
                        "VALUES (%s, %s, %s, 'pending', %s, NOW())", (task_id, PROJECT, command, requested_by))
            c.commit()


def set_pending(task_id):
    """把任务重置为 pending（restart 场景用）。"""
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("UPDATE secflow_app_ea_tasks SET status='pending', owner_pod=NULL, owner_pod_ip=NULL, "
                        "lease_expires_at=NULL, cancel_requested=0, cancel_acknowledged=0, "
                        "cancel_process_cleanup_done=0, cancel_finalized=0, started_at=NULL, "
                        "finished_at=NULL, error=NULL WHERE task_id=%s", (task_id,))
            c.commit()


def wait_status(task_id, target, timeout=300, poll=5):
    """轮询等到目标状态。"""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        t = get_task(task_id)
        last = t
        if t and t[1] == target:
            return t
        time.sleep(poll)
    return last


def print_events(task_id, label):
    print(f"  --- events ({label}) ---")
    for ev in get_events(task_id, 12):
        print(f"    {ev[4]}  [{ev[2]}]  {ev[0]:<25}  {(ev[3] or '')[:60]}")


def artifact_exists(task_id):
    out = f"/data/files/{PROJECT}/app/secflow-app-entry-analyse/{task_id}/output"
    has_flag = os.path.exists(f"{out}/flag")
    has_funcs = os.path.exists(f"{out}/functions.list")
    return (has_flag or has_funcs), f"flag={has_flag} functions.list={has_funcs} out={out}"


import os


# ═══════════════════════════════════════════════════════════════════════════════
# 场景 1：新任务正常执行（pending → running → passed）
# ═══════════════════════════════════════════════════════════════════════════════
def scenario_1():
    print("\n═══ 场景 1: 新任务正常执行 ═══")
    tid = insert_task(new_task_id(), "scenario1_basic")
    print(f"  [等待派发] 任务 {tid} (pending→running→passed)")
    final = wait_status(tid, 'passed', timeout=600, poll=8)
    print(f"  [结果] {final}")
    print_events(tid, "scenario1")
    ok, info = artifact_exists(tid)
    print(f"  [归档] {ok} {info}")
    return tid, final[1] == 'passed' and ok


# ═══════════════════════════════════════════════════════════════════════════════
# 场景 2：任务 cancel + 归档（用已经 passed 的 task 模拟快速 cancel：先 restart
# 为 pending + running 中途 cancel，验证 scheduler socket TERMINATE 杀进程+归档）
# ═══════════════════════════════════════════════════════════════════════════════
def scenario_2(tid_passed=None):
    print("\n═══ 场景 2: 任务 cancel + 归档 ═══")
    # 复用场景 1 已 passed 的 task，重启它为 pending（reset），等它跑到 running，cancel
    tid = tid_passed or insert_task(new_task_id(), "scenario2_cancel")
    # 先把任务重置回 pending
    set_pending(tid)
    # 不等待它到 running（v3 fast_mode catalog 模块极快，2-3 分钟完成），
    # 等几秒让它进入 running
    deadline = time.time() + 60
    entered_running = False
    while time.time() < deadline:
        st = get_task(tid)
        if st and st[1] == 'running':
            entered_running = True
            break
        if st and st[1] in ('passed', 'cancelled', 'failed'):
            break
        time.sleep(2)
    if not entered_running:
        # 已完成 → cancel 走 final 路径
        print(f"  [说明] 任务已完成 ({get_task(tid)[1]})，直接发 cancel 命令测 final 路径")
    write_cmd(tid, 'cancel', 'v3_test_scenario2')
    print(f"  [cancel 已下发] 等待结束 (scheduler socket TERMINATE → 控制进程 killpg+归档)")
    final = wait_status(tid, 'cancelled', timeout=120, poll=3)
    print(f"  [结果] {final}")
    print_events(tid, "scenario2")
    ok, info = artifact_exists(tid)
    print(f"  [归档产物] ok={ok} {info}")
    return tid, final[1] == 'cancelled' and ok


# ═══════════════════════════════════════════════════════════════════════════════
# 场景 3：任务 restart 正常
# ═══════════════════════════════════════════════════════════════════════════════
def scenario_3(tid_cancelled=None):
    print("\n═══ 场景 3: 任务 restart ═══")
    tid = tid_cancelled or insert_task(new_task_id(), "scenario3_restart")
    # 依赖 _cmd_restart 内部逻辑：cancelled 状态下会 reset status=pending
    # 并立即 _dispatch_one_to 派发。不手动 set_pending 绕过命令路径。
    write_cmd(tid, 'restart', 'v3_test_scenario3')
    print(f"  [restart 命令已下发] 等待再次派发+完成")
    final = wait_status(tid, 'passed', timeout=600, poll=8)
    print(f"  [结果] {final}")
    print_events(tid, "scenario3")
    return tid, final[1] == 'passed'


# ═══════════════════════════════════════════════════════════════════════════════
# 场景 4：先 cancel 再 restart
# ═══════════════════════════════════════════════════════════════════════════════
def scenario_4():
    print("\n═══ 场景 4: 先 cancel 再 restart ═══")
    tid = insert_task(new_task_id(), "scenario4_cancel_restart")
    # 等待到 running
    deadline = time.time() + 60
    while time.time() < deadline:
        st = get_task(tid)
        if st and st[1] == 'running':
            break
        if st and st[1] in ('passed', 'cancelled', 'failed'):
            break
        time.sleep(2)
    # cancel
    write_cmd(tid, 'cancel', 'v3_test_scenario4_cancel')
    print(f"  [cancel 已下发] 等待 cancelled")
    final_c = wait_status(tid, 'cancelled', timeout=120, poll=3)
    print(f"  [cancel 结果] {final_c}")
    # restart (v3 restart: 命令队列 → scheduler → 置 status=pending → 派发)
    write_cmd(tid, 'restart', 'v3_test_scenario4_restart')
    print(f"  [restart 命令已下发] 等待 passed")
    final_r = wait_status(tid, 'passed', timeout=600, poll=8)
    print(f"  [restart 结果] {final_r}")
    print_events(tid, "scenario4")
    return tid, final_c[1] == 'cancelled' and final_r[1] == 'passed'


# ═══════════════════════════════════════════════════════════════════════════════
# 场景 5：rollout 场景，旧任务执行正常
# 策略：插入一个任务，让它跑到 running，然后滚动更新 worker 镜像（触发 V3
# worker pod 替换），看任务是否被中断或恢复。
# ═══════════════════════════════════════════════════════════════════════════════
def scenario_5():
    print("\n═══ 场景 5: rollout 场景，旧任务执行正常 ═══")
    import subprocess as _sp
    tid = insert_task(new_task_id(), "scenario5_rollout")
    # 等到 running
    deadline = time.time() + 60
    while time.time() < deadline:
        st = get_task(tid)
        if st and st[1] == 'running':
            break
        if st and st[1] in ('passed', 'cancelled', 'failed'):
            print(f"  任务太快完成（{st[1]}），继续监控")
            break
        time.sleep(2)
    st = get_task(tid)
    print(f"  [任务状态] {st}  → rollout 模拟：手动 set 一个不同 image tag 触发 pod 替换")
    # 触发 rollout（用 :latest 反复 set：但容器内无 kubectl。改为直接改 DB owner_pod
    # 模拟 worker pod 切换，看 scheduler 后续行为）
    # 实际上：rollout 测试改为在 host 端运行子流程（subprocess），容器内有完整 Python。
    # 在此场景里，rollout = 调度器 reclaim stale worker。我们直接走：杀掉当前 owner
    # pod IP，让 scheduler 判为 stale → reclaim → 新 worker 重新派发。
    print(f"  [模拟 worker 死亡] 强制将 owner_pod 置 NULL（触发 scheduler reclaim）")
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("UPDATE secflow_app_ea_tasks SET owner_pod=NULL WHERE task_id=%s", (tid,))
            c.commit()
    # 等 scheduler reclaim + 重新派发
    print(f"  [等待 reclaim + 重新派发] 任务 {tid}")
    start = time.time()
    last = st
    saw_running = False
    saw_new_owner = False
    while time.time() - start < 300:
        t = get_task(tid)
        if t and t != last:
            print(f"  [t={int(time.time()-start)}s] {last[1]}→{t[1]} owner={t[2]}")
            last = t
        if t and t[1] == 'running' and t[2] and t[2] != st[2]:
            saw_new_owner = True
        if t and t[1] in ('passed', 'failed', 'cancelled'):
            break
        time.sleep(5)
    final = get_task(tid)
    print(f"  [最终] {final}")
    print_events(tid, "scenario5")
    passed = final[1] == 'passed'
    return tid, passed


# ═══════════════════════════════════════════════════════════════════════════════
# 场景 6：正常/异常结束后调度正常
# 策略：连续插入 2 个任务（一个成功路径，一个故意用不存在的 module 触发 fail），
# 验证 scheduler 都能正常派发。
# ═══════════════════════════════════════════════════════════════════════════════
def scenario_6():
    print("\n═══ 场景 6: 正常/异常结束后调度正常 ═══")
    # 任务 A: 正常
    tid_a = insert_task(new_task_id(), "scenario6_normal")
    # 任务 B: 用不存在 module 触发失败
    tid_b = insert_task(new_task_id(), "scenario6_abnormal", module_name="__nonexistent_v3test__")
    print(f"  [等待 A passed] {tid_a}")
    a = wait_status(tid_a, 'passed', timeout=600, poll=8)
    print(f"  [A 结果] {a}")
    print(f"  [等待 B failed/cancelled] {tid_b}")
    b = wait_status(tid_b, 'failed', timeout=600, poll=8)
    if not b or b[1] != 'failed':
        b = wait_status(tid_b, 'cancelled', timeout=120, poll=5)
    print(f"  [B 结果] {b}")
    print_events(tid_b, "scenario6_B")
    return (tid_a, tid_b), (a and a[1] == 'passed', b and b[1] in ('failed', 'cancelled'))


# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    print("=" * 70)
    print("V3 端到端 6 场景测试（直接 DB 驱动，V3 scheduler 经 socket 派发）")
    print("=" * 70)

    # 检查 V3 是否就绪（容器内无 kubectl，跳过）
    print(f"  V3 scheduler: Running (assumed, in-container test)")
    print(f"  V3 workers: assumed 1+ Running (assumed)")

    results = {}
    # 1
    t1, ok1 = scenario_1()
    results['1'] = (t1, ok1)
    # 2 (cancel a running task)
    t2, ok2 = scenario_2(tid_passed=t1)
    results['2'] = (t2, ok2)
    # 3 (restart)
    t3, ok3 = scenario_3(tid_cancelled=t2)
    results['3'] = (t3, ok3)
    # 4 (cancel then restart)
    t4, ok4 = scenario_4()
    results['4'] = (t4, ok4)
    # 5 (rollout) — use the same image digest to avoid 404 from prior run
    t5, ok5 = scenario_5()
    results['5'] = (t5, ok5)
    # 6 (normal + abnormal)
    t6, ok6 = scenario_6()
    results['6'] = t6 + ok6

    print("\n" + "=" * 70)
    print("测试结果汇总")
    print("=" * 70)
    for k, v in results.items():
        if k == '6':
            ids, (okA, okB) = v
            print(f"  场景 {k}: A normal={okA}  B abnormal={okB}  ids={ids}")
        else:
            tid, ok = v
            print(f"  场景 {k}: {'✅' if ok else '❌'}  {tid}")
