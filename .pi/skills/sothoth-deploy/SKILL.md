---
name: sothoth-deploy
description: >
  Sothoth 项目的代码提交、CI 构建监控、Pod 更新完整操作流程。
  USE FOR: 提交代码后触发构建、监控 CI 状态、部署新镜像到 K8s Pod、计算镜像 tag。
  DO NOT USE FOR: 代码编写、修改业务逻辑。
metadata:
  version: "1.0.0"
---

# sothoth-deploy — 构建与部署操作指南

---

## 一、正确提交顺序（必须严格遵守）

**先推子仓，再推主仓。** 顺序错误会导致 CI 无法 checkout 子模块而失败。

```
step 1  push 子仓（entry_analyse）到 ict-bin/entry_analyse
step 2  push 主仓 sothoth，更新子模块指针
step 3  CI 自动触发（由主仓 push 触发）
step 4  CI 成功后，计算镜像 tag，kubectl set image 更新 Pod
```

### 操作命令

```bash
# Step 1: 提交并推送 entry_analyse 子仓
cd D:/workspace/pi/sothoth/13-secflow-service/image_build/secflow-app-entry-analyse
git add -A
git commit -m "feat/fix: <描述>"
git push origin main

# Step 2: 在主仓更新子模块指针并推送
cd D:/workspace/pi/sothoth
git add 13-secflow-service/image_build/secflow-app-entry-analyse
git commit -m "update submodule: entry_analyse <子仓commit前7位>"
git pull --rebase --no-recurse-submodules origin v2.1  # 避免 push 被拒
git push
```

> **注意**：如果同时修改了 frontend 子仓，也先推 frontend，再一并更新主仓指针。

---

## 二、监控 CI 构建状态

使用 GitHub Actions API 查询，不使用 digest 轮询。

```python
# 监控脚本（直接在 bash 中 python3 执行）
import sys, json, urllib.request, subprocess, time
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

r = subprocess.run(
    ['git', 'credential', 'fill'],
    input='protocol=https\nhost=github.com\n',
    capture_output=True, text=True, cwd='D:/workspace/pi/sothoth'
)
TOKEN = ''.join(
    l.split('=', 1)[1]
    for l in r.stdout.splitlines()
    if l.startswith('password=')
).strip()

def gh(path):
    req = urllib.request.Request(
        f'https://api.github.com{path}',
        headers={'Authorization': f'Bearer {TOKEN}', 'Accept': 'application/vnd.github+json'}
    )
    with urllib.request.urlopen(req, timeout=15) as rsp:
        return json.loads(rsp.read())

TARGET_RUN_NUMBER = 0  # 设为 0 表示等第一个比已知 run 更新的构建

for i in range(90):  # 最多等 90 * 15 = 22.5 分钟
    runs = gh('/repos/runshine/sothoth/actions/runs?per_page=5')
    for run in runs['workflow_runs']:
        if 'entry-analyse' not in run.get('name', '').lower():
            continue
        num = run['run_number']
        sha = (run['head_sha'] or '')[:8]
        status = run['status']
        conclusion = run.get('conclusion') or '-'
        print(f'[{i*15}s] #{num} {sha} {status} {conclusion}')
        if status == 'completed':
            print('构建完成:', conclusion)
            break
        break
    else:
        time.sleep(15)
        continue
    break
    time.sleep(15)
```

---

## 三、计算镜像 Tag

CI 生成的 tag 格式为：`YYYYMMDD-HHMMSS-SHA7`（北京时间，取 commit 的 committer 时间）。

```python
# 给定 sothoth 的 commit SHA，计算对应的 DATE_TAG
import datetime, subprocess

def compute_date_tag(commit_sha_7: str) -> str:
    """
    从本地 git log 计算 DATE_TAG。
    DATE_TAG = TZ=Asia/Shanghai date -d "@{COMMIT_TS}" +%Y%m%d-%H%M%S + - + SHA7
    """
    full_sha = subprocess.check_output(
        ['git', 'rev-parse', commit_sha_7],
        cwd='D:/workspace/pi/sothoth'
    ).decode().strip()
    
    ts_str = subprocess.check_output(
        ['git', 'show', '-s', '--format=%ct', full_sha],
        cwd='D:/workspace/pi/sothoth'
    ).decode().strip()
    
    commit_ts = int(ts_str)
    dt = datetime.datetime.fromtimestamp(
        commit_ts,
        tz=datetime.timezone(datetime.timedelta(hours=8))  # Asia/Shanghai
    )
    return dt.strftime('%Y%m%d-%H%M%S') + '-' + full_sha[:7]

# 示例
sha = subprocess.check_output(
    ['git', 'rev-parse', '--short=7', 'HEAD'],
    cwd='D:/workspace/pi/sothoth'
).decode().strip()
print('IMAGE_TAG:', compute_date_tag(sha))
# 完整镜像名：ghcr.io/runshine/secflow-app-entry-analyse:{DATE_TAG}
```

或直接用一行命令：

```bash
cd D:/workspace/pi/sothoth
SHA=$(git rev-parse --short=7 HEAD)
TS=$(git show -s --format=%ct HEAD)
python3 -c "
import datetime
ts=$TS; sha='$SHA'
dt=datetime.datetime.fromtimestamp(ts,tz=datetime.timezone(datetime.timedelta(hours=8)))
print('ghcr.io/runshine/secflow-app-entry-analyse:'+dt.strftime('%Y%m%d-%H%M%S')+'-'+sha)
"
```

---

## 四、更新 Pod（部署新镜像）

entry-analyse 有三个 Deployment，必须全部更新。

```bash
NEW_IMAGE="ghcr.io/runshine/secflow-app-entry-analyse:<DATE_TAG>"

kubectl set image deployment/secflow-app-entry-analyse \
    secflow-app-entry-analyse=$NEW_IMAGE -n secflow-ns

kubectl set image deployment/secflow-app-entry-analyse-worker \
    secflow-app-entry-analyse-worker=$NEW_IMAGE -n secflow-ns

kubectl set image deployment/secflow-app-entry-analyse-scheduler \
    secflow-app-entry-analyse-scheduler=$NEW_IMAGE -n secflow-ns
```

### 等待 Pod 就绪

```bash
kubectl rollout status deployment/secflow-app-entry-analyse -n secflow-ns
kubectl rollout status deployment/secflow-app-entry-analyse-worker -n secflow-ns
kubectl rollout status deployment/secflow-app-entry-analyse-scheduler -n secflow-ns
```

### 验证部署结果

```bash
kubectl get pods -n secflow-ns | grep "entry-analyse" | grep -v "Completed\|Terminating"
```

期望输出：全部 Running，且 RESTARTS 为 0。

---

## 五、强制删除卡住的旧 Pod

```bash
# 找到 Terminating 卡住的 pod
kubectl get pods -n secflow-ns | grep "Terminating"

# 强制删除
kubectl delete pod <pod-name> -n secflow-ns --force --grace-period=0
```

---

## 六、三个 Deployment 对应关系

| Deployment | 作用 |
|---|---|
| `secflow-app-entry-analyse` | REST API 服务（接收前端请求） |
| `secflow-app-entry-analyse-worker` | 流水线 Worker（执行 R1~R6 分析） |
| `secflow-app-entry-analyse-scheduler` | 调度器（任务分发与断点续跑） |

三个使用同一个镜像，通过环境变量 `EA_ROLE` 区分启动角色。

---

## 七、完整操作流（一次性 copy-paste）

```bash
# === 1. 推子仓 ===
cd D:/workspace/pi/sothoth/13-secflow-service/image_build/secflow-app-entry-analyse
git push origin main

# === 2. 推主仓 ===
cd D:/workspace/pi/sothoth
git add 13-secflow-service/image_build/secflow-app-entry-analyse
git commit -m "update submodule: entry_analyse $(cd 13-secflow-service/image_build/secflow-app-entry-analyse && git rev-parse --short=7 HEAD)"
git pull --rebase --no-recurse-submodules origin v2.1
git push

# === 3. 计算镜像 tag（等 CI 完成后执行） ===
SHA=$(git rev-parse --short=7 HEAD)
TS=$(git show -s --format=%ct HEAD)
NEW_IMAGE=$(python3 -c "
import datetime
ts=$TS; sha='$SHA'
dt=datetime.datetime.fromtimestamp(ts,tz=datetime.timezone(datetime.timedelta(hours=8)))
print('ghcr.io/runshine/secflow-app-entry-analyse:'+dt.strftime('%Y%m%d-%H%M%S')+'-'+sha)
")
echo "New image: $NEW_IMAGE"

# === 4. 更新三个 Pod ===
for deploy in secflow-app-entry-analyse secflow-app-entry-analyse-worker secflow-app-entry-analyse-scheduler; do
  kubectl set image deployment/$deploy ${deploy}=$NEW_IMAGE -n secflow-ns
done

# === 5. 等待就绪 ===
sleep 60
kubectl get pods -n secflow-ns | grep "entry-analyse" | grep -v "Completed\|Terminating"
```
