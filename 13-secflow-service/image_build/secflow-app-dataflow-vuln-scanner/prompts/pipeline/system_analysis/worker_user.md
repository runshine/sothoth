## 任务描述

{task}

---

## 执行步骤

### 1. 解析任务参数

从上方任务描述中找到：
- **输入文件夹路径**（包含已解包的完整系统文件）
- 默认输出路径：`{working_dir}/docker_output`

### 2. 准备环境

```bash
mkdir -p {working_dir}/docker_output

# 确认输入路径存在
ls -la <INPUT_DIR>
```

### 3. 执行 Docker 系统分析命令

> ⚠️ **TODO**: 请将下方命令替换为同事提供的实际 Docker 镜像名称和命令参数

```bash
docker run --rm \
  -v <INPUT_DIR>:/data/input:ro \
  -v {working_dir}/docker_output:/data/output \
  secflow/system-analyzer:latest \
  --input /data/input --output /data/output
```

### 4. 验证输出

```bash
# 检查输出目录结构 — 预期每个高危模块有一个独立子目录
ls -la {working_dir}/docker_output/

# 列出所有子目录（每个子目录代表一个高危模块）
find {working_dir}/docker_output/ -maxdepth 1 -mindepth 1 -type d
```

确认输出目录中包含一个或多个高危模块子目录。
