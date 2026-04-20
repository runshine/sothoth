## 任务描述

{task}

---

## 执行步骤

### 1. 解析任务参数

从上方任务描述中找到：
- **输入文件夹路径**（包含优化后的反编译源码）
- **反编译源码目录**（从上下文信息中获取，需要传递给下游）
- **模块名称**
- 默认输出路径：`{working_dir}/docker_output`

### 2. 准备环境

```bash
mkdir -p {working_dir}/docker_output

# 确认输入路径存在
ls -la <INPUT_DIR>
```

### 3. 执行 Docker 外部入口分析命令

> ⚠️ **TODO**: 请将下方命令替换为同事提供的实际 Docker 镜像名称和命令参数

```bash
docker run --rm \
  -v <INPUT_DIR>:/data/input:ro \
  -v {working_dir}/docker_output:/data/output \
  secflow/entry-analyzer:latest \
  --input /data/input --output /data/output
```

### 4. 验证输出

```bash
# 检查输出目录 — 预期包含外部消息处理函数入口的分析报告
ls -la {working_dir}/docker_output/

# 列出所有报告文件
find {working_dir}/docker_output/ -type f -name "*.md" -o -name "*.json" -o -name "*.txt" | sort
```

确认输出目录包含函数入口分析报告。
