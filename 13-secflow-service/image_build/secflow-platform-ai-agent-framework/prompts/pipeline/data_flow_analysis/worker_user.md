## 任务描述

{task}

---

## 执行步骤

### 1. 解析任务参数

从上方任务描述中找到：
- **输入文件夹路径**（包含一个外部消息处理函数入口的分析报告）
- **反编译源码目录**（从上下文信息中获取，需要传递给下游）
- **函数名称**
- **模块名称**
- 默认输出路径：`{working_dir}/docker_output`

### 2. 准备环境

```bash
mkdir -p {working_dir}/docker_output

# 确认输入路径存在
ls -la <INPUT_DIR>

# 确认反编译源码目录可访问
ls <DECOMPILED_SOURCE_DIR> | head -20
```

### 3. 执行 Docker 数据流分析命令

> ⚠️ **TODO**: 请将下方命令替换为同事提供的实际 Docker 镜像名称和命令参数
> 注意：数据流分析可能同时需要函数入口报告和反编译源码目录作为输入

```bash
docker run --rm \
  -v <INPUT_DIR>:/data/input:ro \
  -v <DECOMPILED_SOURCE_DIR>:/data/source:ro \
  -v {working_dir}/docker_output:/data/output \
  secflow/dataflow-analyzer:latest \
  --input /data/input --source /data/source --output /data/output
```

### 4. 验证输出

```bash
# 检查输出目录 — 预期包含数据流分析结果
ls -la {working_dir}/docker_output/

# 列出分析结果文件
find {working_dir}/docker_output/ -type f | sort
```

确认输出目录包含数据流分析结果文件。
