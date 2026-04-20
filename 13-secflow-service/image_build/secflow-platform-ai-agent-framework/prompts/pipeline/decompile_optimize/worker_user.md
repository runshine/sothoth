## 任务描述

{task}

---

## 执行步骤

### 1. 解析任务参数

从上方任务描述中找到：
- **输入文件夹路径**（包含一个高危模块的二进制文件）
- **模块名称**
- 默认输出路径：`{working_dir}/docker_output`

### 2. 准备环境

```bash
mkdir -p {working_dir}/docker_output

# 确认输入路径存在，列出模块文件
ls -la <INPUT_DIR>
```

### 3. 执行 Docker 反编译优化命令

> ⚠️ **TODO**: 请将下方命令替换为同事提供的实际 Docker 镜像名称和命令参数

```bash
docker run --rm \
  -v <INPUT_DIR>:/data/input:ro \
  -v {working_dir}/docker_output:/data/output \
  secflow/decompile-optimizer:latest \
  --input /data/input --output /data/output
```

### 4. 验证输出

```bash
# 检查输出目录 — 预期包含优化后的反编译源码（.c/.h 等文件）
ls -la {working_dir}/docker_output/

# 统计源码文件
find {working_dir}/docker_output/ -type f \( -name "*.c" -o -name "*.h" -o -name "*.asm" \) | wc -l
```

确认输出目录包含优化后的反编译源码文件。
