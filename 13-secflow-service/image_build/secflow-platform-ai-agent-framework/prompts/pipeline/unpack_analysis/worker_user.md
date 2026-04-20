## 任务描述

{task}

---

## 执行步骤

### 1. 解析任务参数

从上方任务描述中找到以下关键信息：
- **输入文件夹路径**（包含待解包的产品软件包）
- 如果任务中未明确指定输出路径，默认输出到：`{working_dir}/docker_output`

### 2. 准备环境

```bash
# 确保输出目录存在
mkdir -p {working_dir}/docker_output

# 确认输入路径存在（替换 INPUT_DIR 为从任务描述中解析出的实际路径）
ls -la <INPUT_DIR>
```

### 3. 执行 Docker 解包命令

> ⚠️ **TODO**: 请将下方命令替换为同事提供的实际 Docker 镜像名称和命令参数

```bash
docker run --rm \
  -v <INPUT_DIR>:/data/input:ro \
  -v {working_dir}/docker_output:/data/output \
  secflow/unpack-analyzer:latest \
  --input /data/input --output /data/output
```

### 4. 验证输出

```bash
# 检查输出目录是否有内容
ls -la {working_dir}/docker_output/

# 统计输出文件数量
find {working_dir}/docker_output/ -type f | wc -l
```

确认输出目录包含解包后的文件和文件夹内容。如果输出为空，请报告错误。
