---
name: poc-phase1-binary-dependency
description: (内部) PoC 动态验证的第一阶段 — 解析漏洞报告,追踪源码调用链,把每个函数映射到固件目录里的 ELF 二进制,解析地址与共享库依赖。请勿直接调用,改用 poc-verify-pipeline。
disable-model-invocation: true
---

# 阶段一：二进制依赖分析

根据入口函数名和漏洞报告,追踪源码级调用链,然后把每个函数映射到对应的 binary 与地址。

**本 Skill 由 `poc-verify-pipeline` 主控在内部调用,完成后必须把控制权交还主控,不要自行进入阶段二。**

## 与流水线的集成

开始前,读取 `.pipeline_state.json` 校验 `current_stage` 应为 `"phase1_binary_dependency"`,若已是 `"FAILED"` 或 `"COMPLETED"`,立即终止。

从 `.pipeline_state.json` 读取输入参数:`vuln_report`、`entry_function`、`source_dir`、`binary_dir`、`output_dir`。若这些字段为空,退回读取输出目录中的 `phase1_input.json`。

完成后,把 `.pipeline_state.json` 的 `current_stage` 改为 `"phase2_qiling_emulation"`,并输出信号:"阶段一完成 — binary_dependency_map.json 已生成"。

## 输入

工作目录中存在 `phase1_input.json`:

```json
{
  "vuln_report": "/abs/path/to/vulnerability-report.md",
  "entry_function": "main",
  "source_dir": "/abs/path/to/source/",
  "binary_dir": "/abs/path/to/binaries/",
  "output_dir": "/abs/path/to/output/"
}
```

## 任务

产出 `<output_dir>/binary_dependency_map.json`,其中包含完整的调用链、binary 映射以及所有依赖。

## 执行流程

### 步骤 1: 解析漏洞报告

读取 `<vuln_report>`,抽取以下字段:

- **vuln_function**:漏洞函数名
- **vuln_file**:漏洞所在源文件(如 `httpd/handler.c`)
- **vuln_line**:行号(如有)
- **vuln_address**:二进制地址(如有)
- **vuln_type**:漏洞类型(缓冲区溢出等)

报告可能为 Markdown 或 JSON 格式。Markdown 中请查找 `**漏洞函数**`、`**漏洞文件**`、`**漏洞地址**`、`**漏洞类型**`;JSON 中请读取 `vuln_function.name / .file / .address`、`type`。

### 步骤 2: 从源码追踪调用链

从入口函数(例如 `main`)出发,分析 `<source_dir>` 中的源码,**追踪每一条**通向漏洞函数的函数调用。

追踪方法:

1. 在 `<source_dir>` 中递归查找入口函数定义(形如 `void main(` 或 `int main(`)。
2. 读取该源文件,识别入口函数调用的所有函数,按调用顺序记录。
3. 对每一个被调用的函数,递归执行:定位其定义,识别它又调用了哪些函数。一直追踪到漏洞函数。
4. 终止条件:
   - 已到达漏洞函数 → 收集完整路径
   - 死胡同(没有通向漏洞的调用) → 回溯,尝试其他分支
   - 外部库调用(`printf`、`malloc`、`strcpy` 等) → 跳过(它们不会通向漏洞)
5. 输出格式:去重且有序的函数列表:

```json
[
  {"function": "main", "file": "httpd/main.c"},
  {"function": "init_server", "file": "httpd/server.c", "caller": "main"},
  {"function": "handle_connection", "file": "httpd/server.c", "caller": "init_server"},
  {"function": "parse_http", "file": "httpd/parser.c", "caller": "handle_connection"},
  {"function": "process_request", "file": "httpd/handler.c", "caller": "parse_http"}
]
```

首条记录必为入口函数,末条必为漏洞函数。入口函数没有 `caller` 字段。

### 步骤 3: 枚举 ELF 二进制

递归扫描 `<binary_dir>`,前 4 字节为 `\x7fELF` 的即为 ELF 文件:

```bash
find <binary_dir> -type f -not -type l -exec sh -c 'readelf -h "$1" > /dev/null 2>&1 && echo "$1"' _ {} \;
```

### 步骤 4: 分析每个 binary

对每个 ELF 文件,执行:

```bash
file -b <binary_path>                      # → 架构、类型
readelf -h <binary_path>                   # → 字节序、入口点
readelf -s --dyn-syms <binary_path>        # → 导出符号
readelf -d <binary_path>                   # → NEEDED .so 依赖
nm -D <binary_path>                        # → 符号备查
```

**架构映射**(从 `file` 输出):

| 模式 | 取值 |
|------|------|
| `ARM aarch64` | `aarch64` |
| `ARM` | `arm` |
| `x86-64` | `x86_64` |
| `Intel 80386` | `x86` |
| `MIPS64` | `mips64` |
| `MIPS` | `mips` |

**类型**:`shared object` → `shared_library`,`executable` → `executable`,`.ko` → `kernel_module`

**字节序**:从 `readelf -h` Data 字段读取:`little` 或 `big`。

**符号**:从 `readelf -s --dyn-syms` 抽取类型为 FUNC 的函数名(最右列)。跳过 `@@` 项。

**依赖**:从 `readelf -d` 中所有 `(NEEDED) Shared library: [name]`。

**地址查询**用 `nm -D`:

```bash
nm -D <binary> | grep " T <func_name>$"
```

第一列十六进制数,格式化为 `"0x<hex>"`。

### 步骤 5: 把函数匹配到 binary

对调用链中的每个函数:

1. **精确匹配**:函数名等于符号名 → 已解析
2. **子串匹配**:函数名出现在符号名内(C++ 名字修饰) → 已解析
3. **未找到**:标记为 `missing_functions`

若同一函数出现在多个 binary 中,优先 `executable` 而非 `shared_library`。

### 步骤 6: 收集共享库依赖

对包含调用链函数的每个 binary,递归跟踪其 `NEEDED` 项:

1. 在 `<binary_dir>` 任意位置查找每个 `.so` 文件
2. 把 `.so` 加入必需列表
3. 对该 `.so` 自身的依赖,重复同样过程

这能保证 Qiling 加载时所有库都已就位。

### 步骤 7: 确定架构

统计所有已分析 binary 的架构,出现次数最多的(排除 "unknown")即为固件架构。若并列,优先取包含入口函数的那个 binary 的架构。

### 步骤 8: 写出结果

写入 `<output_dir>/binary_dependency_map.json`:

```json
{
  "entry_function": "main",
  "vuln_function": {
    "name": "process_request",
    "file": "httpd/handler.c",
    "line": 156,
    "address": "0x403000"
  },
  "call_chain": [
    {"function": "main",           "binary": "usr/sbin/httpd", "address": "0x401000", "caller": null},
    {"function": "init_server",    "binary": "usr/sbin/httpd", "address": "0x401200", "caller": "main"},
    {"function": "handle_connection","binary": "usr/sbin/httpd", "address": "0x402000", "caller": "init_server"},
    {"function": "parse_http",     "binary": "usr/sbin/httpd", "address": "0x402500", "caller": "handle_connection"},
    {"function": "process_request","binary": "usr/sbin/httpd", "address": "0x403000", "caller": "parse_http"}
  ],
  "required_binaries": [
    {"path": "/abs/path/binaries/usr/sbin/httpd", "arch": "arm", "kind": "executable", "endian": "little", "dependencies": ["libc.so.0", "libnvram.so"]},
    {"path": "/abs/path/binaries/lib/libc.so.0", "arch": "arm", "kind": "shared_library", "endian": "little", "dependencies": []},
    {"path": "/abs/path/binaries/lib/libnvram.so", "arch": "arm", "kind": "shared_library", "endian": "little", "dependencies": ["libc.so.0"]}
  ],
  "missing_functions": [],
  "architecture": "arm"
}
```

**重要**:`required_binaries` 中所有路径必须为绝对路径(用 `realpath`)。Qiling 要求绝对路径。

## 完成动作

完成输出文件后:

1. 更新 `.pipeline_state.json`,把 `current_stage` 设为 `"phase2_qiling_emulation"`
2. 输出:"阶段一完成 — binary_dependency_map.json 已生成"
3. **不要自行进入阶段二或读取其他 Skill**,把控制权交还 Master。
