---
name: poc-dynamic-verify
description: 根据漏洞报告、入口函数分析、数据流报告、源码和固件解包后的 binary 文件目录，定位漏洞所在 binary 并生成 Qiling Framework 动态仿真脚本，从入口函数模拟执行到漏洞点，验证漏洞是否真实可达。当需要对数据流漏洞扫描结果进行 PoC 动态验证、二进制仿真验证时使用本 skill。
---

# PoC 动态验证 Skill

对静态分析发现的漏洞进行动态仿真验证，确定从入口函数到漏洞函数的执行路径是否真实可达。

## 输入

工作目录下必须存在以下文件/目录：

| 输入 | 路径 | 说明 |
|------|------|------|
| 漏洞报告 | `vulnerability-report.md` | 包含漏洞函数、漏洞点、漏洞类型、触发条件 |
| 入口函数列表 | `entry-list.json` | 入口分析产出的入口函数列表 |
| 数据流报告 | `dataflow-report.md` | 完整的数据流路径报告 |
| 源码目录 | `source/` | 漏洞相关源码 |
| Binary 目录 | `binaries/` | 固件解包后的所有 binary 文件 |

## 工作流

### Phase 1: 二进制依赖分析 (Binary Dependency Analysis)

**目标：** 确定从入口函数到漏洞函数需要哪些 binary 文件。

1. 读取 `vulnerability-report.md`，提取：
   - 漏洞函数名、所在源文件、行号
   - 漏洞类型和触发条件
   - 相关的 taint 参数

2. 读取 `entry-list.json`，提取入口函数列表：
   - 每个入口函数的函数名、所在文件、tag 标记
   - 确认哪些入口函数可能通向漏洞函数

3. 读取 `dataflow-report.md`，提取：
   - 从入口函数到漏洞函数的完整调用链
   - 每个调用步骤中的函数名、所在文件、所属模块
   - 数据流中的 taint 参数传递路径

4. 探索 `binaries/` 目录，确定 binary 文件：
   - 列出所有 binary 文件
   - 用 `file` 命令识别每个 binary 的架构 (ARM/MIPS/x86/...)
   - 用 `readelf -s` 或 `objdump -T` 查找其中包含的函数符号
   - 将调用链中的函数与 binary 文件进行匹配

5. 输出 `binary_dependency_map.json`：

```json
{
  "entry_function": {
    "name": "main",
    "file": "main.c",
    "binary": "binaries/usr/sbin/example",
    "address": "0x401000"
  },
  "vuln_function": {
    "name": "vuln_handler",
    "file": "vuln.c",
    "binary": "binaries/usr/sbin/example",
    "address": "0x403000",
    "line": 156
  },
  "call_chain": [
    {"function": "main", "binary": "usr/sbin/example", "caller": null},
    {"function": "parse_request", "binary": "usr/sbin/example", "caller": "main"},
    {"function": "vuln_handler", "binary": "usr/sbin/example", "caller": "parse_request"}
  ],
  "required_binaries": [
    "binaries/usr/sbin/example",
    "binaries/lib/libc.so.0",
    "binaries/lib/libnvram.so"
  ]
}
```

### Phase 2: 动态仿真 (Qiling Emulation)

**目标：** 使用 Qiling Framework 模拟从入口函数到漏洞函数的真实执行过程。

#### 核心原则

1. **不要 hook/patch/假装执行任何真实执行路径上的函数。** 每个函数都必须真实执行。
2. 如果遇到硬性条件不满足导致无法模拟，可以 patch 略过，但**必须记录**：
   - patch 的地址和函数名
   - 原因分类（见下表）
   - 具体的绕过方式

#### Patch 原因分级

| 级别 | 含义 | 示例 |
|------|------|------|
| `HARD_BLOCK` | 硬件依赖，绝对无法模拟 | MMIO 寄存器读写、硬件 DMA 操作 |
| `ENV_MISSING` | 环境缺失（文件/配置不存在） | 缺少 `/etc/config.xml`、NVRAM 分区 |
| `TIMING` | 时序/并发相关 | `usleep()`、`nanosleep()` 等 |
| `NETWORK` | 网络 I/O 依赖 | `recv()` 等待外部数据、socket connect |
| `CRYPTO` | 加密/解密操作 | 硬件加解密引擎不可用 |

#### 分支条件记录

执行路径上的每个分支判断条件都必须记录：

```json
{
  "address": "0x401234",
  "condition": "if (arg1 == 0xdead)",
  "actual_value": "0xdead",
  "taken": true,
  "source": "from code analysis"
}
```

#### 执行步骤

1. **确定 binary 架构**：
   ```bash
   file <binary_path>
   readelf -h <binary_path>  # 查看 ELF 头
   ```

2. **创建仿真脚本** `emulation_script.py`：
   ```python
   from qiling import Qiling
   from qiling.const import QL_VERBOSE
   
   def my_hook(ql):
       # 记录执行路径
       pass
   
   # 初始化 Qiling
   ql = Qiling(
       ["binaries/usr/sbin/example"],
       "binaries/",  # rootfs 目录
       verbose=QL_VERBOSE.DEBUG
   )
   
   # 设置 hook 点
   base = ql.mem.get_lib_base("binaries/usr/sbin/example")
   ql.hook_address(my_hook, base + 0x403000)  # 漏洞函数入口
   
   # 运行
   ql.run()
   ```

3. **执行仿真并记录**：
   - 每个函数调用和返回
   - 每个分支决策
   - 每个 patch 操作
   - 最终是否到达漏洞点

4. **遇到阻塞时的处理流程**：
   a. 分析阻塞原因（硬件/环境/时序/网络）
   b. 确定最小化 patch 方案
   c. 实现 patch 并记录到 `patch_log.json`
   d. 继续执行

5. **输出产物**：

   - `poc_result.json`：
     ```json
     {
       "status": "verified" | "unreachable" | "partial" | "error",
       "vuln_function": "vuln_handler",
       "entry_function": "main",
       "execution_depth": 1042,
       "reach_vuln_point": true,
       "vuln_trigger_confirmed": false,
       "vuln_trigger_reason": "需要特定输入值触发",
       "total_patches": 3,
       "branch_decisions": [...]
     }
     ```

   - `execution_trace.json`：
     ```json
     {
       "trace": [
         {"address": "0x401000", "function": "main", "event": "call"},
         {"address": "0x401234", "function": "main", "event": "branch", "condition": "arg1 == 0", "taken": false},
         {"address": "0x401100", "function": "parse_request", "event": "call"},
         ...
       ]
     }
     ```

   - `patch_log.json`：
     ```json
     {
       "patches": [
         {
           "address": "0x402000",
           "function": "nvram_get",
           "reason": "ENV_MISSING",
           "detail": "NVRAM 分区文件不存在，返回模拟值",
           "patch_type": "return_value_override",
           "return_value": "0x0"
         }
       ]
     }
     ```

   - `emulation_script.py`：可复现的完整仿真脚本

## 输出格式

在 `poc_result.md` 中给出最终摘要：

```markdown
# PoC 动态验证报告

## 基本信息
- 漏洞函数: vuln_handler
- 入口函数: main
- 目标 Binary: usr/sbin/example
- Binary 架构: ARM 32-bit

## 验证结果
- 状态: verified / unreachable / partial / error
- 是否到达漏洞点: 是 / 否
- 是否确认触发漏洞: 是 / 否

## 执行摘要
- 总执行指令数: 1042
- 函数调用深度: 5
- 应用的 Patch 数: 3
- 记录的分支条件: 5

## Patch 列表
| 地址 | 函数 | 原因 | 说明 |
|------|------|------|------|
| 0x402000 | nvram_get | ENV_MISSING | NVRAM 分区不可用 |
| 0x402100 | usleep | TIMING | 跳过等待 |
| 0x402200 | hw_crypto | HARD_BLOCK | 硬件加解密不可用 |

## 分支条件
| 地址 | 条件 | 实际值 | 分支 |
|------|------|--------|------|
| 0x401234 | arg1 == 0 | 0 | 未跳转 |
| 0x401300 | arg2 > 0x10 | 0x20 | 跳转 |

## 结论
[详细说明验证结论]
```

## 注意事项

- 优先使用 Qiling Framework 而非裸 Unicorn，因为 Qiling 能处理 ELF 加载、动态链接和 syscall 模拟
- 如果 binary 使用了 Qiling 不支持的 syscall，记录为 HARD_BLOCK
- 仿真脚本应保持可读性和可维护性，便于人工审查
- 所有 patch 必须有明确理由，不可随意跳过函数
- 分支条件应尽可能从实际执行中获取真实值