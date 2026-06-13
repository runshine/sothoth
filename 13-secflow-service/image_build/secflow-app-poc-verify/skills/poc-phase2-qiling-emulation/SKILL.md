---
name: poc-phase2-qiling-emulation
description: (内部) PoC 动态验证的第二阶段 — 依据漏洞报告生成 PoC,并在 Qiling 仿真环境中动态执行,验证漏洞是否真实可达、可触发。请勿直接调用,改用 poc-verify-pipeline。
disable-model-invocation: true
---

# 阶段二:PoC 生成与动态验证

本阶段承担**两个核心角色**:

1. **PoC 生成 (PoC Generation)** —— 依据漏洞报告和阶段一的调用链,生成一段能触发该漏洞的输入/操作序列(可以是原始 payload、HTTP 请求、命令行参数、文件内容等,具体形式取决于漏洞类型)。
2. **动态验证 (Dynamic Verification)** —— 把 PoC 喂给固件 binary,通过 Qiling Framework 实际执行调用链,**确认漏洞在运行时是否真实可达、可触发**。

**仿真脚本本身只是 PoC 验证的运行环境,不是本阶段的交付物**;真正的交付物是 `poc_result.json` 中的 `status: "reachable"` 与触发证据。

**本 Skill 由 `poc-verify-pipeline` 主控在内部调用,完成后必须把控制权交还主控,不要自行进入阶段三。**

## 与流水线的集成

开始前,读取 `.pipeline_state.json` 校验 `current_stage` 应为 `"phase2_qiling_emulation"`,若已是 `"FAILED"` 或与期望不符,立即终止。

从 `.pipeline_state.json` 读取参数:`vuln_report`、`output_dir`、`binary_dir`、`rootfs`。阶段一产出的 `binary_dependency_map.json` 应位于 `<output_dir>/`。

完成后,把 `.pipeline_state.json` 的 `current_stage` 改为 `"phase3_verify_report"`,并输出信号:"阶段二完成 — poc_result.json 已生成"。

## 输入

- `vuln_report` — 漏洞报告,需解析其中的漏洞类型、触发条件、影响函数
- `binary_dependency_map.json` — 阶段一产出,提供调用链、架构、所有 binary 路径

`binary_dependency_map.json` 关键字段:

| 字段 | 含义 |
|------|------|
| `entry_function` | 入口函数名(例如 `"main"`) |
| `vuln_function.name` / `.address` | 漏洞函数及其二进制地址 |
| `call_chain[]` | 调用链上每个函数,含 `function`、`binary`、`address`、`caller` |
| `required_binaries[]` | 所需所有 binary,含 `path`(绝对)、`arch`、`kind`、`endian`、`dependencies` |
| `architecture` | `arm` / `aarch64` / `mips` / `x86` / `x86_64` |

## 核心原则

### 1. PoC 先行:基于漏洞报告生成可触发输入

在搭建任何仿真环境之前,**先从漏洞报告出发,推导 PoC 应该长什么样**。常见漏洞类型的 PoC 形态:

| 漏洞类型 | PoC 形态举例 |
|----------|--------------|
| 缓冲区溢出(`strcpy`/`sprintf`/`memcpy` 长度未校验) | 超长字符串/二进制块 |
| 命令注入 | 含 shell 元字符的输入(如 `; cat /etc/passwd`) |
| 路径穿越 | 含 `../` 的路径 |
| 整数溢出导致缓冲区过小 | 特定大数值参数 |
| 格式化字符串 | 含 `%s%s%s%n` 的字符串 |
| 反序列化 | 精心构造的字节流 |
| 鉴权绕过 | 缺失或伪造的鉴权头/cookie |
| 配置项触发 | 特定 NVRAM 键或环境变量值 |

PoC 生成步骤:

1. 通读漏洞报告,定位**触发条件**(什么样的输入会进入漏洞函数?输入从哪个 socket/文件/参数/环境变量进入?有没有长度/字符限制?)
2. 推导出**最小可触发输入**:在不关心真实协议的情况下,**先构造一个能进入漏洞调用链的输入占位**(在阶段三我们再精化为真实 payload)
3. 在 PoC 脚本中把这个输入作为"初始输入"或"测试输入"喂入 Qiling 仿真

### 2. 真实执行优先

调用链上**每一个**函数必须被 Qiling 实际执行。仿真脚本运行的是真实的 binary 指令,走 Qiling 的 CPU 模拟。除非绝对无法执行,**不要通过 hook-and-skip 跳过调用链上的任何函数**。

### 3. 仅在不可避免时打 patch

当 Qiling 无法执行某个函数(硬件依赖、缺环境、不支持的 syscall、网络 I/O)时,应用**最小化且有完整文档说明**的 patch。

### 4. 分支记录

执行路径上的**每一个**条件分支都要被记录:地址、反汇编指令、条件、实际值。

## Patch 等级表

| 等级 | 适用场景 | 默认返回值 |
|------|----------|------------|
| `HARD_BLOCK` | MMIO / DMA / 硬件加密 / IO 端口访问 | `0` 或 `-1` |
| `ENV_MISSING` | 缺配置文件、NVRAM 分区、`/proc` 条目 | `0` |
| `TIMING` | `sleep()`、`usleep()`、`nanosleep()` | `0` |
| `NETWORK` | `socket()`、`connect()`、`recv()`、`send()`、`accept()` | `-1` 或 mock 数据 |
| `CRYPTO` | `EVP_*`、硬件 AES/SHA 引擎 | `0` |
| `UNKNOWN_SYSCALL` | Qiling 查表未覆盖的 syscall | stub |

**禁止 patch 控制流关键函数**。若绕过某函数会改变分支走向,可达性结论将不可信。

## 执行流程

### 步骤 1:复查依赖图

读取 `binary_dependency_map.json`,确认:

- 架构(决定 QL_ARCH 常量)
- 主 binary(call_chain 或 required_binaries 中第一个 executable)
- 入口地址与漏洞地址
- 所有共享库依赖

### 步骤 2:确定 rootfs

若用户单独指定 `rootfs`,使用之;否则用 `binary_dir`。确保其下有 `lib/` 和 `usr/lib/`。

### 步骤 3:生成 PoC 并编写仿真脚本

**(a) PoC 数据准备**

在 `<output_dir>/poc_input/` 下生成 PoC 相关文件,具体形式由漏洞决定:

- 若是 HTTP/网络服务漏洞 → 写一份 `request.bin`(原始 HTTP 请求字节)或 `poc_payload.json` 描述请求
- 若是文件解析漏洞 → 写 `poc_file`(畸形文件)
- 若是 CLI 参数触发 → 写 `poc_args.txt` 列出参数
- 若是配置/NVRAM 触发 → 写 `poc_config.json`

**(b) 仿真脚本骨架**

写 `<output_dir>/emulate.py`,采用以下结构(关键:脚本要从 PoC 数据**回放**输入到被测 binary 的入口):

```python
from qiling import Qiling
from qiling.const import QL_ARCH, QL_INTERCEPT, QL_OS, QL_VERBOSE
import json

# ── Configuration (从 dep_map 读) ──
MAIN_BINARY = "/abs/path/to/main/binary"
ROOTFS      = "/abs/path/to/rootfs"
ARCH        = "arm"               # dep_map.architecture
ENTRY_ADDR  = 0x401000            # call_chain 第一个 entry 的 address
VULN_ADDR   = 0x403000            # vuln_function.address

# ── PoC 加载(从阶段(a)准备的输入) ──
with open("<output_dir>/poc_input/request.bin", "rb") as f:
    POC_INPUT = f.read()
# 或根据漏洞类型:从文件、命令行、stdin 注入

# ── 仿真状态 ──
patches   = []
branches  = []
instr_count = 0
reached   = False
error_msg = ""
poc_was_consumed = False   # PoC 是否被 binary 消费(进入处理路径)

# ── 分支检测 ──
COND_BR = {"je","jne","jz","jnz","ja","jb","jg","jl","jge","jle",
           "beq","bne","bcs","bcc","cbz","cbnz",
           "b.eq","b.ne","b.cs","b.cc","b.gt","b.le","tbz","tbnz",
           "beqz","bnez","blez","bgtz","bc1f","bc1t"}

def on_block(ql, addr, size):
    global instr_count, branches
    instr_count += 1
    try:
        md = ql.arch.disassembler
        if md:
            for insn in md.disasm(ql.mem.read(addr, size), addr):
                if insn.mnemonic.lower() in COND_BR:
                    branches.append({
                        "address": hex(insn.address),
                        "instruction": f"{insn.mnemonic} {insn.op_str}",
                        "condition": f"{insn.mnemonic} {insn.op_str}"
                    })
    except: pass

def on_entry(ql):
    print(f"[*] 入口: {hex(ql.arch.regs.arch_pc)}")

def on_vuln(ql):
    global reached
    reached = True
    print(f"[!!!] 已到达漏洞点: {hex(ql.arch.regs.arch_pc)}")
    ql.emu_stop()

# ── Patch handler ──
def handler(name, level, detail, retval):
    def h(ql):
        patches.append({"address": hex(ql.arch.regs.arch_pc), "function": name,
                        "level": level, "detail": detail, "return_value": retval})
        return int(retval, 16) if retval.startswith("0x") else int(retval)
    return h

# ── 初始化 Qiling ──
ARCH_MAP = {"arm": QL_ARCH.ARM, "aarch64": QL_ARCH.ARM64,
            "mips": QL_ARCH.MIPS, "x86": QL_ARCH.X86, "x86_64": QL_ARCH.X8664}

ql = Qiling([MAIN_BINARY], ROOTFS, archtype=ARCH_MAP[ARCH],
            ostype=QL_OS.LINUX, verbose=QL_VERBOSE.DEBUG)

ql.hook_block(on_block)
ql.hook_address(on_entry, ENTRY_ADDR)
ql.hook_address(on_vuln, VULN_ADDR)

# 注册已知问题函数
PATCHES = {
    "sleep": ("TIMING", "skip sleep", "0"),
    "usleep": ("TIMING", "skip usleep", "0"),
    "nanosleep": ("TIMING", "skip nanosleep", "0"),
    "nvram_get": ("ENV_MISSING", "NVRAM 不可用", "0"),
    "nvram_set": ("ENV_MISSING", "NVRAM 不可用", "0"),
    "nvram_match": ("ENV_MISSING", "NVRAM 不可用", "0"),
    "connect": ("NETWORK", "网络不可用", "-1"),
    "accept": ("NETWORK", "网络不可用", "-1"),
    "recv": ("NETWORK", "网络不可用", "-1"),
    "send": ("NETWORK", "网络不可用", "-1"),
    "socket": ("NETWORK", "网络不可用", "-1"),
}
for name, (lvl, det, rv) in PATCHES.items():
    try: ql.os.set_api(name, handler(name, lvl, det, rv), QL_INTERCEPT.ENTER)
    except: pass

# ── 注入 PoC(根据漏洞类型选择注入方式) ──
# 方式 1:从 stdin 注入(适合 CLI 工具类 binary)
# Qiling 默认就把 argv[0] 作为入口,可以用 hook 拦截 read() 把 PoC 数据返回
# 方式 2:从文件路径注入(把 PoC 写到 rootfs 下的目标路径,触发文件解析)
# 方式 3:从网络 socket 注入(hook accept/recv,把 PoC 当作收到的网络数据返回)

# ── 运行 ──
try:
    ql.run()
    if reached:
        status = "reachable"
    elif poc_was_consumed:
        status = "unreachable"   # PoC 进入了 binary,但漏洞函数没被触发
    else:
        status = "inconclusive"  # PoC 甚至没被消费
except Exception as e:
    status = "error"
    error_msg = str(e)

# ── 写出结果 ──
result = {
    "status": status,                 # reachable / unreachable / inconclusive / error
    "vuln_function": "<vuln_name>",
    "entry_function": "<entry_name>",
    "architecture": ARCH,
    "binary_name": MAIN_BINARY.split("/")[-1],
    "total_instructions": instr_count,
    "reach_vuln_point": reached,
    "poc_input_path": "<output_dir>/poc_input/...",
    "poc_was_consumed": poc_was_consumed,
    "patches": patches,
    "total_patches": len(patches),
    "branches": branches,
    "total_branches": len(branches),
    "error": error_msg
}
with open("<output_dir>/poc_result.json", "w") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)
with open("<output_dir>/patch_log.json", "w") as f:
    json.dump({"total": len(patches), "patches": patches}, f, indent=2, ensure_ascii=False)
with open("<output_dir>/branch_decisions.json", "w") as f:
    json.dump({"total": len(branches), "branches": branches}, f, indent=2, ensure_ascii=False)
```

**关键点**:

- `MAIN_BINARY` 与 `ROOTFS` 必须为绝对路径
- `ENTRY_ADDR` 与 `VULN_ADDR` 取自 dep_map 的 call_chain 与 vuln_function
- 把 `<vuln_name>`、`<entry_name>`、`<output_dir>` 替换为实际值
- **必须**把 PoC 数据注入到 binary 入口(通过 stdin/文件/socket),不是只把脚本写完就完事

### 步骤 4:运行仿真并迭代

```bash
cd <output_dir> && python3 emulate.py
```

若 Qiling 遇到未处理的障碍:

1. 从错误信息定位失败的函数
2. 用 Patch 等级表分类
3. 把新条目加入 `emulate.py` 的 `PATCHES` 字典
4. **重新运行**

**最大 patch 数:20**。超过 20 个不同函数被 patch,意味着该固件对硬件依赖过强,无法做有意义的仿真。

### 步骤 5:写 Markdown 报告

写 `<output_dir>/poc_result.md`:

```markdown
# PoC 动态验证报告

## 基本信息
| 项目 | 值 |
|------|-----|
| 漏洞函数 | `<vuln_func>` |
| 入口函数 | `<entry_func>` |
| 目标 Binary | `<binary_name>` |
| 架构 | `<arch>` |

## 验证结果
| 项目 | 值 |
|------|-----|
| 状态 | **<STATUS>** |
| 到达漏洞点 | ✅ 是 / ❌ 否 |
| 总执行指令 | `<instr_count>` |
| Patch 数 | `<patch_count>` |
| PoC 已被消费 | ✅ 是 / ❌ 否 |

## 调用链
(From dep_map — 每步:函数名、binary、地址)

## Patch 列表
| # | 地址 | 函数 | 等级 | 说明 |
|---|------|------|------|------|
(From patches list)

## 分支条件记录
(从 branches 列表编号列出)
```

### 步骤 6:校验输出

确保 4 个文件全部存在:

- `poc_result.json` — 合法 JSON
- `poc_result.md` — 可读报告
- `patch_log.json` — `{"total": N, "patches": [...]}`
- `branch_decisions.json` — `{"total": N, "branches": [...]}`

## 架构说明

- **ARM Thumb**:符号地址可能置位 bit 0,需去除:`addr & ~1`
- **MIPS 大端**:Qiling 默认小端,大端 binary 需传 `endian=QL_ENDIAN.EB`
- **x86/x86_64**:共享库须能在 `rootfs/lib/` 或 `LD_LIBRARY_PATH` 中找到

## 完成动作

校验 4 个输出文件均存在后:

1. 更新 `.pipeline_state.json`,把 `current_stage` 设为 `"phase3_verify_report"`
2. 输出:"阶段二完成 — poc_result.json 已生成"
3. **不要自行进入阶段三或读取其他 Skill**,把控制权交还 Master。
