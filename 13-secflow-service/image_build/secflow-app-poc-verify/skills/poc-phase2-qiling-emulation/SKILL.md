---
name: poc-phase2-qiling-emulation
description: Phase 2 of POC dynamic verification — write and execute a Qiling Framework emulation script that simulates firmware binary execution from entry function to vulnerability point, recording every branch decision and every unavoidable patch. Use when the user needs to dynamically verify whether a static analysis vulnerability path is actually reachable at runtime through binary emulation, or when a binary_dependency_map.json has been produced by Phase 1.
---

# Phase 2: Qiling Dynamic Emulation

Simulate execution from the entry function to the vulnerability point using Qiling. Determine whether the call path is truly reachable.

## Input

The user provides:
- Path to `binary_dependency_map.json` (Phase 1 output)
- Path to the binary directory
- Path to rootfs (optional, defaults to binary directory)
- Output directory

The `binary_dependency_map.json` contains:

| Field | Meaning |
|-------|---------|
| `entry_function` | Name of the entry function (e.g. `"main"`) |
| `vuln_function.name` / `.address` | Vulnerability function and its binary address |
| `call_chain[]` | Every function on the path with `function`, `binary`, `address`, `caller` |
| `required_binaries[]` | All binaries needed — `path` (absolute), `arch`, `kind`, `endian`, `dependencies` |
| `architecture` | `arm` / `aarch64` / `mips` / `x86` / `x86_64` |

## Core Principles

### 1. True Execution First

Every function on the call chain MUST be actually executed by Qiling. The emulation script runs the real binary instructions through Qiling's CPU emulation. Do not hook-and-skip any function on the path unless it is absolutely impossible to execute.

### 2. Patch Only When Unavoidable

When Qiling cannot execute a function (hardware dependency, missing environment, unsupported syscall, network I/O), apply a **minimal patch with full documentation**.

### 3. Branch Recording

Every conditional branch encountered on the execution path is recorded: address, disassembled instruction, condition, and actual values.

## Patch Level Table

| Level | When to apply | Default return |
|-------|--------------|----------------|
| `HARD_BLOCK` | MMIO / DMA / hardware crypto / IO port access | `0` or `-1` |
| `ENV_MISSING` | Missing config files, NVRAM partitions, `/proc` entries | `0` |
| `TIMING` | `sleep()`, `usleep()`, `nanosleep()` | `0` |
| `NETWORK` | `socket()`, `connect()`, `recv()`, `send()`, `accept()` | `-1` or mock data |
| `CRYPTO` | `EVP_*`, hardware AES/SHA engines | `0` |
| `UNKNOWN_SYSCALL` | Syscall number not in Qiling's table | stub |

**Do NOT patch functions that are critical to control flow.** If bypassing a function would change which branch is taken, the reachability analysis is invalid.

## Procedure

### Step 1: Review the dependency map

Read `binary_dependency_map.json`. Note:
- The architecture (determines which QL_ARCH constant to use)
- The main binary (first executable in `call_chain` or `required_binaries`)
- The entry and vulnerability addresses
- All shared library dependencies

### Step 2: Determine rootfs

If the user specified a separate `rootfs`, use it. Otherwise use the `binary_dir`. Check that it has `lib/` and `usr/lib/` for shared libraries.

### Step 3: Write the emulation script

Write `<output_dir>/emulate.py`. The script follows this structure:

```python
from qiling import Qiling
from qiling.const import QL_ARCH, QL_INTERCEPT, QL_OS, QL_VERBOSE
import json

# ── Configuration (from dep_map) ──
MAIN_BINARY = "/abs/path/to/main/binary"
ROOTFS = "/abs/path/to/rootfs"
ARCH = "arm"                    # from dep_map.architecture
ENTRY_ADDR = 0x401000           # first call_chain entry address
VULN_ADDR  = 0x403000           # vuln_function.address

# ── State ──
patches = []
branches = []
instr_count = 0
reached = False
error_msg = ""

# ── Branch detection ──
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
    print(f"[*] Entry: {hex(ql.arch.regs.arch_pc)}")

def on_vuln(ql):
    global reached
    reached = True
    print(f"[!!!] VULN POINT REACHED: {hex(ql.arch.regs.arch_pc)}")
    ql.emu_stop()

# ── Patch handlers ──
def handler(name, level, detail, retval):
    def h(ql):
        patches.append({"address": hex(ql.arch.regs.arch_pc), "function": name,
                        "level": level, "detail": detail, "return_value": retval})
        return int(retval, 16) if retval.startswith("0x") else int(retval)
    return h

# ── Init Qiling ──
ARCH_MAP = {"arm": QL_ARCH.ARM, "aarch64": QL_ARCH.ARM64,
            "mips": QL_ARCH.MIPS, "x86": QL_ARCH.X86, "x86_64": QL_ARCH.X8664}

ql = Qiling([MAIN_BINARY], ROOTFS, archtype=ARCH_MAP[ARCH],
            ostype=QL_OS.LINUX, verbose=QL_VERBOSE.DEBUG)

ql.hook_block(on_block)
ql.hook_address(on_entry, ENTRY_ADDR)
ql.hook_address(on_vuln, VULN_ADDR)

# Register known problematic functions
PATCHES = {
    "sleep": ("TIMING", "skip sleep", "0"),
    "usleep": ("TIMING", "skip usleep", "0"),
    "nanosleep": ("TIMING", "skip nanosleep", "0"),
    "nvram_get": ("ENV_MISSING", "NVRAM unavailable", "0"),
    "nvram_set": ("ENV_MISSING", "NVRAM unavailable", "0"),
    "nvram_match": ("ENV_MISSING", "NVRAM unavailable", "0"),
    "connect": ("NETWORK", "network unavailable", "-1"),
    "accept": ("NETWORK", "network unavailable", "-1"),
    "recv": ("NETWORK", "network unavailable", "-1"),
    "send": ("NETWORK", "network unavailable", "-1"),
    "socket": ("NETWORK", "network unavailable", "-1"),
}
for name, (lvl, det, rv) in PATCHES.items():
    try: ql.os.set_api(name, handler(name, lvl, det, rv), QL_INTERCEPT.ENTER)
    except: pass

# ── Run ──
try:
    ql.run()
    status = "reachable" if reached else "unreachable"
except Exception as e:
    status = "error"
    error_msg = str(e)

# ── Output ──
result = {
    "status": status,
    "vuln_function": "<vuln_name>",
    "entry_function": "<entry_name>",
    "architecture": ARCH,
    "binary_name": MAIN_BINARY.split("/")[-1],
    "total_instructions": instr_count,
    "reach_vuln_point": reached,
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

**Key points:**
- Use absolute paths for `MAIN_BINARY` and `ROOTFS`
- `ENTRY_ADDR` and `VULN_ADDR` come from `dep_map` call chain and vuln_function
- Fill in `<vuln_name>`, `<entry_name>`, `<output_dir>` from actual values
- Register hook_address for every function in the call chain (for logging)

### Step 4: Run the emulation

```bash
cd <output_dir> && python3 emulate.py
```

If Qiling hits an unhandled obstacle:
1. Identify the failing function from the error message
2. Classify it using the Patch Level table
3. Add a new entry to the `PATCHES` dict in `emulate.py`
4. Re-run

**Maximum patches:** 20. More than 20 distinct patched functions means the firmware is too hardware-dependent for meaningful emulation.

### Step 5: Write the Markdown report

Write `<output_dir>/poc_result.md`:

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

## 调用链
(From dep_map — each step: function name, binary, address)

## Patch 列表
| # | 地址 | 函数 | 级别 | 说明 |
|---|------|------|------|------|
(From patches list)

## 分支条件记录
(Numbered list from branches)
```

### Step 6: Verify outputs

Ensure all four files exist:
- `poc_result.json` — valid JSON
- `poc_result.md` — readable report
- `patch_log.json` — `{"total": N, "patches": [...]}`
- `branch_decisions.json` — `{"total": N, "branches": [...]}`

## Architecture notes

- **ARM Thumb**: symbol addresses may have bit 0 set. Strip it: `addr & ~1`
- **MIPS big-endian**: Qiling defaults to little-endian. Pass `endian=QL_ENDIAN.EB` in the constructor for big-endian binaries
- **x86/x86_64**: shared libraries must be findable under `rootfs/lib/` or via `LD_LIBRARY_PATH`
