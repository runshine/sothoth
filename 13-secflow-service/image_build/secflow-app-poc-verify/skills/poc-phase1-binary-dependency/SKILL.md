---
name: poc-phase1-binary-dependency
description: Phase 1 of POC dynamic verification — analyze source code to trace the call chain from entry function to vulnerability function, then map every function onto actual ELF binaries in the firmware directory, resolving addresses and shared library dependencies. Use when the user needs to determine which binary files are needed for a vulnerability path, identify firmware architecture, or map a source-level call chain to binary artifacts.
---

# Phase 1: Binary Dependency Analysis

From an entry function name and a vulnerability report, trace the source-level call chain, then map each function to its binary and address.

## Input

The working directory contains `phase1_input.json`:

```json
{
  "vuln_report": "/abs/path/to/vulnerability-report.md",
  "entry_function": "main",
  "source_dir": "/abs/path/to/source/",
  "binary_dir": "/abs/path/to/binaries/",
  "output_dir": "/abs/path/to/output/"
}
```

## Task

Produce `<output_dir>/binary_dependency_map.json` containing the complete call chain with binary mappings and all required dependencies.

## Procedure

### Step 1: Parse the vulnerability report

Read `<vuln_report>`. Extract:
- **vuln_function**: the vulnerability function name
- **vuln_file**: the source file containing the vulnerability (e.g. `httpd/handler.c`)
- **vuln_line**: line number if present
- **vuln_address**: binary address if present
- **vuln_type**: vulnerability type (buffer overflow, etc.)

The report may be Markdown or JSON. For Markdown, look for `**漏洞函数**`, `**漏洞文件**`, `**漏洞地址**`, `**漏洞类型**`. For JSON, read `vuln_function.name / .file / .address`, `type`.

### Step 2: Trace the call chain from source

Starting from the entry function (e.g. `main`), trace **every function call** that leads to the vulnerability function by analyzing the source code in `<source_dir>`.

How to trace:

1. Find the source file containing the entry function (search recursively under `<source_dir>` for a definition like `void main(` or `int main(`).

2. Read the source file. Identify every function called by the entry function. Record them in order.

3. For each called function, repeat: find its definition, identify what it calls. Continue until the vulnerability function is reached.

4. Stop criteria:
   - The vulnerability function is reached → collect the full path
   - A dead end (no calls toward vuln) → backtrack and try other branches
   - External library calls (`printf`, `malloc`, `strcpy`) → skip (they don't lead to the vuln)

5. Output format — a deduplicated ordered list of functions:

```json
[
  {"function": "main", "file": "httpd/main.c"},
  {"function": "init_server", "file": "httpd/server.c", "caller": "main"},
  {"function": "handle_connection", "file": "httpd/server.c", "caller": "init_server"},
  {"function": "parse_http", "file": "httpd/parser.c", "caller": "handle_connection"},
  {"function": "process_request", "file": "httpd/handler.c", "caller": "parse_http"}
]
```

The first entry is always the entry function. The last entry is always the vulnerability function. The entry function has no `caller` field.

### Step 3: Enumerate ELF binaries

Scan `<binary_dir>` recursively for ELF files. A file is ELF if its first 4 bytes are `\x7fELF`.

```bash
find <binary_dir> -type f -not -type l -exec sh -c 'readelf -h "$1" > /dev/null 2>&1 && echo "$1"' _ {} \;
```

### Step 4: Analyze each binary

For each ELF file, run:

```bash
file -b <binary_path>                      # → architecture, kind
readelf -h <binary_path>                   # → endianness, entry point
readelf -s --dyn-syms <binary_path>        # → exported symbols
readelf -d <binary_path>                   # → NEEDED .so dependencies
nm -D <binary_path>                        # → fallback symbol lookup
```

**Architecture mapping** (from `file` output):
| Pattern | Value |
|---------|-------|
| `ARM aarch64` | `aarch64` |
| `ARM` | `arm` |
| `x86-64` | `x86_64` |
| `Intel 80386` | `x86` |
| `MIPS64` | `mips64` |
| `MIPS` | `mips` |

**Kind**: `shared object` → `shared_library`, `executable` → `executable`, `.ko` → `kernel_module`

**Endianness** from `readelf -h` Data field: `little` or `big`.

**Symbols**: from `readelf -s --dyn-syms`, extract function names (the rightmost column of lines with FUNC type). Skip `@@` entries.

**Dependencies**: from `readelf -d`, every `(NEEDED) Shared library: [name]`.

**Address lookup** with `nm -D`:
```bash
nm -D <binary> | grep " T <func_name>$"
```
The address is the first hex column, formatted as `"0x<hex>"`.

### Step 5: Match functions to binaries

For each function in the call chain:

1. **Exact match**: function name equals symbol name → resolved
2. **Substring match**: function name appears inside symbol name (C++ mangling) → resolved
3. **Not found**: mark as `missing_functions`

Prefer symbols from `executable` files over `shared_library` files when a function appears in multiple binaries.

### Step 6: Collect shared library dependencies

For every binary that contains a call chain function, recursively follow its `NEEDED` entries:

1. Look up each `.so` name anywhere under `<binary_dir>`
2. Add the `.so` to the required list
3. Repeat for that `.so`'s own dependencies

This ensures Qiling has every library needed at load time.

### Step 7: Determine architecture

Count architectures across all analyzed binaries. The most common (excluding "unknown") is the firmware architecture. If tied, prefer the architecture of the binary containing the entry function.

### Step 8: Write the output

Write `<output_dir>/binary_dependency_map.json`:

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

**Important:** All paths in `required_binaries` MUST be absolute (use `realpath`). Qiling requires absolute paths.
