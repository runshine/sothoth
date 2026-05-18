# binutils / IDA 命令速查

## 一、目标文件锁定

长流程易遇 cwd 漂移，开头固定绝对路径：

```bash
BIN=/absolute/path/to/libxxx.so   # 或 vmlinux / some.ko
RUN=/absolute/path/to/run-dir
```

## 二、快速画像

```bash
file "$BIN"
readelf -h "$BIN" | head -20
readelf -S "$BIN" | awk '{print $2,$3,$6,$7}' | head -30
readelf -d "$BIN" | head -40            # 动态依赖 + SONAME
readelf -n "$BIN"                       # build-id
size "$BIN"
```

## 三、符号导出

```bash
# 全量符号（含未导出）
nm --defined-only -S "$BIN" > "$RUN/nm_all.txt"

# 动态符号（外部可调用）
nm -D --defined-only -S "$BIN" > "$RUN/nm_dyn.txt"

# 带 bind/vis 信息（只有 readelf 有）
readelf --wide -s "$BIN" > "$RUN/readelf_syms.txt"

# GLOBAL FUNC 导出
grep ' FUNC ' "$RUN/readelf_syms.txt" | grep GLOBAL | grep DEFAULT | wc -l
```

## 四、字符串 + xref（不用 IDA 时的快速入口识别）

```bash
strings -n 6 "$BIN" > "$RUN/strings.txt"

# 反汇编全量（慢；大文件建议只对 .text 的子 section 做）
objdump -d --no-show-raw-insn "$BIN" > "$RUN/disasm.txt"

# 从反汇编中找字符串引用
grep -nE '/(dev|proc|sys|data)/[A-Za-z0-9_/.-]+' "$RUN/disasm.txt" > "$RUN/path_refs.txt"
grep -nE 'ohos\.|android\.hardware\.|com\.huawei\.' "$RUN/disasm.txt" > "$RUN/service_refs.txt"
```

## 五、按特征快速粗筛

```bash
# fops / ops 表
grep -E '(_fops|_ops|_operations):' "$RUN/readelf_syms.txt"

# ioctl / 系统调用
grep -E '(unlocked_ioctl|compat_ioctl|_ioctl$)' "$RUN/nm_dyn.txt"

# JNI
grep -E '^\S+ T (Java_|JNI_OnLoad)' "$RUN/nm_dyn.txt"

# genl / netlink
grep -E '(genl_ops|genl_family|netlink_kernel_create)' "$RUN/nm_all.txt"

# binder
grep -E '(onTransact|BnTransact|BpTransact)' "$RUN/nm_dyn.txt"
```

## 六、重定位 / 初始化向量

```bash
readelf -r "$BIN" | head -50                      # 重定位总览
objdump -R "$BIN" | head -50                      # 动态重定位
readelf -x .init_array "$BIN" 2>/dev/null          # 初始化函数表
readelf -x .fini_array "$BIN" 2>/dev/null
```

## 七、IDA Pro headless

> 前置：IDA 在 `$PATH` 或已知路径；`idat` 是不带 GUI 的 batch 版本。

```bash
# 第一次分析（生成 .i64）
idat -A -B "$BIN"                                 # auto + batch + exit

# 跑我们的脚本
idat -A -Lida.log \
     -S"<skill-dir>/scripts/ida_export_candidates.py $RUN" \
     "$BIN"

# 如果是 Apple Silicon，用 macOS 下带 -t 的命令行
/Applications/IDA\ Professional\ 9.0.app/Contents/MacOS/idat \
    -A -Lida.log \
    -S"..." "$BIN"
```

IDA 不可用时回退：只用 binutils + `objdump -d` 提取每个候选 ±200 字节的反汇编，喂给模型。

## 八、常见坑

- `readelf` 要加 `--wide` / `-W`，否则长符号名被截断
- macOS 自带 BSD `grep` 不支持 `-P`，用 `awk`/`sed` 替代
- `nm` 对 stripped 二进制没输出，要依赖 `readelf -s` 里的 `.dynsym`
- 大 `vmlinux` 的 `objdump -d` 输出可达 GB 级，按 section 分片：
  ```bash
  objdump -j .text -d "$BIN" > "$RUN/disasm_text.txt"
  objdump -j .init.text -d "$BIN" > "$RUN/disasm_init.txt"
  ```
- `terminal()` 和 `execute_code` 内部的 `terminal()` 都有 ~50KB 输出上限，全量 `nm` 要先重定向到文件再 grep
