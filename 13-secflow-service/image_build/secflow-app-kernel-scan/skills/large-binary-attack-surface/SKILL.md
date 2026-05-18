---
name: large-binary-attack-surface
description: 针对 100M+、上万/数十万符号的大型 ELF（vmlinux、巨型 .so、大 daemon）做攻击入口全量分析。作为 attack-entry-discovery 的二进制子流程：用 manifest → 预过滤 → 分批 → 回执 → 覆盖率校验的确定性流水线，保证不漏扫，同时控制模型上下文。仅支持 ELF (Linux/Android/Harmony)。
---

# 大型二进制攻击入口分析

## 适用场景

当 attack-entry-discovery 进入二进制分析路径，且目标满足以下**任一**条件时，改走本 skill：

- 二进制大小 ≥ 50MB，或
- 导出符号 ≥ 3000，或
- `readelf -s | wc -l` ≥ 20000，或
- 明确是 `vmlinux` / 大型系统 daemon / 巨型厂商 `.so`

否则直接用 attack-entry-discovery 的 `references/binary_scan_sheet.md` 即可。

## 核心思想

**不让模型一次看完整个二进制。** 用确定性工具建立全量权威清单，模型只处理筛过的候选，每批强制产出回执，最后交叉校验没有漏扫。

流水线：

```
manifest (全量)  →  candidates (筛过的)  →  batches (分片)  →  receipts (回执)  →  verify (missing==0)  →  最终报告
```

详细见 `references/pipeline.md`。

## 标准执行顺序

必须按顺序执行，**不能跳过任何一步**：

### 1. 锁定目标 + 建 run-dir

```bash
BIN=/absolute/path/to/target       # 绝对路径，防 cwd 漂移
RUN=/absolute/path/to/run-XXXXX    # 一次分析一个目录
mkdir -p "$RUN"
```

### 2. 生成全量 manifest

```bash
bash <skill-dir>/scripts/build_manifest.sh "$BIN" "$RUN"
cat "$RUN/stats.json"
```

产出：`manifest.jsonl` (全符号)、`strings.txt`、`sections.txt`、`stats.json`。

### 3. 预过滤候选

```bash
python3 <skill-dir>/scripts/prefilter.py "$RUN"
cat "$RUN/prefilter_stats.json"
```

产出：`candidates.jsonl`（三档 tier），打印 by_tag 统计。
确认 tier1 命中数合理（几十到几百）。**太少说明正则没命中厂商特征，需要按目标调整 prefilter.py 里的 `ATTACK_PATTERNS`**。

### 4. 切分批次

```bash
python3 <skill-dir>/scripts/make_batches.py "$RUN" 40
```

### 5.（推荐）IDA headless 导出候选伪 C

有 IDA 时强烈推荐。没有 IDA 时跳过，模型只基于符号名 + strings + xrefs 判断，准确率会下降。

```bash
idat -A -Lida.log \
     -S"<skill-dir>/scripts/ida_export_candidates.py $RUN" \
     "$BIN"
```

### 6. 按批分析 + 写回执

对每个 `batches/batch_XXX.jsonl`：
- 读取该批所有符号的 `ida_out/<name>.c` 和 `.xrefs`
- 按 `references/batch_prompt.md` 的判定规则输出分析
- 处理完**立刻**追加一行到 `$RUN/receipts.jsonl`，不要攒到最后

每批 receipt 示例：

```json
{"batch":"batch_003.jsonl","processed":["a","b"],"skipped":[{"name":"c","reason":"static init only"}],"error":[]}
```

### 7. 覆盖率校验（硬门禁）

```bash
python3 <skill-dir>/scripts/verify_coverage.py "$RUN"
```

**`missing > 0` 时不得出最终报告。** 必须补处理漏掉的符号。


## 硬约束（和 attack-entry-discovery 一致）

- 厂商定制业务（`hw_*`、`huawei_*`、`vendor_*`、非标命令字/协议号）**排报告前面**
- 过滤 `einj`、`_debug_`、`_test_`、`_selftest` 等低价值接口
- 不能只列符号名，要讲清**怎么从用户态打进去**
- 无法确认的权限标注"需设备侧验证"，不要瞎猜

## 工具链回退矩阵

| 工具 | 有 | 没有 |
|---|---|---|
| IDA Pro | 走 `ida_export_candidates.py`，伪 C 质量最高 | 回退 binutils |
| binutils | 必须，流水线依赖 `readelf/nm/objdump/strings` | 无法进行 |
| Python3 | 必须，脚本需要 | 无法进行 |
| r2 / ghidra | 可选平替 IDA | 不影响 |

## 常见坑

- **cwd 漂移**：多步长流程里 shell cwd 会变，`$BIN`/`$RUN` 一律用绝对路径
- **terminal 输出截断 (~50KB)**：大 `nm`/`objdump` 输出必须先重定向到文件再 grep，不要直接把 `nm` 结果往 Python 里塞
- **只看导出符号**：内核 `vmlinux` 里很多入口是通过 ops 表注册，符号是 `LOCAL` 或 `HIDDEN`，但被全局表引用。prefilter 对 `type=FUNC, size>=32` 也会入 tier2，**不要改掉这条**
- **批太大模型偷懒**：一批 > 60 个符号时，模型通常只认真分析前 20 个，后面凑数。保持 40 附近
- **不写 receipt**：最大的坑。分析完一批**立刻**写 receipt，绝不批量最后写，中途断连或 context 压缩会丢状态
- **tier3 全跳**：可以接受，但必须在 receipt 里以 skipped 形式记录原因（比如 `tier3-bulk-skip: name-only match, low priority`），不能让 verify 失败
- **厂商正则没命中**：prefilter 默认 `ATTACK_PATTERNS` 是通用的，遇到具体厂商（海思 HW、高通 MSM、联发科 MTK 等）要临时加 pattern，比如 `(^hisi_|^msm_|^mtk_)`

## 与其他 skill 的配合

- **上游**：`attack-entry-discovery` 在二进制分支检测到大体量时委派到本 skill
- **覆盖率思路借鉴**：`all-files-completeness-guard`（本 skill 的符号级版）
- **下游**：
  - 入口可达性验证 → `entry-reachability-verification`
  - 普通 app 触达 → `app-jni-poc-verification`
  - 最小 PoC → `poc-verification`

## 参考文件

- `references/pipeline.md` — 流水线总览和产物说明
- `references/batch_prompt.md` — 每批分析 prompt 模板和判定规则
- `references/cheatsheet.md` — binutils / IDA 命令速查
- `scripts/build_manifest.sh` — 全量符号 manifest
- `scripts/prefilter.py` — 三档候选筛选
- `scripts/make_batches.py` — 分批
- `scripts/ida_export_candidates.py` — IDA headless 导出
- `scripts/verify_coverage.py` — 覆盖率硬校验
