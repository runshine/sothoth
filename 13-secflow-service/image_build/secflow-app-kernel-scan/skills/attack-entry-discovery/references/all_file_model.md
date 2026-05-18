# 全量模式（用户要求“所有文件”时强制启用）

这部分是**硬约束**。只要用户要求“所有文件”“全量”“整个目录”，必须先做这里，再开始正常的入口分析。

## 1. 先生成 manifest，再谈扫描

不要一边 grep 一边决定扫描范围。必须先冻结本次扫描快照：

```bash
python3 scripts/completeness_guard.py init \
  --root <target-root> \
  --run-dir <run-dir> \
  --batch-size 100
```

后续只能以 `<run-dir>/manifest.txt` 或 `<run-dir>/batches/batch_*.txt` 为输入源。
`<run-dir>`通常采用项目根目录。

## 2. 不要先按扩展名裁掉文件

默认不要因为“看起来不像 C 源码”就把文件排除在 manifest 之外。对内核源码，全量模式下至少要把以下文件先纳入 manifest：

- `.c` `.h` `.S` `.s`
- `.cpp` `.cc` `.hpp`

二进制需要分析：
- `.ko`, `.elf`, `.so`

如果某些文件最终不适合本 skill 深度分析，也要在回执里标记 `skipped` 并写明原因，不能静默忽略。

## 3. 必须按 batch 处理并落回执

每个一个batch都用调用者agent处理，每处理完一个 batch，立刻标记，**不要等全部处理完再标记**，**不要写python批直接修改result.jsonl文件**，**只能通过这个命令标记**：

```bash
python3 scripts/completeness_guard.py mark-batch \
  --run-dir <run-dir> \
  --batch-id <id> \
  --status processed
```

对不适用或处理失败的单文件，显式记录：

```bash
python3 scripts/completeness_guard.py mark-file \
  --run-dir <run-dir> \
  --status skipped \
  --reason "not_applicable_for_attack_entry_discovery" \
  --path ./path/to/file
```

或：

```bash
python3 scripts/completeness_guard.py mark-file \
  --run-dir <run-dir> \
  --status error \
  --reason "decode_failed" \
  --path ./path/to/file
```

允许的最终状态只有：

- `processed`
- `skipped`
- `error`

不允许存在“没有任何记录”的文件。

## 4. 结束前必须验收

最终必须执行如下命令：

```bash
python3 scripts/completeness_guard.py verify \
  --run-dir <run-dir> \
  --show-missing 20
```

只有同时满足以下条件，才可以说“全量处理完成”：

- `missing == 0`
- `processed + skipped + error == total`

如果 `missing > 0`，继续处理剩余 batch；如果因为环境限制做不完，必须明确说明“未完成”，并列出剩余文件或剩余 batch。

参考命令和判定方式见：`references/usage.md`