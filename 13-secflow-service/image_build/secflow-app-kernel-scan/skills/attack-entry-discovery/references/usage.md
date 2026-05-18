# 用法示例

## 典型提示词

```text
使用 $attack-entry-discovery 对 kernel 目录的所有文件做全量攻击入口梳理。
```

```text
使用 $attack-entry-discovery 对 AI4EXP/kernel_files/vmlinux.elf 做攻击入口分析，按注册点、ops 结构体、handler 的链路恢复真实入口。
```

## 典型命令

初始化一次全量运行：

```bash
python3 scripts/completeness_guard.py init \
  --root /path/to/tree \
  --run-dir ./scanner/full_run_attack_surface \
  --batch-size 200
```

查看当前覆盖率：

```bash
python3 scripts/completeness_guard.py status \
  --run-dir ./scanner/full_run_attack_surface \
  --show-missing 10
```

处理完第 1 批后标记：

```bash
python3 scripts/completeness_guard.py mark-batch \
  --run-dir ./scanner/full_run_attack_surface \
  --batch-id 1 \
  --status processed
```

把不适用文件显式标记为跳过：

```bash
python3 scripts/completeness_guard.py mark-file \
  --run-dir ./scanner/full_run_attack_surface \
  --status skipped \
  --reason "not_source_code_for_target_skill" \
  --path ./README.md
```

最终验收：

```bash
python3 scripts/completeness_guard.py verify \
  --run-dir ./scanner/full_run_attack_surface \
  --show-missing 20
```

## 结果判定

- `missing == 0`：可以宣称“所有文件都已处理”
- `missing > 0`：不能结束任务
- `error > 0`：可以结束，但必须明确哪些文件处理失败
