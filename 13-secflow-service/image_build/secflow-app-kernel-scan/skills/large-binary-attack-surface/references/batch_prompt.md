# 每批分析 Prompt 模板

处理 `batches/batch_XXX.jsonl` 时使用。一次只处理**一个 batch**，不要跨 batch。

## 模型每批的输入

- `batches/batch_XXX.jsonl` 这批要分析的候选
- 对每个候选：
  - `ida_out/<safe_name>.c`（如果有 IDA 输出）
  - `ida_out/<safe_name>.xrefs`（调用者列表）
  - 必要时查 `strings.txt` / `relocs.txt` 做交叉引用

## 每批必须输出

**1. 分析内容（写到 `analysis/batch_XXX.md`）**

对每个候选符号，逐条给出：

- 入口名 / 地址 / tier
- **真实入口判断**：是/否；若否，说明为什么（内部函数、debug、dead code、仅 init 调用）
- 若是真实入口：
  - 触发方式：ioctl / read / netlink / socket / binder / JNI 调用 / 外部命令
  - 相关节点名 / 服务名 / 协议号 / 命令字（从 xref 的字符串和调用上下文反推）
  - 入参来源：是否含用户态可控数据
  - 权限要求初判：需要 root / system / 普通 app / shell
  - 是否值得继续挖（高/中/低），并说明原因

**2. 回执（追加写到 `receipts.jsonl`，一行 JSON）**

```json
{
  "batch": "batch_003.jsonl",
  "processed": ["sym_a", "sym_b", "sym_c"],
  "skipped":   [{"name": "sym_d", "reason": "tier3 name-only, looks like __static helper"}],
  "error":     [{"name": "sym_e", "reason": "decompile empty, need manual"}]
}
```

**回执硬约束**：
- `processed + skipped + error` 的并集必须等于该 batch 的所有符号
- 任何遗漏 = `verify_coverage.py` 拒绝打报告

## 判定规则（避免误判）

判**真实入口**：
- 被 fops/ops 结构体、驱动注册表、JNI table、service table 等引用
- 或处理外部可控数据（ioctl buffer、netlink payload、binder parcel、socket recv、JNI 参数）
- 或通过路径/服务名可达（`/dev/xxx`、`ohos.*.service`、`android.hardware.*`）

判**非入口**（skip 理由要具体，不能只写 "internal"）：
- 仅 `init_module` / `module_init` / static constructor 内部调用
- 数据转换、格式化、日志等纯工具函数
- Debug/einj/test/内部自检路径（名字里含 `debug`/`test`/`dbg`/`einj`/`_selftest`）
- Stub / 空函数 / 仅返回常量

## 单批处理建议

- **批大小 40 个符号**左右最稳。太大模型会偷懒只看前几个；太小开销大。
- 先看 `tier1` 批，再 `tier2`，最后 `tier3`。
- 每批结束立刻写 receipt，**不要批量最后再写**——中途断了就全丢。
- 发现高价值入口，直接写到汇总文件 `hits.jsonl`，最后再去重。

## 汇总阶段

所有批次 `missing == 0` 后：

1. 聚合 `analysis/batch_*.md` 里判定为**真实入口**的条目到最终报告
2. 按攻击面类别（ioctl / netlink / binder / socket / procfs / service / jni / 厂商定制）分组
3. 每类内部按"是否可达"、"是否厂商定制"排序
4. 厂商定制放报告前面，通用接口放后面
5. 输出到 `./AI4Vul/AS_<binary>_<model>_<time>.md`
