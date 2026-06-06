# 污点流: e

## 污点源
- `e` 🔴 TAINTED — 外部 CDI JSON 文件（`/etc/cdi`、`/var/cdi`）的内容经 `cdi_spec_parse_file()` 解析后注入

## 新导入的污点对象
- `edits` (cdi_container_edits\*) 🔴 TAINTED — 由 `cdi_container_edits_append(edits, ...)` 在 L465/L471 写入
  - `edits` 本身在 L436 通过 `util_common_calloc_s` 分配时为 🟢 CLEAN
  - 首次接收外部 JSON 数据后变为 🔴 TAINTED，成为新的污点载体

## 传播路径
```
[外部 CDI JSON 文件]
        │
        ▼ cdi_spec_parse_file() ──→ raw_spec
        │
        ▼ cdi_spec_get_edits(raw_spec)
[spec_edits] 🔴 TAINTED
        │
        ▼ L465: cdi_container_edits_append(edits, spec_edits) ⚠️ DIRECT_SINK
[edits] 🔴 TAINTED ── 新污点载体
        │
        ▼ cdi_device_get_edits(raw_device)
[device_edits] 🔴 TAINTED
        │
        ▼ L471: cdi_container_edits_append(edits, device_edits) ⚠️ DIRECT_SINK
[edits] 🔴 TAINTED ── 累积污染（spec + device edits）
        │
        ▼ L485: cdi_container_edits_apply(e=edits, spec) 📌 USED
        └── e ── 携带污点数据传入外部库函数
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| cdi_container_edits_append | L465 | edits |
| cdi_container_edits_append | L471 | edits |
| cdi_container_edits_apply | L485 | e |