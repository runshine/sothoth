## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `out_str` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_NvsPrintfStrSetter

## 函数信息
- 文件: libipsec.c
- 签名: `IPSEC_NvsPrintfStrSetter(uint8_t* out_str, const char* format, size_t max_len)`

## 数据流树状图

### INPUT-1: out_str (uint8_t*) 🔴 TAINTED
├── [L7735] vsnprintf_truncated_s(out_str, (unsigned int)(max_len + 1), format, ap) → 📌 USED (格式化输出写入 out_str 缓冲区)
│   └── 接收形参: out_str
└── [L7741] *out_str = 0 → 📌 USED (错误处理时写入单字节空字符)

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| out_str | USED | L7735 | 调用 vsnprintf_truncated_s 将数据格式化输出到缓冲区 |
| out_str | USED | L7741 | 错误处理路径写入空字符终止符 |