## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `timer_slot` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_MGTI_TimerDelete

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSEC_MGTI_TimerDelete(void *timer_slot)`

## 数据流树状图

### INPUT-1: timer_slot (uint64_t *) 🔴 TAINTED - 外部调用者传入的指针
├── [L18195] if (timer_slot == NULL) → 安全检查
├── [L18196] timer_entry = (uint64_t *)*timer_slot → timer_entry 🔴 TAINTED（新导入对象）
│   ├── [L18197] if (*timer_slot == 0) → 安全检查
│   ├── [L18200] APPTMR_DeleteTimer(..., *timer_entry) ⚠️ DIRECT_SINK
│   │       └── 污点数据直接作为计时器句柄
│   └── [L18202] VRP_Free_F(timer_entry) 📎 见跟入列表
└── [L18204] *timer_slot = 0 → 输出参数写入清洁值

### 新导入的污点对象: timer_entry (uint64_t *)
- 来源: [L18196] 通过解引用 timer_slot 获得
- 追踪:
  - [L18200] 作为参数传入 APPTMR_DeleteTimer → ⚠️ DIRECT_SINK
  - [L18202] 作为参数传入 VRP_Free_F → 📎 见跟入列表

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| timer_slot | APPTMR_DeleteTimer | L18200 | 污点指针作为计时器句柄 |
| timer_entry | APPTMR_DeleteTimer | L18200 | 污点数据直接作为计时器句柄使用 |

## 高危操作
| 操作 | 位置 | 风险描述 |
|------|------|----------|
| APPTMR_DeleteTimer 调用 | L18200 | 污点数据直接作为计时器句柄，可能导致错误的计时器被删除 |
| VRP_Free_F 调用 | L18202 | 污点指针可能被用于释放内存，若值非法可能导致崩溃 |