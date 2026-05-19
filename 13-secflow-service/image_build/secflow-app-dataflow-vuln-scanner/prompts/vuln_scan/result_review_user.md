请对以下漏洞报告 (`{result_filename}`) 进行**真实性验证**。

## 待验证的漏洞报告
{result_review_context}

你是**证伪者**，证伪对象是"底层问题不存在"。

### 核心检查顺序
1. **代码点是否真实存在**：报告引用的危险操作/校验缺口是否在代码中存在？
2. **底层缺陷是否真实**：哪怕报告对严重度或攻击链描述有误，这个缺陷本身是否仍然成立？
3. **是否有完整拦截保护**：是否存在被报告遗漏的充分校验，使问题根本不存在？
4. **是否只是表述偏差**：如果只是 exploitability / severity / trigger scope 写得不准，但问题本身真实，仍然判通过。

---

## 输出格式

直接输出一个 JSON 对象，禁止任何前言、后记、Markdown 代码块或解释文字。

漏洞真实存在时的输出示例：
```
{"passed":true,"verdict":"CONFIRMED","feedback":"底层无符号下溢问题真实存在，不是误报。","scores":{"issue_truth":0.95},"confidence":0.92}
```

漏洞不存在时的输出示例：
```
{"passed":false,"verdict":"FALSE_POSITIVE","feedback":"报告声称的校验缺失实际上在上层函数中已完整拦截。","scores":{"issue_truth":0.15},"confidence":0.88}
```

### Schema 约束
- 顶层必须且**只能包含**这 5 个键：`passed`、`verdict`、`feedback`、`scores`、`confidence`
- `passed` 必须是布尔值 `true` 或 `false`
- `verdict` 只能是 `CONFIRMED` / `FALSE_POSITIVE`；不要发明其他任何别名
- `feedback` 必须是非空字符串
- `scores` 必须是对象，且必须包含唯一必需字段 `issue_truth`，值为 0.0-1.0 数值
- `confidence` 必须是 0.0-1.0 数值，不能写 HIGH/MEDIUM/LOW
- 不要使用任何其他非标准键名

---

## 重要约束
- **禁止写入任何文件。** 全部输出通过 JSON 返回；
- `FALSE_POSITIVE` 是终态误报标注；`CONFIRMED` 是终态确认标注。
