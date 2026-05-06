请对以下漏洞报告 (`{result_filename}`) 进行**真实性验证**。

## 待验证的漏洞报告
{result_review_context}

## 验证要求
1. 先 `read` task file 与目标 `result_NNN.md`。
2. 仅在确有需要时读取 supporting docs。
3. 重点做证伪：核对代码证据、攻击路径、触发条件、上游校验、实际可利用性。
4. **核心口径**：判断“底层问题是否真实存在、是否不是误报”；不要把严重度高估、攻击链不完整、taint source 写错、仅高权限/配置前提触发等情况当成失败理由。
5. 不要要求框架把漏洞报告全文再次塞进 prompt。

## 输出要求（严格遵守，否则框架会拒绝并要求重新输出）

直接输出一个 JSON 对象，禁止任何前言、后记、Markdown 代码块或解释文字。不要写任何文件。

漏洞真实存在时的输出示例：
```
{"passed":true,"verdict":"CONFIRMED","feedback":"底层无符号下溢问题真实存在，不是误报。","scores":{"issue_truth":0.95},"confidence":0.92}
```

漏洞不存在时的输出示例：
```
{"passed":false,"verdict":"FALSE_POSITIVE","feedback":"报告声称的校验缺失实际上在上层函数中已完整拦截。","scores":{"issue_truth":0.15},"confidence":0.88}
```

关键约束：
- 顶层必须且只能包含：`passed`、`verdict`、`feedback`、`scores`、`confidence`
- `passed` 必须是 `true` 或 `false`
- `verdict` 只能是 `CONFIRMED` / `FALSE_POSITIVE` / `INSUFFICIENT_INFO`
- `scores` 必须包含 `issue_truth`，值为 0.0-1.0 数值
- `confidence` 必须是 0.0-1.0 数值
- 不要使用 `is_false_positive`、`true_positive`、`verification_result` 等非标准键名
