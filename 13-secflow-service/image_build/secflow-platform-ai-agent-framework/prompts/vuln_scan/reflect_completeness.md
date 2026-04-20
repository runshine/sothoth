请暂停当前工作，从攻击者视角对你的分析进行系统性自审。

---

## 输出位置提醒（必须严格遵守）

如果你在自审过程中补充或修正任何输出，唯一正确的位置是：

- `summary.md`：`{working_dir}/summary.md`
- `results/`：`{working_dir}/results/`
- 每个漏洞报告：`{working_dir}/results/result_NNN.md`
- 辅助审计文档：`{supporting_docs_dir}/`
- 调用 `write` / `edit` 工具时，优先直接使用上述**绝对路径**

**严禁**写到 `sessions/`、`sessions/<session>/calls/<call>/`、prompt 文件同级目录，或任何其他目录。

---

## 当前自审范围（按本轮模式执行）

{reflection_scope}

---

{reflection_checklist}
