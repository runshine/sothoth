"""Threat model template catalog and rendering helpers."""

from __future__ import annotations

import re
from typing import Any


BUILTIN_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "builtin-default-validation",
        "scope": "builtin",
        "name": "通用漏洞可利用性验证",
        "description": "围绕漏洞成因、前置条件、利用路径和影响面进行自动化验证。",
        "content": """# 威胁模型

## 攻击者假设
<!-- 攻击者在哪里？拥有什么能力？ -->
- 案例：`{{case_id}}` / {{case_title}}
- 默认假设：攻击者可到达与 `{{subject_locator}}` 相关的输入入口，并可控制触发该路径所需的外部数据。
- 验证目标：判断报告问题是否具备实际可利用性，而不仅是静态告警。

## 攻击面
<!-- 哪些入口点暴露给攻击者？无需前置认证的协议解析入口、网络包处理路径等 -->
- 关注对象：`{{subject_locator}}`
- 漏洞类型/分类：{{category}}
- 严重性：{{severity}}
- 报告摘要：{{summary}}
- 证据线索：{{evidence_summary}}

## 信任边界与补偿控制
<!-- 可信域范围，已知的防御措施（认证门、输入校验层、W^X 等） -->
- 需要确认攻击输入进入目标代码前是否存在认证、授权、格式校验、长度限制、沙箱、编译期/运行期缓解等补偿控制。
- 需要确认源码位置、二进制符号、配置和实际可达路径是否一致。
- 若补偿控制足以阻断利用，请给出证据并说明判定为 ruled_out / inconclusive 的原因。

## 排除范围
<!-- 不在分析范围内的代码：测试代码、mock 文件、第三方库、debug 路径等 -->
- 默认排除测试代码、mock/demo、第三方库、仅 debug 可达路径以及与 `{{subject_locator}}` 无关的变体。
- 不生成 HTML 报告；验证结果由 SecFlow React 报告视图消费结构化 report-data。
""".strip(),
    },
    {
        "id": "builtin-memory-safety",
        "scope": "builtin",
        "name": "内存安全专项验证",
        "description": "面向越界、UAF、空指针、整数溢出等内存安全问题。",
        "content": """# 威胁模型

## 攻击者假设
<!-- 攻击者在哪里？拥有什么能力？ -->
- 案例：`{{case_id}}` / {{case_title}}
- 默认假设：攻击者可控制触发 `{{subject_locator}}` 的外部输入，并尝试制造越界、UAF、空指针、整数溢出或异常分配等内存安全后果。
- 攻击者不默认拥有本地调试权限或源码修改能力。

## 攻击面
<!-- 哪些入口点暴露给攻击者？无需前置认证的协议解析入口、网络包处理路径等 -->
- 重点枚举网络协议解析、IPC/RPC、文件/镜像/配置解析、命令行参数、环境变量等可承载污点数据的入口。
- 目标位置：`{{subject_locator}}`
- 报告摘要：{{summary}}
- 证据线索：{{evidence_summary}}

## 信任边界与补偿控制
<!-- 可信域范围，已知的防御措施（认证门、输入校验层、W^X 等） -->
- 检查输入到达目标代码前是否存在长度检查、边界检查、生命周期/所有权约束、整数转换保护、分配大小限制等源码级控制。
- 检查二进制层面的 NX/W^X、ASLR/PIE、RELRO、栈保护、FORTIFY、沙箱/容器边界等是否阻断实际利用。
- 若只能造成受控崩溃、不可达或被补偿控制阻断，请明确说明证据。

## 排除范围
<!-- 不在分析范围内的代码：测试代码、mock 文件、第三方库、debug 路径等 -->
- 默认排除测试代码、mock/demo、第三方库、仅 debug 可达路径以及与该内存安全告警无关的代码路径。
- 不生成 HTML 报告；验证结果由 SecFlow React 报告视图消费结构化 report-data。
""".strip(),
    },
    {
        "id": "builtin-authz-logic",
        "scope": "builtin",
        "name": "权限与业务逻辑验证",
        "description": "面向认证绕过、越权、策略缺陷和敏感操作保护不足。",
        "content": """# 威胁模型

## 攻击者假设
<!-- 攻击者在哪里？拥有什么能力？ -->
- 案例：`{{case_id}}` / {{case_title}}
- 默认假设：攻击者位于低权限、跨租户、未认证或受限认证身份侧，试图绕过鉴权、授权、策略或业务状态机约束。
- 攻击者不默认拥有管理员权限、服务端本地文件写入权限或可信内部调用身份，除非报告证据明确说明。

## 攻击面
<!-- 哪些入口点暴露给攻击者？无需前置认证的协议解析入口、网络包处理路径等 -->
- 重点枚举 HTTP/API、RPC、CLI、消息队列、回调、异步任务、跨租户资源访问等可触发敏感操作的入口。
- 目标位置：`{{subject_locator}}`
- 报告摘要：{{summary}}
- 证据线索：{{evidence_summary}}

## 信任边界与补偿控制
<!-- 可信域范围，已知的防御措施（认证门、输入校验层、W^X 等） -->
- 检查身份认证、角色/权限、租户/项目边界、资源归属校验、策略引擎、审计/审批流程等补偿控制。
- 检查敏感操作前是否存在缺失校验、错误回退、默认放行、 confused deputy、TOCTOU 或异常路径绕过。
- 若补偿控制已经阻断越权或只能在可信域内部触发，请明确给出证据。

## 排除范围
<!-- 不在分析范围内的代码：测试代码、mock 文件、第三方库、debug 路径等 -->
- 默认排除测试代码、mock/demo、第三方库、仅 debug/运维内部可达路径以及与该权限/逻辑问题无关的功能。
- 不生成 HTML 报告；验证结果由 SecFlow React 报告视图消费结构化 report-data。
""".strip(),
    },
]

_PATTERN = re.compile(r"{{\s*([a-zA-Z0-9_.-]+)\s*}}")


def build_case_variables(case_payload: dict[str, Any]) -> dict[str, str]:
    subject = case_payload.get("subject") if isinstance(case_payload.get("subject"), dict) else {}
    evidence = case_payload.get("evidence") if isinstance(case_payload.get("evidence"), dict) else {}
    return {
        "case_id": str(case_payload.get("id") or ""),
        "case_title": str(case_payload.get("title") or "Untitled case"),
        "summary": str(case_payload.get("summary") or "No summary provided."),
        "severity": str(case_payload.get("severity") or "unknown"),
        "category": str(case_payload.get("category") or case_payload.get("rule_name") or "unknown"),
        "subject_locator": str(subject.get("locator") or subject.get("name") or "unknown"),
        "subject_type": str(subject.get("type") or "unknown"),
        "evidence_summary": str(evidence.get("summary") or evidence.get("reproduction_hint") or "No evidence summary provided."),
    }


def list_templates(project_id: str | None = None) -> list[dict[str, Any]]:
    # MVP: builtin templates. project_id is accepted for forward-compatible project-level templates.
    return [{k: v for k, v in item.items() if k != "content"} for item in BUILTIN_TEMPLATES]


def get_template(template_id: str) -> dict[str, Any] | None:
    return next((item for item in BUILTIN_TEMPLATES if item["id"] == template_id), None)


def render_template(template_id: str, case_payload: dict[str, Any], overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    template = get_template(template_id)
    if template is None:
        raise KeyError(template_id)
    variables = build_case_variables(case_payload)
    for key, value in (overrides or {}).items():
        variables[str(key)] = str(value)

    def replace(match: re.Match[str]) -> str:
        return variables.get(match.group(1), "")

    return {
        "template_id": template["id"],
        "name": template["name"],
        "content": _PATTERN.sub(replace, template["content"]),
        "variables": variables,
    }
