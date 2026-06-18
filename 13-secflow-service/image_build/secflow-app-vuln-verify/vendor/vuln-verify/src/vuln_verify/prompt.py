from __future__ import annotations

from pathlib import Path

_BUILTIN_THREAT_MODEL = """\
# 威胁模型

## 攻击者假设

攻击者可通过网络或本地接口向目标系统发送任意构造的输入，无需前置认证。
攻击者掌握目标软件的公开信息（版本、协议格式、公开漏洞），但无源码或内部文档访问权限。

## 攻击面

- 所有面向外部暴露的协议解析入口（网络包处理、文件解析、IPC 接口等）
- 无需前置认证即可触达的代码路径
- 接受外部可控输入的 API / RPC / 系统调用

## 信任边界与补偿控制

- 所有来自攻击面的输入均不可信，必须先校验后使用
- 假定 OS 平台的标准系统防御已启用：ASLR、NX/DEP、Stack Canary、SAN 等
- 经过认证后的内部调用视为可信域
- 已知的通用防御措施（输入长度校验、类型检查、边界检查等）视为有效控制

## 排除范围

- 测试代码、mock 文件、单元测试辅助代码
- 第三方依赖库（除非漏洞源于本项目对库的 misuse）
- 仅 debug 构建生效的代码路径
- 需物理访问或已获得 root/shell 权限的攻击场景
"""


def load_prompt(threat_path: str | None = None) -> str:
    """加载 verifier 提示词模板，用威胁模型内容替换 {{THREAT_MODEL}}。

    threat_path 为 None 或空时，使用内置通用威胁模型。
    """
    template_dir = Path(__file__).parent.parent.parent / "templates"
    template = (template_dir / "verifier_prompt.md").read_text(encoding="utf-8")
    if threat_path:
        threat = Path(threat_path).read_text(encoding="utf-8")
    else:
        threat = _BUILTIN_THREAT_MODEL
    return template.replace("{{THREAT_MODEL}}", threat)
