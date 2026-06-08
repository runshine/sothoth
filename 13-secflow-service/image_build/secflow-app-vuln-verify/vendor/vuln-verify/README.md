# vuln-verify

自动化漏洞验证系统。接收各类扫描工具产生的大量报告，经多维语义验证后逐条审定，再在全局视角下完成去重、关联与排序，产出漏洞评估结论与优先级排序。

## 安装

```bash
git clone https://github.com/skiyer/vuln-verify.git
cd vuln-verify
uv sync
```

## 用法

```bash
uv run vuln-verify \
  --reports <报告目录> \
  --source-root <源码根目录> \
  --binary-root <二进制根目录> \
  --threat <威胁模型文件> \
  --output <输出目录> \
  [--model <LLM 模型>] \
  [-v | -vv]
```

## 输出

```
output/
├── verify.log            ← 路由决策摘要
├── threat_model.md
├── groups/               ← 路由引擎分组产物
└── verifier_output/      ← 验证引擎产物
    ├── result_*.json     ← 每个报告的独立研判结论
    ├── group_*_analysis.md
    └── group_*.stdout|stderr
```

## 项目结构

```
vuln-verify/
├── src/vuln_verify/       ← 验证引擎（launcher, prompt）
├── packages/vuln-dispatch/ ← 确定性路由引擎（Router）
├── templates/             ← 提示词模板
└── docs/                  ← 设计文档
```

## 设计文档

| 文档 | 内容 |
|:---|:---|
| [architecture_design.md](docs/architecture_design.md) | 系统架构——三引擎设计 |
| [router_design.md](docs/router_design.md) | 确定性路由引擎（Router） |
| [verifier_design.md](docs/verifier_design.md) | 多维语义验证引擎（Verifier）—— 四维校验矩阵 |
| [triager_design.md](docs/triager_design.md) | 智能研判引擎（Triager）—— 全局裁决与聚合 |
| [router_implementation.md](docs/router_implementation.md) | 路由引擎实现细节 |
| [triager_implementation.md](docs/triager_implementation.md) | 研判引擎实现方案 |
| [threat_model_example.md](docs/threat_model_example.md) | 威胁模型填写样例 |
| [presentation_guide.md](docs/presentation_guide.md) | 领导汇报指南 |

## 测试

```bash
uv run python -m pytest packages/vuln-dispatch/tests/ tests/ -v
```
