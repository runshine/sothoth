# Dataflow Vuln Scanner Evolver

交互式进化工具：通过 pi agent 迭代优化 dataflow-vuln-scanner 的漏洞挖掘能力。

## 工作原理

1. 用户选定一批已有漏洞案例（case_ids）作为基准测试集
2. 启动交互式 pi agent 会话
3. 进化 agent 根据用户的「进化目标」生成 MD 文档（skills/ + memory/）
4. 将 MD 文档注入 dataflow-vuln-scanner 的 agent 目录，replay 原始任务
5. 监控 replay 进度，收集结果
6. 用户评估结果，给出调整方向
7. 循环 3-6 直到满意

## 使用方式

```bash
# 基本用法
python cli.py --project-id <project_id> --case-ids <id1,id2,id3>

# 指定配置文件
python cli.py --project-id <project_id> --case-ids <id1,id2> --config config.yaml

# 恢复已有会话
python cli.py --resume <session_dir>
```

## 目录结构

```
cli.py              # 交互式主入口
config.yaml         # 配置文件
core/
├── __init__.py
├── preprocess.py   # 预处理：提取原始任务信息
├── replay.py       # 触发并监控 replay
└── workspace.py    # 会话目录管理
```

## Evolution Workspace 布局

```
/data/files/{project_id}/DATAFLOW_VULN_SCANNER/agent-state/evolution/{session_id}/
├── session.json            # 会话元数据
├── source_tasks.json       # 原始任务快照
├── agents/                 # 各 agent 的 evolution 目录
│   └── {agent_id}/
│       ├── skills/         # 进化策略文档（当轮作战手册）
│       └── memory/         # 历史上下文（跨轮记忆存档）
└── rounds/
    └── round_{N}/
        ├── docs_snapshot/  # 本轮 MD 文档备份
        └── results.json    # 本轮 replay 结果
```
