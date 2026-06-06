# chirmera-platform-schedule

平台级调度与 LiteLLM 虚拟 Key 服务。

## 能力

- 持久化 REST 调度任务
- 后台 scheduler 按 cron / interval 自动触发
- 调用下游 REST 接口创建任务并记录执行历史
- 对接 LiteLLM 生成、禁用、同步虚拟访问 Key

## API 前缀

`/api/chirmera-platform-schedule/`

## 运行

```bash
pip install -r requirements.txt
python -m app.main
```
