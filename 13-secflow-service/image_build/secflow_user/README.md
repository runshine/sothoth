# SecFlow-User

基于 FastAPI 的用户认证微服务。

## 功能

- 用户管理（增删查改）
- 角色管理
- 用户角色绑定（支持多角色）
- 机机Token认证
- 人机Token认证
- Token验证API
- MySQL数据持久化

## 快速开始

```bash
# Docker运行
docker build -t secflow-user .
docker run -d -p 8080:8080 secflow-user

# Docker Compose
docker-compose up -d
```

## API文档

详细文档：[doc/API.md](doc/API.md)

## 项目结构

```
secflow_user/
├── app/
│   ├── main.py           # FastAPI入口
│   ├── database.py       # 数据库配置
│   ├── model.py          # 数据模型
│   ├── schema.py         # Pydantic模式
│   ├── auth.py           # 认证工具
│   ├── dependencies.py   # 认证依赖
│   └── router/           # API路由
├── doc/
│   ├── README.md         # 文档索引
│   └── API.md            # 完整API文档
├── Dockerfile
├── docker-compose.yml
├── k8s-deployment.yaml
├── k8s-configmap.yaml
└── requirements.txt
```