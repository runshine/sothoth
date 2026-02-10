13-secflow-service/image_build/secflow_project文件夹是一个独立的web微服务，使用python语言，请实现下列功能：
1、该微服务对外提供项目管理功能，使用token进行认证，提供基于项目的创建、查询、删除、修改等功能，需要持久化到数据库中，并能多实例部署，项目需要关联到角色上
2、所有的操作都要有权限访问控制，使用token进行认证，每次请求都要获取当前的token，并到为auth的微服务去进行认证，认证的URL为：
#### 3.1.3 验证人机Token

**接口**: `POST /api/v1/auth/validate-human-token`

**说明**: 外部服务验证用户Token的有效性

**请求头**:
```
Authorization: Bearer <human_token>
```

**响应成功**:
```json
{
  "id": 1,
  "username": "admin",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00",
  "updated_at": "2024-01-01T00:00:00",
  "role": ["admin"]
}
```
2、请提供完整的dockerfile文件和依赖的文件
3、请提供完整的doc文档，文档放在单独的doc文件夹下
4、后台持久化使用mysql数据库，启动时有一个配置文件的运行参数，请提供配置参数，不要使用环境变量，而是配置文件，其中auth的微服务域名需要参数化
5、该微服务运行在K8S环境中，请提供deployment的多实例部署和基于clusterip的service配置文件，以及配置的configmap文件，运行的命名空间为sothothv2-ns
6、项目ID为16位的MD5值，全部小写，不要重复
7、配置文件中需要提供一个K8S环境的配置参数，如果是在K8S集群外，使用kubeconfig的方式（用于调试），否则使用serviceaccount的方式管理K8S
8、创建项目时，同步创建一个namespace为secflow_{项目ID}的namespace，删除时删除该namespace下所有的资源
9、服务启动时，验证K8S的连接情况，如果连接失败则错误退出，否则继续


