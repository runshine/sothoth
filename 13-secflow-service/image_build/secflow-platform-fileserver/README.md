# SecFlow Platform File Server

文件管理微服务，支持：

- 按项目、子项目、目录管理文件
- 上传、查询、下载、删除、移动、重命名
- 多 Pod 共享 RWX 存储
- 通过 auth/project 服务完成鉴权与项目访问校验
- 文件按 `/data/files/{project_id}/{subproject_id}/{logical_path}/{original_filename}` 结构落盘
