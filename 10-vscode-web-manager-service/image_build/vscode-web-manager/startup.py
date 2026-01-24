"""
启动初始化模块
"""
import os
import sys
import logging
from typing import Optional

from config import Config
from database import init_db
from managers.kubernetes_manager import KubernetesManager
from managers.task_manager import TaskManager

# 全局管理器实例
k8s_manager: Optional[KubernetesManager] = None
task_manager_instance: Optional[TaskManager] = None  # 重命名以避免命名冲突


def init_system():
    """初始化系统"""
    global k8s_manager, task_manager_instance  # 声明全局变量

    print(f"启动 {Config.APP_NAME} v{Config.VERSION}")
    print(f"数据库: {Config.DATABASE_URL}")
    print(f"存储目录: {Config.BASE_DIR}")
    print(f"API地址: http://0.0.0.0:8080")
    print(f"API文档: http://0.0.0.0:8080/docs")
    print(f"下载功能已启用，最大下载大小: {Config.MAX_DOWNLOAD_SIZE // (1024 * 1024)}MB")
    print(f"Code-Server错误处理已优化，错误信息将返回给客户端")
    print(
        f"项目状态管理: {', '.join([Config.PROJECT_STATUS_PENDING, Config.PROJECT_STATUS_INITIALIZING, Config.PROJECT_STATUS_READY, Config.PROJECT_STATUS_ERROR, Config.PROJECT_STATUS_DELETING])}")
    print(f"项目异步初始化: 上传后自动提交初始化任务")
    print(f"项目删除功能: 强制删除所有K8S资源（包括PVC），避免资源泄露")
    print(f"项目ID生成方式：md5(md5(project_name)_md5(压缩包文件)_time)")

    # 检查是否在K8S集群内部运行
    in_k8s = os.getenv("IN_K8S", "false").lower() == "true"
    if in_k8s:
        print("\n=== 运行在Kubernetes集群内部 ===")
        print("将使用ServiceAccount进行认证")
        print(f"命名空间: {Config.K8S_NAMESPACE}")
        print(f"存储类: {Config.K8S_STORAGE_CLASS}")
        print(f"服务类型: {Config.K8S_SERVICE_TYPE}")

    # 验证K8S配置
    print("\n=== 验证Kubernetes配置 ===")
    k8s_config = Config.validate_k8s_config()

    # 显示配置信息
    print("配置信息:")
    for key, value in k8s_config["info"].items():
        print(f"  • {key}: {value}")

    # 处理警告和错误
    if k8s_config["warnings"]:
        print("\n警告:")
        for warning in k8s_config["warnings"]:
            print(f"  ⚠ {warning}")

    if k8s_config["errors"]:
        print("\n错误:")
        for error in k8s_config["errors"]:
            print(f"  ✗ {error}")
        print("\nKubernetes配置验证失败，程序将退出")
        print("请修复以上错误后重试")
        sys.exit(1)

    # 如果有警告，让用户确认是否继续
    if k8s_config["warnings"] and not in_k8s:
        print("\n警告: Kubernetes配置存在警告")
        print("请确认是否继续运行（yes/no）: ")
        user_input = input().strip().lower()
        if user_input not in ["yes", "y"]:
            print("程序退出")
            sys.exit(0)

    print("\n✓ Kubernetes基础配置验证通过")

    print("\n=== 验证HTTP配置 ===")
    http_config = Config.validate_http_config()

    if http_config["warnings"]:
        for warning in http_config["warnings"]:
            print(f"  ⚠ {warning}")

    if http_config["errors"]:
        print("错误:")
        for error in http_config["errors"]:
            print(f"  ✗ {error}")
        print("\nHTTP配置验证失败，程序将退出")
        sys.exit(1)

    print("✓ HTTP基础配置验证通过")
    print(f"  外部访问地址: {Config.EXTERNAL_ACCESS_URL}")
    print(f"  下载超时时间: {Config.ARCHIVE_DOWNLOAD_TIMEOUT}秒")

    # 检查JWT库
    if not Config.JWT_AVAILABLE:
        print("\n错误: JWT 库不可用，认证功能将无法正常工作，程序将退出")
        print("请安装 PyJWT 或 python-jose: pip install PyJWT 或 pip install python-jose[cryptography]")
        sys.exit(1)

    # 初始化数据库
    print("\n=== 初始化数据库 ===")
    init_db()

    # 初始化管理器
    init_managers()

    print("\n=== 项目状态管理API已启用 ===")
    print("  GET /api/projects/{project_id}/status - 获取项目状态")
    print("  GET /api/projects/{project_id}/init-logs - 获取项目初始化日志")
    print("  GET /api/projects/{project_id}/task-logs - 获取项目任务日志列表")

    print("\n=== 项目异步初始化流程 ===")
    print("  1. 上传压缩包 -> 状态: pending")
    print("  2. 提交初始化任务 -> 状态: initializing")
    print("  3. 执行解压、扫描文件、创建PVC、拷贝文件")
    print("  4. 初始化成功 -> 状态: ready")
    print("  5. 初始化失败 -> 状态: error")

    print("\n=== PVC管理API已启用 ===")
    print("  POST /api/projects/{project_id}/pvc/create - 为项目创建PVC")
    print("  POST /api/projects/{project_id}/pvc/recreate - 重建项目PVC")
    print("  GET /api/projects/{project_id}/pvc/status - 获取PVC状态")
    print("  DELETE /api/projects/{project_id}/pvc - 删除项目PVC")

    print("\n=== 部署监控API已启用 ===")
    print("  GET /api/code-servers/{project_id}/deployment/status - 获取详细部署状态")
    print("  GET /api/code-servers/{project_id}/deployment/logs - 获取所有相关日志")
    print("  GET /api/code-servers/{project_id}/deployment/pods - 获取所有Pod信息")

    print("\n=== 项目删除策略 ===")
    print("  删除项目时强制删除所有资源:")
    print("  - Code-Server (Deployment, Service, Ingress)")
    print("  - PVC")
    print("  - 本地文件 (压缩包、解压目录)")
    print("  - 数据库记录")
    print("  确保无资源泄露")


def init_managers():
    """初始化管理器"""
    global k8s_manager, task_manager_instance

    # 初始化Kubernetes管理器
    try:
        if Config.K8S_AVAILABLE:
            print("\n=== 初始化Kubernetes管理器 ===")
            try:
                k8s_manager = KubernetesManager(validate_connection=True)
                print("✓ Kubernetes管理器初始化成功")
            except Exception as e:
                print(f"✗ Kubernetes管理器初始化失败: {e}")
                print("程序不能继续运行，K8S功能不可用")
                k8s_manager = None
                exit(255)
        else:
            print("\n警告: kubernetes-client 未安装")
            print("如需使用Code-Server功能，请安装: pip install kubernetes")
            print("程序不能继续运行，K8S功能不可用")
            k8s_manager = None
            exit(255)
    except Exception as e:
        print(f"✗ 初始化Kubernetes管理器时发生错误: {e}")
        print("程序不能继续运行，K8S功能不可用")
        k8s_manager = None
        exit(255)

    # 初始化任务管理器
    try:
        print("\n=== 初始化任务管理器 ===")
        task_manager_instance = TaskManager()
        print("✓ 任务管理器初始化成功")
    except Exception as e:
        print(f"✗ 任务管理器初始化失败: {e}")
        sys.exit(1)


def get_k8s_manager():
    """获取Kubernetes管理器实例"""
    return k8s_manager


def get_task_manager():
    """获取任务管理器实例"""
    return task_manager_instance