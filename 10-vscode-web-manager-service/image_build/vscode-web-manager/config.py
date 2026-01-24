"""
配置管理模块
"""
import os
import re
import sys
from typing import Dict, Any


# ============ 检查核心依赖 ============
def check_dependencies():
    """检查所有必需的依赖"""
    missing_deps = []

    # 检查FastAPI相关依赖
    try:
        from fastapi import FastAPI
        from pydantic import BaseModel
    except ImportError as e:
        missing_deps.append(f"FastAPI相关: {e}")

    # 检查SQLAlchemy
    try:
        from sqlalchemy import create_engine
    except ImportError as e:
        missing_deps.append(f"SQLAlchemy: {e}")

    # 检查JWT库
    try:
        import jwt
        JWT_AVAILABLE = True
        JWT_LIB = "pyjwt"
    except ImportError:
        try:
            from jose import jwt
            JWT_AVAILABLE = True
            JWT_LIB = "jose"
        except ImportError:
            JWT_AVAILABLE = False
            missing_deps.append("JWT库 (PyJWT 或 python-jose)")

    # 检查Kubernetes客户端
    try:
        from kubernetes import client, config
        K8S_AVAILABLE = True
    except ImportError:
        K8S_AVAILABLE = False
        # Kubernetes是可选的，不视为缺失依赖

    if missing_deps:
        print("错误: 缺少必需的依赖包")
        for dep in missing_deps:
            print(f"  • {dep}")
        print("\n请运行: pip install fastapi uvicorn sqlalchemy pymysql passlib python-multipart PyJWT kubernetes")
        sys.exit(1)

    return {
        "jwt_available": JWT_AVAILABLE,
        "jwt_lib": JWT_LIB if JWT_AVAILABLE else None,
        "k8s_available": K8S_AVAILABLE
    }


# 在类定义前检查依赖
DEPENDENCIES = check_dependencies()


class Config:
    """应用配置"""
    # 基础配置
    APP_NAME = "源码管理系统"
    VERSION = "1.0.0"
    API_PREFIX = "/api"

    # 依赖可用性
    JWT_AVAILABLE = DEPENDENCIES["jwt_available"]
    JWT_LIB = DEPENDENCIES["jwt_lib"]
    K8S_AVAILABLE = DEPENDENCIES["k8s_available"]

    # 安全配置
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60

    # 数据库配置
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./source_manager.db")

    # 存储配置
    BASE_DIR = os.getenv("BASE_DIR", "/data")
    UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
    ARCHIVE_DIR = os.path.join(BASE_DIR, "archives")
    EXTRACT_DIR = os.path.join(BASE_DIR, "projects")
    DOWNLOAD_DIR = os.path.join(BASE_DIR, "downloads")
    TASK_LOG_DIR = os.path.join(BASE_DIR, "task_logs")

    # Kubernetes配置
    K8S_API_URL = os.getenv("K8S_API_URL", None)
    K8S_API_TOKEN = os.getenv("K8S_API_TOKEN", None)
    K8S_API_CERT = os.getenv("K8S_API_CERT", None)
    K8S_API_KEY = os.getenv("K8S_API_KEY", None)
    K8S_CA_CERT = os.getenv("K8S_CA_CERT", None)
    K8S_VERIFY_SSL = os.getenv("K8S_VERIFY_SSL", "true").lower() == "true"
    K8S_NAMESPACE = os.getenv("K8S_NAMESPACE", "vscode")
    K8S_STORAGE_CLASS = os.getenv("K8S_STORAGE_CLASS", "nfs-storage-192.168.13.66")
    K8S_CODE_SERVER_IMAGE = os.getenv("K8S_CODE_SERVER_IMAGE", "linuxserver/code-server:latest")
    K8S_SERVICE_TYPE = os.getenv("K8S_SERVICE_TYPE", "ClusterIP")
    K8S_SERVICE_PORT = int(os.getenv("K8S_SERVICE_PORT", "80"))
    K8S_CONTAINER_PORT = int(os.getenv("K8S_CONTAINER_PORT", "8443"))
    # PVC存储大小配置
    K8S_DEFAULT_STORAGE_SIZE = os.getenv("K8S_DEFAULT_STORAGE_SIZE", "5Gi")

    # 文件限制
    MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE_MB", "1024")) * 1024 * 1024
    MAX_DOWNLOAD_SIZE = int(os.getenv("MAX_DOWNLOAD_SIZE_MB", "100")) * 1024 * 1024
    ALLOWED_EXTENSIONS = {"zip", "tar", "gz", "tgz", "bz2"}

    # 线程配置
    MAX_WORKERS = 10

    # 项目状态
    PROJECT_STATUS_PENDING = "pending"
    PROJECT_STATUS_INITIALIZING = "initializing"
    PROJECT_STATUS_READY = "ready"
    PROJECT_STATUS_ERROR = "error"
    PROJECT_STATUS_DELETING = "deleting"

    # 调试模式
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

    EXTERNAL_ACCESS_URL = os.getenv("EXTERNAL_ACCESS_URL", "http://vscode-web-manager.sothothv2-ns.svc.cluster.local")
    ARCHIVE_DOWNLOAD_TOKEN = os.getenv("ARCHIVE_DOWNLOAD_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    ARCHIVE_DOWNLOAD_TIMEOUT = int(os.getenv("ARCHIVE_DOWNLOAD_TIMEOUT", "1200"))

    @classmethod
    def init_dirs(cls):
        """初始化目录"""
        for d in [cls.UPLOAD_DIR, cls.ARCHIVE_DIR, cls.EXTRACT_DIR, cls.DOWNLOAD_DIR, cls.TASK_LOG_DIR]:
            os.makedirs(d, exist_ok=True)
            print(f"创建目录: {d}")

    @classmethod
    def validate_http_config(cls) -> Dict[str, Any]:
        """验证HTTP配置"""
        errors = []
        warnings = []

        if not cls.EXTERNAL_ACCESS_URL:
            errors.append("EXTERNAL_ACCESS_URL 不能为空")
        elif not cls.EXTERNAL_ACCESS_URL.startswith(("http://", "https://")):
            errors.append(f"EXTERNAL_ACCESS_URL 必须以 http:// 或 https:// 开头，当前值: {cls.EXTERNAL_ACCESS_URL}")

        if not cls.ARCHIVE_DOWNLOAD_TOKEN:
            warnings.append("ARCHIVE_DOWNLOAD_TOKEN 未设置，下载可能不需要认证")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }

    @classmethod
    def validate_k8s_config(cls) -> Dict[str, Any]:
        """验证K8S配置，有任何错误或警告都视为配置失败"""
        errors = []
        warnings = []
        info = {}

        # 检查是否在K8S集群内部运行
        in_k8s = os.getenv("IN_K8S", "false").lower() == "true"
        info["in_k8s"] = in_k8s

        if in_k8s:
            # 集群内部运行，使用ServiceAccount token，跳过外部配置验证
            info["auth_method"] = "serviceaccount"
            info["api_url"] = "集群内部（使用in-cluster配置）"

            # 只需要验证命名空间
            if not cls.K8S_NAMESPACE or cls.K8S_NAMESPACE.strip() == "":
                errors.append("K8S_NAMESPACE 不能为空")
            else:
                # 检查命名空间格式
                if not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', cls.K8S_NAMESPACE):
                    warnings.append(f"K8S_NAMESPACE 格式可能不正确: {cls.K8S_NAMESPACE}")
        else:
            # 集群外部运行，验证外部配置
            # 检查是否设置了自定义API URL
            if cls.K8S_API_URL:
                info["api_url"] = cls.K8S_API_URL

                # 验证URL格式
                if not cls.K8S_API_URL.startswith(("http://", "https://")):
                    errors.append(f"K8S_API_URL 必须以 http:// 或 https:// 开头，当前值: {cls.K8S_API_URL}")

                # 检查鉴权配置
                if cls.K8S_API_TOKEN:
                    # Token认证
                    info["auth_method"] = "token"
                    # 检查Token长度
                    if len(cls.K8S_API_TOKEN) < 10:
                        warnings.append("K8S_API_TOKEN 长度太短，可能无效")
                elif cls.K8S_API_CERT and cls.K8S_API_KEY:
                    # 证书认证
                    info["auth_method"] = "certificate"
                    # 检查证书文件是否存在
                    if not os.path.exists(cls.K8S_API_CERT):
                        errors.append(f"证书文件不存在: {cls.K8S_API_CERT}")
                    if not os.path.exists(cls.K8S_API_KEY):
                        errors.append(f"密钥文件不存在: {cls.K8S_API_KEY}")
                else:
                    # 尝试使用kubeconfig
                    warnings.append("自定义API URL但未提供鉴权信息，将尝试使用kubeconfig")
                    info["auth_method"] = "kubeconfig"

                # 检查CA证书文件是否存在
                if cls.K8S_CA_CERT and not os.path.exists(cls.K8S_CA_CERT):
                    errors.append(f"CA证书文件不存在: {cls.K8S_CA_CERT}")
            else:
                info["auth_method"] = "kubeconfig"
                info["api_url"] = "使用kubeconfig默认配置"

            # 检查K8S命名空间
            if not cls.K8S_NAMESPACE or cls.K8S_NAMESPACE.strip() == "":
                errors.append("K8S_NAMESPACE 不能为空")
            else:
                # 检查命名空间格式
                if not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', cls.K8S_NAMESPACE):
                    warnings.append(f"K8S_NAMESPACE 格式可能不正确: {cls.K8S_NAMESPACE}")

        # 以下配置在集群内外都需要验证
        # 检查存储类
        if not cls.K8S_STORAGE_CLASS or cls.K8S_STORAGE_CLASS.strip() == "":
            warnings.append("K8S_STORAGE_CLASS 未设置，将使用默认值")

        # 检查服务类型
        valid_service_types = ["LoadBalancer", "NodePort", "ClusterIP"]
        if cls.K8S_SERVICE_TYPE not in valid_service_types:
            errors.append(f"K8S_SERVICE_TYPE 必须为以下值之一: {', '.join(valid_service_types)}")

        # 检查端口配置
        if cls.K8S_SERVICE_PORT < 1 or cls.K8S_SERVICE_PORT > 65535:
            errors.append(f"K8S_SERVICE_PORT 必须在 1-65535 范围内: {cls.K8S_SERVICE_PORT}")

        if cls.K8S_CONTAINER_PORT < 1 or cls.K8S_CONTAINER_PORT > 65535:
            errors.append(f"K8S_CONTAINER_PORT 必须在 1-65535 范围内: {cls.K8S_CONTAINER_PORT}")

        # 修改：有任何错误或警告都视为配置失败
        has_issues = len(errors) > 0 or len(warnings) > 0

        return {
            "valid": not has_issues,  # 没有错误和警告才算有效
            "errors": errors,
            "warnings": warnings,
            "info": info
        }


# 初始化目录
Config.init_dirs()