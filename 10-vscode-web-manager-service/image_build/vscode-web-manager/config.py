"""
配置管理模块
"""
import os
import re
import sys
import yaml
from typing import Dict, Any, Optional


# ============ 配置文件加载 ============

def load_yaml_config(config_path: str = "/data/config.yaml") -> Dict[str, Any]:
    """
    从YAML文件加载配置

    Args:
        config_path: 配置文件路径

    Returns:
        配置字典，如果文件不存在返回空字典
    """
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                if config:
                    print(f"从配置文件加载配置: {config_path}")
                    return config
        except Exception as e:
            print(f"加载配置文件失败 {config_path}: {e}")
    return {}


def get_config_value(config: Dict[str, Any], *key_path: str, default: Any = None) -> Any:
    """
    从嵌套配置字典中获取值

    Args:
        config: 配置字典
        key_path: 嵌套键路径
        default: 默认值

    Returns:
        配置值，如果路径不存在返回默认值
    """
    current = config
    for key in key_path:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


def get_yaml_config(*key_path: str, default: Any = None) -> Any:
    """
    从全局YAML配置中获取值

    Args:
        key_path: 嵌套键路径
        default: 默认值

    Returns:
        配置值，如果路径不存在返回默认值
    """
    return get_config_value(YAML_CONFIG, *key_path, default=default)


# 加载YAML配置文件
YAML_CONFIG = load_yaml_config("config.yaml")


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

    # ============ 数据库配置 ============
    # 优先从YAML配置读取，否则使用环境变量，最后使用默认值
    _db_type = get_yaml_config("database", "type", default="sqlite")
    DATABASE_URL = get_yaml_config("database", "mysql_url", default="") or \
                   os.getenv("DATABASE_URL", f"sqlite:///./source_manager.db")

    # ============ 安全配置 ============
    SECRET_KEY = get_yaml_config("security", "secret_key", default="your-secret-key-change-in-production") or \
                 os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = get_yaml_config("security", "access_token_expire_minutes", default=60)

    # ============ 存储配置 ============
    BASE_DIR = get_yaml_config("storage", "base_dir", default="/data") or os.getenv("BASE_DIR", "/data")
    UPLOAD_DIR = os.path.join(BASE_DIR, get_yaml_config("storage", "upload_dir", default="uploads"))
    ARCHIVE_DIR = os.path.join(BASE_DIR, get_yaml_config("storage", "archive_dir", default="archives"))
    EXTRACT_DIR = os.path.join(BASE_DIR, get_yaml_config("storage", "projects_dir", default="projects"))
    DOWNLOAD_DIR = os.path.join(BASE_DIR, get_yaml_config("storage", "downloads_dir", default="downloads"))
    TASK_LOG_DIR = os.path.join(BASE_DIR, get_yaml_config("storage", "task_log_dir", default="task_logs"))

    # ============ Kubernetes配置 ============
    IN_K8S = get_yaml_config("kubernetes", "in_k8s", default=False) or \
             os.getenv("IN_K8S", "false").lower() == "true"
    K8S_API_URL = get_yaml_config("kubernetes", "api_url", default="") or os.getenv("K8S_API_URL", None)
    K8S_API_TOKEN = get_yaml_config("kubernetes", "api_token", default="") or os.getenv("K8S_API_TOKEN", None)
    K8S_API_CERT = get_yaml_config("kubernetes", "api_cert", default="") or os.getenv("K8S_API_CERT", None)
    K8S_API_KEY = get_yaml_config("kubernetes", "api_key", default="") or os.getenv("K8S_API_KEY", None)
    K8S_CA_CERT = get_yaml_config("kubernetes", "ca_cert", default="") or os.getenv("K8S_API_CERT", None)
    K8S_VERIFY_SSL = get_yaml_config("kubernetes", "verify_ssl", default=True) if "verify_ssl" in get_yaml_config("kubernetes", default={}) else \
                     os.getenv("K8S_VERIFY_SSL", "true").lower() == "true"
    K8S_NAMESPACE = get_yaml_config("kubernetes", "namespace", default="vscode") or os.getenv("K8S_NAMESPACE", "vscode")
    K8S_STORAGE_CLASS = get_yaml_config("kubernetes", "storage_class", default="nfs-storage-192.168.13.66") or \
                        os.getenv("K8S_STORAGE_CLASS", "nfs-storage-192.168.13.66")
    K8S_CODE_SERVER_IMAGE = get_yaml_config("kubernetes", "code_server_image", default="linuxserver/code-server:latest") or \
                            os.getenv("K8S_CODE_SERVER_IMAGE", "linuxserver/code-server:latest")
    K8S_CODE_SERVER_PULL_POLICY = get_yaml_config("kubernetes", "code_server_pull_policy", default="Always") or \
                                   os.getenv("K8S_CODE_SERVER_PULL_POLICY", "Always")
    K8S_CODEWIKI_IMAGE = get_yaml_config("kubernetes", "codewiki_image", default="codewiki-api:latest") or \
                         os.getenv("K8S_CODEWIKI_IMAGE", "codewiki-api:latest")
    K8S_CODEWIKI_PULL_POLICY = get_yaml_config("kubernetes", "codewiki_pull_policy", default="Always") or \
                                os.getenv("K8S_CODEWIKI_PULL_POLICY", "Always")
    K8S_SERVICE_TYPE = get_yaml_config("kubernetes", "service_type", default="ClusterIP") or \
                      os.getenv("K8S_SERVICE_TYPE", "ClusterIP")
    K8S_SERVICE_PORT = int(get_yaml_config("kubernetes", "service_port", default=80) or os.getenv("K8S_SERVICE_PORT", "80"))
    K8S_CODEWIKI_SERVICE_PORT = int(get_yaml_config("kubernetes", "codewiki_service_port", default=8080) or
                                     os.getenv("K8S_CODEWIKI_SERVICE_PORT", "8080"))
    K8S_CONTAINER_PORT = int(get_yaml_config("kubernetes", "container_port", default=8443) or
                             os.getenv("K8S_CONTAINER_PORT", "8443"))
    K8S_CODEWIKI_CONTAINER_PORT = int(get_yaml_config("kubernetes", "codewiki_container_port", default=8080) or
                                       os.getenv("K8S_CODEWIKI_CONTAINER_PORT", "8080"))
    K8S_DEFAULT_STORAGE_SIZE = get_yaml_config("kubernetes", "default_storage_size", default="5Gi") or \
                               os.getenv("K8S_DEFAULT_STORAGE_SIZE", "5Gi")

    # ============ VSCODE Ingress 配置 ============
    VSCODE_INGRESS_DOMAIN = get_yaml_config("vscode", "ingress_domain", default="code-server.sothothv2.com") or \
                            os.getenv("VSCODE_INGRESS_DOMAIN", "code-server.sothothv2.com")

    # ============ 文件限制 ============
    MAX_FILE_SIZE = int(get_yaml_config("storage", "max_file_size_mb", default=1024) or 1024) * 1024 * 1024
    MAX_DOWNLOAD_SIZE = int(get_yaml_config("storage", "max_download_size_mb", default=100) or 100) * 1024 * 1024
    ALLOWED_EXTENSIONS = {"zip", "tar", "gz", "tgz", "bz2"}

    # ============ 线程配置 ============
    MAX_WORKERS = 10

    # ============ 项目状态 ============
    PROJECT_STATUS_PENDING = "pending"
    PROJECT_STATUS_INITIALIZING = "initializing"
    PROJECT_STATUS_READY = "ready"
    PROJECT_STATUS_ERROR = "error"
    PROJECT_STATUS_DELETING = "deleting"

    # ============ 调试模式 ============
    DEBUG = get_yaml_config("debug", default=False) or os.getenv("DEBUG", "false").lower() == "true"

    # ============ HTTP配置 ============
    EXTERNAL_ACCESS_URL = get_yaml_config("http", "external_access_url",
                                          default="http://vscode-web-manager.sothothv2-ns.svc.cluster.local") or \
                         os.getenv("EXTERNAL_ACCESS_URL", "http://vscode-web-manager.sothothv2-ns.svc.cluster.local")
    ARCHIVE_DOWNLOAD_TOKEN = get_yaml_config("http", "archive_download_token",
                                             default="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") or \
                            os.getenv("ARCHIVE_DOWNLOAD_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    ARCHIVE_DOWNLOAD_TIMEOUT = int(get_yaml_config("http", "archive_download_timeout", default=1200) or
                                   os.getenv("ARCHIVE_DOWNLOAD_TIMEOUT", "1200"))

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
        in_k8s = cls.IN_K8S
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
        valid_service_type = ["LoadBalancer", "NodePort", "ClusterIP"]
        if cls.K8S_SERVICE_TYPE not in valid_service_type:
            errors.append(f"K8S_SERVICE_TYPE 必须为以下值之一: {', '.join(valid_service_type)}")

        # 检查端口配置
        if cls.K8S_SERVICE_PORT < 1 or cls.K8S_SERVICE_PORT > 65535:
            errors.append(f"K8S_SERVICE_PORT 必须在 1-65535 范围内: {cls.K8S_SERVICE_PORT}")

        if cls.K8S_CONTAINER_PORT < 1 or cls.K8S_CONTAINER_PORT > 65535:
            error_append(f"K8S_CONTAINER_PORT 必须在 1-65535 范围内: {cls.K8S_CONTAINER_PORT}")

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


# ============ CodeWiki 配置 ============

def get_codewiki_config() -> Dict[str, str]:
    """
    获取CodeWiki配置（从YAML配置读取）

    Returns:
        包含CodeWiki配置的字典
    """
    codewiki_section = get_yaml_config("codewiki", default={})
    if not codewiki_section:
        # 如果YAML中不存在codewiki配置，返回空字典
        return {}
    return codewiki_section


def get_codewiki_env_vars() -> Dict[str, str]:
    """
    获取CodeWiki环境变量配置

    Returns:
        格式化的环境变量字典，供Kubernetes Deployment使用
    """
    env_vars = {}

    # 从YAML配置读取CodeWiki参数
    codewiki_config = get_codewiki_config()

    # 参数名到环境变量名的映射
    param_mapping = {
        "api_key": "CODEWIKI_API_KEY",
        "base_url": "CODEWIKI_BASE_URL",
        "main_model": "CODEWIKI_MAIN_MODEL",
        "cluster_model": "CODEWIKI_CLUSTER_MODEL",
        "fallback_model": "CODEWIKI_FALLBACK_MODEL"
    }

    for param_name, env_name in param_mapping.items():
        value = codewiki_config.get(param_name, "")
        if value:
            env_vars[env_name] = value

    return env_vars


def validate_codewiki_config() -> Dict[str, Any]:
    """
    验证CodeWiki必需配置是否存在

    Returns:
        验证结果字典
    """
    errors = []
    warnings = []

    # 从YAML配置读取CodeWiki参数
    codewiki_config = get_codewiki_config()

    # 必需的配置参数
    required_params = {
        "api_key": "API Key（用于Claude API认证）",
        "base_url": "API Base URL（Claude API地址）",
        "main_model": "主模型（主要使用的AI模型）",
        "cluster_model": "集群模型（用于代码分析）",
        "fallback_model": "降级模型（主模型不可用时的备选）"
    }

    for param_name, description in required_params.items():
        value = codewiki_config.get(param_name, "")
        if not value or value == f"your-{param_name.replace('_', '-')}":
            errors.append(f"缺少必需参数 '{param_name}'，请在config.yaml的codewiki部分配置")
        else:
            # 检查值是否合理
            if param_name == "api_key" and len(value) < 10:
                warnings.append(f"API Key 长度可能太短，可能无效")
            if param_name == "base_url" and not value.startswith(("http://", "https://")):
                warnings.append(f"base_url 必须以 http:// 或 https:// 开头，当前值: {value}")

    env_config = get_codewiki_env_vars()

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "env_config": env_config
    }


# ============ 动态环境变量配置 ============

def get_dynamic_env_vars(service_type: str = None) -> Dict[str, str]:
    """
    获取动态环境变量配置

    Args:
        service_type: 服务类型，可选 'code_server', 'codewiki' 或 None（返回所有）

    Returns:
        动态环境变量字典
    """
    dynamic_env = get_yaml_config("dynamic_env", default={})

    result = {}

    # 先添加全局环境变量
    global_vars = dynamic_env.get("global", {})
    result.update(global_vars)

    # 如果指定了服务类型，添加该服务的环境变量
    if service_type and service_type in dynamic_env:
        service_vars = dynamic_env.get(service_type, {})
        result.update(service_vars)

    return result


def get_code_server_dynamic_env() -> Dict[str, str]:
    """获取 code-server 的动态环境变量"""
    return get_dynamic_env_vars("code_server")


def get_codewiki_dynamic_env() -> Dict[str, str]:
    """获取 codewiki 的动态环境变量（包含全局环境变量）"""
    return get_dynamic_env_vars("codewiki")


def validate_dynamic_env_config() -> Dict[str, Any]:
    """
    验证动态环境变量配置

    Returns:
        验证结果字典
    """
    dynamic_env = get_yaml_config("dynamic_env", default={})

    errors = []
    warnings = []

    # 检查动态环境变量配置
    if dynamic_env:
        # 检查 global 部分
        global_vars = dynamic_env.get("global", {})
        if global_vars:
            for key, value in global_vars.items():
                if not isinstance(value, str):
                    warnings.append(f"global 环境变量 '{key}' 值类型应为字符串")
                if not key.isidentifier() and not key.isupper():
                    warnings.append(f"环境变量名 '{key}' 建议使用大写字母和下划线")

        # 检查 code_server 部分
        code_server_vars = dynamic_env.get("code_server", {})
        if code_server_vars:
            for key, value in code_server_vars.items():
                if not isinstance(value, str):
                    warnings.append(f"code_server 环境变量 '{key}' 值类型应为字符串")

        # 检查 codewiki 部分
        codewiki_vars = dynamic_env.get("codewiki", {})
        if codewiki_vars:
            for key, value in codewiki_vars.items():
                if not isinstance(value, str):
                    warnings.append(f"codewiki 环境变量 '{key}' 值类型应为字符串")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "global_vars": dynamic_env.get("global", {}),
        "code_server_vars": dynamic_env.get("code_server", {}),
        "codewiki_vars": dynamic_env.get("codewiki", {})
    }