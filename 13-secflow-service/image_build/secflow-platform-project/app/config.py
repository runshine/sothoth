"""
配置文件加载模块
"""

import os
import re
import logging
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel


logger = logging.getLogger(__name__)


class DatabaseConfig(BaseModel):
    """数据库配置"""
    host: str
    port: int
    username: str
    password: str
    name: str
    table_prefix: str = "secflow_project_"
    pool_size: int = 10
    max_overflow: int = 20

    @property
    def url(self) -> str:
        """生成数据库连接URL"""
        return f"mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.name}"


class AuthServiceConfig(BaseModel):
    """Auth服务配置"""
    host: str
    port: int
    validate_token_path: str = "/api/auth/validate-human-token"
    timeout: int = 10
    token_cache_enabled: bool = True
    token_cache_ttl_minutes: int = 15

    @property
    def validate_url(self) -> str:
        """生成验证token的URL"""
        return f"http://{self.host}:{self.port}{self.validate_token_path}"


class RegistryMenuLevelConfig(BaseModel):
    """菜单层级配置"""
    name: Optional[str] = None
    name_en: Optional[str] = None


class RegistryMenuConfig(BaseModel):
    """菜单配置"""
    id: str
    path: str
    icon: Optional[str] = None
    order: int = 0
    level1: Optional[RegistryMenuLevelConfig] = None
    level2: Optional[RegistryMenuLevelConfig] = None
    level3: Optional[RegistryMenuLevelConfig] = None


class RegistryConfig(BaseModel):
    """Menu注册中心配置"""
    enabled: bool = True
    menu_service_url: str
    service_id: str
    service_name: str
    host: str = "0.0.0.0"
    port: int
    maturity: str = "开发中"
    description: str
    api_prefix: str
    menu: Optional[RegistryMenuConfig] = None


class KubernetesConfig(BaseModel):
    """K8S配置"""
    in_cluster: bool = True
    kubeconfig: Optional[str] = None
    connection_timeout: int = 30


class K8sServiceConfig(BaseModel):
    """platform-k8s 服务配置"""
    host: str = "secflow-platform-k8s"
    port: int = 80
    timeout: int = 30


class TLSSecretConfig(BaseModel):
    """TLS Secret配置"""
    name: str = "project-tls-secret"
    crt_file: str = "/etc/secflow/certs/tls.crt"
    key_file: str = "/etc/secflow/certs/tls.key"


class AppConfig(BaseModel):
    """应用配置"""
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class LoggingConfig(BaseModel):
    """日志配置"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Config(BaseModel):
    """主配置类"""
    database: DatabaseConfig
    auth_service: AuthServiceConfig
    registry: RegistryConfig
    kubernetes: KubernetesConfig
    k8s_service: K8sServiceConfig = K8sServiceConfig()
    tls_secret: TLSSecretConfig
    app: AppConfig
    logging: LoggingConfig = LoggingConfig()


_config: Optional[Config] = None


def load_config(config_path: Optional[str] = None) -> Config:
    """
    加载配置文件

    Args:
        config_path: 配置文件路径，默认使用config.yaml

    Returns:
        Config对象
    """
    global _config

    if _config is not None:
        return _config

    if config_path is None:
        # 默认查找当前目录或父目录的config.yaml
        possible_paths = [
            "config.yaml",
            os.path.join(os.path.dirname(__file__), "config.yaml"),
            os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
        ]
        for path in possible_paths:
            if os.path.exists(path):
                config_path = path
                break

    if config_path is None or not os.path.exists(config_path):
        raise FileNotFoundError(f"配置文件未找到: {config_path}")

    with open(config_path, 'r', encoding='utf-8') as f:
        config_data = yaml.safe_load(f)

    _config = Config(**config_data)

    # 验证TLS证书文件
    tls_valid, tls_error = validate_tls_files(_config.tls_secret)
    if not tls_valid:
        raise RuntimeError(f"TLS证书验证失败: {tls_error}")

    return _config


def get_config() -> Config:
    """获取配置对象"""
    global _config
    if _config is None:
        return load_config()
    return _config


def reload_config(config_path: Optional[str] = None) -> Config:
    """重新加载配置"""
    global _config
    _config = None
    return load_config(config_path)


def validate_tls_files(tls_config: TLSSecretConfig) -> tuple[bool, str]:
    """
    验证TLS证书文件是否存在且格式正确

    Args:
        tls_config: TLS Secret配置

    Returns:
        tuple: (是否验证通过, 错误信息)
    """
    crt_file = tls_config.crt_file
    key_file = tls_config.key_file

    # 检查证书文件是否存在
    if not os.path.exists(crt_file):
        return False, f"TLS证书文件不存在: {crt_file}"

    # 检查私钥文件是否存在
    if not os.path.exists(key_file):
        return False, f"TLS私钥文件不存在: {key_file}"

    # 检查证书文件是否可读
    if not os.access(crt_file, os.R_OK):
        return False, f"TLS证书文件不可读: {crt_file}"

    # 检查私钥文件是否可读
    if not os.access(key_file, os.R_OK):
        return False, f"TLS私钥文件不可读: {key_file}"

    try:
        # 读取并验证证书文件内容
        with open(crt_file, 'r', encoding='utf-8') as f:
            crt_content = f.read()

        if not crt_content.strip():
            return False, f"TLS证书文件为空: {crt_file}"

        # 检查证书基本格式 (PEM格式)
        if '-----BEGIN CERTIFICATE-----' not in crt_content:
            return False, f"TLS证书文件格式错误，缺少BEGIN CERTIFICATE标记: {crt_file}"

        if '-----END CERTIFICATE-----' not in crt_content:
            return False, f"TLS证书文件格式错误，缺少END CERTIFICATE标记: {crt_file}"

        # 验证证书链（检查是否有至少一个证书）
        cert_matches = re.findall(r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----', crt_content)
        if not cert_matches:
            return False, f"TLS证书文件未找到有效的证书: {crt_file}"

    except Exception as e:
        return False, f"读取TLS证书文件失败: {crt_file}, 错误: {e}"

    try:
        # 读取并验证私钥文件内容
        with open(key_file, 'r', encoding='utf-8') as f:
            key_content = f.read()

        if not key_content.strip():
            return False, f"TLS私钥文件为空: {key_file}"

        # 检查私钥基本格式 (支持PKCS#1和PKCS#8)
        valid_key_begin = (
            '-----BEGIN PRIVATE KEY-----' in key_content or
            '-----BEGIN RSA PRIVATE KEY-----' in key_content or
            '-----BEGIN EC PRIVATE KEY-----' in key_content
        )
        valid_key_end = (
            '-----END PRIVATE KEY-----' in key_content or
            '-----END RSA PRIVATE KEY-----' in key_content or
            '-----END EC PRIVATE KEY-----' in key_content
        )

        if not valid_key_begin:
            return False, f"TLS私钥文件格式错误，缺少BEGIN PRIVATE KEY标记: {key_file}"

        if not valid_key_end:
            return False, f"TLS私钥文件格式错误，缺少END PRIVATE KEY标记: {key_file}"

    except Exception as e:
        return False, f"读取TLS私钥文件失败: {key_file}, 错误: {e}"

    logger.info(f"TLS证书验证通过: CRT={crt_file}, KEY={key_file}, 证书链包含 {len(cert_matches)} 个证书")
    return True, ""
