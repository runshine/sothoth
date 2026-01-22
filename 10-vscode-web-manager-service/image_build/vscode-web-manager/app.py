"""
source_manager.py - 源码管理系统单文件版本
优化错误处理：将Code-Server相关API的错误信息返回给客户端

更新内容：
1. 增强KubernetesManager支持自定义鉴权配置（Token认证、证书认证）
2. 删除项目时默认删除所有相关资源（文件和Code-Server）
3. 启动时检测K8S先关的配置是否正确，不正确需要报错并退出
4. 修复Kubernetes连接验证中的API调用错误
5. 修改project_id生成方式为md5(md5(project_name)_md5(上传的压缩包)_time)
6. 修改PVC创建逻辑：项目创建时立即创建PVC并拷贝文件
7. 修改Code-Server创建逻辑：直接使用已有的PVC
8. 修改Code-Server删除逻辑：保留PVC，只删除运行资源
9. 新增重建PVC的API
10. 源码项目异步初始化，定义项目状态，提供状态查询和日志查询接口
11. 删除项目时强制删除所有K8S资源（包括PVC），避免资源泄露
"""

import os
import sys
import time
import json
import uuid
import hashlib
import shutil
import zipfile
import tarfile
import secrets
import threading
import mimetypes
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Union
from concurrent.futures import ThreadPoolExecutor
import base64
import re
from kubernetes.stream import stream
from urllib.parse import quote_plus  # 添加这行

# ============ Kubernetes API 配置示例 ============
"""
Kubernetes API 配置示例：

1. 使用Token认证：
   export K8S_API_URL="https://your-k8s-api-server:6443"
   export K8S_API_TOKEN="your-bearer-token-here"
   export K8S_VERIFY_SSL="false"  # 如果使用自签名证书

2. 使用证书认证：
   export K8S_API_URL="https://your-k8s-api-server:6443"
   export K8S_API_CERT="/path/to/client.crt"
   export K8S_API_KEY="/path/to/client.key"
   export K8S_CA_CERT="/path/to/ca.crt"  # 可选

3. 集群内配置：
   export IN_K8S="true"
   # 自动使用ServiceAccount token

4. 使用kubeconfig：
   # 不设置K8S_API_URL，自动使用~/.kube/config
"""

# ============ 配置 ============
class Config:
    """应用配置"""
    # 基础配置
    APP_NAME = "源码管理系统"
    VERSION = "1.0.0"
    API_PREFIX = "/api"

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
    K8S_STORAGE_CLASS = os.getenv("K8S_STORAGE_CLASS", "nfs-client")
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
    def init_dirs(cls):
        """初始化目录"""
        for d in [cls.UPLOAD_DIR, cls.ARCHIVE_DIR, cls.EXTRACT_DIR, cls.DOWNLOAD_DIR, cls.TASK_LOG_DIR]:
            os.makedirs(d, exist_ok=True)
            print(f"创建目录: {d}")

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

# ============ 初始化配置 ============
Config.init_dirs()

# ============ 日志配置 ============
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============ 导入依赖 ============
try:
    from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Query, BackgroundTasks, Request, status, Body
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
    from pydantic import BaseModel, Field
    import uvicorn
    from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, BigInteger, ForeignKey, func, desc, and_, or_
    from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship, joinedload
    from sqlalchemy.pool import QueuePool
    from passlib.context import CryptContext
    FASTAPI_AVAILABLE = True
except ImportError as e:
    print(f"错误: 缺少依赖 - {e}")
    print("请运行: pip install fastapi uvicorn sqlalchemy pymysql passlib python-multipart")
    sys.exit(1)

# 尝试不同的 JWT 导入方式
try:
    # 尝试导入 PyJWT
    import jwt
    JWT_AVAILABLE = True
    JWT_LIB = "pyjwt"
    print("使用 PyJWT 库")
except ImportError:
    try:
        # 尝试导入 python-jose 的 JWT
        from jose import jwt
        JWT_AVAILABLE = True
        JWT_LIB = "jose"
        print("使用 python-jose JWT 库")
    except ImportError:
        JWT_AVAILABLE = False
        print("警告: JWT 库不可用，请安装 PyJWT 或 python-jose")
        print("pip install PyJWT 或 pip install python-jose[cryptography]")

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    print("警告: kubernetes-client 未安装，K8S功能将不可用")

# ============ 数据库模型 ============
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())

class Project(Base):
    __tablename__ = "projects"
    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text)
    original_filename = Column(String(500))
    archive_path = Column(String(500))
    extract_path = Column(String(500))
    file_count = Column(Integer, default=0)
    total_size = Column(BigInteger, default=0)
    archive_size = Column(BigInteger, default=0)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    # 项目状态
    status = Column(String(20), default=Config.PROJECT_STATUS_PENDING)  # pending, initializing, ready, error, deleting
    init_log_path = Column(String(500))  # 初始化日志文件路径
    init_error = Column(Text)  # 初始化错误信息
    # PVC相关字段
    pvc_name = Column(String(100), nullable=True)
    pvc_status = Column(String(20), default="pending")  # pending, creating, ready, error
    pvc_size = Column(String(20), default="5Gi")
    file_synced = Column(Boolean, default=False)  # 文件是否已同步到PVC
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    initialized_at = Column(DateTime)  # 初始化完成时间
    owner = relationship("User", backref="projects")

class ProjectFile(Base):
    __tablename__ = "project_files"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(String(64), ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    file_path = Column(String(1000), nullable=False)
    file_name = Column(String(300), nullable=False, index=True)
    file_size = Column(BigInteger, default=0)
    file_type = Column(String(50))
    created_at = Column(DateTime, server_default=func.now())
    project = relationship("Project", backref="files")

class CodeServer(Base):
    __tablename__ = "code_servers"
    id = Column(String(64), primary_key=True, index=True)
    project_id = Column(String(64), ForeignKey("projects.id", ondelete="CASCADE"), unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    deployment_name = Column(String(100))
    service_name = Column(String(100))
    service_ip = Column(String(100))
    service_port = Column(Integer)
    access_url = Column(String(500))
    status = Column(String(20), default="pending")  # pending, creating, running, stopped, error, deleting
    pod_name = Column(String(100))
    pod_status = Column(String(50))
    cpu_limit = Column(String(20), default="1000m")
    memory_limit = Column(String(20), default="1024Mi")
    password = Column(String(100))  # 存储访问密码
    created_at = Column(DateTime, server_default=func.now())
    started_at = Column(DateTime)
    stopped_at = Column(DateTime)
    owner = relationship("User", backref="code_servers")
    project = relationship("Project", backref="code_server", uselist=False)

class ProjectTaskLog(Base):
    __tablename__ = "project_task_logs"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(String(64), ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    task_type = Column(String(50), nullable=False)  # init, delete, recreate_pvc
    task_id = Column(String(100), nullable=False, index=True)
    status = Column(String(20), default="running")  # running, completed, failed
    log_path = Column(String(500))  # 日志文件路径
    error_message = Column(Text)
    created_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime)
    project = relationship("Project", backref="task_logs")


# ============ 数据库连接 ============

# 使用安全的数据库URL
safe_database_url = Config.DATABASE_URL
print(f"使用数据库URL: {safe_database_url}")

engine = create_engine(
    safe_database_url,  # 使用安全的URL
    poolclass=QueuePool,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,  # 添加连接健康检查
    echo=Config.DEBUG,   # 调试模式下显示SQL
    connect_args={
        'ssl': False,
        'connect_timeout': 10
    } if safe_database_url.startswith("mysql") else {"check_same_thread": False}
    # SQLite的连接参数保持不变
    # connect_args={"check_same_thread": False} if safe_database_url.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """初始化数据库"""
    try:
        Base.metadata.create_all(bind=engine)
        print("数据库表创建成功")

        # 创建默认管理员
        db = SessionLocal()
        try:
            admin = db.query(User).filter(User.username == "admin").first()
            if not admin:
                pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
                admin = User(
                    username="admin",
                    email="admin@example.com",
                    password_hash=pwd_context.hash("admin123"),
                    is_admin=True
                )
                db.add(admin)
                db.commit()
                print("创建默认管理员: admin/admin123")
        except Exception as e:
            print(f"创建默认管理员失败: {e}")
            print(f"错误详情: {type(e).__name__}: {str(e)}")
            db.rollback()
        finally:
            db.close()
    except Exception as e:
        print(f"初始化数据库失败: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()  # 打印详细堆栈信息
        exit(255)

# ============ 认证工具 ============
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    if not JWT_AVAILABLE:
        raise RuntimeError("JWT 库不可用")

    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    if JWT_LIB == "pyjwt":
        encoded_jwt = jwt.encode(to_encode, Config.SECRET_KEY, algorithm=Config.ALGORITHM)
    else:  # jose
        encoded_jwt = jwt.encode(to_encode, Config.SECRET_KEY, algorithm=Config.ALGORITHM)

    return encoded_jwt

async def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: Session = Depends(get_db)
):
    if not JWT_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT 库不可用",
        )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        token = credentials.credentials
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=[Config.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None or not user.is_active:
        raise credentials_exception

    return user

# ============ 错误处理工具 ============
class CodeServerError(Exception):
    """Code-Server操作异常"""
    def __init__(self, message: str, details: Optional[Dict] = None, status_code: int = 500):
        self.message = message
        self.details = details or {}
        self.status_code = status_code
        super().__init__(self.message)

class ProjectError(Exception):
    """项目操作异常"""
    def __init__(self, message: str, details: Optional[Dict] = None, status_code: int = 500):
        self.message = message
        self.details = details or {}
        self.status_code = status_code
        super().__init__(self.message)

# ============ 文件工具 ============
class FileUtils:
    @staticmethod
    def calculate_md5(file_path: str) -> str:
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    @staticmethod
    def generate_project_id(project_name: str, file_md5: str) -> str:
        """生成项目ID：md5(md5(project_name)_file_md5_time)"""
        # 计算项目名的MD5
        name_md5 = hashlib.md5(project_name.encode()).hexdigest()
        # 拼接字符串：name_md5_file_md5
        combined_str = f"{name_md5}_{file_md5}_{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        # 对拼接后的字符串计算MD5
        return hashlib.md5(combined_str.encode()).hexdigest()

    @staticmethod
    def allowed_file(filename: str) -> bool:
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

    @staticmethod
    def extract_archive(file_path: str, extract_to: str) -> bool:
        try:
            if file_path.endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as f:
                    f.extractall(extract_to)
            elif file_path.endswith('.tar.gz') or file_path.endswith('.tgz'):
                with tarfile.open(file_path, 'r:gz') as f:
                    f.extractall(extract_to)
            elif file_path.endswith('.tar'):
                with tarfile.open(file_path, 'r:') as f:
                    f.extractall(extract_to)
            elif file_path.endswith('.bz2'):
                with tarfile.open(file_path, 'r:bz2') as f:
                    f.extractall(extract_to)
            else:
                raise ValueError(f"不支持的格式: {file_path}")
            return True
        except Exception as e:
            logger.error(f"解压失败: {e}")
            return False

    @staticmethod
    def scan_files(directory: str) -> List[Dict[str, Any]]:
        files = []
        try:
            for root, _, filenames in os.walk(directory):
                for filename in filenames:
                    if filename.startswith('.'):
                        continue
                    file_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(file_path, directory)
                    try:
                        size = os.path.getsize(file_path)
                        mime, _ = mimetypes.guess_type(filename)
                        files.append({
                            "path": rel_path,
                            "name": filename,
                            "size": size,
                            "type": mime or "application/octet-stream"
                        })
                    except:
                        continue
        except Exception as e:
            logger.error(f"扫描文件失败: {e}")
        return files

    @staticmethod
    def is_safe_path(base_path: str, requested_path: str) -> bool:
        """检查请求路径是否在基础路径内（防止目录遍历攻击）"""
        try:
            # 规范化路径
            base_path = os.path.abspath(base_path)
            requested_full_path = os.path.abspath(os.path.join(base_path, requested_path))

            # 检查请求路径是否在基础路径内
            return os.path.commonpath([base_path]) == os.path.commonpath([base_path, requested_full_path])
        except Exception:
            return False

    @staticmethod
    def download_file(project_extract_path: str, file_path: str, user_id: int) -> Optional[str]:
        """
        下载单个文件

        Args:
            project_extract_path: 项目解压路径
            file_path: 项目内相对文件路径
            user_id: 用户ID（用于创建临时目录）

        Returns:
            临时文件路径或None
        """
        try:
            # 检查路径安全性
            if not FileUtils.is_safe_path(project_extract_path, file_path):
                logger.error(f"路径不安全: {file_path}")
                return None

            # 构建完整文件路径
            full_path = os.path.join(project_extract_path, file_path)

            # 检查文件是否存在
            if not os.path.exists(full_path) or not os.path.isfile(full_path):
                logger.error(f"文件不存在: {full_path}")
                return None

            # 检查文件大小
            file_size = os.path.getsize(full_path)
            if file_size > Config.MAX_DOWNLOAD_SIZE:
                logger.error(f"文件太大: {file_size} > {Config.MAX_DOWNLOAD_SIZE}")
                return None

            # 创建用户临时目录
            user_temp_dir = os.path.join(Config.DOWNLOAD_DIR, str(user_id))
            os.makedirs(user_temp_dir, exist_ok=True)

            # 生成临时文件名
            filename = os.path.basename(file_path)
            temp_filename = f"{int(time.time())}_{filename}"
            temp_path = os.path.join(user_temp_dir, temp_filename)

            # 复制文件到临时目录
            shutil.copy2(full_path, temp_path)

            # 清理旧的临时文件（保留最近10个文件）
            temp_files = sorted(
                [f for f in os.listdir(user_temp_dir) if f.endswith(f"_{filename}")],
                key=lambda x: os.path.getmtime(os.path.join(user_temp_dir, x))
            )

            for old_file in temp_files[:-10]:  # 保留最近10个，删除其他
                try:
                    os.remove(os.path.join(user_temp_dir, old_file))
                except:
                    pass

            return temp_path

        except Exception as e:
            logger.error(f"下载文件失败: {e}")
            return None

    @staticmethod
    def download_directory(project_extract_path: str, dir_path: str, user_id: int) -> Optional[str]:
        """
        下载目录（打包为zip）

        Args:
            project_extract_path: 项目解压路径
            dir_path: 项目内相对目录路径
            user_id: 用户ID（用于创建临时目录）

        Returns:
            临时zip文件路径或None
        """
        try:
            # 检查路径安全性
            if not FileUtils.is_safe_path(project_extract_path, dir_path):
                logger.error(f"路径不安全: {dir_path}")
                return None

            # 构建完整目录路径
            full_path = os.path.join(project_extract_path, dir_path)

            # 检查目录是否存在
            if not os.path.exists(full_path) or not os.path.isdir(full_path):
                logger.error(f"目录不存在: {full_path}")
                return None

            # 创建用户临时目录
            user_temp_dir = os.path.join(Config.DOWNLOAD_DIR, str(user_id))
            os.makedirs(user_temp_dir, exist_ok=True)

            # 生成临时zip文件名
            dir_name = os.path.basename(dir_path) or "root"
            temp_filename = f"{int(time.time())}_{dir_name}.zip"
            temp_path = os.path.join(user_temp_dir, temp_filename)

            # 创建zip文件
            with zipfile.ZipFile(temp_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(full_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        # 计算相对路径
                        rel_path = os.path.relpath(file_path, project_extract_path)
                        zipf.write(file_path, rel_path)

            # 清理旧的临时文件（保留最近10个文件）
            temp_files = sorted(
                [f for f in os.listdir(user_temp_dir) if f.endswith(f"_{dir_name}.zip")],
                key=lambda x: os.path.getmtime(os.path.join(user_temp_dir, x))
            )

            for old_file in temp_files[:-10]:  # 保留最近10个，删除其他
                try:
                    os.remove(os.path.join(user_temp_dir, old_file))
                except:
                    pass

            return temp_path

        except Exception as e:
            logger.error(f"下载目录失败: {e}")
            return None

    @staticmethod
    def download_project_files(project_extract_path: str, file_paths: List[str], user_id: int) -> Optional[str]:
        """
        下载多个文件（打包为zip）

        Args:
            project_extract_path: 项目解压路径
            file_paths: 项目内相对文件路径列表
            user_id: 用户ID（用于创建临时目录）

        Returns:
            临时zip文件路径或None
        """
        try:
            # 创建用户临时目录
            user_temp_dir = os.path.join(Config.DOWNLOAD_DIR, str(user_id))
            os.makedirs(user_temp_dir, exist_ok=True)

            # 生成临时zip文件名
            temp_filename = f"{int(time.time())}_selected_files.zip"
            temp_path = os.path.join(user_temp_dir, temp_filename)

            # 创建zip文件
            with zipfile.ZipFile(temp_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in file_paths:
                    # 检查路径安全性
                    if not FileUtils.is_safe_path(project_extract_path, file_path):
                        logger.warning(f"跳过不安全的路径: {file_path}")
                        continue

                    # 构建完整文件路径
                    full_path = os.path.join(project_extract_path, file_path)

                    # 检查文件是否存在
                    if os.path.exists(full_path) and os.path.isfile(full_path):
                        zipf.write(full_path, file_path)
                    elif os.path.exists(full_path) and os.path.isdir(full_path):
                        # 如果是目录，添加目录下所有文件
                        for root, dirs, files in os.walk(full_path):
                            for file in files:
                                file_full_path = os.path.join(root, file)
                                rel_path = os.path.relpath(file_full_path, project_extract_path)
                                zipf.write(file_full_path, rel_path)

            # 清理旧的临时文件（保留最近10个文件）
            temp_files = sorted(
                [f for f in os.listdir(user_temp_dir) if f.endswith("_selected_files.zip")],
                key=lambda x: os.path.getmtime(os.path.join(user_temp_dir, x))
            )

            for old_file in temp_files[:-10]:  # 保留最近10个，删除其他
                try:
                    os.remove(os.path.join(user_temp_dir, old_file))
                except:
                    pass

            return temp_path

        except Exception as e:
            logger.error(f"下载多个文件失败: {e}")
            return None

# ============ 日志记录工具 ============
class TaskLogger:
    """任务日志记录器"""

    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        self.log_buffer = []
        self.start_time = datetime.now(timezone.utc)

    def log(self, message: str, level: str = "INFO"):
        """记录日志"""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.log_buffer.append(log_entry)

        # 立即写入文件
        try:
            with open(self.log_file_path, 'a', encoding='utf-8') as f:
                f.write(log_entry + "\n")
        except Exception as e:
            print(f"写入日志文件失败: {e}")

    def info(self, message: str):
        self.log(message, "INFO")

    def error(self, message: str):
        self.log(message, "ERROR")

    def warning(self, message: str):
        self.log(message, "WARNING")

    def get_log_content(self, lines: int = 100) -> str:
        """获取日志内容"""
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
                if lines <= 0:
                    return "".join(all_lines)
                return "".join(all_lines[-lines:])
        except Exception as e:
            return f"读取日志文件失败: {str(e)}\n缓冲区日志:\n" + "\n".join(self.log_buffer[-lines:])

    def get_all_logs(self) -> str:
        """获取所有日志"""
        return self.get_log_content(lines=0)

# ============ Kubernetes管理器 ============
class KubernetesManager:
    def __init__(self, validate_connection: bool = True):
        self.namespace = Config.K8S_NAMESPACE
        self.storage_class = Config.K8S_STORAGE_CLASS
        self.api_url = Config.K8S_API_URL
        self.api_token = Config.K8S_API_TOKEN
        self.api_cert = Config.K8S_API_CERT
        self.api_key = Config.K8S_API_KEY
        self.ca_cert = Config.K8S_CA_CERT
        self.verify_ssl = Config.K8S_VERIFY_SSL

        if not K8S_AVAILABLE:
            self.available = False
            logger.error("Kubernetes客户端不可用，请安装kubernetes-client")
            raise RuntimeError("Kubernetes客户端不可用")

        try:
            logger.info(f"开始初始化Kubernetes客户端...")
            logger.info(f"IN_K8S环境变量: {os.getenv('IN_K8S', '未设置')}")
            logger.info(f"K8S_API_URL: {self.api_url}")
            logger.info(f"K8S_NAMESPACE: {self.namespace}")

            if os.getenv("IN_K8S", "false").lower() == "true":
                logger.info("检测到IN_K8S=true，尝试使用集群内配置...")
                try:
                    config.load_incluster_config()
                    logger.info("✓ 使用集群内K8S配置成功")
                except Exception as e:
                    logger.error(f"✗ 加载集群内配置失败: {str(e)}")
                    raise
            elif self.api_url:
                # 使用自定义API URL和鉴权配置
                logger.info(f"使用自定义API URL: {self.api_url}")
                configuration = client.Configuration()
                configuration.host = self.api_url

                # 设置鉴权方式
                if self.api_token:
                    # Token认证
                    configuration.api_key['authorization'] = f"Bearer {self.api_token}"
                    configuration.api_key_prefix['authorization'] = 'Bearer'
                    logger.info(f"使用Token认证访问K8S API")
                elif self.api_cert and self.api_key:
                    # 证书认证
                    configuration.cert_file = self.api_cert
                    configuration.key_file = self.api_key
                    logger.info(f"使用证书认证访问K8S API")
                else:
                    # 尝试使用kubeconfig
                    logger.warning("自定义API URL但未提供鉴权信息，尝试使用kubeconfig")
                    try:
                        config.load_kube_config()
                        logger.info("✓ 使用kubeconfig配置成功")
                    except Exception as e:
                        logger.error(f"✗ 加载kubeconfig失败: {str(e)}")
                        raise

                # SSL配置
                if self.ca_cert:
                    configuration.ssl_ca_cert = self.ca_cert
                configuration.verify_ssl = self.verify_ssl

                # 应用配置
                client.Configuration.set_default(configuration)
                logger.info(f"✓ 使用自定义K8S API URL配置成功")
            else:
                # 默认使用kubeconfig
                logger.info("未指定API URL，尝试使用kubeconfig配置...")
                try:
                    config.load_kube_config()
                    logger.info("✓ 使用kubeconfig配置成功")
                except Exception as e:
                    logger.error(f"✗ 加载kubeconfig失败: {str(e)}")
                    raise

            # 初始化各个API客户端
            logger.info("初始化Kubernetes API客户端...")
            try:
                self.core_v1 = client.CoreV1Api()
                self.apps_v1 = client.AppsV1Api()
                self.batch_v1 = client.BatchV1Api()
                self.networking_v1 = client.NetworkingV1Api()
                self.storage_v1 = client.StorageV1Api()
                logger.info("✓ Kubernetes API客户端初始化成功")
            except Exception as e:
                logger.error(f"✗ 初始化API客户端失败: {str(e)}")
                raise

            self.available = True

            # 验证连接
            if validate_connection:
                logger.info("开始验证Kubernetes连接...")
                try:
                    self._validate_connection()
                    logger.info("✓ Kubernetes连接验证成功")
                except Exception as e:
                    logger.error(f"✗ Kubernetes连接验证失败: {str(e)}")
                    raise

            logger.info(f"✓ Kubernetes客户端初始化成功，命名空间: {self.namespace}")

        except Exception as e:
            logger.error(f"✗ Kubernetes客户端初始化失败")
            logger.error(f"错误类型: {type(e).__name__}")
            logger.error(f"错误信息: {str(e)}")

            # 打印详细的堆栈信息
            import traceback
            error_details = traceback.format_exc()
            logger.error(f"详细堆栈信息:\n{error_details}")

            self.available = False

            # 根据不同的异常类型提供更详细的错误信息
            error_message = "Kubernetes客户端初始化失败"
            error_details = {"error_type": type(e).__name__, "error": str(e)}

            # 添加特定错误信息
            if "Unauthorized" in str(e) or "Forbidden" in str(e):
                error_message = "Kubernetes认证失败"
                error_details["suggestion"] = "请检查Token、证书或kubeconfig文件的权限"
            elif "Connection refused" in str(e) or "timed out" in str(e):
                error_message = "无法连接到Kubernetes API服务器"
                error_details["suggestion"] = "请检查K8S_API_URL是否正确，网络是否可达"
            elif "certificate verify failed" in str(e):
                error_message = "SSL证书验证失败"
                error_details["suggestion"] = "请检查K8S_CA_CERT证书或设置K8S_VERIFY_SSL=false"
            elif "No such file or directory" in str(e):
                error_message = "配置文件或证书文件不存在"
                error_details["suggestion"] = "请检查证书文件路径是否正确"

            raise CodeServerError(
                message=error_message,
                details=error_details,
                status_code=500
            )

    def _validate_connection(self):
        """严格验证K8S连接和配置"""
        validation_errors = []

        try:
            # 检查是否在K8S集群内部
            in_k8s = os.getenv("IN_K8S", "false").lower() == "true"

            if in_k8s:
                logger.info("在Kubernetes集群内部运行，使用ServiceAccount认证")

            # 尝试获取K8S版本信息
            try:
                version_info = client.VersionApi().get_code()
                logger.info(f"Kubernetes连接成功，版本: {version_info.git_version}")
            except Exception as e:
                validation_errors.append(f"无法获取Kubernetes版本: {str(e)}")
                raise RuntimeError(f"无法连接到Kubernetes API: {str(e)}")

            # 严格验证命名空间是否存在
            try:
                namespace_info = self.core_v1.read_namespace(name=self.namespace)
                logger.info(f"命名空间验证成功: {self.namespace} (状态: {namespace_info.status.phase})")
            except ApiException as e:
                if e.status == 403:
                    validation_errors.append(f"无权访问命名空间 {self.namespace}，请检查权限配置")
                    raise RuntimeError(f"命名空间权限不足: {self.namespace}")
                elif e.status == 404:
                    validation_errors.append(f"命名空间不存在: {self.namespace}")
                    raise RuntimeError(f"命名空间不存在: {self.namespace}")
                else:
                    validation_errors.append(f"验证命名空间失败: {e.reason}")
                    raise RuntimeError(f"命名空间验证失败: {e.reason}")

            # 严格验证存储类是否存在
            try:
                storage_classes = self.storage_v1.list_storage_class()
                storage_class_names = [sc.metadata.name for sc in storage_classes.items]

                if not self.storage_class:
                    validation_errors.append("K8S_STORAGE_CLASS 配置不能为空")
                    raise RuntimeError("存储类配置为空")

                if self.storage_class not in storage_class_names:
                    validation_errors.append(f"存储类不存在: {self.storage_class}")
                    validation_errors.append(f"可用的存储类: {', '.join(storage_class_names)}")
                    raise RuntimeError(f"存储类不存在: {self.storage_class}")

                logger.info(f"存储类验证成功: {self.storage_class}")
            except ApiException as e:
                validation_errors.append(f"验证存储类失败: {e.reason}")
                raise RuntimeError(f"存储类验证失败: {e.reason}")
            except Exception as e:
                validation_errors.append(f"获取存储类列表失败: {str(e)}")
                raise RuntimeError(f"存储类验证失败: {str(e)}")

            # 验证服务类型是否有效
            valid_service_types = ["LoadBalancer", "NodePort", "ClusterIP"]
            if Config.K8S_SERVICE_TYPE not in valid_service_types:
                validation_errors.append(f"服务类型无效: {Config.K8S_SERVICE_TYPE}，有效值: {', '.join(valid_service_types)}")
                raise RuntimeError(f"服务类型无效: {Config.K8S_SERVICE_TYPE}")

            # 验证端口配置
            if Config.K8S_SERVICE_PORT < 1 or Config.K8S_SERVICE_PORT > 65535:
                validation_errors.append(f"服务端口无效: {Config.K8S_SERVICE_PORT}")
                raise RuntimeError(f"服务端口无效: {Config.K8S_SERVICE_PORT}")

            if Config.K8S_CONTAINER_PORT < 1 or Config.K8S_CONTAINER_PORT > 65535:
                validation_errors.append(f"容器端口无效: {Config.K8S_CONTAINER_PORT}")
                raise RuntimeError(f"容器端口无效: {Config.K8S_CONTAINER_PORT}")

            # 验证命名空间格式（Kubernetes命名空间命名规则）
            if not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', self.namespace):
                validation_errors.append(f"命名空间格式无效: {self.namespace}，只能包含小写字母、数字和连字符")
                raise RuntimeError(f"命名空间格式无效: {self.namespace}")

            # 验证是否具有必要的权限
            try:
                # 检查是否有创建Deployment的权限
                self.apps_v1.list_namespaced_deployment(namespace=self.namespace, limit=1)
                logger.info(f"Deployment权限验证成功")
            except ApiException as e:
                if e.status == 403:
                    validation_errors.append(f"缺少创建Deployment的权限")
                    raise RuntimeError(f"权限不足: 无法创建Deployment")

            try:
                # 检查是否有创建Service的权限
                self.core_v1.list_namespaced_service(namespace=self.namespace, limit=1)
                logger.info(f"Service权限验证成功")
            except ApiException as e:
                if e.status == 403:
                    validation_errors.append(f"缺少创建Service的权限")
                    raise RuntimeError(f"权限不足: 无法创建Service")

            try:
                # 检查是否有创建PVC的权限
                self.core_v1.list_namespaced_persistent_volume_claim(namespace=self.namespace, limit=1)
                logger.info(f"PVC权限验证成功")
            except ApiException as e:
                if e.status == 403:
                    validation_errors.append(f"缺少创建PVC的权限")
                    raise RuntimeError(f"权限不足: 无法创建PVC")

            logger.info("所有Kubernetes配置验证通过")
            return True

        except Exception as e:
            if validation_errors:
                error_msg = "Kubernetes配置验证失败:\n" + "\n".join(f"  • {error}" for error in validation_errors)
                logger.error(error_msg)
            raise

    def generate_resource_name(self, project_id: str, resource_type: str) -> str:
        # 由于project_id现在是一个32字符的MD5，直接取前8位
        short_id = project_id[:8]
        name = f"code-{resource_type}-{short_id}".lower()
        name = re.sub(r'[^a-z0-9-]', '-', name)
        return name[:63].strip('-')

    def create_pvc(self, project_id: str, storage_size: str = "5Gi") -> str:
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        pvc_name = self.generate_resource_name(project_id, "pvc")

        try:
            pvc = client.V1PersistentVolumeClaim(
                metadata=client.V1ObjectMeta(
                    name=pvc_name,
                    namespace=self.namespace,
                    labels={
                        "app": "code-server",
                        "project-id": project_id,
                        "managed-by": "source-manager"
                    }
                ),
                spec=client.V1PersistentVolumeClaimSpec(
                    access_modes=["ReadWriteMany"],
                    storage_class_name=self.storage_class,
                    resources=client.V1ResourceRequirements(
                        requests={"storage": storage_size}
                    )
                )
            )

            self.core_v1.create_namespaced_persistent_volume_claim(
                namespace=self.namespace, body=pvc
            )
            logger.info(f"创建PVC: {pvc_name}")
            return pvc_name
        except ApiException as e:
            if e.status == 409:
                logger.warning(f"PVC已存在: {pvc_name}")
                return pvc_name
            logger.error(f"创建PVC失败: {e}")
            raise CodeServerError(
                message="创建PVC失败",
                details={
                    "project_id": project_id,
                    "pvc_name": pvc_name,
                    "error": str(e),
                    "status": e.status,
                    "reason": e.reason
                },
                status_code=500
            )

    def delete_pvc(self, project_id: str) -> bool:
        """删除PVC"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        pvc_name = self.generate_resource_name(project_id, "pvc")

        try:
            self.core_v1.delete_namespaced_persistent_volume_claim(
                name=pvc_name, namespace=self.namespace
            )
            logger.info(f"删除PVC: {pvc_name}")
            return True
        except ApiException as e:
            if e.status == 404:
                logger.warning(f"PVC不存在: {pvc_name}")
                return True
            logger.error(f"删除PVC失败: {e}")
            raise CodeServerError(
                message="删除PVC失败",
                details={
                    "project_id": project_id,
                    "pvc_name": pvc_name,
                    "error": str(e)
                },
                status_code=500
            )

    def recreate_pvc(self, project_id: str, storage_size: str = "5Gi") -> str:
        """重建PVC：先删除旧的，再创建新的"""
        try:
            # 先删除旧的PVC
            self.delete_pvc(project_id)
            # 等待PVC完全删除
            time.sleep(5)
            # 创建新的PVC
            pvc_name = self.create_pvc(project_id, storage_size)
            logger.info(f"重建PVC成功: {pvc_name}")
            return pvc_name
        except Exception as e:
            logger.error(f"重建PVC失败: {e}")
            raise

    def copy_archive_to_pvc(self, project_id: str, archive_path: str, pvc_name: str) -> bool:
        """复制压缩包到PVC并在PVC中解压 - 使用curl下载方式"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 检查HTTP配置
        if not Config.EXTERNAL_ACCESS_URL:
            raise CodeServerError(
                message="HTTP配置不完整，无法通过下载方式复制文件",
                details={"project_id": project_id, "config_error": "EXTERNAL_ACCESS_URL未设置"},
                status_code=500
            )

        job_name = f"extract-{project_id[:8]}"
        job_name = re.sub(r'[^a-z0-9-]', '-', job_name.lower())[:63]

        try:
            # 首先检查是否已有运行中的解压任务
            try:
                existing_jobs = self.batch_v1.list_namespaced_job(
                    namespace=self.namespace,
                    label_selector=f"job-name={job_name}"
                )
                if existing_jobs:
                    logger.info(f"解压任务已存在: {job_name}")
                    # 检查任务状态
                    if not existing_jobs.items:
                        logger.info(f"解压任务已失败，重新创建: {job_name}")
                        # 删除失败的任务
                        self.batch_v1.delete_namespaced_job(
                            name=job_name,
                            namespace=self.namespace,
                            propagation_policy="Background"
                        )
                    else:
                        job = existing_jobs.items[0]
                        if job.status.succeeded:
                            logger.info(f"解压任务已成功完成: {job_name}")
                            return True
                        elif job.status.failed:
                            logger.info(f"解压任务已失败，重新创建: {job_name}")
                            # 删除失败的任务
                            self.batch_v1.delete_namespaced_job(
                                name=job_name,
                                namespace=self.namespace,
                                propagation_policy="Background"
                            )
                        else:
                            logger.info(f"解压任务正在进行中: {job_name}")
                            return True
            except:
                pass

            # 检查压缩包文件是否存在
            if not os.path.exists(archive_path):
                raise CodeServerError(
                    message="压缩包文件不存在",
                    details={
                        "project_id": project_id,
                        "archive_path": archive_path
                    },
                    status_code=404
                )

            # 获取压缩包文件名和扩展名
            archive_filename = os.path.basename(archive_path)
            archive_ext = os.path.splitext(archive_filename)[1].lower()
            file_size = os.path.getsize(archive_path)

            logger.info(f"通过HTTP下载文件到PVC: {archive_filename}, 大小: {file_size} 字节")

            # 构建下载URL
            download_url = f"{Config.EXTERNAL_ACCESS_URL}{Config.API_PREFIX}/projects/{project_id}/download/archive-token?token={Config.ARCHIVE_DOWNLOAD_TOKEN}"

            # 解压命令
            extract_command = f"""
            # 安装必要的工具
            
            # 创建临时目录
            mkdir -p /temp
            
            echo "开始下载文件: {archive_filename}"
            echo "下载URL: {download_url}"
            echo "目标PVC: {pvc_name}"
            
            # 下载压缩包
            echo "使用curl下载文件..."
            curl -L --retry 3 --retry-delay 5 --max-time {Config.ARCHIVE_DOWNLOAD_TIMEOUT} \\
                 -o /temp/{archive_filename} \\
                 "{download_url}"
            
            # 检查下载结果
            download_status=$?
            if [ $download_status -ne 0 ]; then
                echo "下载失败，curl退出状态: $download_status"
                echo "尝试使用wget..."
                apk add --no-cache wget
                wget --tries=3 --timeout={Config.ARCHIVE_DOWNLOAD_TIMEOUT} \\
                     -O /temp/{archive_filename} \\
                     "{download_url}"
                wget_status=$?
                if [ $wget_status -ne 0 ]; then
                    echo "wget也失败，退出状态: $wget_status"
                    exit 1
                fi
            fi
            
            # 验证下载的文件
            if [ ! -f /temp/{archive_filename} ]; then
                echo "错误: 下载的文件不存在"
                exit 1
            fi
            
            actual_size=$(wc -c < /temp/{archive_filename})
            echo "下载完成，文件大小: $actual_size 字节"
            
            if [ $actual_size -lt 100 ]; then
                echo "警告: 下载的文件过小，可能是错误页面"
                echo "文件内容:"
                head -c 500 /temp/{archive_filename}
                exit 1
            fi
            
            echo "文件下载成功，开始解压..."
            
            # 切换到工作目录
            cd /workspace
            
            # 根据文件类型解压
            echo "开始解压文件..."
            case "{archive_ext}" in
                .zip)
                    echo "解压ZIP文件..."
                    unzip -o /temp/{archive_filename} -d /workspace/
                    ;;
                .tar)
                    echo "解压TAR文件..."
                    tar -xf /temp/{archive_filename} -C /workspace/
                    ;;
                .tar.gz|.tgz)
                    echo "解压TAR.GZ文件..."
                    tar -xzf /temp/{archive_filename} -C /workspace/
                    ;;
                .tar.bz2)
                    echo "解压TAR.BZ2文件..."
                    tar -xjf /temp/{archive_filename} -C /workspace/
                    ;;
                .gz)
                    echo "解压GZ文件..."
                    gzip -d /temp/{archive_filename} -c > /workspace/$(basename {archive_filename} .gz)
                    ;;
                *)
                    echo "未知的文件格式: {archive_ext}"
                    echo "尝试作为普通文件复制..."
                    cp /temp/{archive_filename} /workspace/
                    ;;
            esac
            
            # 清理临时文件
            rm -rf /temp/*
            
            # 检查解压结果
            echo "解压完成，检查工作目录内容:"
            ls -la /workspace/
            file_count=$(find /workspace -type f | wc -l)
            dir_count=$(find /workspace -type d | wc -l)
            echo "文件数量: $file_count"
            echo "目录数量: $dir_count"
            
            if [ $file_count -eq 0 ]; then
                echo "警告: 解压后没有找到任何文件"
            fi
            
            echo "任务完成"
            """

            # 设置环境变量
            env_vars = [
                client.V1EnvVar(name="DOWNLOAD_URL", value=download_url),
                client.V1EnvVar(name="ARCHIVE_FILENAME", value=archive_filename),
                client.V1EnvVar(name="PROJECT_ID", value=project_id),
                client.V1EnvVar(name="EXTERNAL_ACCESS_URL", value=Config.EXTERNAL_ACCESS_URL),
                client.V1EnvVar(name="ARCHIVE_DOWNLOAD_TIMEOUT", value=str(Config.ARCHIVE_DOWNLOAD_TIMEOUT))
            ]

            job = client.V1Job(
                metadata=client.V1ObjectMeta(
                    name=job_name,
                    namespace=self.namespace,
                    labels={
                        "app": "archive-download-extract",
                        "project-id": project_id,
                        "managed-by": "source-manager"
                    },
                    annotations={
                        "download-url": download_url,
                        "archive-filename": archive_filename,
                        "project-id": project_id
                    }
                ),
                spec=client.V1JobSpec(
                    backoff_limit=3,  # 允许重试3次
                    ttl_seconds_after_finished=600,  # 10分钟后删除
                    template=client.V1PodTemplateSpec(
                        metadata=client.V1ObjectMeta(
                            labels={
                                "app": "archive-download-extract",
                                "project-id": project_id,
                                "job-name": job_name
                            }
                        ),
                        spec=client.V1PodSpec(
                            restart_policy="OnFailure",  # 失败时重启
                            containers=[client.V1Container(
                                name="download-extract",
                                image="ghcr.io/runshine/vpn-monitor:latest",
                                command=["/bin/sh", "-c"],
                                args=[extract_command],
                                env=env_vars,
                                volume_mounts=[
                                    client.V1VolumeMount(
                                        name="workspace",
                                        mount_path="/workspace"
                                    ),
                                    client.V1VolumeMount(
                                        name="temp",
                                        mount_path="/temp"
                                    )
                                ],
                                resources=client.V1ResourceRequirements(
                                    requests={
                                        "cpu": "200m",
                                        "memory": "256Mi"
                                    },
                                    limits={
                                        "cpu": "1000m",
                                        "memory": "1024Mi"
                                    }
                                )
                            )],
                            volumes=[
                                client.V1Volume(
                                    name="workspace",
                                    persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                        claim_name=pvc_name
                                    )
                                ),
                                client.V1Volume(
                                    name="temp",
                                    empty_dir=client.V1EmptyDirVolumeSource()
                                )
                            ]
                        )
                    )
                )
            )

            self.batch_v1.create_namespaced_job(namespace=self.namespace, body=job)
            logger.info(f"创建下载解压任务: {job_name}")
            logger.info(f"下载URL: {download_url}")
            logger.info(f"目标PVC: {pvc_name}")

            # 等待任务完成
            max_wait_time = 600  # 10分钟
            start_time = time.time()
            last_status = None

            while time.time() - start_time < max_wait_time:
                time.sleep(5)
                try:
                    job_status = self.batch_v1.read_namespaced_job_status(
                        name=job_name, namespace=self.namespace
                    )

                    current_status = {
                        "active": job_status.status.active or 0,
                        "succeeded": job_status.status.succeeded or 0,
                        "failed": job_status.status.failed or 0
                    }

                    # 只有状态变化时才记录
                    if current_status != last_status:
                        logger.info(f"任务状态: 活跃={current_status['active']}, 成功={current_status['succeeded']}, 失败={current_status['failed']}")
                        last_status = current_status

                    if job_status.status.succeeded:
                        logger.info(f"下载解压任务成功完成: {job_name}")

                        # 获取成功日志
                        try:
                            pods = self.core_v1.list_namespaced_pod(
                                namespace=self.namespace,
                                label_selector=f"job-name={job_name}"
                            )
                            if pods.items:
                                pod = pods.items[0]
                                log_content = self.core_v1.read_namespaced_pod_log(
                                    name=pod.metadata.name,
                                    namespace=self.namespace,
                                    container="download-extract",
                                    tail_lines=50  # 获取更多日志用于记录
                                )
                                logger.info(f"下载解压任务成功日志(最后50行):\n{log_content}")
                        except Exception as log_error:
                            logger.warning(f"获取成功日志失败: {log_error}")

                        return True

                    elif job_status.status.failed:
                        logger.error(f"下载解压任务失败: {job_name}")

                        # 详细记录失败信息
                        error_details = {
                            "project_id": project_id,
                            "job_name": job_name,
                            "download_url": download_url,
                            "pvc_name": pvc_name,
                            "archive_filename": archive_filename,
                            "archive_size": file_size,
                            "error_timestamp": datetime.now(timezone.utc).isoformat()
                        }

                        pods_details = []
                        pods = self.core_v1.list_namespaced_pod(
                            namespace=self.namespace,
                            label_selector=f"job-name={job_name}"
                        )

                        for pod in pods.items:
                            pod_detail = {
                                "pod_name": pod.metadata.name,
                                "pod_status": pod.status.phase,
                                "creation_timestamp": pod.metadata.creation_timestamp.isoformat() if pod.metadata.creation_timestamp else None,
                                "containers": []
                            }

                            try:
                                pod_status = self.core_v1.read_namespaced_pod_status(
                                    name=pod.metadata.name, namespace=self.namespace
                                )

                                if pod_status.status.container_statuses:
                                    for container in pod_status.status.container_statuses:
                                        container_detail = {
                                            "container_name": container.name,
                                            "ready": container.ready,
                                            "restart_count": container.restart_count,
                                            "image": container.image
                                        }

                                        if container.state.terminated and container.state.terminated.exit_code != 0:
                                            container_detail.update({
                                                "exit_code": container.state.terminated.exit_code,
                                                "reason": container.state.terminated.reason,
                                                "message": container.state.terminated.message,
                                                "started_at": container.state.terminated.started_at.isoformat() if container.state.terminated.started_at else None,
                                                "finished_at": container.state.terminated.finished_at.isoformat() if container.state.terminated.finished_at else None
                                            })

                                            # 获取容器日志
                                            try:
                                                log_content = self.core_v1.read_namespaced_pod_log(
                                                    name=pod.metadata.name,
                                                    namespace=self.namespace,
                                                    container=container.name,
                                                    tail_lines=200  # 获取更多日志用于诊断
                                                )
                                                container_detail["logs"] = log_content

                                                # 记录关键错误信息
                                                error_lines = []
                                                for line in log_content.split('\n'):
                                                    line_lower = line.lower()
                                                    if any(keyword in line_lower for keyword in ['error', 'failed', 'exit', 'failed to', 'unable to', 'cannot']):
                                                        error_lines.append(line.strip())

                                                if error_lines:
                                                    container_detail["error_lines"] = error_lines[:10]  # 只保留前10个错误行

                                            except Exception as log_error:
                                                container_detail["log_error"] = str(log_error)

                                        elif container.state.waiting:
                                            container_detail.update({
                                                "state": "waiting",
                                                "reason": container.state.waiting.reason,
                                                "message": container.state.waiting.message
                                            })

                                        pod_detail["containers"].append(container_detail)
                            except Exception as pod_error:
                                pod_detail["pod_error"] = str(pod_error)

                            pods_details.append(pod_detail)

                        error_details["pods"] = pods_details

                        # 获取Job事件信息
                        try:
                            events = self.core_v1.list_namespaced_event(
                                namespace=self.namespace,
                                field_selector=f"involvedObject.name={job_name},involvedObject.kind=Job"
                            )

                            job_events = []
                            for event in events.items[:10]:  # 只取最近10个事件
                                job_events.append({
                                    "type": event.type,
                                    "reason": event.reason,
                                    "message": event.message,
                                    "count": event.count,
                                    "first_timestamp": event.first_timestamp.isoformat() if event.first_timestamp else None,
                                    "last_timestamp": event.last_timestamp.isoformat() if event.last_timestamp else None
                                })

                            if job_events:
                                error_details["job_events"] = job_events
                        except Exception as event_error:
                            error_details["events_error"] = str(event_error)

                        # 记录详细的错误信息到日志
                        logger.error(f"PVC拷贝失败详细信息:")
                        logger.error(f"项目ID: {project_id}")
                        logger.error(f"Job名称: {job_name}")
                        logger.error(f"下载URL: {download_url}")
                        logger.error(f"PVC名称: {pvc_name}")
                        logger.error(f"压缩包: {archive_filename} ({file_size} 字节)")

                        for pod_detail in pods_details:
                            logger.error(f"Pod: {pod_detail['pod_name']}, 状态: {pod_detail['pod_status']}")
                            for container in pod_detail.get('containers', []):
                                if 'exit_code' in container:
                                    logger.error(f"  容器 {container['container_name']}: 退出代码 {container['exit_code']}, 原因: {container.get('reason', '未知')}")
                                    if 'error_lines' in container:
                                        for error_line in container['error_lines']:
                                            logger.error(f"    错误: {error_line}")

                        # 抛出详细的错误信息
                        raise CodeServerError(
                            message="通过HTTP下载并解压文件到PVC失败",
                            details=error_details,
                            status_code=500
                        )

                except ApiException as e:
                    logger.warning(f"获取任务状态失败: {e}")
                    continue

            # 如果超时，记录详细错误
            timeout_details = {
                "project_id": project_id,
                "job_name": job_name,
                "download_url": download_url,
                "pvc_name": pvc_name,
                "archive_filename": archive_filename,
                "timeout_seconds": max_wait_time,
                "last_known_status": last_status,
                "error_timestamp": datetime.now(timezone.utc).isoformat()
            }

            logger.error(f"PVC拷贝任务超时: {timeout_details}")

            raise CodeServerError(
                message="下载解压文件超时",
                details=timeout_details,
                status_code=504
            )

        except CodeServerError:
            # 重新抛出，保留原有异常
            raise
        except Exception as e:
            logger.error(f"创建下载解压任务失败: {e}")

            # 记录创建任务时的错误
            creation_error_details = {
                "project_id": project_id,
                "archive_path": archive_path,
                "pvc_name": pvc_name,
                "error_type": type(e).__name__,
                "error": str(e),
                "error_timestamp": datetime.now(timezone.utc).isoformat()
            }

            raise CodeServerError(
                message="创建文件下载解压任务失败",
                details=creation_error_details,
                status_code=500
            )

    def create_deployment(self, project_id: str, password: str, pvc_name: str, cpu_limit: str = "1000m", memory_limit: str = "1024Mi") -> str:
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        deploy_name = self.generate_resource_name(project_id, "deploy")

        try:
            deployment = client.V1Deployment(
                metadata=client.V1ObjectMeta(
                    name=deploy_name,
                    namespace=self.namespace,
                    labels={
                        "app": "code-server",
                        "project-id": project_id,
                        "managed-by": "source-manager"
                    }
                ),
                spec=client.V1DeploymentSpec(
                    replicas=1,
                    selector=client.V1LabelSelector(
                        match_labels={"app": "code-server", "project-id": project_id}
                    ),
                    template=client.V1PodTemplateSpec(
                        metadata=client.V1ObjectMeta(
                            labels={"app": "code-server", "project-id": project_id}
                        ),
                        spec=client.V1PodSpec(
                            containers=[client.V1Container(
                                name="code-server",
                                image=Config.K8S_CODE_SERVER_IMAGE,
                                ports=[client.V1ContainerPort(container_port=Config.K8S_CONTAINER_PORT)],
                                env=[
                                    client.V1EnvVar(name="PASSWORD", value=password),
                                    client.V1EnvVar(name="PUID", value="1000"),
                                    client.V1EnvVar(name="PGID", value="1000"),
                                    client.V1EnvVar(name="TZ", value="Asia/Shanghai"),
                                    client.V1EnvVar(name="PROJECT_ID", value=project_id),
                                    client.V1EnvVar(name="SUDO_PASSWORD", value=password)
                                ],
                                volume_mounts=[client.V1VolumeMount(
                                    name="workspace",
                                    mount_path="/config/workspace"
                                )],
                                resources=client.V1ResourceRequirements(
                                    requests={
                                        "cpu": "500m",
                                        "memory": "512Mi"
                                    },
                                    limits={
                                        "cpu": cpu_limit,
                                        "memory": memory_limit
                                    }
                                ),
                                readiness_probe=client.V1Probe(
                                    http_get=client.V1HTTPGetAction(
                                        path="/",
                                        port=Config.K8S_CONTAINER_PORT,
                                        scheme="HTTP"
                                    ),
                                    initial_delay_seconds=10,
                                    period_seconds=5,
                                    timeout_seconds=1,
                                    success_threshold=1,
                                    failure_threshold=3
                                ),
                                liveness_probe=client.V1Probe(
                                    http_get=client.V1HTTPGetAction(
                                        path="/",
                                        port=Config.K8S_CONTAINER_PORT,
                                        scheme="HTTP"
                                    ),
                                    initial_delay_seconds=30,
                                    period_seconds=10,
                                    timeout_seconds=1,
                                    success_threshold=1,
                                    failure_threshold=3
                                )
                            )],
                            volumes=[client.V1Volume(
                                name="workspace",
                                persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                    claim_name=pvc_name
                                )
                            )]
                        )
                    )
                )
            )

            self.apps_v1.create_namespaced_deployment(
                namespace=self.namespace, body=deployment
            )
            logger.info(f"创建Deployment: {deploy_name}")
            return deploy_name
        except ApiException as e:
            if e.status == 409:
                logger.warning(f"Deployment已存在: {deploy_name}")
                return deploy_name
            logger.error(f"创建Deployment失败: {e}")
            raise CodeServerError(
                message="创建Deployment失败",
                details={
                    "project_id": project_id,
                    "deployment_name": deploy_name,
                    "error": str(e),
                    "status": e.status,
                    "reason": e.reason
                },
                status_code=500
            )

    def create_service(self, project_id: str) -> Dict[str, Any]:
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        svc_name = self.generate_resource_name(project_id, "svc")

        try:
            service = client.V1Service(
                metadata=client.V1ObjectMeta(
                    name=svc_name,
                    namespace=self.namespace,
                    labels={
                        "app": "code-server",
                        "project-id": project_id,
                        "managed-by": "source-manager"
                    }
                ),
                spec=client.V1ServiceSpec(
                    type=Config.K8S_SERVICE_TYPE,
                    selector={"app": "code-server", "project-id": project_id},
                    ports=[client.V1ServicePort(
                        port=Config.K8S_SERVICE_PORT,
                        target_port=Config.K8S_CONTAINER_PORT,
                        name="http"
                    )]
                )
            )

            svc = self.core_v1.create_namespaced_service(namespace=self.namespace, body=service)
            logger.info(f"创建Service: {svc_name}, 类型: {Config.K8S_SERVICE_TYPE}")

            access_info = {
                "name": svc_name,
                "port": Config.K8S_SERVICE_PORT,
                "type": Config.K8S_SERVICE_TYPE
            }

            # 根据服务类型获取访问信息
            if Config.K8S_SERVICE_TYPE == "LoadBalancer":
                # 等待LoadBalancer IP分配
                for i in range(30):
                    time.sleep(5)
                    try:
                        svc = self.core_v1.read_namespaced_service(
                            name=svc_name, namespace=self.namespace
                        )
                        if svc.status.load_balancer.ingress:
                            ingress = svc.status.load_balancer.ingress[0]
                            if ingress.ip:
                                access_info["ip"] = ingress.ip
                                access_info["url"] = f"http://{ingress.ip}:{Config.K8S_SERVICE_PORT}"
                                break
                            elif ingress.hostname:
                                access_info["hostname"] = ingress.hostname
                                access_info["url"] = f"https://{ingress.hostname}:{Config.K8S_SERVICE_PORT}"
                                break
                    except ApiException:
                        continue

            elif Config.K8S_SERVICE_TYPE == "NodePort":
                # 获取NodePort
                if svc.spec.ports and svc.spec.ports[0].node_port:
                    node_port = svc.spec.ports[0].node_port
                    access_info["node_port"] = node_port

                    # 获取节点IP
                    try:
                        nodes = self.core_v1.list_node()
                        if nodes.items:
                            node = nodes.items[0]
                            for addr in node.status.addresses:
                                if addr.type == "ExternalIP":
                                    access_info["node_ip"] = addr.address
                                    access_info["url"] = f"http://{addr.address}:{node_port}"
                                    break
                                elif addr.type == "InternalIP":
                                    access_info["node_ip"] = addr.address
                                    access_info["url"] = f"http://{addr.address}:{node_port}"
                    except:
                        access_info["url"] = f"NodePort: {node_port}"

            elif Config.K8S_SERVICE_TYPE == "ClusterIP":
                access_info["cluster_ip"] = svc.spec.cluster_ip
                access_info["url"] = f"http://{svc_name}.{self.namespace}.svc.cluster.local:{Config.K8S_SERVICE_PORT}"

            return access_info
        except ApiException as e:
            if e.status == 409:
                logger.warning(f"Service已存在: {svc_name}")
                # 获取现有服务信息
                try:
                    svc = self.core_v1.read_namespaced_service(
                        name=svc_name, namespace=self.namespace
                    )
                    return {"name": svc_name, "port": Config.K8S_SERVICE_PORT}
                except:
                    return {"name": svc_name}
            logger.error(f"创建Service失败: {e}")
            raise CodeServerError(
                message="创建Service失败",
                details={
                    "project_id": project_id,
                    "service_name": svc_name,
                    "error": str(e),
                    "status": e.status,
                    "reason": e.reason
                },
                status_code=500
            )

    def create_ingress(self, project_id: str, host: str = None) -> Optional[str]:
        """创建Ingress（可选）"""
        if not self.available:
            return None

        ingress_name = self.generate_resource_name(project_id, "ingress")
        svc_name = self.generate_resource_name(project_id, "svc")

        if not host:
            host = f"{project_id[:8]}.{os.getenv('VSCODE_INGRESS_DOMAIN', 'code-server.sothothv2.com')}"

        try:
            ingress = client.V1Ingress(
                metadata=client.V1ObjectMeta(
                    name=ingress_name,
                    namespace=self.namespace,
                    annotations={
                        "nginx.ingress.kubernetes.io/rewrite-target": "/",
                        "nginx.ingress.kubernetes.io/proxy-body-size": "1024m"
                    },
                    labels={
                        "app": "code-server",
                        "project-id": project_id,
                        "managed-by": "source-manager"
                    }
                ),
                spec=client.V1IngressSpec(
                    ingress_class_name = "nginx",
                    tls = [client.V1IngressTLS(
                        hosts=[host],
                        secret_name="wildcard-sothothv2.com-tls"
                    )]
                    ,
                    rules=[client.V1IngressRule(
                        host=host,
                        http=client.V1HTTPIngressRuleValue(
                            paths=[client.V1HTTPIngressPath(
                                path="/",
                                path_type="Prefix",
                                backend=client.V1IngressBackend(
                                    service=client.V1IngressServiceBackend(
                                        name=svc_name,
                                        port=client.V1ServiceBackendPort(
                                            number=Config.K8S_SERVICE_PORT
                                        )
                                    )
                                )
                            )]
                        )
                    )]
                )
            )

            self.networking_v1.create_namespaced_ingress(
                namespace=self.namespace, body=ingress
            )
            logger.info(f"创建Ingress: {ingress_name}, Host: {host}")
            return host
        except Exception as e:
            logger.warning(f"创建Ingress失败（可能是Ingress控制器未安装）: {e}")
            # Ingress创建失败不是致命错误，只记录警告
            return None

    def delete_runtime_resources(self, project_id: str) -> Dict[str, Any]:
        """
        删除运行时资源（Deployment, Service, Ingress），但不删除PVC

        Args:
            project_id: 项目ID

        Returns:
            删除结果
        """
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        results = {}
        errors = []

        # 删除Ingress（如果存在）
        ingress_name = self.generate_resource_name(project_id, "ingress")
        try:
            self.networking_v1.delete_namespaced_ingress(
                name=ingress_name, namespace=self.namespace
            )
            results["ingress"] = {"deleted": True, "name": ingress_name}
        except ApiException as e:
            if e.status != 404:
                error_info = {
                    "resource": "ingress",
                    "name": ingress_name,
                    "error": str(e),
                    "status": e.status
                }
                errors.append(error_info)
                results["ingress"] = {"deleted": False, "error": str(e)}

        # 删除Service
        svc_name = self.generate_resource_name(project_id, "svc")
        try:
            self.core_v1.delete_namespaced_service(
                name=svc_name, namespace=self.namespace
            )
            results["service"] = {"deleted": True, "name": svc_name}
        except ApiException as e:
            if e.status != 404:
                error_info = {
                    "resource": "service",
                    "name": svc_name,
                    "error": str(e),
                    "status": e.status
                }
                errors.append(error_info)
                results["service"] = {"deleted": False, "error": str(e)}

        # 删除Deployment
        deploy_name = self.generate_resource_name(project_id, "deploy")
        try:
            self.apps_v1.delete_namespaced_deployment(
                name=deploy_name, namespace=self.namespace
            )
            results["deployment"] = {"deleted": True, "name": deploy_name}
        except ApiException as e:
            if e.status != 404:
                error_info = {
                    "resource": "deployment",
                    "name": deploy_name,
                    "error": str(e),
                    "status": e.status
                }
                errors.append(error_info)
                results["deployment"] = {"deleted": False, "error": str(e)}

        # 注意：不删除PVC，保留数据

        if errors:
            raise CodeServerError(
                message="删除Kubernetes运行时资源时发生错误",
                details={
                    "project_id": project_id,
                    "errors": errors,
                    "results": results
                },
                status_code=500
            )

        return results

    def delete_all_resources(self, project_id: str) -> Dict[str, Any]:
        """
        删除所有资源（包括PVC）

        Args:
            project_id: 项目ID

        Returns:
            删除结果
        """
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        results = {}
        errors = []

        # 先删除运行时资源
        try:
            runtime_results = self.delete_runtime_resources(project_id)
            results.update(runtime_results)
        except CodeServerError as e:
            # 记录错误但继续删除PVC
            errors.extend(e.details.get("errors", []))
            results.update(e.details.get("results", {}))

        # 删除PVC
        pvc_name = self.generate_resource_name(project_id, "pvc")
        try:
            self.core_v1.delete_namespaced_persistent_volume_claim(
                name=pvc_name, namespace=self.namespace
            )
            results["pvc"] = {"deleted": True, "name": pvc_name}
        except ApiException as e:
            if e.status != 404:
                error_info = {
                    "resource": "pvc",
                    "name": pvc_name,
                    "error": str(e),
                    "status": e.status
                }
                errors.append(error_info)
                results["pvc"] = {"deleted": False, "error": str(e)}

        if errors:
            raise CodeServerError(
                message="删除Kubernetes资源时发生错误",
                details={
                    "project_id": project_id,
                    "errors": errors,
                    "results": results
                },
                status_code=500
            )

        return results

    def scale_deployment(self, project_id: str, replicas: int) -> bool:
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        deploy_name = self.generate_resource_name(project_id, "deploy")

        try:
            deployment = self.apps_v1.read_namespaced_deployment(
                name=deploy_name, namespace=self.namespace
            )
            deployment.spec.replicas = replicas
            self.apps_v1.replace_namespaced_deployment(
                name=deploy_name, namespace=self.namespace, body=deployment
            )
            logger.info(f"调整Deployment {deploy_name} 副本数为: {replicas}")
            return True
        except ApiException as e:
            if e.status == 404:
                raise CodeServerError(
                    message="Deployment不存在",
                    details={
                        "project_id": project_id,
                        "deployment_name": deploy_name,
                        "error": str(e)
                    },
                    status_code=404
                )
            logger.error(f"调整副本数失败: {e}")
            raise CodeServerError(
                message="调整Deployment副本数失败",
                details={
                    "project_id": project_id,
                    "deployment_name": deploy_name,
                    "replicas": replicas,
                    "error": str(e)
                },
                status_code=500
            )

    def get_deployment_status(self, project_id: str) -> Dict[str, Any]:
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        deploy_name = self.generate_resource_name(project_id, "deploy")

        try:
            deployment = self.apps_v1.read_namespaced_deployment(
                name=deploy_name, namespace=self.namespace
            )

            # 获取Pod信息
            pods = self.core_v1.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=f"app=code-server,project-id={project_id}"
            )

            pod_info = []
            for pod in pods.items[:3]:  # 最多显示3个pod
                pod_info.append({
                    "name": pod.metadata.name,
                    "status": pod.status.phase,
                    "ip": pod.status.pod_ip,
                    "node": pod.spec.node_name
                })

            return {
                "name": deploy_name,
                "namespace": self.namespace,
                "replicas": deployment.status.replicas if deployment.status else 0,
                "ready_replicas": deployment.status.ready_replicas if deployment.status else 0,
                "available_replicas": deployment.status.available_replicas if deployment.status else 0,
                "pods": pod_info,
                "conditions": [
                    {
                        "type": cond.type,
                        "status": cond.status,
                        "reason": cond.reason,
                        "message": cond.message
                    }
                    for cond in (deployment.status.conditions if deployment.status else [])
                ]
            }
        except ApiException as e:
            if e.status == 404:
                raise CodeServerError(
                    message="Deployment不存在",
                    details={
                        "project_id": project_id,
                        "deployment_name": deploy_name,
                        "error": str(e)
                    },
                    status_code=404
                )
            logger.error(f"获取Deployment状态失败: {e}")
            raise CodeServerError(
                message="获取Deployment状态失败",
                details={
                    "project_id": project_id,
                    "deployment_name": deploy_name,
                    "error": str(e)
                },
                status_code=500
            )

    def get_service_info(self, project_id: str) -> Dict[str, Any]:
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        svc_name = self.generate_resource_name(project_id, "svc")

        try:
            service = self.core_v1.read_namespaced_service(
                name=svc_name, namespace=self.namespace
            )

            info = {
                "name": svc_name,
                "namespace": self.namespace,
                "type": service.spec.type,
                "cluster_ip": service.spec.cluster_ip,
                "ports": [
                    {
                        "name": port.name,
                        "port": port.port,
                        "target_port": port.target_port,
                        "node_port": port.node_port
                    }
                    for port in service.spec.ports
                ]
            }

            if service.status.load_balancer and service.status.load_balancer.ingress:
                info["load_balancer"] = []
                for ingress in service.status.load_balancer.ingress:
                    info["load_balancer"].append({
                        "ip": ingress.ip,
                        "hostname": ingress.hostname
                    })

            return info
        except ApiException as e:
            if e.status == 404:
                raise CodeServerError(
                    message="Service不存在",
                    details={
                        "project_id": project_id,
                        "service_name": svc_name,
                        "error": str(e)
                    },
                    status_code=404
                )
            logger.error(f"获取Service信息失败: {e}")
            raise CodeServerError(
                message="获取Service信息失败",
                details={
                    "project_id": project_id,
                    "service_name": svc_name,
                    "error": str(e)
                },
                status_code=500
            )

    def get_pvc_status(self, project_id: str) -> Dict[str, Any]:
        """获取PVC状态"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        pvc_name = self.generate_resource_name(project_id, "pvc")

        try:
            pvc = self.core_v1.read_namespaced_persistent_volume_claim(
                name=pvc_name, namespace=self.namespace
            )

            return {
                "name": pvc.metadata.name,
                "namespace": pvc.metadata.namespace,
                "storage_class": pvc.spec.storage_class_name,
                "status": pvc.status.phase,
                "capacity": pvc.status.capacity.get("storage") if pvc.status.capacity else None,
                "access_modes": pvc.spec.access_modes,
                "volume_name": pvc.spec.volume_name if hasattr(pvc.spec, 'volume_name') else None,
                "creation_timestamp": pvc.metadata.creation_timestamp
            }
        except ApiException as e:
            if e.status == 404:
                raise CodeServerError(
                    message="PVC不存在",
                    details={
                        "project_id": project_id,
                        "pvc_name": pvc_name,
                        "error": str(e)
                    },
                    status_code=404
                )
            logger.error(f"获取PVC信息失败: {e}")
            raise CodeServerError(
                message="获取PVC信息失败",
                details={
                    "project_id": project_id,
                    "pvc_name": pvc_name,
                    "error": str(e)
                },
                status_code=500
            )


# ============ 任务管理器 ============
class TaskManager:
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=Config.MAX_WORKERS)
        self.tasks = {}

        # 启动一个空任务来初始化线程池
        self._init_thread_pool()

        logger.info(f"任务管理器初始化成功，最大线程数: {Config.MAX_WORKERS}")

    def _init_thread_pool(self):
        """初始化线程池，确保线程池在启动时就运行"""
        try:
            # 提交一个空任务来启动线程池
            def init_task():
                logger.info("线程池初始化任务执行完成")
                return "initialized"

            future = self.executor.submit(init_task)
            # 等待一小段时间让任务开始执行
            time.sleep(0.1)
            logger.info("线程池初始化完成")
        except Exception as e:
            logger.warning(f"线程池初始化时出现警告: {e}")
            # 即使初始化有警告，也继续运行

    def submit(self, task_type: str, func, *args, **kwargs) -> str:
        task_id = str(uuid.uuid4())

        def task_wrapper():
            try:
                result = func(*args, **kwargs)
                self.tasks[task_id] = {
                    "status": "completed",
                    "result": result,
                    "completed_at": datetime.now(timezone.utc)
                }
                return result
            except CodeServerError as e:
                self.tasks[task_id] = {
                    "status": "failed",
                    "error": {
                        "message": e.message,
                        "details": e.details,
                        "status_code": e.status_code
                    },
                    "completed_at": datetime.now(timezone.utc)
                }
                logger.error(f"任务 {task_id} 失败: {e.message}")
                raise
            except ProjectError as e:
                self.tasks[task_id] = {
                    "status": "failed",
                    "error": {
                        "message": e.message,
                        "details": e.details,
                        "status_code": e.status_code
                    },
                    "completed_at": datetime.now(timezone.utc)
                }
                logger.error(f"任务 {task_id} 失败: {e.message}")
                raise
            except Exception as e:
                self.tasks[task_id] = {
                    "status": "failed",
                    "error": {
                        "message": str(e),
                        "details": {"type": type(e).__name__},
                        "status_code": 500
                    },
                    "completed_at": datetime.now(timezone.utc)
                }
                logger.error(f"任务 {task_id} 失败: {e}")
                raise

        future = self.executor.submit(task_wrapper)
        self.tasks[task_id] = {
            "status": "running",
            "future": future,
            "task_type": task_type,
            "started_at": datetime.now(timezone.utc)
        }

        logger.info(f"提交任务: {task_id}, 类型: {task_type}")
        return task_id

    def get_status(self, task_id: str) -> Dict[str, Any]:
        task_info = self.tasks.get(task_id, {"status": "not_found"})

        if task_info["status"] == "running":
            future = task_info.get("future")
            if future and future.done():
                try:
                    result = future.result()
                    task_info["status"] = "completed"
                    task_info["result"] = result
                except Exception as e:
                    task_info["status"] = "failed"
                    if not task_info.get("error"):
                        task_info["error"] = {
                            "message": str(e),
                            "details": {"type": type(e).__name__},
                            "status_code": 500
                        }

        return task_info

    def is_healthy(self) -> bool:
        """检查任务管理器是否健康"""
        try:
            # 检查线程池是否已关闭
            if self.executor._shutdown:
                return False

            # 检查是否有可用的工作线程
            # 注意：ThreadPoolExecutor 没有直接的方法检查活跃线程数
            # 但我们可以检查是否有线程在运行或等待
            if hasattr(self.executor, '_threads'):
                # 检查是否有活跃线程
                return len(self.executor._threads) > 0
            else:
                # 如果无法检查线程状态，假设健康
                return True
        except Exception as e:
            logger.warning(f"检查任务管理器健康状态失败: {e}")
            return True  # 即使检查失败，也假设健康，避免误报


# ============ 项目初始化任务函数 ============
def initialize_project_task(project_id: str, archive_path: str, storage_size: str = "5Gi", create_pvc: bool = True):
    """项目初始化任务：解压、扫描文件、创建PVC、拷贝文件"""
    logger.info(f"开始初始化项目: project_id={project_id}")

    # 创建日志文件
    log_file_path = os.path.join(Config.TASK_LOG_DIR, f"project_init_{project_id}_{int(time.time())}.log")
    task_logger = TaskLogger(log_file_path)

    db = SessionLocal()
    project_task_log = None

    try:
        # 记录任务开始
        task_logger.info(f"开始项目初始化任务: {project_id}")
        task_logger.info(f"存档文件: {archive_path}")
        task_logger.info(f"存储大小: {storage_size}")
        task_logger.info(f"创建PVC: {create_pvc}")

        # 创建任务日志记录
        project_task_log = ProjectTaskLog(
            project_id=project_id,
            task_type="init",
            task_id=f"init_{project_id}_{int(time.time())}",
            status="running",
            log_path=log_file_path
        )
        db.add(project_task_log)
        db.commit()

        # 获取项目
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            error_msg = f"项目不存在: {project_id}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="项目不存在",
                details={"project_id": project_id},
                status_code=404
            )

        # 更新项目状态
        project.status = Config.PROJECT_STATUS_INITIALIZING
        project.init_log_path = log_file_path
        project.init_error = None
        db.commit()

        # 步骤1: 解压文件到本地目录（用于文件扫描）
        task_logger.info("步骤1: 解压文件到本地目录（用于文件扫描）")
        extract_dir = os.path.join(Config.EXTRACT_DIR, project_id)

        try:
            os.makedirs(extract_dir, exist_ok=True)
            task_logger.info(f"创建本地解压目录: {extract_dir}")
        except Exception as e:
            error_msg = f"创建本地解压目录失败: {str(e)}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="创建本地解压目录失败",
                details={"project_id": project_id, "error": str(e)},
                status_code=500
            )

        # 检查存档文件是否存在
        if not os.path.exists(archive_path):
            error_msg = f"存档文件不存在: {archive_path}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="存档文件不存在",
                details={"project_id": project_id, "archive_path": archive_path},
                status_code=404
            )

        # 解压文件到本地目录
        task_logger.info(f"开始解压文件到本地目录: {archive_path} -> {extract_dir}")
        if not FileUtils.extract_archive(archive_path, extract_dir):
            error_msg = "解压文件失败"
            task_logger.error(error_msg)
            raise ProjectError(
                message="解压文件失败",
                details={"project_id": project_id, "archive_path": archive_path},
                status_code=500
            )

        project.extract_path = extract_dir
        task_logger.info("文件解压到本地目录成功")

        # 步骤2: 扫描文件
        task_logger.info("步骤2: 扫描文件")
        files_info = FileUtils.scan_files(extract_dir)
        total_size = sum(f["size"] for f in files_info)

        # 保存文件信息到数据库
        for file_info in files_info:
            db_file = ProjectFile(
                project_id=project_id,
                file_path=file_info["path"],
                file_name=file_info["name"],
                file_size=file_info["size"],
                file_type=file_info["type"]
            )
            db.add(db_file)

        project.file_count = len(files_info)
        project.total_size = total_size
        db.commit()

        task_logger.info(f"扫描完成: 共 {len(files_info)} 个文件，总大小 {total_size} 字节")

        # 步骤3: 创建PVC并拷贝文件
        if create_pvc:
            task_logger.info("步骤3: 创建PVC并拷贝压缩包")

            # 检查K8S是否可用
            if not K8S_AVAILABLE:
                error_msg = "Kubernetes功能不可用"
                task_logger.error(error_msg)
                raise ProjectError(
                    message="Kubernetes功能不可用",
                    details={"project_id": project_id},
                    status_code=503
                )

            # 初始化K8S管理器
            try:
                k8s = KubernetesManager(validate_connection=False)
                if not k8s.available:
                    error_msg = "Kubernetes客户端初始化失败"
                    task_logger.error(error_msg)
                    raise ProjectError(
                        message="Kubernetes客户端不可用",
                        details={"project_id": project_id},
                        status_code=503
                    )
            except Exception as e:
                error_msg = f"Kubernetes客户端初始化失败: {str(e)}"
                task_logger.error(error_msg)
                raise ProjectError(
                    message="Kubernetes客户端初始化失败",
                    details={"project_id": project_id, "error": str(e)},
                    status_code=500
                )

            # 更新项目状态
            project.pvc_status = "creating"
            db.commit()

            # 创建PVC
            task_logger.info(f"开始创建PVC，存储大小: {storage_size}")
            try:
                pvc_name = k8s.create_pvc(project_id, storage_size)
                project.pvc_name = pvc_name
                project.pvc_size = storage_size
                db.commit()
                task_logger.info(f"PVC创建成功: {pvc_name}")
            except CodeServerError as e:
                error_msg = f"创建PVC失败: {e.message}"
                task_logger.error(error_msg)
                project.pvc_status = "error"
                db.commit()
                raise ProjectError(
                    message="创建PVC失败",
                    details={
                        "project_id": project_id,
                        "error": e.message,
                        "details": e.details
                    },
                    status_code=e.status_code
                )

            # 等待PVC绑定
            task_logger.info(f"等待PVC绑定: {pvc_name}")
            for i in range(30):
                time.sleep(2)
                try:
                    pvc = k8s.core_v1.read_namespaced_persistent_volume_claim(
                        name=pvc_name, namespace=k8s.namespace
                    )
                    if pvc.status.phase == "Bound":
                        task_logger.info(f"PVC已绑定: {pvc_name}")
                        project.pvc_status = "ready"
                        db.commit()
                        break
                    elif pvc.status.phase == "Pending":
                        task_logger.info(f"PVC状态: Pending ({i+1}/30)")
                    else:
                        task_logger.warning(f"PVC状态: {pvc.status.phase}")
                except:
                    task_logger.warning(f"获取PVC状态失败 ({i+1}/30)")
                    continue

            # 复制压缩包到PVC并解压
            task_logger.info(f"复制压缩包到PVC并解压: {pvc_name}")
            try:
                # 使用新的方法：复制压缩包到PVC并在PVC中解压
                k8s.copy_archive_to_pvc(project_id, archive_path, pvc_name)
                project.file_synced = True
                db.commit()
                task_logger.info("压缩包复制并解压到PVC成功")
            except CodeServerError as e:
                error_msg = f"复制并解压文件到PVC失败: {e.message}"
                task_logger.error(error_msg)
                project.pvc_status = "error"
                db.commit()
                raise ProjectError(
                    message="复制并解压文件到PVC失败",
                    details={
                        "project_id": project_id,
                        "error": e.message,
                        "details": e.details
                    },
                    status_code=e.status_code
                )
        else:
            task_logger.info("跳过PVC创建，用户选择不创建PVC")

        # 更新项目状态为就绪
        project.status = Config.PROJECT_STATUS_READY
        project.initialized_at = datetime.now(timezone.utc)
        db.commit()

        # 更新任务日志
        if project_task_log:
            project_task_log.status = "completed"
            project_task_log.completed_at = datetime.now(timezone.utc)
            db.commit()

        result = {
            "success": True,
            "project_id": project_id,
            "status": Config.PROJECT_STATUS_READY,
            "file_count": project.file_count,
            "total_size": project.total_size,
            "pvc_name": project.pvc_name if create_pvc else None,
            "pvc_status": project.pvc_status if create_pvc else None,
            "file_synced": project.file_synced if create_pvc else None,
            "initialized_at": project.initialized_at.isoformat() if project.initialized_at else None,
            "message": "项目初始化成功"
        }

        task_logger.info(f"项目初始化成功: {result}")
        return result

    except ProjectError:
        # 记录错误状态
        try:
            if 'project' in locals():
                project.status = Config.PROJECT_STATUS_ERROR
                project.init_error = str(sys.exc_info()[1])
                db.commit()

            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(sys.exc_info()[1])
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        # 重新抛出异常
        raise

    except Exception as e:
        # 记录未预期的错误
        error_msg = f"项目初始化过程中发生未预期的错误: {str(e)}"
        task_logger.error(error_msg)

        try:
            if 'project' in locals():
                project.status = Config.PROJECT_STATUS_ERROR
                project.init_error = str(e)
                db.commit()

            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(e)
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        raise ProjectError(
            message="项目初始化失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()
        task_logger.info("项目初始化任务结束")


# ============ 项目删除任务函数 ============
def delete_project_task(project_id: str, user_id: int):
    """删除项目任务：删除所有K8S资源和本地文件"""
    logger.info(f"开始删除项目: project_id={project_id}")

    # 创建日志文件
    log_file_path = os.path.join(Config.TASK_LOG_DIR, f"project_delete_{project_id}_{int(time.time())}.log")
    task_logger = TaskLogger(log_file_path)

    db = SessionLocal()
    project_task_log = None

    try:
        # 记录任务开始
        task_logger.info(f"开始项目删除任务: {project_id}")
        task_logger.info(f"用户ID: {user_id}")

        # 创建任务日志记录
        project_task_log = ProjectTaskLog(
            project_id=project_id,
            task_type="delete",
            task_id=f"delete_{project_id}_{int(time.time())}",
            status="running",
            log_path=log_file_path
        )
        db.add(project_task_log)
        db.commit()

        # 获取项目
        project = db.query(Project).filter(
            Project.id == project_id,
            Project.user_id == user_id
        ).first()

        if not project:
            error_msg = f"项目不存在或无权访问: {project_id}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="项目不存在或无权访问",
                details={"project_id": project_id, "user_id": user_id},
                status_code=404
            )

        # 更新项目状态
        project.status = Config.PROJECT_STATUS_DELETING
        db.commit()

        # 步骤1: 删除Code-Server（如果存在）
        task_logger.info("步骤1: 检查并删除Code-Server")
        code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()

        if code_server:
            task_logger.info(f"发现Code-Server，状态: {code_server.status}")

            # 检查K8S是否可用
            if K8S_AVAILABLE:
                try:
                    k8s = KubernetesManager(validate_connection=False)
                    if k8s.available:
                        # 删除Kubernetes运行时资源
                        task_logger.info("删除Kubernetes运行时资源")
                        try:
                            k8s.delete_runtime_resources(project_id)
                            task_logger.info("Kubernetes运行时资源删除成功")
                        except CodeServerError as e:
                            task_logger.warning(f"删除Kubernetes运行时资源失败: {e.message}")
                            # 继续删除其他资源
                        except Exception as e:
                            task_logger.warning(f"删除Kubernetes运行时资源失败: {str(e)}")
                    else:
                        task_logger.warning("Kubernetes客户端不可用，跳过资源删除")
                except Exception as e:
                    task_logger.warning(f"Kubernetes客户端初始化失败，跳过资源删除: {str(e)}")
            else:
                task_logger.warning("Kubernetes功能不可用，跳过资源删除")

            # 删除数据库记录
            db.delete(code_server)
            db.commit()
            task_logger.info("Code-Server数据库记录删除成功")
        else:
            task_logger.info("未发现Code-Server")

        # 步骤1.5: 清理可能残留的初始化PVC的Job（新增）
        task_logger.info("步骤1.5: 检查并清理可能残留的初始化PVC的Job")
        if K8S_AVAILABLE:
            try:
                k8s = KubernetesManager(validate_connection=False)
                if k8s.available:
                    # 查找与项目相关的Job
                    job_name_prefix = f"extract-{project_id[:8]}"
                    job_name_prefix = re.sub(r'[^a-z0-9-]', '-', job_name_prefix.lower())

                    try:
                        # 查找所有job
                        all_jobs = k8s.batch_v1.list_namespaced_job(
                            namespace=k8s.namespace,
                            label_selector=f"project-id={project_id}"
                        )

                        for job in all_jobs.items:
                            job_name = job.metadata.name
                            task_logger.info(f"发现相关Job: {job_name}")

                            try:
                                # 删除Job
                                k8s.batch_v1.delete_namespaced_job(
                                    name=job_name,
                                    namespace=k8s.namespace,
                                    propagation_policy="Background"  # 同时删除相关的Pod
                                )
                                task_logger.info(f"已删除Job: {job_name}")

                                # 等待Job删除完成
                                for i in range(10):
                                    time.sleep(1)
                                    try:
                                        k8s.batch_v1.read_namespaced_job(
                                            name=job_name,
                                            namespace=k8s.namespace
                                        )
                                    except ApiException as e:
                                        if e.status == 404:
                                            task_logger.info(f"Job删除确认: {job_name}")
                                            break
                                        else:
                                            task_logger.warning(f"检查Job状态失败: {e}")
                                    except Exception as e:
                                        task_logger.warning(f"检查Job状态异常: {str(e)}")

                            except ApiException as e:
                                if e.status == 404:
                                    task_logger.info(f"Job已不存在: {job_name}")
                                else:
                                    task_logger.warning(f"删除Job失败: {job_name}, 错误: {e}")
                            except Exception as e:
                                task_logger.warning(f"删除Job异常: {job_name}, 错误: {str(e)}")

                    except ApiException as e:
                        if e.status != 404:
                            task_logger.warning(f"查询Job列表失败: {e}")
                    except Exception as e:
                        task_logger.warning(f"查询Job列表异常: {str(e)}")
                else:
                    task_logger.warning("Kubernetes客户端不可用，跳过Job清理")
            except Exception as e:
                task_logger.warning(f"Kubernetes客户端初始化失败，跳过Job清理: {str(e)}")
        else:
            task_logger.warning("Kubernetes功能不可用，跳过Job清理")

        # 步骤2: 删除PVC（如果存在）
        task_logger.info("步骤2: 检查并删除PVC")
        if project.pvc_name:
            task_logger.info(f"发现PVC: {project.pvc_name}")

            if K8S_AVAILABLE:
                try:
                    k8s = KubernetesManager(validate_connection=False)
                    if k8s.available:
                        # 删除PVC
                        task_logger.info(f"删除PVC: {project.pvc_name}")
                        try:
                            k8s.delete_pvc(project_id)
                            task_logger.info("PVC删除成功")
                        except CodeServerError as e:
                            task_logger.warning(f"删除PVC失败: {e.message}")
                            # 继续删除其他资源
                        except Exception as e:
                            task_logger.warning(f"删除PVC失败: {str(e)}")
                    else:
                        task_logger.warning("Kubernetes客户端不可用，跳过PVC删除")
                except Exception as e:
                    task_logger.warning(f"Kubernetes客户端初始化失败，跳过PVC删除: {str(e)}")
            else:
                task_logger.warning("Kubernetes功能不可用，跳过PVC删除")
        else:
            task_logger.info("未发现PVC")

        # 步骤3: 删除本地文件
        task_logger.info("步骤3: 删除本地文件")

        # 删除存档文件
        if project.archive_path and os.path.exists(project.archive_path):
            try:
                os.remove(project.archive_path)
                task_logger.info(f"删除存档文件: {project.archive_path}")
            except Exception as e:
                task_logger.warning(f"删除存档文件失败: {str(e)}")

        # 删除解压目录
        if project.extract_path and os.path.exists(project.extract_path):
            try:
                shutil.rmtree(project.extract_path)
                task_logger.info(f"删除解压目录: {project.extract_path}")
            except Exception as e:
                task_logger.warning(f"删除解压目录失败: {str(e)}")

        # 清理用户的临时下载文件
        user_download_dir = os.path.join(Config.DOWNLOAD_DIR, str(user_id))
        if os.path.exists(user_download_dir):
            try:
                # 删除与该项目相关的临时文件
                for filename in os.listdir(user_download_dir):
                    filepath = os.path.join(user_download_dir, filename)
                    try:
                        # 检查文件是否属于该项目（通过文件名包含项目ID判断）
                        if project_id in filename or os.path.getmtime(filepath) < time.time() - 86400:  # 24小时前
                            os.remove(filepath)
                            task_logger.info(f"删除临时文件: {filename}")
                    except:
                        pass
            except Exception as e:
                task_logger.warning(f"清理临时下载文件失败: {str(e)}")

        # 步骤4: 删除项目文件记录
        task_logger.info("步骤4: 删除项目文件记录")
        try:
            db.query(ProjectFile).filter(ProjectFile.project_id == project_id).delete()
            task_logger.info("项目文件记录删除成功")
        except Exception as e:
            task_logger.warning(f"删除项目文件记录失败: {str(e)}")

        # 步骤5: 删除项目任务日志记录
        task_logger.info("步骤5: 删除项目任务日志记录")
        try:
            db.query(ProjectTaskLog).filter(ProjectTaskLog.project_id == project_id).delete()
            task_logger.info("项目任务日志记录删除成功")
        except Exception as e:
            task_logger.warning(f"删除项目任务日志记录失败: {str(e)}")

        # 步骤6: 删除项目记录
        task_logger.info("步骤6: 删除项目记录")
        db.delete(project)
        db.commit()
        task_logger.info("项目记录删除成功")

        # 更新任务日志
        if project_task_log:
            project_task_log.status = "completed"
            project_task_log.completed_at = datetime.now(timezone.utc)
            db.commit()

        result = {
            "success": True,
            "project_id": project_id,
            "message": "项目删除成功",
            "deleted_resources": {
                "code_server": code_server is not None,
                "pvc": project.pvc_name is not None,
                "archive_file": project.archive_path is not None,
                "extract_dir": project.extract_path is not None
            }
        }

        task_logger.info(f"项目删除成功: {result}")
        return result

    except ProjectError:
        # 记录错误状态
        try:
            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(sys.exc_info()[1])
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        # 重新抛出异常
        raise

    except Exception as e:
        # 记录未预期的错误
        error_msg = f"项目删除过程中发生未预期的错误: {str(e)}"
        task_logger.error(error_msg)

        try:
            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(e)
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        raise ProjectError(
            message="项目删除失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()
        task_logger.info("项目删除任务结束")

# ============ PVC管理任务函数 ============
def create_project_pvc_task(project_id: str, storage_size: str = "5Gi"):
    """创建项目PVC并拷贝压缩包"""
    logger.info(f"开始创建项目PVC: project_id={project_id}")

    # 创建日志文件
    log_file_path = os.path.join(Config.TASK_LOG_DIR, f"pvc_create_{project_id}_{int(time.time())}.log")
    task_logger = TaskLogger(log_file_path)

    db = SessionLocal()
    project_task_log = None

    try:
        task_logger.info(f"开始创建项目PVC任务: {project_id}")
        task_logger.info(f"存储大小: {storage_size}")

        # 创建任务日志记录
        project_task_log = ProjectTaskLog(
            project_id=project_id,
            task_type="create_pvc",
            task_id=f"pvc_create_{project_id}_{int(time.time())}",
            status="running",
            log_path=log_file_path
        )
        db.add(project_task_log)
        db.commit()

        # 获取项目
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            error_msg = f"项目不存在: {project_id}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="项目不存在",
                details={"project_id": project_id},
                status_code=404
            )

        # 检查是否有压缩包
        if not project.archive_path or not os.path.exists(project.archive_path):
            error_msg = f"项目压缩包不存在: {project.archive_path}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="项目压缩包不存在，无法创建PVC",
                details={"project_id": project_id, "archive_path": project.archive_path},
                status_code=400
            )

        # 更新项目状态
        project.pvc_status = "creating"
        db.commit()

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            error_msg = "Kubernetes功能不可用"
            task_logger.error(error_msg)
            raise ProjectError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 步骤1: 创建PVC
        pvc_name = k8s.create_pvc(project_id, storage_size)
        project.pvc_name = pvc_name
        project.pvc_size = storage_size
        db.commit()

        # 等待PVC绑定
        task_logger.info(f"等待PVC绑定: {pvc_name}")
        for i in range(30):
            time.sleep(2)
            try:
                pvc = k8s.core_v1.read_namespaced_persistent_volume_claim(
                    name=pvc_name, namespace=k8s.namespace
                )
                if pvc.status.phase == "Bound":
                    task_logger.info(f"PVC已绑定: {pvc_name}")
                    project.pvc_status = "ready"
                    db.commit()
                    break
                elif pvc.status.phase == "Pending":
                    task_logger.info(f"PVC状态: Pending ({i+1}/30)")
                else:
                    task_logger.warning(f"PVC状态: {pvc.status.phase}")
            except:
                task_logger.warning(f"获取PVC状态失败 ({i+1}/30)")
                continue

        # 步骤2: 复制压缩包到PVC并解压
        task_logger.info(f"复制压缩包到PVC并解压: {pvc_name}")
        try:
            k8s.copy_archive_to_pvc(project_id, project.archive_path, pvc_name)
            project.file_synced = True
            db.commit()
            task_logger.info("压缩包复制并解压到PVC成功")
        except CodeServerError as e:
            error_msg = f"复制并解压文件到PVC失败: {e.message}"
            task_logger.error(error_msg)
            project.pvc_status = "error"
            db.commit()
            # 复制文件失败是严重错误，需要抛出异常
            raise ProjectError(
                message="复制并解压文件到PVC失败",
                details={
                    "project_id": project_id,
                    "error": e.message,
                    "details": e.details
                },
                status_code=e.status_code
            )

        # 更新任务日志
        if project_task_log:
            project_task_log.status = "completed"
            project_task_log.completed_at = datetime.now(timezone.utc)
            db.commit()

        result = {
            "success": True,
            "project_id": project_id,
            "pvc_name": pvc_name,
            "pvc_size": storage_size,
            "file_synced": project.file_synced,
            "status": "ready"
        }

        task_logger.info(f"项目PVC创建成功: {result}")
        return result

    except ProjectError:
        # 记录错误状态
        try:
            if 'project' in locals():
                project.pvc_status = "error"
                db.commit()

            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(sys.exc_info()[1])
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        # 重新抛出异常
        raise

    except Exception as e:
        task_logger.error(f"创建项目PVC失败: {e}")

        # 更新状态为错误
        try:
            if 'project' in locals():
                project.pvc_status = "error"
                db.commit()

            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(e)
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        # 包装为ProjectError
        raise ProjectError(
            message="创建项目PVC失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()
        task_logger.info("项目PVC创建任务结束")

def recreate_project_pvc_task(project_id: str, storage_size: str = None):
    """重建项目PVC的逻辑 - 直接清空并重新拷贝解压"""
    logger.info(f"开始重建项目PVC: project_id={project_id}")

    # 创建日志文件
    log_file_path = os.path.join(Config.TASK_LOG_DIR, f"pvc_recreate_{project_id}_{int(time.time())}.log")
    task_logger = TaskLogger(log_file_path)

    db = SessionLocal()
    project_task_log = None

    try:
        task_logger.info(f"开始重建项目PVC任务: {project_id}")
        task_logger.info(f"存储大小: {storage_size or '使用原大小'}")

        # 创建任务日志记录
        project_task_log = ProjectTaskLog(
            project_id=project_id,
            task_type="recreate_pvc",
            task_id=f"pvc_recreate_{project_id}_{int(time.time())}",
            status="running",
            log_path=log_file_path
        )
        db.add(project_task_log)
        db.commit()

        # 获取项目
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            error_msg = f"项目不存在: {project_id}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="项目不存在",
                details={"project_id": project_id},
                status_code=404
            )

        # 检查项目是否还有压缩包
        if not project.archive_path or not os.path.exists(project.archive_path):
            error_msg = f"项目压缩包不存在，无法重建PVC: {project.archive_path}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="项目压缩包不存在，无法重建PVC",
                details={"project_id": project_id, "archive_path": project.archive_path},
                status_code=400
            )

        # 更新项目状态
        project.pvc_status = "recreating"
        project.file_synced = False
        db.commit()

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            error_msg = "Kubernetes功能不可用"
            task_logger.error(error_msg)
            raise ProjectError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 步骤1: 清空PVC内容
        task_logger.info("步骤1: 清空PVC内容")
        pvc_name = project.pvc_name or k8s.generate_resource_name(project_id, "pvc")

        # 如果PVC不存在，先创建它
        pvc_exists = False
        try:
            k8s.core_v1.read_namespaced_persistent_volume_claim(
                name=pvc_name, namespace=k8s.namespace
            )
            pvc_exists = True
            task_logger.info(f"PVC已存在: {pvc_name}")
        except ApiException as e:
            if e.status == 404:
                task_logger.info(f"PVC不存在: {pvc_name}")
                pvc_exists = False
            else:
                raise

        if not pvc_exists:
            # 创建新的PVC
            target_storage_size = storage_size or project.pvc_size or Config.K8S_DEFAULT_STORAGE_SIZE
            task_logger.info(f"创建新的PVC: {pvc_name}, 大小: {target_storage_size}")
            try:
                pvc_name = k8s.create_pvc(project_id, target_storage_size)
                project.pvc_name = pvc_name
                project.pvc_size = target_storage_size
                db.commit()
            except Exception as e:
                error_msg = f"创建PVC失败: {str(e)}"
                task_logger.error(error_msg)
                raise ProjectError(
                    message="创建PVC失败",
                    details={"project_id": project_id, "error": str(e)},
                    status_code=500
                )
        else:
            # PVC已存在，清空内容
            task_logger.info(f"清空PVC内容: {pvc_name}")
            try:
                # 创建一个临时Pod来清空PVC内容
                cleanup_pod_name = f"cleanup-{project_id[:8]}"
                cleanup_pod_name = re.sub(r'[^a-z0-9-]', '-', cleanup_pod_name.lower())[:63]

                cleanup_pod = client.V1Pod(
                    metadata=client.V1ObjectMeta(
                        name=cleanup_pod_name,
                        namespace=k8s.namespace,
                        labels={
                            "app": "pvc-cleanup",
                            "project-id": project_id,
                            "managed-by": "source-manager"
                        }
                    ),
                    spec=client.V1PodSpec(
                        restart_policy="Never",
                        containers=[client.V1Container(
                            name="cleanup",
                            image="alpine:latest",
                            command=["sh", "-c", "rm -rf /workspace/* && echo 'PVC内容已清空'"],
                            volume_mounts=[client.V1VolumeMount(
                                name="workspace",
                                mount_path="/workspace"
                            )],
                            resources=client.V1ResourceRequirements(
                                requests={
                                    "cpu": "100m",
                                    "memory": "128Mi"
                                }
                            )
                        )],
                        volumes=[client.V1Volume(
                            name="workspace",
                            persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                claim_name=pvc_name
                            )
                        )]
                    )
                )

                k8s.core_v1.create_namespaced_pod(
                    namespace=k8s.namespace, body=cleanup_pod
                )
                task_logger.info(f"创建清空Pod: {cleanup_pod_name}")

                # 等待Pod完成
                for i in range(30):
                    time.sleep(2)
                    try:
                        pod_status = k8s.core_v1.read_namespaced_pod_status(
                            name=cleanup_pod_name, namespace=k8s.namespace
                        )
                        if pod_status.status.phase == "Succeeded":
                            task_logger.info(f"清空Pod完成: {cleanup_pod_name}")
                            break
                        elif pod_status.status.phase == "Failed":
                            task_logger.warning(f"清空Pod失败: {cleanup_pod_name}")
                            # 继续执行，即使清空失败
                            break
                    except:
                        task_logger.warning(f"获取清空Pod状态失败 ({i+1}/30)")
                        continue

                # 删除清空Pod
                try:
                    k8s.core_v1.delete_namespaced_pod(
                        name=cleanup_pod_name, namespace=k8s.namespace,
                        grace_period_seconds=0
                    )
                    task_logger.info(f"删除清空Pod: {cleanup_pod_name}")
                except:
                    pass

            except Exception as e:
                task_logger.warning(f"清空PVC内容失败: {str(e)}")
                # 继续执行，即使清空失败

        # 步骤2: 复制压缩包到PVC并解压
        task_logger.info(f"步骤2: 复制压缩包到PVC并解压: {pvc_name}")
        try:
            k8s.copy_archive_to_pvc(project_id, project.archive_path, pvc_name)
            project.file_synced = True
            project.pvc_status = "ready"
            db.commit()
            task_logger.info("压缩包复制并解压到PVC成功")
        except CodeServerError as e:
            error_msg = f"复制并解压文件到PVC失败: {e.message}"
            task_logger.error(error_msg)
            project.pvc_status = "error"
            db.commit()
            # 复制文件失败是严重错误，需要抛出异常
            raise ProjectError(
                message="复制并解压文件到PVC失败",
                details={
                    "project_id": project_id,
                    "error": e.message,
                    "details": e.details
                },
                status_code=e.status_code
            )

        # 更新任务日志
        if project_task_log:
            project_task_log.status = "completed"
            project_task_log.completed_at = datetime.now(timezone.utc)
            db.commit()

        result = {
            "success": True,
            "project_id": project_id,
            "pvc_name": pvc_name,
            "pvc_size": project.pvc_size,
            "file_synced": project.file_synced,
            "status": "ready",
            "message": "PVC重建成功，内容已清空并重新解压"
        }

        task_logger.info(f"项目PVC重建成功: {result}")
        return result

    except ProjectError:
        # 记录错误状态
        try:
            if 'project' in locals():
                project.pvc_status = "error"
                db.commit()

            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(sys.exc_info()[1])
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        # 重新抛出异常
        raise

    except Exception as e:
        task_logger.error(f"重建项目PVC失败: {e}")

        # 更新状态为错误
        try:
            if 'project' in locals():
                project.pvc_status = "error"
                db.commit()

            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(e)
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        # 包装为ProjectError
        raise ProjectError(
            message="重建项目PVC失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()
        task_logger.info("项目PVC重建任务结束")


# ============ Code-Server任务函数 ============
def create_code_server_task(project_id: str, user_id: int, password: str = None, cpu_limit: str = "1000m", memory_limit: str = "1024Mi"):
    """创建Code-Server的实际逻辑（使用已有的PVC）"""
    logger.info(f"开始创建Code-Server: project_id={project_id}")

    db = SessionLocal()
    try:
        # 获取项目
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise CodeServerError(
                message="项目不存在",
                details={"project_id": project_id},
                status_code=404
            )

        # 检查项目状态是否为就绪
        if project.status != Config.PROJECT_STATUS_READY:
            raise CodeServerError(
                message=f"项目状态为 {project.status}，无法创建Code-Server。请等待项目初始化完成。",
                details={
                    "project_id": project_id,
                    "project_status": project.status,
                    "required_status": Config.PROJECT_STATUS_READY
                },
                status_code=400
            )

        # 检查项目是否有可用的PVC
        if not project.pvc_name or project.pvc_status != "ready":
            raise CodeServerError(
                message="项目PVC不可用，请先确保PVC已创建并准备就绪",
                details={
                    "project_id": project_id,
                    "pvc_name": project.pvc_name,
                    "pvc_status": project.pvc_status
                },
                status_code=400
            )

        # 检查是否已存在Code-Server
        existing = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
        if existing and existing.status in ["creating", "running"]:
            raise CodeServerError(
                message="Code-Server已存在",
                details={
                    "project_id": project_id,
                    "existing_status": existing.status
                },
                status_code=400
            )

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            raise CodeServerError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 生成密码（如果未提供）
        if not password:
            password = secrets.token_urlsafe(12)

        # 步骤1: 检查Deployment是否已经存在
        deploy_name = k8s.generate_resource_name(project_id, "deploy")
        deployment_exists = False
        deployment_replicas = 0

        try:
            # 尝试获取Deployment信息
            deployment = k8s.apps_v1.read_namespaced_deployment(
                name=deploy_name, namespace=k8s.namespace
            )
            deployment_exists = True
            deployment_replicas = deployment.spec.replicas if deployment.spec.replicas is not None else 0
            logger.info(f"Deployment已存在: {deploy_name}, 副本数: {deployment_replicas}")
        except ApiException as e:
            if e.status == 404:
                logger.info(f"Deployment不存在: {deploy_name}")
                deployment_exists = False
            else:
                # 其他API错误，继续按正常流程处理
                logger.warning(f"获取Deployment状态失败: {e}")
                deployment_exists = False
        except Exception as e:
            logger.warning(f"检查Deployment状态时发生异常: {e}")
            deployment_exists = False

        # 步骤2: 根据Deployment状态决定执行流程
        if deployment_exists and deployment_replicas == 0:
            # 情况1: Deployment存在但副本数为0，直接调整副本数为1
            logger.info(f"Deployment存在但副本数为0，直接调整为1: {deploy_name}")

            # 创建或更新Code-Server记录
            if not existing:
                code_server = CodeServer(
                    id=f"cs-{project_id[:12]}",
                    project_id=project_id,
                    user_id=user_id,
                    status="running",
                    password=password,
                    cpu_limit=cpu_limit,
                    memory_limit=memory_limit,
                    deployment_name=deploy_name,
                    started_at=datetime.now(timezone.utc)
                )
                db.add(code_server)
            else:
                code_server = existing
                code_server.status = "running"
                code_server.password = password or code_server.password
                code_server.cpu_limit = cpu_limit or code_server.cpu_limit
                code_server.memory_limit = memory_limit or code_server.memory_limit
                code_server.started_at = datetime.now(timezone.utc)
                code_server.stopped_at = None

            db.commit()

            # 调整副本数
            try:
                deployment.spec.replicas = 1
                k8s.apps_v1.replace_namespaced_deployment(
                    name=deploy_name, namespace=k8s.namespace, body=deployment
                )
                logger.info(f"Deployment副本数已调整为1: {deploy_name}")
            except ApiException as e:
                logger.error(f"调整Deployment副本数失败: {e}")
                raise CodeServerError(
                    message="调整Deployment副本数失败",
                    details={
                        "project_id": project_id,
                        "deployment_name": deploy_name,
                        "error": str(e),
                        "status": e.status,
                        "reason": e.reason
                    },
                    status_code=500
                )

            # 获取Service信息（如果存在）
            svc_name = k8s.generate_resource_name(project_id, "svc")
            try:
                service = k8s.core_v1.read_namespaced_service(
                    name=svc_name, namespace=k8s.namespace
                )
                code_server.service_name = service.metadata.name
                code_server.service_port = service.spec.ports[0].port if service.spec.ports else None
                code_server.service_ip = service.spec.cluster_ip

                # 构建访问URL
                if service.spec.type == "LoadBalancer":
                    # 等待LoadBalancer IP分配
                    for i in range(10):
                        time.sleep(3)
                        try:
                            svc = k8s.core_v1.read_namespaced_service(
                                name=svc_name, namespace=k8s.namespace
                            )
                            if svc.status.load_balancer.ingress:
                                ingress = svc.status.load_balancer.ingress[0]
                                if ingress.ip:
                                    code_server.service_ip = ingress.ip
                                    code_server.access_url = f"http://{ingress.ip}:{code_server.service_port}"
                                    break
                                elif ingress.hostname:
                                    code_server.access_url = f"https://{ingress.hostname}:{code_server.service_port}"
                                    break
                        except:
                            continue

                elif service.spec.type == "NodePort":
                    if service.spec.ports and service.spec.ports[0].node_port:
                        node_port = service.spec.ports[0].node_port
                        # 获取节点IP
                        try:
                            nodes = k8s.core_v1.list_node()
                            if nodes.items:
                                node = nodes.items[0]
                                for addr in node.status.addresses:
                                    if addr.type == "ExternalIP":
                                        code_server.service_ip = addr.address
                                        code_server.access_url = f"http://{addr.address}:{node_port}"
                                        break
                                    elif addr.type == "InternalIP":
                                        code_server.service_ip = addr.address
                                        code_server.access_url = f"http://{addr.address}:{node_port}"
                                        break
                        except:
                            code_server.access_url = f"NodePort: {node_port}"

                elif service.spec.type == "ClusterIP":
                    code_server.access_url = f"https://{svc_name}.{k8s.namespace}.svc.cluster.local:{code_server.service_port}"

                logger.info(f"获取Service信息: {svc_name}, 访问URL: {code_server.access_url}")
            except ApiException as e:
                if e.status == 404:
                    logger.warning(f"Service不存在: {svc_name}")
                else:
                    logger.warning(f"获取Service信息失败: {e}")
            except Exception as e:
                logger.warning(f"获取Service信息时发生异常: {e}")

            # 获取Pod信息
            logger.info("等待Deployment就绪...")
            for i in range(30):
                time.sleep(3)
                try:
                    deploy_status = k8s.get_deployment_status(project_id)
                    if "error" not in deploy_status and deploy_status.get("ready_replicas", 0) is not None and deploy_status.get("ready_replicas", 0) >= 1:
                        # 获取Pod信息
                        pods = k8s.core_v1.list_namespaced_pod(
                            namespace=k8s.namespace,
                            label_selector=f"app=code-server,project-id={project_id}"
                        )
                        if pods.items:
                            pod = pods.items[0]
                            code_server.pod_name = pod.metadata.name
                            code_server.pod_status = pod.status.phase
                        break
                    else:
                        logger.info(f"等待Deployment就绪 ({i+1}/30): {deploy_status.get('ready_replicas', 0)}个就绪副本")
                except Exception as e:
                    logger.warning(f"检查Deployment状态失败: {e}")
                    continue

            db.commit()

            result = {
                "success": True,
                "project_id": project_id,
                "project_name": project.name,
                "access_url": code_server.access_url,
                "password": password,
                "deployment": deploy_name,
                "service": code_server.service_name,
                "pvc": project.pvc_name,
                "status": "running",
                "operation": "scaled_up",  # 标记操作为扩容
                "message": "Deployment已存在但副本数为0，已调整为1并启动"
            }

            logger.info(f"Code-Server启动成功（通过扩容）: {result}")
            return result

        else:
            # 情况2: Deployment不存在或副本数不为0，执行正常创建流程
            logger.info(f"执行正常Code-Server创建流程: {deploy_name}")

            # 创建或更新Code-Server记录
            if not existing:
                code_server = CodeServer(
                    id=f"cs-{project_id[:12]}",
                    project_id=project_id,
                    user_id=user_id,
                    status="creating",
                    password=password,
                    cpu_limit=cpu_limit,
                    memory_limit=memory_limit
                )
                db.add(code_server)
            else:
                code_server = existing
                code_server.status = "creating"
                code_server.password = password or code_server.password
                code_server.cpu_limit = cpu_limit or code_server.cpu_limit
                code_server.memory_limit = memory_limit or code_server.memory_limit

            db.commit()

            # 如果Deployment存在但副本数不为0，先删除旧的Deployment
            if deployment_exists and deployment_replicas > 0:
                logger.info(f"Deployment已存在且副本数为{deployment_replicas}，先删除旧的Deployment")
                try:
                    k8s.apps_v1.delete_namespaced_deployment(
                        name=deploy_name, namespace=k8s.namespace
                    )
                    # 等待删除完成
                    for i in range(10):
                        time.sleep(2)
                        try:
                            k8s.apps_v1.read_namespaced_deployment(
                                name=deploy_name, namespace=k8s.namespace
                            )
                        except ApiException as e:
                            if e.status == 404:
                                logger.info(f"Deployment删除成功: {deploy_name}")
                                break
                        except:
                            continue
                except ApiException as e:
                    if e.status != 404:
                        logger.error(f"删除旧的Deployment失败: {e}")
                        raise CodeServerError(
                            message="删除旧的Deployment失败",
                            details={
                                "project_id": project_id,
                                "deployment_name": deploy_name,
                                "error": str(e)
                            },
                            status_code=500
                        )

            # 执行正常创建流程
            deploy_name = k8s.create_deployment(project_id, password, project.pvc_name, cpu_limit, memory_limit)
            code_server.deployment_name = deploy_name
            db.commit()

            # 创建Service
            service_info = k8s.create_service(project_id)
            code_server.service_name = service_info["name"]
            code_server.service_port = service_info.get("port")
            code_server.service_ip = service_info.get("ip")
            code_server.access_url = service_info.get("url")
            db.commit()

            # 创建Ingress（可选）
            try:
                host = k8s.create_ingress(project_id)
                if host:
                    code_server.access_url = f"https://{host}"
                    db.commit()
            except Exception as e:
                logger.warning(f"创建Ingress失败: {e}")
                # Ingress创建失败不是致命错误

            # 等待Deployment就绪
            logger.info("等待Deployment就绪...")
            for i in range(60):
                time.sleep(5)
                try:
                    deploy_status = k8s.get_deployment_status(project_id)
                    if "error" not in deploy_status and deploy_status.get("ready_replicas", 0) is not None and deploy_status.get("ready_replicas", 0) >= 1:
                        # 获取Pod信息
                        pods = k8s.core_v1.list_namespaced_pod(
                            namespace=k8s.namespace,
                            label_selector=f"app=code-server,project-id={project_id}"
                        )
                        if pods.items:
                            pod = pods.items[0]
                            code_server.pod_name = pod.metadata.name
                            code_server.pod_status = pod.status.phase
                        break
                    else:
                        logger.info(f"等待Deployment就绪 ({i+1}/60): {deploy_status.get('ready_replicas', 0)}个就绪副本")
                except Exception as e:
                    logger.warning(f"检查Deployment状态失败: {e}")
                    continue

            code_server.status = "running"
            code_server.started_at = datetime.now(timezone.utc)
            db.commit()

            result = {
                "success": True,
                "project_id": project_id,
                "project_name": project.name,
                "access_url": code_server.access_url,
                "password": password,
                "deployment": deploy_name,
                "service": service_info["name"],
                "pvc": project.pvc_name,
                "status": "running",
                "operation": "created",  # 标记操作为新建
                "message": "Code-Server创建成功"
            }

            logger.info(f"Code-Server创建成功: {result}")
            return result

    except Exception as e:
        logger.error(f"创建Code-Server失败: {e}")

        # 更新状态为错误
        try:
            if 'code_server' in locals():
                code_server.status = "error"
                db.commit()
        except:
            pass

        # 如果异常已经是CodeServerError，直接抛出
        if isinstance(e, CodeServerError):
            raise
        # 否则包装为CodeServerError
        raise CodeServerError(
            message="创建Code-Server失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()

def start_code_server_task(project_id: str):
    """启动Code-Server的实际逻辑"""
    logger.info(f"启动Code-Server: project_id={project_id}")

    db = SessionLocal()
    try:
        # 获取Code-Server
        code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
        if not code_server:
            raise CodeServerError(
                message="Code-Server不存在",
                details={"project_id": project_id},
                status_code=404
            )

        # 获取项目并检查状态
        project = db.query(Project).filter(Project.id == project_id).first()
        if project and project.status != Config.PROJECT_STATUS_READY:
            raise CodeServerError(
                message=f"项目状态为 {project.status}，无法启动Code-Server。请等待项目初始化完成。",
                details={
                    "project_id": project_id,
                    "project_status": project.status,
                    "required_status": Config.PROJECT_STATUS_READY
                },
                status_code=400
            )

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            raise CodeServerError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 检查Deployment是否存在
        try:
            deploy_status = k8s.get_deployment_status(project_id)
            if "error" in deploy_status:
                # Deployment不存在，需要重新创建
                logger.info(f"Deployment不存在，重新创建: {project_id}")
                return create_code_server_task(
                    project_id,
                    code_server.user_id,
                    code_server.password,
                    code_server.cpu_limit,
                    code_server.memory_limit
                )
        except CodeServerError:
            # Deployment不存在，重新创建
            logger.info(f"Deployment不存在，重新创建: {project_id}")
            return create_code_server_task(
                project_id,
                code_server.user_id,
                code_server.password,
                code_server.cpu_limit,
                code_server.memory_limit
            )

        # 启动Deployment（设置副本数为1）
        k8s.scale_deployment(project_id, 1)

        code_server.status = "running"
        code_server.started_at = datetime.now(timezone.utc)
        code_server.stopped_at = None
        db.commit()

        # 等待启动完成
        for i in range(30):
            time.sleep(2)
            try:
                deploy_status = k8s.get_deployment_status(project_id)
                if "error" not in deploy_status and deploy_status.get("ready_replicas", 0) >= 1:
                    break
            except:
                continue

        result = {
            "success": True,
            "project_id": project_id,
            "project_name": project.name if project else "未知项目",
            "status": "running",
            "message": "Code-Server启动成功"
        }

        logger.info(f"Code-Server启动成功: {result}")
        return result

    except Exception as e:
        logger.error(f"启动Code-Server失败: {e}")

        # 如果异常已经是CodeServerError，直接抛出
        if isinstance(e, CodeServerError):
            raise
        # 否则包装为CodeServerError
        raise CodeServerError(
            message="启动Code-Server失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()

def stop_code_server_task(project_id: str):
    """停止Code-Server的实际逻辑"""
    logger.info(f"停止Code-Server: project_id={project_id}")

    db = SessionLocal()
    try:
        # 获取Code-Server
        code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
        if not code_server:
            raise CodeServerError(
                message="Code-Server不存在",
                details={"project_id": project_id},
                status_code=404
            )

        project = db.query(Project).filter(Project.id == project_id).first()

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            raise CodeServerError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 停止Deployment（设置副本数为0）
        k8s.scale_deployment(project_id, 0)

        code_server.status = "stopped"
        code_server.stopped_at = datetime.now(timezone.utc)
        db.commit()

        result = {
            "success": True,
            "project_id": project_id,
            "project_name": project.name if project else "未知项目",
            "status": "stopped",
            "message": "Code-Server停止成功"
        }

        logger.info(f"Code-Server停止成功: {result}")
        return result

    except Exception as e:
        logger.error(f"停止Code-Server失败: {e}")

        # 如果异常已经是CodeServerError，直接抛出
        if isinstance(e, CodeServerError):
            raise
        # 否则包装为CodeServerError
        raise CodeServerError(
            message="停止Code-Server失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()

def delete_code_server_task(project_id: str):
    """删除Code-Server的实际逻辑（只删除运行时资源，保留PVC）"""
    logger.info(f"删除Code-Server: project_id={project_id}")

    db = SessionLocal()
    try:
        # 获取Code-Server
        code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
        if not code_server:
            raise CodeServerError(
                message="Code-Server不存在",
                details={"project_id": project_id},
                status_code=404
            )

        project = db.query(Project).filter(Project.id == project_id).first()

        code_server.status = "deleting"
        db.commit()

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if k8s.available:
            try:
                # 只删除运行时资源，保留PVC
                results = k8s.delete_runtime_resources(project_id)
                logger.info(f"删除Kubernetes运行时资源成功: {results}")
            except CodeServerError as e:
                # 即使删除资源失败，也要删除数据库记录
                logger.error(f"删除Kubernetes运行时资源失败: {e.message}")
                results = {"errors": e.details}
        else:
            results = {"error": "Kubernetes客户端不可用"}

        # 删除数据库记录
        db.delete(code_server)
        db.commit()

        result = {
            "success": True,
            "project_id": project_id,
            "project_name": project.name if project else "未知项目",
            "deleted_resources": results,
            "pvc_preserved": True,
            "message": "Code-Server删除成功，PVC已保留"
        }

        logger.info(f"Code-Server删除成功: {result}")
        return result

    except Exception as e:
        logger.error(f"删除Code-Server失败: {e}")

        # 如果异常已经是CodeServerError，直接抛出
        if isinstance(e, CodeServerError):
            raise
        # 否则包装为CodeServerError
        raise CodeServerError(
            message="删除Code-Server失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()

def restart_code_server_task(project_id: str):
    """重启Code-Server的实际逻辑"""
    logger.info(f"重启Code-Server: project_id={project_id}")

    # 先停止
    try:
        stop_result = stop_code_server_task(project_id)
    except CodeServerError as e:
        # 如果停止失败，尝试继续重启
        logger.warning(f"停止Code-Server失败，尝试继续重启: {e.message}")

    # 等待一段时间
    time.sleep(5)

    # 再启动
    start_result = start_code_server_task(project_id)
    return start_result

def update_code_server_task(project_id: str, cpu_limit: str = None, memory_limit: str = None):
    """更新Code-Server配置的实际逻辑"""
    logger.info(f"更新Code-Server配置: project_id={project_id}")

    db = SessionLocal()
    try:
        # 获取Code-Server
        code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
        if not code_server:
            raise CodeServerError(
                message="Code-Server不存在",
                details={"project_id": project_id},
                status_code=404
            )

        # 获取项目并检查状态
        project = db.query(Project).filter(Project.id == project_id).first()
        if project and project.status != Config.PROJECT_STATUS_READY:
            raise CodeServerError(
                message=f"项目状态为 {project.status}，无法更新Code-Server配置。请等待项目初始化完成。",
                details={
                    "project_id": project_id,
                    "project_status": project.status,
                    "required_status": Config.PROJECT_STATUS_READY
                },
                status_code=400
            )

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            raise CodeServerError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 获取当前Deployment
        deploy_name = k8s.generate_resource_name(project_id, "deploy")

        try:
            deployment = k8s.apps_v1.read_namespaced_deployment(
                name=deploy_name, namespace=k8s.namespace
            )

            # 更新资源限制
            if cpu_limit or memory_limit:
                containers = deployment.spec.template.spec.containers
                for container in containers:
                    if container.name == "code-server":
                        if cpu_limit:
                            container.resources.limits["cpu"] = cpu_limit
                            container.resources.requests["cpu"] = f"{int(cpu_limit.replace('m', ''))//2}m" if cpu_limit.endswith('m') else "500m"
                            code_server.cpu_limit = cpu_limit

                        if memory_limit:
                            container.resources.limits["memory"] = memory_limit
                            container.resources.requests["memory"] = f"{int(memory_limit.replace('Mi', ''))//2}Mi" if memory_limit.endswith('Mi') else "512Mi"
                            code_server.memory_limit = memory_limit

                # 更新Deployment
                k8s.apps_v1.replace_namespaced_deployment(
                    name=deploy_name, namespace=k8s.namespace, body=deployment
                )

                db.commit()

                result = {
                    "success": True,
                    "project_id": project_id,
                    "project_name": project.name if project else "未知项目",
                    "cpu_limit": cpu_limit or code_server.cpu_limit,
                    "memory_limit": memory_limit or code_server.memory_limit,
                    "message": "Code-Server配置更新成功"
                }

                logger.info(f"Code-Server配置更新成功: {result}")
                return result
            else:
                raise CodeServerError(
                    message="未提供更新参数",
                    details={"project_id": project_id},
                    status_code=400
                )

        except ApiException as e:
            logger.error(f"更新Code-Server配置失败: {e}")
            raise CodeServerError(
                message="更新Code-Server配置失败",
                details={
                    "project_id": project_id,
                    "deployment_name": deploy_name,
                    "error": str(e)
                },
                status_code=500
            )

    except Exception as e:
        logger.error(f"更新Code-Server配置失败: {e}")

        # 如果异常已经是CodeServerError，直接抛出
        if isinstance(e, CodeServerError):
            raise
        # 否则包装为CodeServerError
        raise CodeServerError(
            message="更新Code-Server配置失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()

# ============ Pydantic模型 ============
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class ChangePassword(BaseModel):
    old_password: str
    new_password: str

class CodeServerCreate(BaseModel):
    password: Optional[str] = None
    cpu_limit: Optional[str] = "1000m"
    memory_limit: Optional[str] = "1024Mi"

class CodeServerUpdate(BaseModel):
    cpu_limit: Optional[str] = None
    memory_limit: Optional[str] = None

class DownloadRequest(BaseModel):
    file_path: str  # 项目内相对文件路径

class MultiDownloadRequest(BaseModel):
    file_paths: List[str]  # 多个项目内相对文件路径

class RecreatePVCRequest(BaseModel):
    storage_size: Optional[str] = None  # 存储大小，如 "5Gi"

class ErrorResponse(BaseModel):
    message: str
    details: Optional[Dict] = None
    status_code: int = 500

# ============ 初始化组件 ============
init_db()
k8s_manager = None
task_manager = None

# ============ FastAPI应用 ============
app = FastAPI(
    title=Config.APP_NAME,
    version=Config.VERSION,
    docs_url="/docs" if Config.DEBUG else None,
    redoc_url="/redoc" if Config.DEBUG else None
)

# 添加中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ 错误处理中间件 ============
@app.exception_handler(CodeServerError)
async def codeserver_error_handler(request: Request, exc: CodeServerError):
    """处理Code-Server相关错误"""
    logger.error(f"Code-Server错误: {exc.message}, 详情: {exc.details}")

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "message": exc.message,
                "details": exc.details,
                "status_code": exc.status_code,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
    )

@app.exception_handler(ProjectError)
async def project_error_handler(request: Request, exc: ProjectError):
    """处理项目相关错误"""
    logger.error(f"项目错误: {exc.message}, 详情: {exc.details}")

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "message": exc.message,
                "details": exc.details,
                "status_code": exc.status_code,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """处理HTTP异常"""
    logger.error(f"HTTP异常: {exc.detail}, 状态码: {exc.status_code}")

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "message": exc.detail,
                "status_code": exc.status_code,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """处理通用异常"""
    logger.error(f"未处理的异常: {exc}", exc_info=True)

    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "message": "内部服务器错误",
                "details": {
                    "error_type": type(exc).__name__,
                    "error": str(exc)
                } if Config.DEBUG else None,
                "status_code": 500,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
    )

# ============ API路由 ============

@app.post(f"{Config.API_PREFIX}/auth/register")
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """用户注册"""
    # 检查用户名
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="用户名已存在")

    # 检查邮箱
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="邮箱已存在")

    # 创建用户
    user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=get_password_hash(user_data.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "注册成功",
        "user_id": user.id,
        "username": user.username
    }

@app.post(f"{Config.API_PREFIX}/auth/login")
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """用户登录"""
    user = db.query(User).filter(User.username == user_data.username).first()

    if not user or not verify_password(user_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="用户名或密码错误")

    if not user.is_active:
        raise HTTPException(status_code=400, detail="用户已被禁用")

    # 创建访问令牌
    access_token_expires = timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin
        }
    }

@app.post(f"{Config.API_PREFIX}/auth/change-password")
async def change_password(
        data: ChangePassword,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """修改密码"""
    if not verify_password(data.old_password, user.password_hash):
        raise HTTPException(status_code=400, detail="旧密码错误")

    user.password_hash = get_password_hash(data.new_password)
    db.commit()

    return {"message": "密码修改成功"}

@app.get(f"{Config.API_PREFIX}/auth/me")
async def get_me(user: User = Depends(get_current_user)):
    """获取当前用户信息"""
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
        "created_at": user.created_at
    }

@app.post(f"{Config.API_PREFIX}/projects/upload")
async def upload_project(
        file: UploadFile = File(...),
        project_name: str = Form(...),
        description: Optional[str] = Form(None),
        storage_size: str = Form(Config.K8S_DEFAULT_STORAGE_SIZE),
        create_pvc: bool = Form(True, description="是否立即创建PVC"),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """上传项目（异步初始化）"""
    # 检查文件类型
    if not FileUtils.allowed_file(file.filename):
        raise HTTPException(
            status_code=400,
            detail=f"不支持的文件类型，支持的类型: {', '.join(Config.ALLOWED_EXTENSIONS)}"
        )

    # 创建临时文件
    temp_path = os.path.join(Config.UPLOAD_DIR, f"temp_{user.id}_{file.filename}")

    try:
        # 保存文件
        file_size = 0
        with open(temp_path, "wb") as f:
            while True:
                chunk = await file.read(8192)
                if not chunk:
                    break
                file_size += len(chunk)
                if file_size > Config.MAX_FILE_SIZE:
                    os.remove(temp_path)
                    raise HTTPException(
                        status_code=400,
                        detail=f"文件大小超过限制 ({Config.MAX_FILE_SIZE // (1024*1024)}MB)"
                    )
                f.write(chunk)

        # 计算MD5
        file_md5 = FileUtils.calculate_md5(temp_path)

        # 生成项目ID（使用新的生成方式）
        project_id = FileUtils.generate_project_id(project_name, file_md5)

        # 检查是否已存在
        existing = db.query(Project).filter(Project.id == project_id).first()
        if existing:
            os.remove(temp_path)
            return JSONResponse(
                status_code=200,
                content={
                    "project_id": project_id,
                    "message": "项目已存在",
                    "existing": True
                }
            )

        # 保存原始文件
        ext = file.filename.rsplit('.', 1)[1].lower()
        archive_path = os.path.join(Config.ARCHIVE_DIR, f"{project_id}.{ext}")
        shutil.move(temp_path, archive_path)

        # 创建项目记录，状态为pending
        project = Project(
            id=project_id,
            name=project_name,
            description=description,
            original_filename=file.filename,
            archive_path=archive_path,
            extract_path=None,  # 初始化任务会设置
            archive_size=file_size,
            file_count=0,  # 初始化任务会设置
            total_size=0,  # 初始化任务会设置
            user_id=user.id,
            status=Config.PROJECT_STATUS_PENDING,  # 初始状态
            pvc_status="pending",
            pvc_size=storage_size
        )
        db.add(project)
        db.commit()

        # 提交异步初始化任务
        task_id = task_manager.submit(
            "initialize_project",
            initialize_project_task,
            project_id,
            archive_path,
            storage_size,
            create_pvc
        )

        return {
            "project_id": project_id,
            "name": project_name,
            "status": Config.PROJECT_STATUS_PENDING,
            "task_id": task_id,
            "message": "项目上传成功，正在异步初始化...",
            "create_pvc": create_pvc
        }

    except Exception as e:
        # 清理临时文件
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass

        logger.error(f"上传项目失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get(f"{Config.API_PREFIX}/projects")
async def list_projects(
        page: int = Query(1, ge=1),
        size: int = Query(10, ge=1, le=100),
        search: Optional[str] = None,
        status: Optional[str] = Query(None, description="项目状态过滤"),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取项目列表"""
    query = db.query(Project).filter(Project.user_id == user.id)

    if search:
        search_pattern = f"%{search}%"
        # 搜索项目名或文件名
        file_project_ids = db.query(ProjectFile).filter(
            ProjectFile.file_name.like(search_pattern)
        ).distinct().subquery()

        query = query.filter(
            (Project.name.like(search_pattern)) |
            (Project.id.in_(file_project_ids))
        )

    if status:
        query = query.filter(Project.status == status)

    total = query.count()
    projects = query.order_by(Project.created_at.desc()).offset((page-1)*size).limit(size).all()

    result = []
    for project in projects:
        code_server = db.query(CodeServer).filter(CodeServer.project_id == project.id).first()

        result.append({
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "status": project.status,
            "file_count": project.file_count,
            "total_size": project.total_size,
            "pvc_name": project.pvc_name,
            "pvc_status": project.pvc_status,
            "file_synced": project.file_synced,
            "created_at": project.created_at,
            "initialized_at": project.initialized_at,
            "code_server_status": code_server.status if code_server else None
        })

    return {
        "total": total,
        "page": page,
        "size": size,
        "projects": result
    }

@app.get(f"{Config.API_PREFIX}/projects/{{project_id}}")
async def get_project(
        project_id: str,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取项目详情"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 获取文件列表（如果项目已初始化）
    files = []
    if project.status == Config.PROJECT_STATUS_READY:
        files = db.query(ProjectFile).filter(ProjectFile.project_id == project_id).all()

    # 获取Code-Server信息
    code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()

    # 获取PVC信息（如果K8S可用）
    pvc_info = None
    if k8s_manager and k8s_manager.available and project.pvc_name:
        try:
            pvc_info = k8s_manager.get_pvc_status(project_id)
        except:
            pvc_info = {"error": "无法获取PVC状态"}

    return {
        "project": {
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "status": project.status,
            "original_filename": project.original_filename,
            "file_count": project.file_count,
            "total_size": project.total_size,
            "archive_size": project.archive_size,
            "pvc_name": project.pvc_name,
            "pvc_status": project.pvc_status,
            "pvc_size": project.pvc_size,
            "file_synced": project.file_synced,
            "init_log_path": project.init_log_path,
            "init_error": project.init_error,
            "created_at": project.created_at,
            "initialized_at": project.initialized_at
        },
        "files": [
            {
                "path": f.file_path,
                "name": f.file_name,
                "size": f.file_size,
                "type": f.file_type
            }
            for f in files
        ] if files else [],
        "code_server": {
            "status": code_server.status if code_server else None,
            "access_url": code_server.access_url if code_server else None,
            "deployment": code_server.deployment_name if code_server else None,
            "created_at": code_server.created_at if code_server else None
        } if code_server else None,
        "pvc_info": pvc_info
    }

@app.get(f"{Config.API_PREFIX}/projects/{{project_id}}/status")
async def get_project_status(
        project_id: str,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取项目状态"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 获取最近的任务日志
    task_log = db.query(ProjectTaskLog).filter(
        ProjectTaskLog.project_id == project_id
    ).order_by(ProjectTaskLog.created_at.desc()).first()

    return {
        "project_id": project_id,
        "name": project.name,
        "status": project.status,
        "pvc_status": project.pvc_status,
        "file_synced": project.file_synced,
        "init_log_path": project.init_log_path,
        "init_error": project.init_error,
        "created_at": project.created_at,
        "initialized_at": project.initialized_at,
        "last_task": {
            "task_type": task_log.task_type if task_log else None,
            "status": task_log.status if task_log else None,
            "created_at": task_log.created_at if task_log else None,
            "completed_at": task_log.completed_at if task_log else None
        } if task_log else None
    }

@app.get(f"{Config.API_PREFIX}/projects/{{project_id}}/init-logs")
async def get_project_init_logs(
        project_id: str,
        lines: int = Query(100, ge=1, le=5000, description="日志行数"),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取项目初始化日志"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    if not project.init_log_path or not os.path.exists(project.init_log_path):
        raise HTTPException(status_code=404, detail="初始化日志不存在")

    try:
        # 读取日志文件
        with open(project.init_log_path, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
            if lines <= 0:
                log_content = "".join(all_lines)
            else:
                log_content = "".join(all_lines[-lines:])

        return {
            "project_id": project_id,
            "project_name": project.name,
            "status": project.status,
            "log_path": project.init_log_path,
            "lines": len(all_lines),
            "log_content": log_content
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"读取日志文件失败: {str(e)}")

@app.get(f"{Config.API_PREFIX}/projects/{{project_id}}/task-logs")
async def get_project_task_logs(
        project_id: str,
        task_type: Optional[str] = Query(None, description="任务类型过滤"),
        limit: int = Query(10, ge=1, le=100, description="返回数量"),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取项目任务日志列表"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    query = db.query(ProjectTaskLog).filter(ProjectTaskLog.project_id == project_id)

    if task_type:
        query = query.filter(ProjectTaskLog.task_type == task_type)

    task_logs = query.order_by(ProjectTaskLog.created_at.desc()).limit(limit).all()

    result = []
    for log in task_logs:
        log_content = None
        if log.log_path and os.path.exists(log.log_path):
            try:
                with open(log.log_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    log_content = "".join(lines[-50:])  # 最后50行
            except:
                log_content = "读取日志文件失败"

        result.append({
            "id": log.id,
            "task_type": log.task_type,
            "task_id": log.task_id,
            "status": log.status,
            "log_path": log.log_path,
            "error_message": log.error_message,
            "created_at": log.created_at,
            "completed_at": log.completed_at,
            "log_preview": log_content
        })

    return {
        "project_id": project_id,
        "project_name": project.name,
        "total": len(task_logs),
        "task_logs": result
    }

# ============ PVC管理API ============

@app.post(f"{Config.API_PREFIX}/projects/{{project_id}}/pvc/create")
async def create_project_pvc(
        project_id: str,
        storage_size: str = Form(Config.K8S_DEFAULT_STORAGE_SIZE),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """为项目创建PVC并拷贝文件"""
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法创建PVC。请等待项目初始化完成。"
        )

    # 检查项目是否有源码
    if not project.extract_path or not os.path.exists(project.extract_path):
        raise HTTPException(status_code=400, detail="项目源码不存在，无法创建PVC")

    # 检查是否已有PVC
    if project.pvc_name and project.pvc_status == "ready":
        raise HTTPException(
            status_code=400,
            detail=f"PVC已存在: {project.pvc_name}"
        )

    # 检查K8S是否可用
    if not K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法创建PVC"
        )

    # 提交任务
    task_id = task_manager.submit(
        "create_project_pvc",
        create_project_pvc_task,
        project_id,
        project.extract_path,
        storage_size
    )

    return {
        "task_id": task_id,
        "message": "PVC创建任务已提交",
        "project_id": project_id,
        "project_name": project.name,
        "storage_size": storage_size
    }

@app.post(f"{Config.API_PREFIX}/projects/{{project_id}}/pvc/recreate")
async def recreate_project_pvc(
        project_id: str,
        request: RecreatePVCRequest,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """重建项目PVC（删除旧的，创建新的，重新拷贝文件）"""
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY and project.status  != Config.PROJECT_STATUS_ERROR:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法重建PVC。请等待项目初始化完成。"
        )

    # 检查项目是否有源码
    if not project.extract_path or not os.path.exists(project.extract_path):
        raise HTTPException(status_code=400, detail="项目源码不存在，无法重建PVC")

    # 检查K8S是否可用
    if not K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法重建PVC"
        )

    # 提交任务
    task_id = task_manager.submit(
        "recreate_project_pvc",
        recreate_project_pvc_task,
        project_id,
        request.storage_size
    )

    return {
        "task_id": task_id,
        "message": "PVC重建任务已提交",
        "project_id": project_id,
        "project_name": project.name,
        "storage_size": request.storage_size or project.pvc_size
    }

@app.get(f"{Config.API_PREFIX}/projects/{{project_id}}/pvc/status")
async def get_project_pvc_status(
        project_id: str,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取项目PVC状态"""
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    if not project.pvc_name:
        raise HTTPException(status_code=404, detail="项目未创建PVC")

    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(status_code=503, detail="Kubernetes功能不可用")

    try:
        pvc_info = k8s_manager.get_pvc_status(project_id)

        return {
            "project_id": project_id,
            "project_name": project.name,
            "pvc_name": project.pvc_name,
            "pvc_status": project.pvc_status,
            "pvc_size": project.pvc_size,
            "file_synced": project.file_synced,
            "k8s_pvc_info": pvc_info
        }
    except CodeServerError as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"获取PVC状态失败: {str(e)}"
        )

@app.delete(f"{Config.API_PREFIX}/projects/{{project_id}}/pvc")
async def delete_project_pvc(
        project_id: str,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """删除项目PVC"""
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    if not project.pvc_name:
        raise HTTPException(status_code=404, detail="项目未创建PVC")

    # 检查是否有运行的Code-Server
    code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
    if code_server and code_server.status in ["creating", "running"]:
        raise HTTPException(
            status_code=400,
            detail="有运行的Code-Server，请先停止或删除Code-Server"
        )

    # 检查K8S是否可用
    if not K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法删除PVC"
        )

    try:
        # 同步删除PVC
        if k8s_manager and k8s_manager.available:
            k8s_manager.delete_pvc(project_id)

        # 更新数据库
        project.pvc_name = None
        project.pvc_status = "pending"
        project.file_synced = False
        db.commit()

        return {
            "success": True,
            "project_id": project_id,
            "project_name": project.name,
            "message": "PVC删除成功"
        }
    except CodeServerError as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"删除PVC失败: {str(e)}"
        )

# ============ 部署状态和日志查询API ============

@app.get(f"{Config.API_PREFIX}/code-servers/{{project_id}}/deployment/status")
async def get_deployment_status(
        project_id: str,
        include_pods: bool = Query(True, description="是否包含Pod信息"),
        include_events: bool = Query(True, description="是否包含事件信息"),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取Code-Server部署的详细状态"""
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    # 检查Code-Server是否存在
    code_server = db.query(CodeServer).filter(
        CodeServer.project_id == project_id
    ).first()

    if not code_server:
        raise HTTPException(status_code=404, detail="Code-Server不存在")

    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(status_code=503, detail="Kubernetes功能不可用")

    try:
        # 获取Deployment状态
        deploy_status = k8s_manager.get_deployment_status(project_id)

        result = {
            "project_id": project_id,
            "project_name": project.name,
            "deployment": deploy_status,
            "code_server_status": code_server.status,
            "created_at": code_server.created_at,
            "started_at": code_server.started_at
        }

        # 获取Pod详细信息
        if include_pods and deploy_status.get("pods"):
            pod_details = []
            for pod_info in deploy_status["pods"]:
                try:
                    pod = k8s_manager.core_v1.read_namespaced_pod(
                        name=pod_info["name"], namespace=k8s_manager.namespace
                    )

                    # 获取容器状态
                    container_statuses = []
                    if pod.status.container_statuses:
                        for container in pod.status.container_statuses:
                            status = {}
                            if container.state.running:
                                status["state"] = "running"
                                status["started_at"] = container.state.running.started_at
                            elif container.state.waiting:
                                status["state"] = "waiting"
                                status["reason"] = container.state.waiting.reason
                                status["message"] = container.state.waiting.message
                            elif container.state.terminated:
                                status["state"] = "terminated"
                                status["exit_code"] = container.state.terminated.exit_code
                                status["reason"] = container.state.terminated.reason
                                status["message"] = container.state.terminated.message
                                status["finished_at"] = container.state.terminated.finished_at

                            container_statuses.append({
                                "name": container.name,
                                "ready": container.ready,
                                "restart_count": container.restart_count,
                                "image": container.image,
                                "status": status
                            })

                    pod_details.append({
                        "name": pod_info["name"],
                        "namespace": pod.metadata.namespace,
                        "node": pod.spec.node_name,
                        "ip": pod.status.pod_ip,
                        "host_ip": pod.status.host_ip,
                        "phase": pod.status.phase,
                        "start_time": pod.status.start_time,
                        "containers": container_statuses,
                        "conditions": [
                            {
                                "type": cond.type,
                                "status": cond.status,
                                "reason": cond.reason,
                                "message": cond.message,
                                "last_transition_time": cond.last_transition_time
                            }
                            for cond in (pod.status.conditions or [])
                        ]
                    })
                except ApiException as e:
                    pod_details.append({
                        "name": pod_info["name"],
                        "error": f"获取Pod信息失败: {e.reason if e.reason else str(e)}"
                    })

            result["pod_details"] = pod_details

        # 获取事件信息
        if include_events:
            try:
                # 获取Deployment事件
                deploy_events = k8s_manager.core_v1.list_namespaced_event(
                    namespace=k8s_manager.namespace,
                    field_selector=f"involvedObject.name={deploy_status.get('name')},involvedObject.kind=Deployment"
                )

                # 获取Pod事件
                pod_events = k8s_manager.core_v1.list_namespaced_event(
                    namespace=k8s_manager.namespace,
                    field_selector=f"involvedObject.fieldPath=spec.containers{{code-server}},involvedObject.kind=Pod"
                )

                events = []
                for event in deploy_events.items[:50]:  # 限制数量
                    events.append({
                        "type": "deployment",
                        "name": event.metadata.name,
                        "reason": event.reason,
                        "message": event.message,
                        "source": f"{event.source.component}: {event.source.host}" if event.source else None,
                        "count": event.count,
                        "first_timestamp": event.first_timestamp,
                        "last_timestamp": event.last_timestamp,
                        "type": event.type
                    })

                for event in pod_events.items[:50]:
                    events.append({
                        "type": "pod",
                        "name": event.metadata.name,
                        "reason": event.reason,
                        "message": event.message,
                        "source": f"{event.source.component}: {event.source.host}" if event.source else None,
                        "count": event.count,
                        "first_timestamp": event.first_timestamp,
                        "last_timestamp": event.last_timestamp,
                        "type": event.type
                    })

                # 按时间排序
                events.sort(key=lambda x: x.get("last_timestamp") or x.get("first_timestamp") or "", reverse=True)
                result["events"] = events[:100]  # 最多返回100个事件

            except Exception as e:
                result["events_error"] = f"获取事件失败: {str(e)}"

        return result

    except ApiException as e:
        if e.status == 404:
            raise HTTPException(
                status_code=404,
                detail=f"Deployment不存在: {project_id}"
            )
        raise HTTPException(
            status_code=500,
            detail=f"获取部署状态失败: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"获取部署状态失败: {str(e)}"
        )

@app.get(f"{Config.API_PREFIX}/code-servers/{{project_id}}/deployment/logs")
async def get_deployment_logs(
        project_id: str,
        log_type: str = Query("all", description="日志类型: all, code-server, init, copy-job"),
        lines: int = Query(100, ge=1, le=5000, description="日志行数"),
        previous: bool = Query(False, description="是否获取上一次的日志（适用于已终止的容器）"),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取Code-Server部署相关的所有日志"""
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    # 检查Code-Server是否存在
    code_server = db.query(CodeServer).filter(
        CodeServer.project_id == project_id
    ).first()

    if not code_server:
        raise HTTPException(status_code=404, detail="Code-Server不存在")

    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(status_code=503, detail="Kubernetes功能不可用")

    try:
        # 获取Deployment状态
        deploy_status = k8s_manager.get_deployment_status(project_id)
        logs_result = {
            "project_id": project_id,
            "project_name": project.name,
            "log_type": log_type,
            "lines": lines,
            "logs": []
        }

        # 获取Code-Server Pod日志
        if log_type in ["all", "code-server"] and deploy_status.get("pods"):
            for pod_info in deploy_status["pods"]:
                try:
                    # 获取容器日志
                    log_content = k8s_manager.core_v1.read_namespaced_pod_log(
                        name=pod_info["name"],
                        namespace=k8s_manager.namespace,
                        container="code-server",
                        tail_lines=lines,
                        previous=previous
                    )

                    logs_result["logs"].append({
                        "source": "code-server",
                        "pod": pod_info["name"],
                        "container": "code-server",
                        "content": log_content
                    })
                except ApiException as e:
                    logs_result["logs"].append({
                        "source": "code-server",
                        "pod": pod_info["name"],
                        "error": f"获取日志失败: {e.reason if e.reason else str(e)}"
                    })

        # 获取初始化容器日志
        if log_type in ["all", "init"] and deploy_status.get("pods"):
            for pod_info in deploy_status["pods"]:
                try:
                    pod = k8s_manager.core_v1.read_namespaced_pod(
                        name=pod_info["name"], namespace=k8s_manager.namespace
                    )

                    # 检查是否有初始化容器
                    if pod.spec.init_containers:
                        for init_container in pod.spec.init_containers:
                            try:
                                init_log = k8s_manager.core_v1.read_namespaced_pod_log(
                                    name=pod_info["name"],
                                    namespace=k8s_manager.namespace,
                                    container=init_container.name,
                                    tail_lines=lines,
                                    previous=previous
                                )

                                logs_result["logs"].append({
                                    "source": "init-container",
                                    "pod": pod_info["name"],
                                    "container": init_container.name,
                                    "content": init_log
                                })
                            except ApiException as e:
                                logs_result["logs"].append({
                                    "source": "init-container",
                                    "pod": pod_info["name"],
                                    "container": init_container.name,
                                    "error": f"获取日志失败: {e.reason if e.reason else str(e)}"
                                })
                except ApiException:
                    continue

        # 获取复制任务日志
        if log_type in ["all", "copy-job"]:
            try:
                # 查找复制任务相关的Pod
                copy_jobs = k8s_manager.batch_v1.list_namespaced_job(
                    namespace=k8s_manager.namespace,
                    label_selector=f"project-id={project_id},app=file-copy"
                )

                for job in copy_jobs.items:
                    # 获取Job的Pod
                    job_pods = k8s_manager.core_v1.list_namespaced_pod(
                        namespace=k8s_manager.namespace,
                        label_selector=f"job-name={job.metadata.name}"
                    )

                    for pod in job_pods.items:
                        try:
                            copy_log = k8s_manager.core_v1.read_namespaced_pod_log(
                                name=pod.metadata.name,
                                namespace=k8s_manager.namespace,
                                container="copy",
                                tail_lines=lines,
                                previous=previous
                            )

                            logs_result["logs"].append({
                                "source": "copy-job",
                                "job": job.metadata.name,
                                "pod": pod.metadata.name,
                                "container": "copy",
                                "content": copy_log
                            })
                        except ApiException as e:
                            logs_result["logs"].append({
                                "source": "copy-job",
                                "job": job.metadata.name,
                                "pod": pod.metadata.name,
                                "error": f"获取日志失败: {e.reason if e.reason else str(e)}"
                            })
            except ApiException as e:
                logs_result["logs"].append({
                    "source": "copy-job",
                    "error": f"查找复制任务失败: {e.reason if e.reason else str(e)}"
                })

        return logs_result

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"获取部署日志失败: {str(e)}"
        )

@app.get(f"{Config.API_PREFIX}/code-servers/{{project_id}}/deployment/pods")
async def get_deployment_pods(
        project_id: str,
        include_all: bool = Query(False, description="是否包含所有相关Pod（包括历史Pod）"),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取Code-Server相关的所有Pod信息"""
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(status_code=503, detail="Kubernetes功能不可用")

    try:
        pods_result = []

        # 获取Code-Server相关的Pod
        try:
            code_server_pods = k8s_manager.core_v1.list_namespaced_pod(
                namespace=k8s_manager.namespace,
                label_selector=f"project-id={project_id},app=code-server"
            )

            for pod in code_server_pods.items:
                pod_info = {
                    "name": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "labels": pod.metadata.labels,
                    "creation_timestamp": pod.metadata.creation_timestamp,
                    "phase": pod.status.phase,
                    "node": pod.spec.node_name,
                    "ip": pod.status.pod_ip,
                    "host_ip": pod.status.host_ip,
                    "type": "code-server"
                }

                # 获取容器状态
                if pod.status.container_statuses:
                    containers = []
                    for container in pod.status.container_statuses:
                        container_info = {
                            "name": container.name,
                            "image": container.image,
                            "ready": container.ready,
                            "restart_count": container.restart_count
                        }

                        if container.state.running:
                            container_info["state"] = "running"
                            container_info["started_at"] = container.state.running.started_at
                        elif container.state.waiting:
                            container_info["state"] = "waiting"
                            container_info["reason"] = container.state.waiting.reason
                            container_info["message"] = container.state.waiting.message
                        elif container.state.terminated:
                            container_info["state"] = "terminated"
                            container_info["exit_code"] = container.state.terminated.exit_code
                            container_info["reason"] = container.state.terminated.reason
                            container_info["message"] = container.state.terminated.message

                        containers.append(container_info)

                    pod_info["containers"] = containers

                pods_result.append(pod_info)
        except ApiException as e:
            pods_result.append({
                "type": "code-server",
                "error": f"获取Pod列表失败: {e.reason if e.reason else str(e)}"
            })

        # 获取复制任务相关的Pod
        if include_all:
            try:
                copy_jobs = k8s_manager.batch_v1.list_namespaced_job(
                    namespace=k8s_manager.namespace,
                    label_selector=f"project-id={project_id},app=file-copy"
                )

                for job in copy_jobs.items:
                    job_pods = k8s_manager.core_v1.list_namespaced_pod(
                        namespace=k8s_manager.namespace,
                        label_selector=f"job-name={job.metadata.name}"
                    )

                    for pod in job_pods.items:
                        pod_info = {
                            "name": pod.metadata.name,
                            "namespace": pod.metadata.namespace,
                            "labels": pod.metadata.labels,
                            "creation_timestamp": pod.metadata.creation_timestamp,
                            "phase": pod.status.phase,
                            "type": "copy-job",
                            "job_name": job.metadata.name
                        }

                        pods_result.append(pod_info)
            except ApiException as e:
                pods_result.append({
                    "type": "copy-job",
                    "error": f"获取复制任务Pod失败: {e.reason if e.reason else str(e)}"
                })

        # 按创建时间排序
        pods_result.sort(key=lambda x: x.get("creation_timestamp") or "", reverse=True)

        return {
            "project_id": project_id,
            "project_name": project.name,
            "total_pods": len(pods_result),
            "pods": pods_result
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"获取Pod信息失败: {str(e)}"
        )

# ============ 文件下载API ============

@app.get(f"{Config.API_PREFIX}/projects/{{project_id}}/download")
async def download_file(
        project_id: str,
        file_path: str = Query(..., description="项目内相对文件路径"),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    下载项目中的单个文件

    Args:
        project_id: 项目ID
        file_path: 项目内相对文件路径，例如：src/main.py 或 docs/README.md
    """
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法下载文件。请等待项目初始化完成。"
        )

    # 检查项目解压路径是否存在
    if not project.extract_path or not os.path.exists(project.extract_path):
        raise HTTPException(status_code=404, detail="项目文件不存在")

    # 下载文件
    temp_path = FileUtils.download_file(project.extract_path, file_path, user.id)

    if not temp_path:
        raise HTTPException(status_code=404, detail="文件不存在或无法下载")

    # 获取文件名
    filename = os.path.basename(file_path)

    # 返回文件
    return FileResponse(
        path=temp_path,
        filename=filename,
        media_type="application/octet-stream"
    )

@app.get(f"{Config.API_PREFIX}/projects/{{project_id}}/download/dir")
async def download_directory(
        project_id: str,
        dir_path: str = Query(..., description="项目内相对目录路径"),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    下载项目中的目录（打包为zip）

    Args:
        project_id: 项目ID
        dir_path: 项目内相对目录路径，例如：src 或 docs
    """
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法下载目录。请等待项目初始化完成。"
        )

    # 检查项目解压路径是否存在
    if not project.extract_path or not os.path.exists(project.extract_path):
        raise HTTPException(status_code=404, detail="项目文件不存在")

    # 下载目录（打包为zip）
    temp_path = FileUtils.download_directory(project.extract_path, dir_path, user.id)

    if not temp_path:
        raise HTTPException(status_code=404, detail="目录不存在或无法下载")

    # 获取目录名
    dir_name = os.path.basename(dir_path) or "root"
    filename = f"{dir_name}.zip"

    # 返回文件
    return FileResponse(
        path=temp_path,
        filename=filename,
        media_type="application/zip"
    )

@app.post(f"{Config.API_PREFIX}/projects/{{project_id}}/download/multiple")
async def download_multiple_files(
        project_id: str,
        download_request: MultiDownloadRequest,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    下载项目中的多个文件（打包为zip）

    Args:
        project_id: 项目ID
        download_request: 包含多个文件路径的请求体
    """
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法下载文件。请等待项目初始化完成。"
        )

    # 检查项目解压路径是否存在
    if not project.extract_path or not os.path.exists(project.extract_path):
        raise HTTPException(status_code=404, detail="项目文件不存在")

    # 检查文件路径列表是否为空
    if not download_request.file_paths:
        raise HTTPException(status_code=400, detail="文件路径列表不能为空")

    # 下载多个文件（打包为zip）
    temp_path = FileUtils.download_project_files(
        project.extract_path,
        download_request.file_paths,
        user.id
    )

    if not temp_path:
        raise HTTPException(status_code=404, detail="文件不存在或无法下载")

    # 返回文件
    return FileResponse(
        path=temp_path,
        filename="selected_files.zip",
        media_type="application/zip"
    )

@app.get(f"{Config.API_PREFIX}/projects/{{project_id}}/download/stream")
async def download_file_stream(
        project_id: str,
        file_path: str = Query(..., description="项目内相对文件路径"),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    流式下载项目中的文件（适用于大文件）

    Args:
        project_id: 项目ID
        file_path: 项目内相对文件路径
    """
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法下载文件。请等待项目初始化完成。"
        )

    # 检查项目解压路径是否存在
    if not project.extract_path or not os.path.exists(project.extract_path):
        raise HTTPException(status_code=404, detail="项目文件不存在")

    # 检查路径安全性
    if not FileUtils.is_safe_path(project.extract_path, file_path):
        raise HTTPException(status_code=400, detail="文件路径不安全")

    # 构建完整文件路径
    full_path = os.path.join(project.extract_path, file_path)

    # 检查文件是否存在
    if not os.path.exists(full_path) or not os.path.isfile(full_path):
        raise HTTPException(status_code=404, detail="文件不存在")

    # 检查文件大小
    file_size = os.path.getsize(full_path)
    if file_size > Config.MAX_DOWNLOAD_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"文件太大，最大支持 {Config.MAX_DOWNLOAD_SIZE // (1024*1024)}MB"
        )

    # 获取文件名
    filename = os.path.basename(file_path)

    # 流式返回文件
    def file_generator():
        with open(full_path, "rb") as f:
            while chunk := f.read(8192):
                yield chunk

    return StreamingResponse(
        file_generator(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Length": str(file_size)
        }
    )

@app.get(f"{Config.API_PREFIX}/projects/{{project_id}}/download/archive")
async def download_project_archive(
        project_id: str,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    下载整个项目的原始压缩包
    """
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    # 检查原始压缩包是否存在
    if not project.archive_path or not os.path.exists(project.archive_path):
        raise HTTPException(status_code=404, detail="项目压缩包不存在")

    # 获取原始文件名
    original_filename = project.original_filename
    if not original_filename:
        original_filename = f"{project.name}.zip"

    # 返回文件
    return FileResponse(
        path=project.archive_path,
        filename=original_filename,
        media_type="application/octet-stream"
    )

@app.delete(f"{Config.API_PREFIX}/projects/{{project_id}}")
async def delete_project(
        project_id: str,
        background_tasks: BackgroundTasks,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """删除项目（异步删除所有相关资源）"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 提交异步删除任务
    task_id = task_manager.submit(
        "delete_project",
        delete_project_task,
        project_id,
        user.id
    )

    return {
        "task_id": task_id,
        "message": "项目删除任务已提交",
        "project_id": project_id,
        "project_name": project.name
    }

@app.get(f"{Config.API_PREFIX}/projects/{{project_id}}/search")
async def search_files_in_project(
        project_id: str,
        filename: str = Query(...),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """在项目中搜索文件"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法搜索文件。请等待项目初始化完成。"
        )

    files = db.query(ProjectFile).filter(
        ProjectFile.project_id == project_id,
        ProjectFile.file_name.like(f"%{filename}%")
    ).all()

    return [
        {
            "project_id": project_id,
            "project_name": project.name,
            "file_path": f.file_path,
            "file_name": f.file_name,
            "file_size": f.file_size,
            "file_type": f.file_type
        }
        for f in files
    ]

@app.get(f"{Config.API_PREFIX}/search")
async def global_search(
        q: str = Query(...),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """全局搜索"""
    search_pattern = f"%{q}%"

    # 搜索项目
    projects = db.query(Project).filter(
        Project.user_id == user.id,
        (Project.name.like(search_pattern)) |
        (Project.description.like(search_pattern))
    ).all()

    # 搜索文件
    files = db.query(ProjectFile).join(Project).filter(
        Project.user_id == user.id,
        ProjectFile.file_name.like(search_pattern)
    ).all()

    return {
        "projects": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "file_count": p.file_count,
                "status": p.status
            }
            for p in projects
        ],
        "files": [
            {
                "project_id": f.project_id,
                "project_name": f.project.name,
                "path": f.file_path,
                "name": f.file_name,
                "size": f.file_size
            }
            for f in files
        ]
    }

# ============ Code-Server 相关API ============

@app.post(f"{Config.API_PREFIX}/projects/{{project_id}}/code-server")
async def create_code_server(
        project_id: str,
        background_tasks: BackgroundTasks,
        config_data: CodeServerCreate = Body(...),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """创建Code-Server（使用已有的PVC）"""
    # 检查项目
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法创建Code-Server。请等待项目初始化完成。"
        )

    # 检查项目PVC状态
    if not project.pvc_name or project.pvc_status != "ready":
        raise HTTPException(
            status_code=400,
            detail=f"项目PVC不可用，状态: {project.pvc_status}，请先创建PVC"
        )

    # 检查是否已存在Code-Server
    existing = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
    if existing and existing.status in ["creating", "running"]:
        raise HTTPException(
            status_code=400,
            detail=f"Code-Server已存在，状态: {existing.status}"
        )

    # 检查K8S是否可用
    if not K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，请检查K8S客户端配置"
        )

    # 检查K8S管理器是否已初始化
    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes管理器不可用，请检查K8S配置"
        )

    # 提交任务
    task_id = task_manager.submit(
        "create_code_server",
        create_code_server_task,
        project_id,
        user.id,
        config_data.password,
        config_data.cpu_limit,
        config_data.memory_limit
    )

    return {
        "task_id": task_id,
        "message": "Code-Server创建任务已提交",
        "project_id": project_id,
        "project_name": project.name,
        "pvc_name": project.pvc_name
    }

@app.get(f"{Config.API_PREFIX}/code-servers")
async def list_code_servers(
        page: int = Query(1, ge=1),
        size: int = Query(10, ge=1, le=100),
        status: Optional[str] = Query(None),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取Code-Server列表"""
    query = db.query(CodeServer).filter(CodeServer.user_id == user.id)

    if status:
        query = query.filter(CodeServer.status == status)

    total = query.count()
    servers = query.order_by(CodeServer.created_at.desc()).offset((page-1)*size).limit(size).all()

    result = []
    for cs in servers:
        project = db.query(Project).filter(Project.id == cs.project_id).first()

        result.append({
            "id": cs.id,
            "project_id": cs.project_id,
            "project_name": project.name if project else "未知项目",
            "project_status": project.status if project else None,
            "status": cs.status,
            "access_url": cs.access_url,
            "deployment": cs.deployment_name,
            "service": cs.service_name,
            "pvc": project.pvc_name if project else None,
            "pod_status": cs.pod_status,
            "cpu_limit": cs.cpu_limit,
            "memory_limit": cs.memory_limit,
            "created_at": cs.created_at,
            "started_at": cs.started_at
        })

    return {
        "total": total,
        "page": page,
        "size": size,
        "code_servers": result
    }

@app.get(f"{Config.API_PREFIX}/code-servers/{{project_id}}")
async def get_code_server(
        project_id: str,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取Code-Server详情"""
    cs = db.query(CodeServer).filter(
        CodeServer.project_id == project_id,
        CodeServer.user_id == user.id
    ).first()

    if not cs:
        raise HTTPException(status_code=404, detail="Code-Server不存在")

    project = db.query(Project).filter(Project.id == project_id).first()

    # 获取K8S详细信息
    k8s_info = {}
    if k8s_manager and k8s_manager.available:
        try:
            k8s_info["deployment"] = k8s_manager.get_deployment_status(project_id)
            k8s_info["service"] = k8s_manager.get_service_info(project_id)
            if project and project.pvc_name:
                k8s_info["pvc"] = k8s_manager.get_pvc_status(project_id)
        except CodeServerError as e:
            k8s_info["error"] = {
                "message": e.message,
                "details": e.details
            }
        except Exception as e:
            k8s_info["error"] = {
                "message": "获取K8S信息失败",
                "details": {"error": str(e)}
            }

    return {
        "code_server": {
            "id": cs.id,
            "project_id": cs.project_id,
            "project_name": project.name if project else "未知项目",
            "project_status": project.status if project else None,
            "status": cs.status,
            "access_url": cs.access_url,
            "password": cs.password,
            "deployment_name": cs.deployment_name,
            "service_name": cs.service_name,
            "pvc_name": project.pvc_name if project else None,
            "pod_name": cs.pod_name,
            "pod_status": cs.pod_status,
            "cpu_limit": cs.cpu_limit,
            "memory_limit": cs.memory_limit,
            "created_at": cs.created_at,
            "started_at": cs.started_at,
            "stopped_at": cs.stopped_at
        },
        "k8s_info": k8s_info
    }

@app.delete(f"{Config.API_PREFIX}/code-servers/{{project_id}}")
async def delete_code_server(
        project_id: str,
        background_tasks: BackgroundTasks,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """删除Code-Server（只删除运行时资源，保留PVC）"""
    cs = db.query(CodeServer).filter(
        CodeServer.project_id == project_id,
        CodeServer.user_id == user.id
    ).first()

    if not cs:
        raise HTTPException(status_code=404, detail="Code-Server不存在")

    # 检查K8S是否可用
    if not K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法删除Code-Server资源"
        )

    # 检查K8S管理器是否已初始化
    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes管理器不可用，无法删除Code-Server资源"
        )

    # 提交任务
    task_id = task_manager.submit(
        "delete_code_server",
        delete_code_server_task,
        project_id
    )

    return {
        "task_id": task_id,
        "message": "Code-Server删除任务已提交（PVC将保留）",
        "project_id": project_id
    }

@app.post(f"{Config.API_PREFIX}/code-servers/{{project_id}}/stop")
async def stop_code_server(
        project_id: str,
        background_tasks: BackgroundTasks,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """停止Code-Server"""
    cs = db.query(CodeServer).filter(
        CodeServer.project_id == project_id,
        CodeServer.user_id == user.id
    ).first()

    if not cs:
        raise HTTPException(status_code=404, detail="Code-Server不存在")

    # 检查K8S是否可用
    if not K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法停止Code-Server"
        )

    # 检查K8S管理器是否已初始化
    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes管理器不可用，无法停止Code-Server"
        )

    # 提交任务
    task_id = task_manager.submit(
        "stop_code_server",
        stop_code_server_task,
        project_id
    )

    return {
        "task_id": task_id,
        "message": "Code-Server停止任务已提交",
        "project_id": project_id
    }

@app.post(f"{Config.API_PREFIX}/code-servers/{{project_id}}/start")
async def start_code_server(
        project_id: str,
        background_tasks: BackgroundTasks,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """启动Code-Server"""
    cs = db.query(CodeServer).filter(
        CodeServer.project_id == project_id,
        CodeServer.user_id == user.id
    ).first()

    if not cs:
        raise HTTPException(status_code=404, detail="Code-Server不存在")

    # 检查K8S是否可用
    if not K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法启动Code-Server"
        )

    # 检查K8S管理器是否已初始化
    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes管理器不可用，无法启动Code-Server"
        )

    # 提交任务
    task_id = task_manager.submit(
        "start_code_server",
        start_code_server_task,
        project_id
    )

    return {
        "task_id": task_id,
        "message": "Code-Server启动任务已提交",
        "project_id": project_id
    }

@app.post(f"{Config.API_PREFIX}/code-servers/{{project_id}}/restart")
async def restart_code_server(
        project_id: str,
        background_tasks: BackgroundTasks,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """重启Code-Server"""
    cs = db.query(CodeServer).filter(
        CodeServer.project_id == project_id,
        CodeServer.user_id == user.id
    ).first()

    if not cs:
        raise HTTPException(status_code=404, detail="Code-Server不存在")

    # 检查K8S是否可用
    if not K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法重启Code-Server"
        )

    # 检查K8S管理器是否已初始化
    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes管理器不可用，无法重启Code-Server"
        )

    # 提交任务
    task_id = task_manager.submit(
        "restart_code_server",
        restart_code_server_task,
        project_id
    )

    return {
        "task_id": task_id,
        "message": "Code-Server重启任务已提交",
        "project_id": project_id
    }

@app.put(f"{Config.API_PREFIX}/code-servers/{{project_id}}")
async def update_code_server(
        project_id: str,
        background_tasks: BackgroundTasks,
        update_data: CodeServerUpdate = Body(...),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """更新Code-Server配置"""
    cs = db.query(CodeServer).filter(
        CodeServer.project_id == project_id,
        CodeServer.user_id == user.id
    ).first()

    if not cs:
        raise HTTPException(status_code=404, detail="Code-Server不存在")

    if not update_data.cpu_limit and not update_data.memory_limit:
        raise HTTPException(
            status_code=400,
            detail="请至少提供一个更新参数（cpu_limit或memory_limit）"
        )

    # 检查K8S是否可用
    if not K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法更新Code-Server配置"
        )

    # 检查K8S管理器是否已初始化
    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes管理器不可用，无法更新Code-Server配置"
        )

    # 提交任务
    task_id = task_manager.submit(
        "update_code_server",
        update_code_server_task,
        project_id,
        update_data.cpu_limit,
        update_data.memory_limit
    )

    return {
        "task_id": task_id,
        "message": "Code-Server配置更新任务已提交",
        "project_id": project_id
    }

@app.get(f"{Config.API_PREFIX}/code-servers/{{project_id}}/logs")
async def get_code_server_logs(
        project_id: str,
        lines: int = Query(100, ge=1, le=1000),
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取Code-Server日志"""
    cs = db.query(CodeServer).filter(
        CodeServer.project_id == project_id,
        CodeServer.user_id == user.id
    ).first()

    if not cs:
        raise HTTPException(status_code=404, detail="Code-Server不存在")

    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(status_code=503, detail="Kubernetes功能不可用")

    try:
        # 获取Pod名称
        deploy_status = k8s_manager.get_deployment_status(project_id)
        if not deploy_status.get("pods"):
            raise HTTPException(status_code=404, detail="未找到运行的Pod")

        pod_name = deploy_status["pods"][0]["name"]

        # 获取Pod日志
        log_content = k8s_manager.core_v1.read_namespaced_pod_log(
            name=pod_name,
            namespace=k8s_manager.namespace,
            container="code-server",
            tail_lines=lines
        )

        return {
            "pod_name": pod_name,
            "lines": lines,
            "logs": log_content
        }
    except ApiException as e:
        error_details = {
            "project_id": project_id,
            "status": e.status,
            "reason": e.reason
        }

        if e.status == 404:
            raise HTTPException(
                status_code=404,
                detail=f"获取日志失败: Pod不存在或已停止"
            )
        else:
            raise HTTPException(
                status_code=500,
                detail=f"获取日志失败: {str(e)}"
            )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"获取日志失败: {str(e)}"
        )

@app.get(f"{Config.API_PREFIX}/tasks/{{task_id}}")
async def get_task_status(task_id: str):
    """获取任务状态"""
    status_info = task_manager.get_status(task_id)

    # 如果任务失败，返回详细的错误信息
    if status_info["status"] == "failed":
        error_info = status_info.get("error", {})
        raise HTTPException(
            status_code=error_info.get("status_code", 500),
            detail={
                "message": error_info.get("message", "任务执行失败"),
                "details": error_info.get("details", {}),
                "task_id": task_id
            }
        )

    return {"task_id": task_id, **status_info}


@app.get(f"{Config.API_PREFIX}/projects/{{project_id}}/download/archive-token")
async def download_project_archive_with_token(
        project_id: str,
        token: str = Query(..., description="下载令牌"),
        db: Session = Depends(get_db)
):
    """
    通过令牌下载项目压缩包（无需用户认证）
    """
    # 验证令牌
    if token != Config.ARCHIVE_DOWNLOAD_TOKEN:
        raise HTTPException(
            status_code=403,
            detail="无效的下载令牌"
        )

    # 获取项目
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 检查原始压缩包是否存在
    if not project.archive_path or not os.path.exists(project.archive_path):
        raise HTTPException(status_code=404, detail="项目压缩包不存在")

    # 获取原始文件名
    original_filename = project.original_filename
    if not original_filename:
        original_filename = f"{project.name}.zip"

    # 返回文件
    return FileResponse(
        path=project.archive_path,
        filename=original_filename,
        media_type="application/octet-stream"
    )


@app.get("/health")
async def health_check():
    """基础健康检查"""
    return {
        "status": "healthy",
        "service": Config.APP_NAME,
        "version": Config.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get(f"{Config.API_PREFIX}/health")
async def detailed_health_check(db: Session = Depends(get_db)):
    """详细健康检查"""
    checks = {}

    # 数据库检查
    try:
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        checks["database"] = "healthy"
    except Exception as e:
        checks["database"] = f"unhealthy: {str(e)}"

    # 存储检查
    for name, path in [
        ("uploads", Config.UPLOAD_DIR),
        ("archives", Config.ARCHIVE_DIR),
        ("projects", Config.EXTRACT_DIR),
        ("downloads", Config.DOWNLOAD_DIR),
        ("task_logs", Config.TASK_LOG_DIR)
    ]:
        try:
            if os.path.exists(path):
                checks[f"storage_{name}"] = "healthy"
            else:
                checks[f"storage_{name}"] = f"unhealthy: 目录不存在"
        except Exception as e:
            checks[f"storage_{name}"] = f"unhealthy: {str(e)}"

    # Kubernetes检查
    if k8s_manager and k8s_manager.available:
        try:
            k8s_manager.core_v1.list_namespaced_pod(
                namespace=k8s_manager.namespace, limit=1
            )
            checks["kubernetes"] = "healthy"
            checks["k8s_api_url"] = k8s_manager.api_url or "default"
            checks["k8s_namespace"] = k8s_manager.namespace
            checks["k8s_auth"] = "配置成功"
        except Exception as e:
            checks["kubernetes"] = f"unhealthy: {str(e)}"
    else:
        checks["kubernetes"] = "unhealthy: Kubernetes管理器不可用"

    # JWT库检查
    if JWT_AVAILABLE:
        checks["jwt_library"] = "healthy"
    else:
        checks["jwt_library"] = "unhealthy: JWT库不可用"

    # FastAPI检查
    if FASTAPI_AVAILABLE:
        checks["fastapi"] = "healthy"
    else:
        checks["fastapi"] = "unhealthy: FastAPI库不可用"

    # 任务管理器检查
    if task_manager:
        try:
            # 使用任务管理器自身的健康检查方法
            if task_manager.is_healthy():
                checks["task_manager"] = "healthy"
            else:
                checks["task_manager"] = "unhealthy: 任务管理器线程池异常"
        except Exception as e:
            checks["task_manager"] = f"unhealthy: 检查失败: {str(e)}"
    else:
        checks["task_manager"] = "unhealthy: 任务管理器未初始化"

    # 统计信息
    try:
        user_count = db.query(User).count()
        project_count = db.query(Project).count()
        codeserver_count = db.query(CodeServer).count()

        # 项目状态统计
        project_status_stats = {}
        statuses = db.query(Project.status, func.count(Project.id)).group_by(Project.status).all()
        for status, count in statuses:
            project_status_stats[status] = count

        # 检查是否有错误状态的项目
        has_error_projects = project_status_stats.get(Config.PROJECT_STATUS_ERROR, 0) > 0
        stats_status = "healthy" if not has_error_projects else "unhealthy: 存在错误状态的项目"

        checks["stats"] = {
            "status": stats_status,
            "details": {
                "users": user_count,
                "projects": project_count,
                "code_servers": codeserver_count,
                "project_status": project_status_stats
            }
        }
    except Exception as e:
        checks["stats"] = f"unhealthy: 统计信息获取失败: {str(e)}"

    # 确定总体状态：如果所有检查都是healthy，则总体为healthy
    all_healthy = True
    error_messages = []

    for check_name, check_result in checks.items():
        if check_name.startswith("storage_") or check_name == "stats":
            # 存储和统计检查的特殊处理
            if isinstance(check_result, dict):
                if check_result.get("status", "").startswith("unhealthy"):
                    all_healthy = False
                    error_messages.append(f"{check_name}: {check_result['status']}")
            elif isinstance(check_result, str) and check_result.startswith("unhealthy"):
                all_healthy = False
                error_messages.append(f"{check_name}: {check_result}")
        elif isinstance(check_result, str) and check_result.startswith("unhealthy"):
            all_healthy = False
            error_messages.append(f"{check_name}: {check_result}")

    overall_status = "healthy" if all_healthy else "unhealthy"

    result = {
        "status": overall_status,
        "service": Config.APP_NAME,
        "version": Config.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks
    }

    if not all_healthy:
        result["errors"] = error_messages
        result["message"] = f"发现 {len(error_messages)} 个问题"

    return result


@app.get("/")
async def root():
    """根路径"""
    return {
        "message": f"欢迎使用 {Config.APP_NAME}",
        "version": Config.VERSION,
        "api_prefix": Config.API_PREFIX,
        "docs": "/docs" if Config.DEBUG else None,
        "k8s_available": K8S_AVAILABLE,
        "k8s_api_url": Config.K8S_API_URL or "default",
        "project_status_definitions": {
            "pending": "等待中",
            "initializing": "初始化中",
            "ready": "就绪",
            "error": "错误",
            "deleting": "删除中"
        }
    }

# ============ 启动应用 ============
def main():
    """主启动函数"""
    print(f"启动 {Config.APP_NAME} v{Config.VERSION}")
    print(f"数据库: {Config.DATABASE_URL}")
    print(f"存储目录: {Config.BASE_DIR}")
    print(f"API地址: http://0.0.0.0:8000")
    print(f"API文档: http://0.0.0.0:8000/docs")
    print(f"下载功能已启用，最大下载大小: {Config.MAX_DOWNLOAD_SIZE // (1024*1024)}MB")
    print(f"Code-Server错误处理已优化，错误信息将返回给客户端")
    print(f"项目状态管理: {', '.join([Config.PROJECT_STATUS_PENDING, Config.PROJECT_STATUS_INITIALIZING, Config.PROJECT_STATUS_READY, Config.PROJECT_STATUS_ERROR, Config.PROJECT_STATUS_DELETING])}")
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
    if not JWT_AVAILABLE:
        print("\n错误: JWT 库不可用，认证功能将无法正常工作，程序将退出")
        print("请安装 PyJWT 或 python-jose: pip install PyJWT 或 pip install python-jose[cryptography]")
        sys.exit(1)

    # 尝试初始化K8S管理器
    global k8s_manager, task_manager

    try:
        if K8S_AVAILABLE:
            print("\n=== 严格验证Kubernetes连接和配置 ===")
            try:
                print("正在连接Kubernetes集群...")
                print("如果连接失败，请检查以下配置：")
                if in_k8s:
                    print("1. 确保ServiceAccount有足够权限")
                    print("2. 确保命名空间存在")
                    print("3. 确保存储类存在")
                else:
                    print("1. 确保Kubernetes集群正在运行")
                    print("2. 确保kubeconfig文件正确配置")
                    print("3. 确保指定的命名空间存在")
                    print("4. 确保指定的存储类存在")
                    print("5. 确保有足够权限")

                k8s_manager = KubernetesManager(validate_connection=True)

                print("\n✓ Kubernetes连接成功")
                print(f"  集群版本: 已连接")
                print(f"  命名空间: {k8s_manager.namespace} (已存在)")
                print(f"  存储类: {k8s_manager.storage_class} (已存在)")
                print(f"  服务类型: {Config.K8S_SERVICE_TYPE}")
                print(f"  服务端口: {Config.K8S_SERVICE_PORT}")
                print(f"  容器端口: {Config.K8S_CONTAINER_PORT}")
                print(f"  权限验证: 全部通过")

                # 显示命名空间详细信息
                try:
                    namespace = k8s_manager.core_v1.read_namespace(name=k8s_manager.namespace)
                    print(f"  命名空间状态: {namespace.status.phase}")
                except:
                    pass

            except CodeServerError as e:
                print(f"\n✗ Kubernetes连接或配置验证失败: {e.message}")
                print(f"\n错误详情:")
                if e.details:
                    for key, value in e.details.items():
                        print(f"  {key}: {value}")

                print(f"\n状态码: {e.status_code}")
                print(f"\n请检查以下配置:")

                if in_k8s:
                    print("1. 确保ServiceAccount有足够权限")
                    print("2. 确保命名空间存在且可访问")
                    print("3. 确保存储类存在")
                    print("4. 检查Pod的ServiceAccount配置")
                else:
                    print("1. 确保Kubernetes集群正在运行")
                    print("2. 确保kubeconfig文件正确配置（默认~/.kube/config）")
                    print("3. 确保指定的命名空间存在")
                    print("4. 确保指定的存储类存在")
                    print("5. 确保有足够权限创建资源")

                print("\n常见问题解决:")
                print("1. 检查网络连接: ping <k8s-api-server>")
                print("2. 检查证书: openssl s_client -connect <k8s-api-server>:6443")
                print("3. 检查kubectl配置: kubectl cluster-info")
                print("4. 检查权限: kubectl auth can-i create deployment")

                sys.exit(1)
            except Exception as e:
                print(f"\n✗ Kubernetes连接或配置验证失败: {str(e)}")
                print(f"\n错误类型: {type(e).__name__}")

                import traceback
                print(f"\n详细堆栈信息:")
                print("-" * 80)
                traceback.print_exc()
                print("-" * 80)

                sys.exit(1)
        else:
            print("\n警告: kubernetes-client 未安装")
            print("如需使用Code-Server功能，请安装: pip install kubernetes")
            print("程序将继续运行，但K8S功能不可用")
            k8s_manager = None
    except Exception as e:
        print(f"\n✗ Kubernetes管理器初始化失败: {e}")
        print("程序将退出")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # 初始化任务管理器
    try:
        task_manager = TaskManager()
        print("\n✓ 任务管理器初始化成功")
    except Exception as e:
        print(f"✗ 任务管理器初始化失败: {e}")
        sys.exit(1)

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

    print("\n=== 启动服务 ===")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
        reload=Config.DEBUG
    )


if __name__ == "__main__":
    main()