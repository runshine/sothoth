#!/usr/bin/env python3
"""
WEB API服务器 - Docker Compose服务管理中心
增强版本：修复分布式锁问题，增强连接检查
支持多种压缩格式：.zip, .tar, .tar.gz, .tgz, .tar.bz2, .tbz, .tbz2, .tar.xz, .txz
"""

import os
import sys
import json
import yaml
import time
import uuid
import hashlib
import shutil
import zipfile
import threading
import logging
import argparse
import tempfile
import mimetypes
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict, field
from concurrent.futures import ThreadPoolExecutor, Future
import redis
import requests
from urllib.parse import urlparse
import base64
import io
from flask import send_file, redirect
import tarfile
import traceback

import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse
import base64
import requests
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import io
import zipfile
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime
import json
import yaml
from flask import send_file, redirect, Response

# ===================== 数据库抽象层 =====================

try:
    import pymysql
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False

try:
    from DBUtils.PooledDB import PooledDB
    POOLDB_AVAILABLE = True
except ImportError:
    try:
        from dbutils.pooled_db import PooledDB
        POOLDB_AVAILABLE = True
    except ImportError:
        POOLDB_AVAILABLE = False

import sqlite3

class DatabaseConnection:
    """数据库连接抽象类 - 支持连接池"""

    # 类级别的连接池缓存
    _mysql_pool = None
    _pool_lock = threading.Lock()

    def __init__(self, db_config: Dict, use_pool: bool = True):
        self.db_config = db_config
        self.db_type = db_config.get('type', 'sqlite')
        self.use_pool = use_pool and self.db_type == 'mysql'
        self.logger = logging.getLogger(__name__)
        self.connection = None
        self._is_pooled = False

    def _init_mysql_pool(self) -> bool:
        """初始化MySQL连接池"""
        if DatabaseConnection._mysql_pool is not None:
            return True

        with DatabaseConnection._pool_lock:
            if DatabaseConnection._mysql_pool is not None:
                return True

            if not POOLDB_AVAILABLE:
                self.logger.warning("DBUtils未安装，使用普通连接。建议安装: pip install DBUtils")
                return False

            try:
                DatabaseConnection._mysql_pool = PooledDB(
                    creator=pymysql,
                    host=self.db_config.get('host', 'localhost'),
                    port=self.db_config.get('port', 3306),
                    user=self.db_config.get('user', 'root'),
                    password=self.db_config.get('password', ''),
                    database=self.db_config.get('database', 'webapi'),
                    charset='utf8mb4',
                    cursorclass=pymysql.cursors.DictCursor,
                    autocommit=False,
                    mincached=2,      # 最小空闲连接数
                    maxcached=5,      # 最大空闲连接数
                    maxshared=0,      # 最大共享连接数
                    maxconnections=20, # 最大连接数
                    blocking=True,     # 连接池满时等待
                    maxusage=None,     # 不限制连接使用次数
                    setsession=[],     # 初始化会话设置
                    ping=1,            # 每次使用前ping，失效则重连
                )
                self.logger.info("MySQL连接池初始化成功")
                return True
            except Exception as e:
                self.logger.error(f"MySQL连接池初始化失败: {str(e)}")
                return False

    def connect(self) -> bool:
        """建立数据库连接（从连接池获取或新建）"""
        try:
            if self.connection is not None:
                return True

            if self.db_type == 'mysql':
                if not MYSQL_AVAILABLE:
                    self.logger.error("pymysql未安装，请使用 'pip install pymysql' 安装")
                    return False

                # 尝试使用连接池
                if self.use_pool and self._init_mysql_pool():
                    self.connection = DatabaseConnection._mysql_pool.connection()
                    self._is_pooled = True
                    self.logger.debug("从连接池获取MySQL连接")
                else:
                    # 回退到普通连接
                    self.connection = pymysql.connect(
                        host=self.db_config.get('host', 'localhost'),
                        port=self.db_config.get('port', 3306),
                        user=self.db_config.get('user', 'root'),
                        password=self.db_config.get('password', ''),
                        database=self.db_config.get('database', 'webapi'),
                        charset='utf8mb4',
                        cursorclass=pymysql.cursors.DictCursor,
                        autocommit=False,
                        connect_timeout=10
                    )
                    self.logger.debug("新建MySQL连接")
                return True

            elif self.db_type == 'sqlite':
                db_path = self.db_config.get('path', './webapi_server.db')
                db_dir = os.path.dirname(db_path)
                if db_dir:
                    os.makedirs(db_dir, exist_ok=True)

                self.connection = sqlite3.connect(db_path, check_same_thread=False)
                self.connection.row_factory = sqlite3.Row
                return True

            else:
                self.logger.error(f"不支持的数据库类型: {self.db_type}")
                return False

        except pymysql.Error as e:
            self.logger.error(f"MySQL数据库连接失败: {str(e)}")
            return False
        except sqlite3.Error as e:
            self.logger.error(f"SQLite数据库连接失败: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"数据库连接失败: {str(e)}")
            return False

    def test_connection(self) -> bool:
        """测试数据库连接是否正常（不关闭连接）"""
        try:
            if not self.connect():
                return False
            cursor = self.connection.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            return True
        except Exception as e:
            self.logger.error(f"数据库连接测试失败: {str(e)}")
            return False

    def close(self):
        """关闭数据库连接（回收到连接池或真正关闭）"""
        if self.connection:
            try:
                if self._is_pooled:
                    # 连接池的连接会自动回收到池中
                    self.connection.close()
                    self.logger.debug("归还MySQL连接到连接池")
                else:
                    self.connection.close()
            except:
                pass
            finally:
                self.connection = None
                self._is_pooled = False

    def execute(self, query: str, params: tuple = ()):
        """执行SQL语句"""
        cursor = self.connection.cursor()
        try:
            cursor.execute(query, params)
            self.connection.commit()
            return cursor
        except Exception as e:
            self.connection.rollback()
            raise e

    def executemany(self, query: str, params_list: List[tuple]):
        """批量执行SQL语句"""
        cursor = self.connection.cursor()
        try:
            cursor.executemany(query, params_list)
            self.connection.commit()
            return cursor
        except Exception as e:
            self.connection.rollback()
            raise e

    def fetch_one(self, query: str, params: tuple = ()):
        """获取单条记录"""
        cursor = self.connection.cursor()
        cursor.execute(query, params)
        result = cursor.fetchone()

        if self.db_type == 'sqlite' and result:
            return dict(result)
        return result

    def fetch_all(self, query: str, params: tuple = ()):
        """获取所有记录"""
        cursor = self.connection.cursor()
        cursor.execute(query, params)
        results = cursor.fetchall()

        if self.db_type == 'sqlite':
            return [dict(row) for row in results]
        return results

    def get_lastrowid(self):
        """获取最后插入的ID"""
        if self.db_type == 'mysql':
            return self.connection.cursor().lastrowid
        else:  # sqlite
            return self.connection.cursor().lastrowid

    def table_exists(self, table_name: str) -> bool:
        """检查表是否存在"""
        try:
            if self.db_type == 'mysql':
                query = """
                        SELECT COUNT(*) as count FROM information_schema.tables
                        WHERE table_schema = DATABASE() AND table_name = %s \
                        """
                result = self.fetch_one(query, (table_name,))
                return result['count'] > 0 if result else False

            elif self.db_type == 'sqlite':
                query = "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
                result = self.fetch_one(query, (table_name,))
                return result is not None

            return False

        except Exception as e:
            self.logger.error(f"检查表是否存在失败: {str(e)}")
            return False

    def __enter__(self):
        if not self.connect():
            raise ConnectionError(f"无法连接到{self.db_type}数据库")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # 只有在非连接池模式下才关闭连接
        # 连接池模式会将连接归还给池，不需要手动关闭
        if not self._is_pooled:
            self.close()

class DatabaseManager:
    """数据库管理器（支持MySQL和SQLite）- 持久化连接"""

    def __init__(self, db_config: Dict):
        self.db_config = db_config
        self.db_type = db_config.get('type', 'sqlite')
        self.logger = logging.getLogger(__name__)
        self._db = DatabaseConnection(self.db_config, use_pool=True)

        # 初始化数据库连接和表结构
        if not self._db.connect():
            raise ConnectionError(f"数据库连接失败，请检查配置: {db_config}")

        self.init_database()
        self.logger.info(f"数据库持久化连接已建立 ({self.db_type})")

    def test_connection(self) -> bool:
        """测试数据库连接"""
        return self._db.test_connection()

    def get_connection(self) -> DatabaseConnection:
        """获取数据库连接（持久化连接）"""
        # 检查连接是否有效，如果失效则重连
        if not self._db.test_connection():
            self.logger.warning("数据库连接已失效，正在重新连接...")
            if not self._db.connect():
                raise ConnectionError(f"无法重新连接到{self.db_type}数据库")
        return self._db

    def close(self):
        """关闭持久化数据库连接"""
        if self._db:
            self._db.close()
            self.logger.info("数据库持久化连接已关闭")

    def init_database(self):
        """初始化数据库（创建表和索引）- 使用持久化连接"""
        db = self._db  # 直接使用持久化连接，不通过 get_connection()

        # 创建服务模板表
        if self.db_type == 'mysql':
            db.execute('''
                       CREATE TABLE IF NOT EXISTS secflow_agent_service_templates (
                                                                        id INT AUTO_INCREMENT PRIMARY KEY,
                                                                        name VARCHAR(100) UNIQUE NOT NULL,
                           description TEXT,
                           type VARCHAR(20) NOT NULL,
                           file_path TEXT NOT NULL,
                           created_by VARCHAR(100),
                           created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                           updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                           metadata JSON,
                           INDEX idx_templates_name (name),
                           INDEX idx_templates_updated (updated_at)
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                       ''')
        else:
            db.execute('''
                       CREATE TABLE IF NOT EXISTS secflow_agent_service_templates (
                                                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                                        name TEXT UNIQUE NOT NULL,
                                                                        description TEXT,
                                                                        type TEXT NOT NULL,
                                                                        file_path TEXT NOT NULL,
                                                                        created_by TEXT,
                                                                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                                        metadata TEXT
                       )
                       ''')

        # 创建任务表
        if self.db_type == 'mysql':
            db.execute('''
                       CREATE TABLE IF NOT EXISTS secflow_agent_tasks (
                                                            id INT AUTO_INCREMENT PRIMARY KEY,
                                                            task_id VARCHAR(36) UNIQUE NOT NULL,
                           task_type VARCHAR(20) NOT NULL,
                           service_name VARCHAR(100) NOT NULL,
                           agent_key VARCHAR(32) NOT NULL,
                           project_id VARCHAR(100),
                           status VARCHAR(20) NOT NULL DEFAULT 'pending',
                           progress INT DEFAULT 0,
                           message TEXT,
                           created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                           started_at TIMESTAMP NULL,
                           completed_at TIMESTAMP NULL,
                           pod_id VARCHAR(100),
                           INDEX idx_tasks_task_id (task_id),
                           INDEX idx_tasks_status (status),
                           INDEX idx_tasks_agent_key (agent_key),
                           INDEX idx_tasks_project (project_id),
                           INDEX idx_tasks_created (created_at)
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                       ''')
        else:
            db.execute('''
                       CREATE TABLE IF NOT EXISTS secflow_agent_tasks (
                                                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                            task_id TEXT UNIQUE NOT NULL,
                                                            task_type TEXT NOT NULL,
                                                            service_name TEXT NOT NULL,
                                                            agent_key TEXT NOT NULL,
                                                            project_id TEXT,
                                                            status TEXT NOT NULL DEFAULT 'pending',
                                                            progress INTEGER DEFAULT 0,
                                                            message TEXT,
                                                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                            started_at TIMESTAMP,
                                                            completed_at TIMESTAMP,
                                                            pod_id TEXT
                       )
                       ''')
            # 为SQLite创建索引
            db.execute('CREATE INDEX IF NOT EXISTS idx_tasks_task_id ON secflow_agent_tasks(task_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_tasks_status ON secflow_agent_tasks(status)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_tasks_agent_key ON secflow_agent_tasks(agent_key)')

        # 创建任务日志表
        if self.db_type == 'mysql':
            db.execute('''
                       CREATE TABLE IF NOT EXISTS secflow_agent_task_logs (
                                                                id INT AUTO_INCREMENT PRIMARY KEY,
                                                                log_id VARCHAR(36) UNIQUE NOT NULL,
                           task_id VARCHAR(36) NOT NULL,
                           level VARCHAR(10) NOT NULL DEFAULT 'INFO',
                           message TEXT NOT NULL,
                           timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                           pod_id VARCHAR(100),
                           INDEX idx_logs_task_id (task_id),
                           INDEX idx_logs_timestamp (timestamp),
                           FOREIGN KEY (task_id) REFERENCES secflow_agent_tasks(task_id) ON DELETE CASCADE
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                       ''')
        else:
            db.execute('''
                       CREATE TABLE IF NOT EXISTS secflow_agent_task_logs (
                                                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                                log_id TEXT UNIQUE NOT NULL,
                                                                task_id TEXT NOT NULL,
                                                                level TEXT NOT NULL DEFAULT 'INFO',
                                                                message TEXT NOT NULL,
                                                                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                                pod_id TEXT,
                                                                FOREIGN KEY (task_id) REFERENCES secflow_agent_tasks(task_id) ON DELETE CASCADE
                           )
                       ''')
            # 为SQLite创建索引
            db.execute('CREATE INDEX IF NOT EXISTS idx_logs_task_id ON secflow_agent_task_logs(task_id)')

        # 创建Agent状态表（用于多POD状态同步）
        if self.db_type == 'mysql':
            db.execute('''
                       CREATE TABLE IF NOT EXISTS secflow_agent_agent_status (
                                                                   id INT AUTO_INCREMENT PRIMARY KEY,
                                                                   agent_key VARCHAR(32) UNIQUE NOT NULL,
                           ip_address VARCHAR(45) NOT NULL,
                           hostname VARCHAR(100) NOT NULL,
                           project_id VARCHAR(100) NOT NULL,
                           full_name VARCHAR(255) NOT NULL,
                           status VARCHAR(20) NOT NULL DEFAULT 'unknown',
                           last_seen TIMESTAMP NULL,
                           system_info JSON,
                           services JSON,
                           pod_id VARCHAR(100),
                           updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                           INDEX idx_secflow_agent_agent_status_key (agent_key),
                           INDEX idx_secflow_agent_agent_status_project (project_id),
                           INDEX idx_secflow_agent_agent_status_updated (updated_at)
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                       ''')
        else:
            db.execute('''
                       CREATE TABLE IF NOT EXISTS secflow_agent_agent_status (
                                                                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                                   agent_key TEXT UNIQUE NOT NULL,
                                                                   ip_address TEXT NOT NULL,
                                                                   hostname TEXT NOT NULL,
                                                                   project_id TEXT NOT NULL,
                                                                   full_name TEXT NOT NULL,
                                                                   status TEXT NOT NULL DEFAULT 'unknown',
                                                                   last_seen TIMESTAMP,
                                                                   system_info TEXT,
                                                                   services TEXT,
                                                                   pod_id TEXT,
                                                                   updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                           )
                       ''')
            # 为SQLite创建索引
            db.execute('CREATE INDEX IF NOT EXISTS idx_secflow_agent_agent_status_project ON secflow_agent_agent_status(project_id)')

        self.logger.info(f"数据库初始化完成（使用{self.db_type.upper()}）")

    def execute_query(self, query: str, params: tuple = ()):
        """执行查询 - 使用持久化连接"""
        db = self.get_connection()
        return db.execute(query, params)

    def execute_transaction(self, queries: List[Tuple[str, tuple]]):
        """执行事务（多个查询）- 使用持久化连接"""
        db = self.get_connection()
        try:
            for query, params in queries:
                db.execute(query, params)
        except Exception as e:
            raise e

    def fetch_one(self, query: str, params: tuple = ()):
        """获取单条记录 - 使用持久化连接"""
        db = self.get_connection()
        return db.fetch_one(query, params)

    def fetch_all(self, query: str, params: tuple = ()):
        """获取所有记录 - 使用持久化连接"""
        db = self.get_connection()
        return db.fetch_all(query, params)

# ===================== Redis分布式锁（修复版） =====================

class RedisDistributedLock:
    """Redis分布式锁（修复单进程问题）"""

    def __init__(self, redis_client: redis.Redis, lock_key: str, timeout: int = 30):
        self.redis = redis_client
        self.lock_key = f"lock:{lock_key}"
        self.timeout = timeout
        self.identifier = str(uuid.uuid4())
        self.logger = logging.getLogger(__name__)
        self._acquired = False

    def acquire(self, block: bool = True, block_timeout: int = None, retry_interval: float = 0.1) -> bool:
        """获取锁（修复单进程问题）"""
        if block:
            if block_timeout is None:
                block_timeout = self.timeout

            end_time = time.time() + block_timeout
            attempts = 0

            while time.time() < end_time:
                attempts += 1
                if self._try_acquire():
                    self.logger.debug(f"成功获取锁 {self.lock_key}，尝试次数: {attempts}")
                    self._acquired = True
                    return True

                # 指数退避
                sleep_time = retry_interval * (2 ** min(attempts, 5))
                time.sleep(sleep_time)

            self.logger.warning(f"获取锁 {self.lock_key} 超时，尝试次数: {attempts}")
            return False
        else:
            success = self._try_acquire()
            if success:
                self._acquired = True
                self.logger.debug(f"成功获取锁 {self.lock_key}")
            return success

    def _try_acquire(self) -> bool:
        """尝试获取锁"""
        try:
            # 检查Redis连接
            if not self.redis.ping():
                self.logger.error("Redis连接异常")
                return False

            # 使用SET命令的NX和EX参数实现原子操作
            result = self.redis.set(
                self.lock_key,
                self.identifier,
                ex=self.timeout,
                nx=True
            )

            return bool(result)

        except redis.exceptions.ConnectionError as e:
            self.logger.error(f"Redis连接失败: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"获取锁失败: {str(e)}")
            return False

    def release(self) -> bool:
        """释放锁"""
        if not self._acquired:
            self.logger.warning(f"尝试释放未获取的锁: {self.lock_key}")
            return True

        try:
            # 检查Redis连接
            if not self.redis.ping():
                self.logger.error("Redis连接异常，无法释放锁")
                return False

            # 使用Lua脚本确保原子性
            lua_script = """
            if redis.call("get", KEYS[1]) == ARGV[1] then
                return redis.call("del", KEYS[1])
            else
                return 0
            end
            """

            result = self.redis.eval(lua_script, 1, self.lock_key, self.identifier)
            success = bool(result)

            if success:
                #self.logger.debug(f"成功释放锁 {self.lock_key}")
                pass
            else:
                self.logger.warning(f"释放锁失败或锁已过期: {self.lock_key}")

            self._acquired = False
            return success

        except redis.exceptions.ConnectionError as e:
            self.logger.error(f"Redis连接失败，无法释放锁: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"释放锁失败: {str(e)}")
            return False

    def is_acquired(self) -> bool:
        """检查是否已获取锁"""
        if not self._acquired:
            return False

        try:
            # 检查锁是否仍然有效
            value = self.redis.get(self.lock_key)
            return value == self.identifier.encode() if value else False
        except:
            return False

    def __enter__(self):
        # 单实例模式：不强制获取锁
        if self.acquire(block=True, block_timeout=5):
            return self
        else:
            self.logger.warning(f"无法获取锁 {self.lock_key}，继续执行...")
            # 创建一个虚拟的上下文管理器
            return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._acquired:
            self.release()

class RedisManager:
    """Redis管理器"""

    def __init__(self, redis_url: str, enabled: bool = True):
        self.redis_url = redis_url
        self.enabled = enabled
        self.client = None
        self.logger = logging.getLogger(__name__)

        if self.enabled:
            self._connect()

    def _connect(self) -> bool:
        """连接Redis"""
        try:
            self.client = redis.from_url(
                self.redis_url,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                max_connections=10
            )

            # 测试连接
            if self.client.ping():
                self.logger.info("Redis连接成功")
                return True
            else:
                self.logger.warning("Redis连接测试失败")
                self.enabled = False
                return False

        except redis.exceptions.ConnectionError as e:
            self.logger.warning(f"Redis连接失败: {str(e)}，Redis功能将禁用")
            self.enabled = False
            return False
        except Exception as e:
            self.logger.warning(f"Redis初始化失败: {str(e)}，Redis功能将禁用")
            self.enabled = False
            return False

    def test_connection(self) -> bool:
        """测试Redis连接"""
        if not self.enabled:
            return False

        try:
            return self.client.ping()
        except:
            self.enabled = False
            return False

    def get_lock(self, lock_key: str, timeout: int = 30) -> RedisDistributedLock:
        """获取分布式锁"""
        if not self.enabled or not self.client:
            # 返回一个虚拟锁，总是能"获取"成功
            return self._get_dummy_lock(lock_key, timeout)

        return RedisDistributedLock(self.client, lock_key, timeout)

    def _get_dummy_lock(self, lock_key: str, timeout: int = 30) -> RedisDistributedLock:
        """获取虚拟锁（用于单实例或Redis不可用的情况）"""
        class DummyRedisLock:
            def __init__(self, lock_key: str):
                self.lock_key = lock_key
                self._acquired = True
                self.logger = logging.getLogger(__name__)

            def acquire(self, *args, **kwargs) -> bool:
                #self.logger.debug(f"虚拟锁已获取: {self.lock_key}")
                self._acquired = True
                return True

            def release(self) -> bool:
                #self.logger.debug(f"虚拟锁已释放: {self.lock_key}")
                self._acquired = False
                return True

            def is_acquired(self) -> bool:
                return self._acquired

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                self.release()

        return DummyRedisLock(lock_key)

# ===================== 配置和常量 =====================

# 支持的压缩格式
SUPPORTED_FORMATS = [
    '.zip', '.tar', '.tar.gz', '.tgz',
    '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz'
]

# 压缩文件扩展名映射
COMPRESSION_EXT_MAPPING = {
    '.zip': 'zip',
    '.tar': 'tar',
    '.tar.gz': 'gz',
    '.tgz': 'gz',
    '.tar.bz2': 'bz2',
    '.tbz': 'bz2',
    '.tbz2': 'bz2',
    '.tar.xz': 'xz',
    '.txz': 'xz'
}

DEFAULT_CONFIG = {
    'port': 18080,
    'host': '0.0.0.0',
    'debug': False,
    'secret_key': 'change-this-secret-key-in-production',
    'services_root': './services',
    'templates_root': './templates',
    'database': {
        'type': 'sqlite',  # sqlite 或 mysql
        'path': './webapi_server.db',  # SQLite专用
        'host': 'localhost',  # MySQL专用
        'port': 3306,  # MySQL专用
        'user': 'root',  # MySQL专用
        'password': '',  # MySQL专用
        'database': 'webapi'  # MySQL专用
    },
    'redis_url': 'redis://localhost:6379/0',
    'redis_enabled': True,  # 是否启用Redis
    'nacos_url': 'http://localhost:8848',
    'nacos_namespace': 'public',
    'agent_api_port': 11187,
    'agent_auth_token': 'default_token_change_me',
    'refresh_interval': 30,
    'max_workers': 10,
    'upload_max_size': 100 * 1024 * 1024,
    'token_expiration': 24 * 3600,
    'log_level': 'INFO',
    'log_file': './webapi_server.log',
    'pod_id': os.environ.get('POD_NAME', 'webapi-server-1'),
    'lock_timeout': 30,
    'max_secflow_agent_task_logs': 1000,
    'task_log_retention_days': 7,
    'supported_formats': SUPPORTED_FORMATS,  # 添加支持的格式列表
    # ===================== 超时配置 =====================
    'agent_api_timeouts': {
        'default': (10, 30),           # 默认：连接10秒，读取30秒
        'health_check': (5, 10),       # 健康检查：连接5秒，读取10秒
        'deploy_create': (10, 60),     # 创建服务：连接10秒，读取60秒
        'deploy_start': (10, 300),     # 启动服务：连接10秒，读取300秒（5分钟）
        'deploy_stop': (10, 120),      # 停止服务：连接10秒，读取120秒
        'deploy_delete': (10, 60),     # 删除服务：连接10秒，读取60秒
        'undeploy': (10, 180),         # 卸载服务：连接10秒，读取180秒
        'file_upload': (10, 600),      # 文件上传：连接10秒，读取600秒（10分钟）
        'stream': (10, 3600),          # 流式响应：连接10秒，读取3600秒（1小时）
        'proxy': (10, 300),            # 代理请求：连接10秒，读取300秒
    },
}

# ===================== 连接检查工具 =====================

class ConnectionChecker:
    """连接检查器"""

    @staticmethod
    def check_database(db_config: Dict) -> Tuple[bool, str]:
        """检查数据库连接"""
        try:
            db = DatabaseConnection(db_config)
            if db.test_connection():
                return True, f"{db_config.get('type', 'sqlite').upper()}数据库连接正常"
            else:
                return False, f"{db_config.get('type', 'sqlite').upper()}数据库连接失败"
        except Exception as e:
            return False, f"数据库连接检查失败: {str(e)}"

    @staticmethod
    def check_nacos(nacos_url: str, namespace: str = 'public',
                    username: str = None, password: str = None) -> Tuple[bool, str]:
        """检查Nacos连接（支持v3 API认证）"""
        try:
            url = f"{nacos_url.rstrip('/')}/nacos/v1/ns/service/list"
            params = {
                'pageNo': 1,
                'pageSize': 10,
                'namespaceId': namespace
            }

            # 准备认证信息
            auth = None
            if username and password:
                auth = (username, password)

            response = requests.get(url, params=params, timeout=10, auth=auth)
            if response.status_code == 200:
                return True, "Nacos连接正常"
            elif response.status_code == 401:
                # 尝试使用v3 API
                v3_url = f"{nacos_url.rstrip('/')}/nacos/v3/ns/service/list"
                v3_response = requests.get(v3_url, params=params, timeout=10, auth=auth)
                if v3_response.status_code == 200:
                    return True, "Nacos v3 API连接正常"
                else:
                    return False, f"Nacos v3 API连接失败: HTTP {v3_response.status_code}"
            else:
                return False, f"Nacos连接失败: HTTP {response.status_code}"

        except requests.exceptions.ConnectionError as e:
            return False, f"Nacos连接失败: {str(e)}"
        except requests.exceptions.Timeout as e:
            return False, f"Nacos连接超时: {str(e)}"
        except Exception as e:
            return False, f"Nacos连接检查失败: {str(e)}"

    @staticmethod
    def check_redis(redis_url: str) -> Tuple[bool, str]:
        """检查Redis连接"""
        try:
            client = redis.from_url(redis_url, socket_timeout=5, socket_connect_timeout=5)
            if client.ping():
                return True, "Redis连接正常"
            else:
                return False, "Redis连接测试失败"

        except redis.exceptions.ConnectionError as e:
            return False, f"Redis连接失败: {str(e)}"
        except Exception as e:
            return False, f"Redis连接检查失败: {str(e)}"

    @staticmethod
    def check_all_connections(config: Dict) -> Dict[str, Tuple[bool, str]]:
        """检查所有连接"""
        results = {}

        # 检查数据库
        db_result = ConnectionChecker.check_database(config.get('database', {}))
        results['database'] = db_result

        # 检查Nacos（必须连接）
        nacos_result = ConnectionChecker.check_nacos(
            config.get('nacos_url', ''),
            config.get('nacos_namespace', 'public'),
            config.get('nacos_username'),
            config.get('nacos_password')
        )
        results['nacos'] = nacos_result

        # 检查Redis（可选）
        if config.get('redis_enabled', True):
            redis_result = ConnectionChecker.check_redis(config.get('redis_url', ''))
            results['redis'] = redis_result
        else:
            results['redis'] = (True, "Redis已禁用")

        return results
# ===================== 数据类定义 =====================

@dataclass
class ProjectInfo:
    """项目信息"""
    id: str
    agent_count: int = 0
    online_agents: int = 0
    services_count: int = 0
    last_refresh: Optional[datetime] = None
    agents: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        data = asdict(self)
        if self.last_refresh:
            data['last_refresh'] = self.last_refresh.isoformat()
        return data

@dataclass
class AgentInfo:
    """Agent信息"""
    key: str
    ip_address: str
    hostname: str
    project_id: str
    full_name: str
    status: str = 'unknown'
    last_seen: Optional[datetime] = None
    system_info: Optional[Dict] = None
    services: List[Dict] = field(default_factory=list)
    pod_id: str = ''

    def to_dict(self) -> Dict:
        data = asdict(self)
        if self.last_seen:
            data['last_seen'] = self.last_seen.isoformat()
        return data

@dataclass
class ServiceTemplate:
    """服务模板"""
    name: str
    description: str = ''
    type: str = 'yaml'
    file_path: str = ''
    created_by: str = ''
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        return data

@dataclass
class TaskInfo:
    """任务信息"""
    task_id: str
    task_type: str
    service_name: str
    agent_key: str
    project_id: str = ''
    status: str = 'pending'
    progress: int = 0
    message: str = ''
    logs: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    pod_id: str = ''

    def to_dict(self) -> Dict:
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        if self.started_at:
            data['started_at'] = self.started_at.isoformat()
        if self.completed_at:
            data['completed_at'] = self.completed_at.isoformat()
        return data

# ===================== 模板管理器（完整增强版，支持多种压缩格式） =====================

class EnhancedTemplateManager:
    """完整增强版模板管理器，支持多种压缩格式"""

    def __init__(self, templates_root: str, db_manager: DatabaseManager, supported_formats: List[str] = None):
        self.templates_root = Path(templates_root)
        self.db = db_manager
        self.templates_root.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

        # 设置支持的格式
        self.supported_formats = supported_formats or SUPPORTED_FORMATS
        self.compression_map = COMPRESSION_EXT_MAPPING

        self.logger.info(f"模板管理器初始化，支持格式: {', '.join(self.supported_formats)}")

    # 新增方法：获取模板目录下指定文件的内容
    def get_template_file_by_path(self, template_name: str, file_path: str,
                                  encoding: str = 'utf-8') -> Tuple[bool, Union[str, bytes], str, Dict]:
        """
        获取模板目录下指定文件的内容

        Args:
            template_name: 模板名称
            file_path: 相对路径（相对于模板目录）
            encoding: 文本文件编码

        Returns:
            (success, content_or_error, content_type, file_info)
        """
        try:
            # 检查模板是否存在
            template = self.get_template(template_name)
            if not template:
                return False, f"模板 '{template_name}' 不存在", "text/plain", {}

            # 获取模板目录
            template_dir = self.templates_root / template_name
            file_path = template_dir / file_path
            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}", "text/plain", {}

            # 构建完整路径，防止路径遍历攻击
            safe_path = self._get_safe_path(template_dir, file_path)
            if not safe_path:
                return False, f"无效的文件路径: {file_path}", "text/plain", {}

            # 检查文件是否存在
            if not safe_path.exists() or not safe_path.is_file():
                return False, f"文件不存在: {file_path}", "text/plain", {}

            # 获取文件信息
            stat_info = safe_path.stat()
            file_info = {
                'name': safe_path.name,
                'path': str(safe_path.relative_to(template_dir)),
                'size': stat_info.st_size,
                'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'is_directory': False
            }

            # 确定内容类型
            content_type, is_text = self._get_file_type(safe_path)
            file_info['content_type'] = content_type
            file_info['is_text'] = is_text

            # 读取文件内容
            try:
                if is_text:
                    with open(safe_path, 'r', encoding=encoding) as f:
                        content = f.read()
                else:
                    with open(safe_path, 'rb') as f:
                        content = f.read()
            except Exception as e:
                return False, f"读取文件失败: {str(e)}", "text/plain", file_info

            return True, content, content_type, file_info

        except Exception as e:
            self.logger.error(f"获取模板文件失败: {str(e)}", exc_info=True)
            return False, f"获取文件失败: {str(e)}", "text/plain", {}

    # 新增方法：更新模板目录下指定文件的内容
    def update_template_file(self, template_name: str, file_path: str, content: Union[str, bytes],
                             encoding: str = 'utf-8', updated_by: str = 'system') -> Tuple[bool, str, Dict]:
        """
        更新模板目录下指定文件的内容，并更新原始压缩文件（如果存在）

        Args:
            template_name: 模板名称
            file_path: 相对路径（相对于模板目录）
            content: 文件内容（字符串或字节）
            encoding: 文本文件编码
            updated_by: 更新者

        Returns:
            (success, message, update_info)
        """
        try:
            # 检查模板是否存在
            template = self.get_template(template_name)
            if not template:
                return False, f"模板 '{template_name}' 不存在", {}

            template_type = template['type']
            template_dir = self.templates_root / template_name
            file_path = template_dir / file_path
            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}", {}

            # 构建完整路径，防止路径遍历攻击
            safe_path = self._get_safe_path(template_dir, file_path)
            if not safe_path:
                return False, f"无效的文件路径: {file_path}", {}

            # 确保父目录存在
            safe_path.parent.mkdir(parents=True, exist_ok=True)

            # 备份原文件（如果存在）
            backup_info = {}
            if safe_path.exists():
                backup_path = safe_path.with_suffix(f'{safe_path.suffix}.backup.{datetime.now().strftime("%Y%m%d%H%M%S")}')
                shutil.copy2(safe_path, backup_path)
                backup_info['backup_file'] = str(backup_path.relative_to(template_dir))

            # 写入新内容
            try:
                if isinstance(content, str):
                    with open(safe_path, 'w', encoding=encoding) as f:
                        f.write(content)
                    file_size = len(content.encode(encoding))
                elif isinstance(content, bytes):
                    with open(safe_path, 'wb') as f:
                        f.write(content)
                    file_size = len(content)
                else:
                    return False, f"不支持的内容类型: {type(content)}", {}
            except Exception as e:
                return False, f"写入文件失败: {str(e)}", {}

            # 获取更新后的文件信息
            stat_info = safe_path.stat()
            update_info = {
                'template_name': template_name,
                'file_path': str(safe_path.relative_to(template_dir)),
                'file_size': file_size,
                'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'updated_by': updated_by,
                'updated_at': datetime.now().isoformat(),
                'backup_info': backup_info
            }

            # 如果是YAML文件，验证其格式
            if safe_path.suffix.lower() in ['.yaml', '.yml']:
                try:
                    with open(safe_path, 'r', encoding='utf-8') as f:
                        yaml_content = f.read()

                    is_valid, error_msg = self.validate_yaml_content(yaml_content, template_type, safe_path.name)
                    if not is_valid:
                        # 恢复备份
                        if backup_info.get('backup_file'):
                            backup_full_path = template_dir / backup_info['backup_file']
                            if backup_full_path.exists():
                                shutil.copy2(backup_full_path, safe_path)
                                safe_path.unlink()

                        return False, f"YAML格式验证失败: {error_msg}", {}

                    update_info['yaml_valid'] = True
                except Exception as e:
                    self.logger.warning(f"YAML验证失败: {str(e)}")
            # 如果模板是压缩格式，需要更新原始压缩文件
            if template_type == 'archive':
                archive_updated, archive_message = self._update_archive_file(template_name, safe_path, updated_by)
                update_info['archive_updated'] = archive_updated
                update_info['archive_message'] = archive_message

                if not archive_updated:
                    self.logger.warning(f"更新压缩文件失败: {archive_message}")

            # 更新模板元数据
            metadata = template.get('metadata', {})
            if 'updated_files' not in metadata:
                metadata['updated_files'] = []

            metadata['updated_files'].append({
                'file_path': str(safe_path.relative_to(template_dir)),
                'updated_at': datetime.now().isoformat(),
                'updated_by': updated_by,
                'file_size': file_size
            })

            # 限制更新的文件记录数量
            if len(metadata['updated_files']) > 50:
                metadata['updated_files'] = metadata['updated_files'][-50:]

            # 更新数据库
            metadata_json = json.dumps(metadata)
            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    "UPDATE secflow_agent_service_templates SET updated_at = NOW(), metadata = %s WHERE name = %s",
                    (metadata_json, template_name)
                )
            else:
                self.db.execute_query(
                    "UPDATE secflow_agent_service_templates SET updated_at = datetime('now'), metadata = ? WHERE name = ?",
                    (metadata_json, template_name)
                )

            self.logger.info(f"模板文件更新成功: {template_name}/{file_path}, 大小: {file_size} 字节")
            return True, f"文件更新成功", update_info

        except Exception as e:
            self.logger.error(f"更新模板文件失败: {str(e)}", exc_info=True)
            return False, f"更新文件失败: {str(e)}", {}

    # 新增方法：更新压缩文件中的对应文件
    def _update_archive_file(self, template_name: str, updated_file: Path, updated_by: str) -> Tuple[bool, str]:
        """更新压缩文件中的对应文件"""
        try:
            template = self.get_template(template_name)
            if not template or template['type'] != 'archive':
                return False, "不是压缩模板"

            archive_path = Path(template['file_path'])
            if not archive_path.exists():
                return False, f"原始压缩文件不存在: {archive_path}"

            template_dir = self.templates_root / template_name
            relative_path = updated_file.relative_to(template_dir)

            # 备份原压缩文件
            backup_path = archive_path.with_suffix(f'{archive_path.suffix}.backup.{datetime.now().strftime("%Y%m%d%H%M%S")}')
            shutil.copy2(archive_path, backup_path)

            # 获取文件扩展名以确定压缩格式
            filename = archive_path.name.lower()

            if filename.endswith('.zip'):
                # 更新ZIP文件
                success = self._update_zip_file(archive_path, updated_file, relative_path)
            elif any(filename.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']):
                # 更新TAR文件
                success = self._update_tar_file(archive_path, updated_file, relative_path)
            else:
                return False, f"不支持的压缩格式: {filename}"

            if success:
                # 更新元数据
                metadata = template.get('metadata', {})
                if 'archive_updates' not in metadata:
                    metadata['archive_updates'] = []

                metadata['archive_updates'].append({
                    'file': str(relative_path),
                    'updated_at': datetime.now().isoformat(),
                    'updated_by': updated_by,
                    'backup_file': backup_path.name
                })

                # 限制记录数量
                if len(metadata['archive_updates']) > 20:
                    metadata['archive_updates'] = metadata['archive_updates'][-20:]

                self.logger.info(f"压缩文件更新成功: {template_name}, 文件: {relative_path}")
                return True, f"压缩文件更新成功，备份: {backup_path.name}"
            else:
                # 恢复备份
                if backup_path.exists():
                    shutil.copy2(backup_path, archive_path)
                return False, "更新压缩文件失败"

        except Exception as e:
            self.logger.error(f"更新压缩文件失败: {str(e)}", exc_info=True)
            return False, f"更新压缩文件失败: {str(e)}"

    # 新增方法：更新ZIP文件中的单个文件
    def _update_zip_file(self, zip_path: Path, updated_file: Path, relative_path: Path) -> bool:
        """更新ZIP文件中的单个文件"""
        try:
            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_zip = Path(temp_dir) / 'updated.zip'

                # 创建新的ZIP文件
                with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as new_zip:
                    # 复制原ZIP中除了要更新的文件外的所有文件
                    with zipfile.ZipFile(zip_path, 'r') as old_zip:
                        for item in old_zip.infolist():
                            # 如果是我们要更新的文件，跳过
                            if item.filename == str(relative_path):
                                continue

                            # 读取并写入其他文件
                            with old_zip.open(item.filename) as f:
                                content = f.read()
                                new_zip.writestr(item, content)

                    # 添加更新的文件
                    new_zip.write(updated_file, str(relative_path))

                # 替换原ZIP文件
                shutil.copy2(temp_zip, zip_path)
                return True

        except Exception as e:
            self.logger.error(f"更新ZIP文件失败: {str(e)}")
            return False

    # 新增方法：更新TAR文件中的单个文件
    def _update_tar_file(self, tar_path: Path, updated_file: Path, relative_path: Path) -> bool:
        """更新TAR文件中的单个文件"""
        try:
            # 获取压缩模式
            filename = tar_path.name.lower()
            mode = 'r'
            if filename.endswith('.gz') or filename.endswith('.tgz'):
                mode = 'r:gz'
            elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                mode = 'r:bz2'
            elif filename.endswith('.xz') or filename.endswith('.txz'):
                mode = 'r:xz'

            write_mode = mode.replace('r:', 'w:') if ':' in mode else 'w'

            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_tar = Path(temp_dir) / 'updated.tar'

                # 创建新的TAR文件
                with tarfile.open(temp_tar, write_mode) as new_tar:
                    # 复制原TAR中除了要更新的文件外的所有文件
                    with tarfile.open(tar_path, mode) as old_tar:
                        for item in old_tar.getmembers():
                            # 如果是我们要更新的文件，跳过
                            if item.name == str(relative_path):
                                continue

                            # 提取并重新添加文件
                            try:
                                extracted = old_tar.extractfile(item)
                                if extracted:
                                    # 创建TarInfo对象
                                    tar_info = tarfile.TarInfo(name=item.name)
                                    tar_info.size = item.size
                                    tar_info.mtime = item.mtime
                                    tar_info.mode = item.mode
                                    tar_info.type = item.type

                                    # 添加文件到新TAR
                                    new_tar.addfile(tar_info, extracted)
                            except Exception as e:
                                self.logger.warning(f"处理TAR文件项 {item.name} 失败: {e}")
                                continue

                    # 添加更新的文件
                    new_tar.add(updated_file, arcname=str(relative_path))

                # 替换原TAR文件
                shutil.copy2(temp_tar, tar_path)
                return True

        except Exception as e:
            self.logger.error(f"更新TAR文件失败: {str(e)}")
            return False

    # 新增方法：删除模板目录下的指定文件
    def delete_template_file(self, template_name: str, file_path: str, deleted_by: str = 'system') -> Tuple[bool, str, Dict]:
        """
        删除模板目录下指定文件，并更新原始压缩文件（如果存在）

        Args:
            template_name: 模板名称
            file_path: 相对路径（相对于模板目录）
            deleted_by: 删除者

        Returns:
            (success, message, delete_info)
        """
        try:
            # 检查模板是否存在
            template = self.get_template(template_name)
            if not template:
                return False, f"模板 '{template_name}' 不存在", {}

            template_type = template['type']
            template_dir = self.templates_root / template_name
            file_path = template_dir / file_path
            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}", {}

            # 构建完整路径，防止路径遍历攻击
            safe_path = self._get_safe_path(template_dir, file_path)
            if not safe_path:
                return False, f"无效的文件路径: {file_path}", {}

            # 检查文件是否存在
            if not safe_path.exists():
                return False, f"文件不存在: {file_path}", {}

            # 如果是YAML文件，检查是否是主文件
            if safe_path.suffix.lower() in ['.yaml', '.yml']:
                # 检查是否是docker-compose文件
                if safe_path.name.lower() in ['docker-compose.yaml', 'docker-compose.yml']:
                    return False, "不能删除docker-compose文件，它是模板的核心文件", {}

                # 如果是YAML模板类型且删除的是主YAML文件
                if template_type == 'yaml' and safe_path == Path(template['file_path']):
                    return False, "不能删除YAML模板的主文件", {}

            # 如果是目录，不能删除
            if safe_path.is_dir():
                return False, f"不能删除目录，请使用专门的目录删除API", {}

            # 获取文件信息（用于返回和记录）
            stat_info = safe_path.stat()
            file_info = {
                'template_name': template_name,
                'file_path': str(safe_path.relative_to(template_dir)),
                'file_name': safe_path.name,
                'file_size': stat_info.st_size,
                'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'deleted_by': deleted_by,
                'deleted_at': datetime.now().isoformat()
            }

            # 删除文件
            try:
                safe_path.unlink()
                self.logger.info(f"模板文件删除成功: {template_name}/{file_path}")
            except Exception as e:
                return False, f"删除文件失败: {str(e)}", {}

            # 如果模板是压缩格式，需要更新原始压缩文件
            if template_type == 'archive':
                archive_updated, archive_message = self._delete_from_archive_file(template_name, safe_path, deleted_by)
                file_info['archive_updated'] = archive_updated
                file_info['archive_message'] = archive_message

                if not archive_updated:
                    self.logger.warning(f"从压缩文件中删除失败: {archive_message}")

            # 更新模板元数据
            metadata = template.get('metadata', {})
            if 'deleted_files' not in metadata:
                metadata['deleted_files'] = []

            metadata['deleted_files'].append(file_info.copy())

            # 限制删除的文件记录数量
            if len(metadata['deleted_files']) > 50:
                metadata['deleted_files'] = metadata['deleted_files'][-50:]

            # 更新数据库
            metadata_json = json.dumps(metadata)
            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    "UPDATE secflow_agent_service_templates SET updated_at = NOW(), metadata = %s WHERE name = %s",
                    (metadata_json, template_name)
                )
            else:
                self.db.execute_query(
                    "UPDATE secflow_agent_service_templates SET updated_at = datetime('now'), metadata = ? WHERE name = ?",
                    (metadata_json, template_name)
                )

            return True, f"文件删除成功", file_info

        except Exception as e:
            self.logger.error(f"删除模板文件失败: {str(e)}", exc_info=True)
            return False, f"删除文件失败: {str(e)}", {}

    # 新增方法：从压缩文件中删除对应文件
    def _delete_from_archive_file(self, template_name: str, deleted_file: Path, deleted_by: str) -> Tuple[bool, str]:
        """从压缩文件中删除对应文件"""
        try:
            template = self.get_template(template_name)
            if not template or template['type'] != 'archive':
                return False, "不是压缩模板"

            archive_path = Path(template['file_path'])
            if not archive_path.exists():
                return False, f"原始压缩文件不存在: {archive_path}"

            template_dir = self.templates_root / template_name
            relative_path = deleted_file.relative_to(template_dir)

            # 获取文件扩展名以确定压缩格式
            filename = archive_path.name.lower()

            if filename.endswith('.zip'):
                # 从ZIP文件中删除
                success = self._delete_from_zip_file(archive_path, relative_path)
            elif any(filename.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']):
                # 从TAR文件中删除
                success = self._delete_from_tar_file(archive_path, relative_path)
            else:
                return False, f"不支持的压缩格式: {filename}"

            if success:
                # 更新元数据
                metadata = template.get('metadata', {})
                if 'archive_deletions' not in metadata:
                    metadata['archive_deletions'] = []

                metadata['archive_deletions'].append({
                    'file': str(relative_path),
                    'deleted_at': datetime.now().isoformat(),
                    'deleted_by': deleted_by,
                })

                # 限制记录数量
                if len(metadata['archive_deletions']) > 20:
                    metadata['archive_deletions'] = metadata['archive_deletions'][-20:]

                self.logger.info(f"从压缩文件中删除成功: {template_name}, 文件: {relative_path}")
                return True, f"从压缩文件中删除成功"
            else:
                return False, "从压缩文件中删除失败"

        except Exception as e:
            self.logger.error(f"从压缩文件中删除失败: {str(e)}", exc_info=True)
            return False, f"从压缩文件中删除失败: {str(e)}"

    # 新增方法：从ZIP文件中删除单个文件
    def _delete_from_zip_file(self, zip_path: Path, relative_path: Path) -> bool:
        """从ZIP文件中删除单个文件"""
        try:
            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_zip = Path(temp_dir) / 'updated.zip'

                # 创建新的ZIP文件（不包含要删除的文件）
                with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as new_zip:
                    # 复制原ZIP中除了要删除的文件外的所有文件
                    with zipfile.ZipFile(zip_path, 'r') as old_zip:
                        for item in old_zip.infolist():
                            # 如果是要删除的文件，跳过
                            if item.filename == str(relative_path):
                                continue

                            # 读取并写入其他文件
                            with old_zip.open(item.filename) as f:
                                content = f.read()
                                new_zip.writestr(item, content)

                # 替换原ZIP文件
                shutil.copy2(temp_zip, zip_path)
                return True

        except Exception as e:
            self.logger.error(f"从ZIP文件中删除失败: {str(e)}")
            return False

    # 新增方法：从TAR文件中删除单个文件
    def _delete_from_tar_file(self, tar_path: Path, relative_path: Path) -> bool:
        """从TAR文件中删除单个文件"""
        try:
            # 获取压缩模式
            filename = tar_path.name.lower()
            mode = 'r'
            if filename.endswith('.gz') or filename.endswith('.tgz'):
                mode = 'r:gz'
            elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                mode = 'r:bz2'
            elif filename.endswith('.xz') or filename.endswith('.txz'):
                mode = 'r:xz'

            write_mode = mode.replace('r:', 'w:') if ':' in mode else 'w'

            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_tar = Path(temp_dir) / 'updated.tar'

                # 创建新的TAR文件（不包含要删除的文件）
                with tarfile.open(temp_tar, write_mode) as new_tar:
                    # 复制原TAR中除了要删除的文件外的所有文件
                    with tarfile.open(tar_path, mode) as old_tar:
                        for item in old_tar.getmembers():
                            # 如果是要删除的文件，跳过
                            if item.name == str(relative_path):
                                continue

                            # 提取并重新添加文件
                            try:
                                extracted = old_tar.extractfile(item)
                                if extracted:
                                    # 创建TarInfo对象
                                    tar_info = tarfile.TarInfo(name=item.name)
                                    tar_info.size = item.size
                                    tar_info.mtime = item.mtime
                                    tar_info.mode = item.mode
                                    tar_info.type = item.type

                                    # 添加文件到新TAR
                                    new_tar.addfile(tar_info, extracted)
                            except Exception as e:
                                self.logger.warning(f"处理TAR文件项 {item.name} 失败: {e}")
                                continue

                # 替换原TAR文件
                shutil.copy2(temp_tar, tar_path)
                return True

        except Exception as e:
            self.logger.error(f"从TAR文件中删除失败: {str(e)}")
            return False

    # 新增方法：删除模板目录下的目录
    def delete_template_directory(self, template_name: str, dir_path: str, deleted_by: str = 'system',
                                  force: bool = False) -> Tuple[bool, str, Dict]:
        """
        删除模板目录下的指定目录

        Args:
            template_name: 模板名称
            dir_path: 相对路径（相对于模板目录）
            deleted_by: 删除者
            force: 是否强制删除非空目录

        Returns:
            (success, message, delete_info)
        """
        try:
            # 检查模板是否存在
            template = self.get_template(template_name)
            if not template:
                return False, f"模板 '{template_name}' 不存在", {}

            template_dir = self.templates_root / template_name
            dir_path = template_dir / dir_path
            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}", {}

            # 构建完整路径，防止路径遍历攻击
            safe_path = self._get_safe_path(template_dir, dir_path)
            if not safe_path:
                return False, f"无效的目录路径: {dir_path}", {}

            # 检查目录是否存在
            if not safe_path.exists() or not safe_path.is_dir():
                return False, f"目录不存在: {dir_path}", {}

            # 检查是否试图删除根目录
            if safe_path == template_dir:
                return False, "不能删除模板根目录", {}

            # 检查是否包含docker-compose文件
            for yaml_name in ['docker-compose.yaml', 'docker-compose.yml']:
                yaml_file = safe_path / yaml_name
                if yaml_file.exists():
                    return False, f"目录中包含docker-compose文件，不能删除", {}

            # 检查目录是否为空
            dir_items = list(safe_path.iterdir())
            if dir_items and not force:
                return False, f"目录不为空，使用force=true参数强制删除", {}

            # 计算目录大小
            dir_size = sum(f.stat().st_size for f in safe_path.rglob('*') if f.is_file())

            # 记录删除信息
            delete_info = {
                'template_name': template_name,
                'dir_path': str(safe_path.relative_to(template_dir)),
                'dir_name': safe_path.name,
                'dir_size': dir_size,
                'file_count': len([f for f in safe_path.rglob('*') if f.is_file()]),
                'deleted_by': deleted_by,
                'deleted_at': datetime.now().isoformat(),
                'force': force
            }

            # 删除目录
            try:
                if force:
                    shutil.rmtree(safe_path)
                else:
                    safe_path.rmdir()

                self.logger.info(f"模板目录删除成功: {template_name}/{dir_path}")
            except Exception as e:
                return False, f"删除目录失败: {str(e)}", {}

            # 如果模板是压缩格式，需要更新原始压缩文件
            if template['type'] == 'archive':
                # 需要遍历删除压缩文件中的所有相关文件
                archive_updated, archive_message = self._delete_directory_from_archive(template_name, safe_path, deleted_by)
                delete_info['archive_updated'] = archive_updated
                delete_info['archive_message'] = archive_message

                if not archive_updated:
                    self.logger.warning(f"从压缩文件中删除目录失败: {archive_message}")

            # 更新模板元数据
            metadata = template.get('metadata', {})
            if 'deleted_directories' not in metadata:
                metadata['deleted_directories'] = []

            metadata['deleted_directories'].append(delete_info.copy())

            # 限制删除的目录记录数量
            if len(metadata['deleted_directories']) > 20:
                metadata['deleted_directories'] = metadata['deleted_directories'][-20:]

            # 更新数据库
            metadata_json = json.dumps(metadata)
            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    "UPDATE secflow_agent_service_templates SET updated_at = NOW(), metadata = %s WHERE name = %s",
                    (metadata_json, template_name)
                )
            else:
                self.db.execute_query(
                    "UPDATE secflow_agent_service_templates SET updated_at = datetime('now'), metadata = ? WHERE name = ?",
                    (metadata_json, template_name)
                )

            return True, f"目录删除成功", delete_info

        except Exception as e:
            self.logger.error(f"删除模板目录失败: {str(e)}", exc_info=True)
            return False, f"删除目录失败: {str(e)}", {}

    # 新增方法：从压缩文件中删除目录
    def _delete_directory_from_archive(self, template_name: str, deleted_dir: Path, deleted_by: str) -> Tuple[bool, str]:
        """从压缩文件中删除目录及其所有文件"""
        try:
            template = self.get_template(template_name)
            if not template or template['type'] != 'archive':
                return False, "不是压缩模板"

            archive_path = Path(template['file_path'])
            if not archive_path.exists():
                return False, f"原始压缩文件不存在: {archive_path}"

            template_dir = self.templates_root / template_name
            relative_dir = deleted_dir.relative_to(template_dir)

            # 获取文件扩展名以确定压缩格式
            filename = archive_path.name.lower()

            if filename.endswith('.zip'):
                # 从ZIP文件中删除目录
                success = self._delete_dir_from_zip_file(archive_path, relative_dir)
            elif any(filename.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']):
                # 从TAR文件中删除目录
                success = self._delete_dir_from_tar_file(archive_path, relative_dir)
            else:
                return False, f"不支持的压缩格式: {filename}"

            if success:
                # 更新元数据
                metadata = template.get('metadata', {})
                if 'archive_dir_deletions' not in metadata:
                    metadata['archive_dir_deletions'] = []

                metadata['archive_dir_deletions'].append({
                    'directory': str(relative_dir),
                    'deleted_at': datetime.now().isoformat(),
                    'deleted_by': deleted_by,
                })

                # 限制记录数量
                if len(metadata['archive_dir_deletions']) > 20:
                    metadata['archive_dir_deletions'] = metadata['archive_dir_deletions'][-20:]

                self.logger.info(f"从压缩文件中删除目录成功: {template_name}, 目录: {relative_dir}")
                return True, f"从压缩文件中删除目录成功"
            else:

                return False, "从压缩文件中删除目录失败"

        except Exception as e:
            self.logger.error(f"从压缩文件中删除目录失败: {str(e)}", exc_info=True)
            return False, f"从压缩文件中删除目录失败: {str(e)}"

    # 新增方法：从ZIP文件中删除目录
    def _delete_dir_from_zip_file(self, zip_path: Path, relative_dir: Path) -> bool:
        """从ZIP文件中删除目录及其所有文件"""
        try:
            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_zip = Path(temp_dir) / 'updated.zip'

                # 创建新的ZIP文件（不包含要删除的目录中的文件）
                with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as new_zip:
                    # 复制原ZIP中除了要删除的目录外的所有文件
                    with zipfile.ZipFile(zip_path, 'r') as old_zip:
                        for item in old_zip.infolist():
                            # 如果是要删除的目录中的文件，跳过
                            if str(item.filename).startswith(str(relative_dir) + '/'):
                                continue

                            # 读取并写入其他文件
                            with old_zip.open(item.filename) as f:
                                content = f.read()
                                new_zip.writestr(item, content)

                # 替换原ZIP文件
                shutil.copy2(temp_zip, zip_path)
                return True

        except Exception as e:
            self.logger.error(f"从ZIP文件中删除目录失败: {str(e)}")
            return False

    # 新增方法：从TAR文件中删除目录
    def _delete_dir_from_tar_file(self, tar_path: Path, relative_dir: Path) -> bool:
        """从TAR文件中删除目录及其所有文件"""
        try:
            # 获取压缩模式
            filename = tar_path.name.lower()
            mode = 'r'
            if filename.endswith('.gz') or filename.endswith('.tgz'):
                mode = 'r:gz'
            elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                mode = 'r:bz2'
            elif filename.endswith('.xz') or filename.endswith('.txz'):
                mode = 'r:xz'

            write_mode = mode.replace('r:', 'w:') if ':' in mode else 'w'

            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_tar = Path(temp_dir) / 'updated.tar'

                # 创建新的TAR文件（不包含要删除的目录中的文件）
                with tarfile.open(temp_tar, write_mode) as new_tar:
                    # 复制原TAR中除了要删除的目录外的所有文件
                    with tarfile.open(tar_path, mode) as old_tar:
                        for item in old_tar.getmembers():
                            # 如果是要删除的目录中的文件，跳过
                            if str(item.name).startswith(str(relative_dir) + '/'):
                                continue

                            # 提取并重新添加文件
                            try:
                                extracted = old_tar.extractfile(item)
                                if extracted:
                                    # 创建TarInfo对象
                                    tar_info = tarfile.TarInfo(name=item.name)
                                    tar_info.size = item.size
                                    tar_info.mtime = item.mtime
                                    tar_info.mode = item.mode
                                    tar_info.type = item.type

                                    # 添加文件到新TAR
                                    new_tar.addfile(tar_info, extracted)
                            except Exception as e:
                                self.logger.warning(f"处理TAR文件项 {item.name} 失败: {e}")
                                continue

                # 替换原TAR文件
                shutil.copy2(temp_tar, tar_path)
                return True

        except Exception as e:
            self.logger.error(f"从TAR文件中删除目录失败: {str(e)}")
            return False

    # 新增辅助方法：获取安全的文件路径
    def _get_safe_path(self, base_dir: Path, file_path: str) -> Optional[Path]:
        """获取安全的文件路径，防止路径遍历攻击"""
        try:
            # 规范化路径
            normalized = Path(file_path).resolve()
            base_normalized = base_dir.resolve()

            # 确保路径在基础目录内
            try:
                relative = normalized.relative_to(base_normalized)
            except ValueError:
                return None

            # 防止使用..等路径遍历
            if '..' in str(relative):
                return None

            # 构建完整路径
            full_path = base_dir / relative

            # 确保仍然是基础目录的子目录
            if not str(full_path.resolve()).startswith(str(base_normalized)):
                return None

            return full_path
        except Exception as e:
            self.logger.warning(f"路径安全检查失败: {str(e)}")
            return None

    # 新增辅助方法：获取文件类型
    def _get_file_type(self, file_path: Path) -> Tuple[str, bool]:
        """获取文件类型和是否为文本文件"""
        # 根据扩展名判断
        ext = file_path.suffix.lower()

        # 文本文件扩展名
        text_extensions = {
            '.txt', '.md', '.yml', '.yaml', '.json', '.xml', '.html', '.htm',
            '.css', '.js', '.py', '.java', '.c', '.cpp', '.h', '.hpp',
            '.sh', '.bash', '.bat', '.cmd', '.ps1', '.sql', '.ini', '.cfg',
            '.conf', '.properties', '.log', '.csv', '.tsv', '.rst', '.tex'
        }

        # 特殊文件类型
        if ext in {'.yml', '.yaml'}:
            return 'text/yaml', True
        elif ext == '.json':
            return 'application/json', True
        elif ext == '.xml':
            return 'application/xml', True
        elif ext == '.html' or ext == '.htm':
            return 'text/html', True
        elif ext == '.css':
            return 'text/css', True
        elif ext == '.js':
            return 'application/javascript', True
        elif ext in {'.py', '.java', '.c', '.cpp', '.h', '.hpp', '.sh', '.bash'}:
            return 'text/plain', True

        # 压缩文件类型
        elif ext == '.zip':
            return 'application/zip', False
        elif ext == '.tar':
            return 'application/x-tar', False
        elif ext in {'.gz', '.tgz'}:
            return 'application/gzip', False
        elif ext in {'.bz2', '.tbz', '.tbz2'}:
            return 'application/x-bzip2', False
        elif ext in {'.xz', '.txz'}:
            return 'application/x-xz', False

        # 默认文本文件判断
        elif ext in text_extensions:
            return 'text/plain', True
        else:
            # 尝试判断是否为文本文件
            try:
                with open(file_path, 'rb') as f:
                    chunk = f.read(1024)
                    # 检查是否包含空字节（二进制文件的特征）
                    if b'\x00' in chunk:
                        return 'application/octet-stream', False
                    # 尝试解码为UTF-8
                    chunk.decode('utf-8', errors='ignore')
                    return 'text/plain', True
            except:
                return 'application/octet-stream', False

    # 新增方法：列出模板目录下的所有文件
    def list_template_files(self, template_name: str, path: str = '') -> Tuple[bool, Union[List[Dict], str]]:
        """
        列出模板目录下的所有文件和目录

        Args:
            template_name: 模板名称
            path: 相对路径（相对于模板目录）

        Returns:
            (success, files_or_error)
        """
        try:
            # 检查模板是否存在
            template = self.get_template(template_name)
            if not template:
                return False, f"模板 '{template_name}' 不存在"

            # 获取模板目录
            template_dir = self.templates_root / template_name
            path = template_dir / path
            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}"

            # 构建完整路径，防止路径遍历攻击
            if path:
                safe_path = self._get_safe_path(template_dir, path)
                if not safe_path:
                    return False, f"无效的路径: {path}"
                target_dir = safe_path
            else:
                target_dir = template_dir

            # 确保是目录
            if not target_dir.is_dir():
                return False, f"不是目录: {path}"

            # 列出文件和目录
            files = []
            try:
                for item in target_dir.iterdir():
                    try:
                        stat_info = item.stat()
                        files.append({
                            'name': item.name,
                            'path': str(item.relative_to(template_dir)),
                            'size': stat_info.st_size if item.is_file() else 0,
                            'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                            'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                            'is_directory': item.is_dir(),
                            'is_file': item.is_file()
                        })
                    except Exception as e:
                        self.logger.warning(f"获取文件信息失败 {item}: {str(e)}")
                        continue
            except Exception as e:
                return False, f"列出文件失败: {str(e)}"

            # 按目录优先排序
            files.sort(key=lambda x: (not x['is_directory'], x['name'].lower()))

            # 添加父目录（如果不是根目录）
            if target_dir != template_dir:
                parent_path = target_dir.parent.relative_to(template_dir)
                files.insert(0, {
                    'name': '..',
                    'path': str(parent_path) if str(parent_path) != '.' else '',
                    'size': 0,
                    'created_time': '',
                    'modified_time': '',
                    'is_directory': True,
                    'is_file': False
                })

            return True, files

        except Exception as e:
            self.logger.error(f"列出模板文件失败: {str(e)}", exc_info=True)
            return False, f"列出文件失败: {str(e)}"
    def _get_compression_type(self, filename: str) -> str:
        """获取压缩文件类型"""
        filename_lower = filename.lower()
        for ext in self.supported_formats:
            if filename_lower.endswith(ext):
                if ext == '.zip':
                    return 'zip'
                elif ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']:
                    return 'tar'
        return 'unknown'

    def _extract_archive(self, file_path: Path, extract_to: Path):
        """解压各种压缩格式"""
        filename = file_path.name.lower()

        if filename.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)

        elif any(filename.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']):
            # 确定压缩模式
            mode = 'r'
            if filename.endswith('.gz') or filename.endswith('.tgz'):
                mode = 'r:gz'
            elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                mode = 'r:bz2'
            elif filename.endswith('.xz') or filename.endswith('.txz'):
                mode = 'r:xz'
            elif filename.endswith('.tar'):
                mode = 'r'

            with tarfile.open(file_path, mode) as tar_ref:
                tar_ref.extractall(extract_to)

        else:
            raise ValueError(f"不支持的压缩格式: {file_path.name}")

    def validate_yaml_content(self, yaml_content: str, template_type: str, filename: str = None) -> Tuple[bool, str]:
        """
        验证YAML内容的有效性

        Args:
            yaml_content: YAML内容字符串
            template_type: 模板类型（yaml或archive）
            filename: 文件名（可选，用于错误信息）

        Returns:
            (is_valid, error_message)
        """
        try:
            # 尝试解析YAML
            parsed = yaml.safe_load(yaml_content)

            if parsed is None:
                return False, "YAML内容为空或格式无效"

            # 检查是否为字典格式
            if not isinstance(parsed, dict):
                return False, "YAML顶层必须是字典格式"

            # 检查必须包含services部分
            if 'services' not in parsed:
                return False, "YAML文件必须包含services部分"

            # 检查services部分的格式
            services = parsed.get('services', {})
            if not isinstance(services, dict):
                return False, "services部分必须是字典格式"

            # 检查services部分不能为空
            if len(services) == 0:
                return False, "services部分不能为空"

            # 检查版本号（可选）
            version = parsed.get('version')
            if version and not isinstance(version, str):
                return False, "version字段必须是字符串格式"

            # 验证每个服务的格式
            for service_name, service_config in services.items():
                if not isinstance(service_config, dict):
                    return False, f"服务 '{service_name}' 的配置必须是字典格式"

                # 检查必要的字段
                if 'image' not in service_config:
                    self.logger.warning(f"服务 '{service_name}' 没有指定image字段")

            return True, "YAML格式有效"

        except yaml.YAMLError as e:
            return False, f"YAML格式错误: {e}"
        except Exception as e:
            return False, f"验证失败: {str(e)}"

    def create_template(self, name: str, description: str, template_type: str,
                        file_content: bytes, filename: str, created_by: str) -> Tuple[bool, str]:
        """创建模板（增强版，支持多种压缩格式）"""
        template_dir = None
        file_path = None
        db_cleanup_needed = False

        try:
            # 检查模板名称是否已存在
            existing = self.db.fetch_one(
                "SELECT id FROM secflow_agent_service_templates WHERE name = %s"
                if self.db.db_type == 'mysql' else
                "SELECT id FROM secflow_agent_service_templates WHERE name = ?",
                (name,)
            )
            if existing:
                return False, f"模板名称 '{name}' 已存在"

            # 创建模板目录
            template_dir = self.templates_root / name
            template_dir.mkdir(parents=True, exist_ok=False)

            file_path = template_dir / filename

            # 检查文件扩展名
            file_ext = Path(filename).suffix.lower()

            # 根据模板类型处理文件
            if template_type == 'yaml':
                try:
                    # 验证是否为有效的YAML文件
                    try:
                        yaml_content = file_content.decode('utf-8')
                    except UnicodeDecodeError:
                        raise ValueError("文件编码错误，无法解码为UTF-8格式")

                    # 使用验证函数
                    is_valid, error_msg = self.validate_yaml_content(yaml_content, template_type, filename)
                    if not is_valid:
                        raise ValueError(error_msg)

                    # 写入文件
                    with open(file_path, 'wb') as f:
                        f.write(file_content)

                    self.logger.info(f"YAML模板 '{name}' 格式验证成功")

                except Exception as e:
                    raise ValueError(str(e))

            elif template_type == 'archive':
                # 保存压缩文件
                with open(file_path, 'wb') as f:
                    f.write(file_content)

                # 检查是否是支持的压缩格式
                is_supported = False
                for ext in self.supported_formats:
                    if filename.lower().endswith(ext):
                        is_supported = True
                        break

                if not is_supported:
                    raise ValueError(f"不支持的压缩格式: {filename}，支持的格式: {', '.join(self.supported_formats)}")

                try:
                    # 解压文件
                    self._extract_archive(file_path, template_dir)

                    # 查找并验证YAML文件
                    yaml_files = []
                    found_yaml = None

                    # 首先查找特定的YAML文件
                    for yaml_name in ['docker-compose.yaml', 'docker-compose.yml']:
                        for yaml_path in template_dir.rglob(yaml_name):
                            if yaml_path.is_file():
                                yaml_files.append(yaml_path)

                    # 如果没找到标准名称，查找任何YAML文件
                    if not yaml_files:
                        yaml_files = list(template_dir.rglob('*.yaml'))
                        yaml_files.extend(list(template_dir.rglob('*.yml')))

                    # 检查是否找到YAML文件
                    if not yaml_files:
                        raise ValueError("压缩文件中未找到YAML文件")

                    # 验证每个找到的YAML文件
                    yaml_content = None
                    for yaml_file in yaml_files:
                        try:
                            with open(yaml_file, 'r', encoding='utf-8') as f:
                                content = f.read()

                            # 使用验证函数
                            is_valid, error_msg = self.validate_yaml_content(content, template_type, yaml_file.name)
                            if is_valid:
                                yaml_content = content
                                found_yaml = yaml_file
                                self.logger.info(f"在压缩文件中找到有效的YAML文件: {yaml_file}")
                                break
                            else:
                                self.logger.warning(f"文件 {yaml_file} 验证失败: {error_msg}")
                        except Exception as e:
                            self.logger.warning(f"文件 {yaml_file} 读取失败: {str(e)}")
                            continue

                    # 检查是否找到有效的YAML文件
                    if not yaml_content or not found_yaml:
                        raise ValueError("压缩文件中未找到包含有效services部分的YAML文件")

                    # 额外验证：确保services部分不为空
                    parsed = yaml.safe_load(yaml_content)
                    services = parsed.get('services', {})
                    if not services or len(services) == 0:
                        raise ValueError("YAML文件中的services部分不能为空")

                    self.logger.info(f"压缩模板 '{name}' 验证成功，找到有效YAML文件: {found_yaml}")

                except (zipfile.BadZipFile, tarfile.ReadError) as e:
                    raise ValueError(f"无效的压缩文件格式: {str(e)}")
                except Exception as e:
                    if not str(e).startswith("压缩文件"):
                        raise ValueError(f"压缩文件处理失败: {str(e)}")
                    else:
                        raise e

            else:
                raise ValueError(f"不支持的模板类型: {template_type}")

            # 准备元数据
            metadata = {
                'file_size': len(file_content),
                'original_filename': filename,
                'created_by': created_by,
                'created_at': datetime.now().isoformat(),
                'template_type': template_type,
                'compression_type': self.compression_map.get(file_ext, 'unknown') if template_type == 'archive' else None
            }

            if template_type == 'archive' and found_yaml:
                metadata['main_yaml_file'] = str(found_yaml.relative_to(template_dir))

            metadata_json = json.dumps(metadata)

            # 插入数据库记录
            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    "INSERT INTO secflow_agent_service_templates (name, description, type, file_path, created_by, created_at, updated_at, metadata) "
                    "VALUES (%s, %s, %s, %s, %s, NOW(), NOW(), %s)",
                    (name, description, template_type, str(file_path), created_by, metadata_json)
                )
            else:
                self.db.execute_query(
                    "INSERT INTO secflow_agent_service_templates (name, description, type, file_path, created_by, created_at, updated_at, metadata) "
                    "VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?)",
                    (name, description, template_type, str(file_path), created_by, metadata_json)
                )

            db_cleanup_needed = True
            self.logger.info(f"模板 '{name}' 创建成功，类型: {template_type}")
            return True, f"模板 '{name}' 创建成功"

        except Exception as e:
            error_msg = str(e)
            self.logger.error(f"创建模板失败: {error_msg}")

            # 清理逻辑
            try:
                # 1. 删除创建的目录（如果存在）
                if template_dir and template_dir.exists():
                    self.logger.info(f"清理模板目录: {template_dir}")
                    shutil.rmtree(template_dir, ignore_errors=True)

                # 2. 删除数据库记录（如果已插入）
                if db_cleanup_needed:
                    self.logger.info(f"清理数据库记录: {name}")
                    self.db.execute_query(
                        "DELETE FROM secflow_agent_service_templates WHERE name = %s"
                        if self.db.db_type == 'mysql' else
                        "DELETE FROM secflow_agent_service_templates WHERE name = ?",
                        (name,)
                    )

                # 3. 清理其他可能的文件
                if file_path and file_path.exists():
                    try:
                        file_path.unlink()
                    except:
                        pass

            except Exception as cleanup_error:
                self.logger.error(f"清理失败: {str(cleanup_error)}")

            return False, f"创建模板失败: {error_msg}"

    def get_template(self, name: str) -> Optional[Dict]:
        """获取模板信息（包含元数据）"""
        template = self.db.fetch_one(
            "SELECT * FROM secflow_agent_service_templates WHERE name = %s"
            if self.db.db_type == 'mysql' else
            "SELECT * FROM secflow_agent_service_templates WHERE name = ?",
            (name,)
        )

        if template:
            # 解析metadata字段
            if template.get('metadata'):
                if isinstance(template['metadata'], str):
                    try:
                        template['metadata'] = json.loads(template['metadata'])
                    except:
                        template['metadata'] = {}
            else:
                template['metadata'] = {}

            # 获取文件信息
            file_path = Path(template['file_path'])
            if file_path.exists():
                template['file_size'] = file_path.stat().st_size
                template['file_modified'] = datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
            else:
                template['file_size'] = 0
                template['file_modified'] = None

            # 获取目录信息
            template_dir = self.templates_root / name
            if template_dir.exists():
                template['directory_size'] = self._get_directory_size(template_dir)
            else:
                template['directory_size'] = 0

        return template

    def _get_directory_size(self, path: Path) -> int:
        """计算目录总大小"""
        total_size = 0
        for file_path in path.rglob('*'):
            if file_path.is_file():
                total_size += file_path.stat().st_size
        return total_size

    def get_template_file(self, name: str) -> Optional[Path]:
        """获取模板文件路径（兼容旧接口）"""
        try:
            template = self.get_template(name)
            if not template:
                return None

            file_path = Path(template['file_path'])
            if file_path.exists():
                return file_path
            else:
                return None
        except Exception as e:
            self.logger.error(f"获取模板文件失败: {str(e)}")
            return None

    def get_yaml_content(self, name: str) -> Tuple[bool, Union[str, Dict], str]:
        """
        获取模板的YAML内容

        Returns:
            (success, content_or_error, message)
            成功时: (True, yaml_content_string, '')
            失败时: (False, error_message, error_details)
        """
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在", ""

            template_type = template['type']
            file_path = Path(template['file_path'])

            if not file_path.exists():
                return False, f"模板文件不存在: {file_path}", ""

            if template_type == 'yaml':
                # 直接读取YAML文件
                with open(file_path, 'r', encoding='utf-8') as f:
                    yaml_content = f.read()
                    return True, yaml_content, ""

            elif template_type == 'archive':
                # 从压缩文件中提取YAML
                template_dir = self.templates_root / name

                # 查找YAML文件
                yaml_files = []
                for pattern in ['docker-compose.yaml', 'docker-compose.yml']:
                    yaml_files.extend(list(template_dir.rglob(pattern)))

                if not yaml_files:
                    yaml_files = list(template_dir.rglob('*.yaml'))
                    yaml_files.extend(list(template_dir.rglob('*.yml')))

                if not yaml_files:
                    return False, "压缩文件中未找到YAML文件", "no_yaml_in_archive"

                # 读取第一个YAML文件
                yaml_file = yaml_files[0]
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    yaml_content = f.read()
                    return True, yaml_content, ""

            else:
                return False, f"不支持的模板类型: {template_type}", "unsupported_type"

        except Exception as e:
            self.logger.error(f"获取YAML内容失败: {str(e)}")
            return False, f"获取YAML内容失败: {str(e)}", str(e)

    def update_yaml_content(self, name: str, yaml_content: str, updated_by: str) -> Tuple[bool, str]:
        """
        更新模板的YAML内容

        对于yaml格式：直接替换原文件
        对于archive格式：替换解压目录中的yaml文件，并重新打包
        """
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在"

            # 验证YAML内容
            try:
                parsed = yaml.safe_load(yaml_content)
                if not parsed or 'services' not in parsed:
                    return False, "YAML内容必须包含services部分"
            except yaml.YAMLError as e:
                return False, f"YAML格式错误: {e}"

            template_type = template['type']
            template_dir = self.templates_root / name

            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}"

            if template_type == 'yaml':
                # 直接更新YAML文件
                file_path = Path(template['file_path'])

                # 备份原文件
                backup_path = file_path.with_suffix(f'.yaml.backup.{datetime.now().strftime("%Y%m%d%H%M%S")}')
                shutil.copy2(file_path, backup_path)

                # 写入新内容
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(yaml_content)

                # 更新文件大小信息
                new_size = file_path.stat().st_size
                metadata = template.get('metadata', {})
                metadata['file_size'] = new_size
                metadata['last_updated_by'] = updated_by
                metadata['last_updated_at'] = datetime.now().isoformat()

                self.db.execute_query(
                    "UPDATE secflow_agent_service_templates SET updated_at = NOW(), metadata = %s WHERE name = %s"
                    if self.db.db_type == 'mysql' else
                    "UPDATE secflow_agent_service_templates SET updated_at = datetime('now'), metadata = ? WHERE name = ?",
                    (json.dumps(metadata), name)
                )

                self.logger.info(f"YAML模板 '{name}' 更新成功，新大小: {new_size} 字节")
                return True, f"模板 '{name}' 更新成功，备份文件: {backup_path.name}"

            elif template_type == 'archive':
                # 更新压缩包中的YAML
                archive_path = Path(template['file_path'])

                # 备份原压缩文件
                backup_path = archive_path.with_suffix(f'.archive.backup.{datetime.now().strftime("%Y%m%d%H%M%S")}')
                shutil.copy2(archive_path, backup_path)

                # 查找解压目录中的YAML文件
                yaml_files = []
                for pattern in ['docker-compose.yaml', 'docker-compose.yml']:
                    yaml_files.extend(list(template_dir.rglob(pattern)))

                if not yaml_files:
                    # 尝试查找任何YAML文件
                    yaml_files = list(template_dir.rglob('*.yaml'))
                    yaml_files.extend(list(template_dir.rglob('*.yml')))

                if not yaml_files:
                    return False, "未找到YAML文件进行更新"

                # 更新第一个找到的YAML文件（通常是主文件）
                yaml_file = yaml_files[0]

                # 备份原YAML文件
                yaml_backup = yaml_file.with_suffix(f'.yaml.backup.{datetime.now().strftime("%Y%m%d%H%M%S")}')
                shutil.copy2(yaml_file, yaml_backup)

                # 写入新内容
                with open(yaml_file, 'w', encoding='utf-8') as f:
                    f.write(yaml_content)

                # 重新创建压缩文件
                # 先删除原压缩文件
                archive_path.unlink()

                # 创建新压缩文件（根据原文件扩展名）
                filename = archive_path.name.lower()

                if filename.endswith('.zip'):
                    # 创建ZIP文件
                    with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        for file_path in template_dir.rglob('*'):
                            if file_path.is_file():
                                # 计算相对路径
                                rel_path = file_path.relative_to(template_dir)
                                # 添加文件到ZIP
                                zipf.write(file_path, rel_path)

                elif any(filename.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']):
                    # 创建TAR文件
                    mode = 'w'
                    if filename.endswith('.gz') or filename.endswith('.tgz'):
                        mode = 'w:gz'
                    elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                        mode = 'w:bz2'
                    elif filename.endswith('.xz') or filename.endswith('.txz'):
                        mode = 'w:xz'
                    elif filename.endswith('.tar'):
                        mode = 'w'

                    with tarfile.open(archive_path, mode) as tarf:
                        for file_path in template_dir.rglob('*'):
                            if file_path.is_file():
                                # 计算相对路径
                                rel_path = file_path.relative_to(template_dir)
                                # 添加文件到TAR
                                tarf.add(file_path, arcname=rel_path)

                # 更新元数据
                new_size = archive_path.stat().st_size
                metadata = template.get('metadata', {})
                metadata['file_size'] = new_size
                metadata['last_updated_by'] = updated_by
                metadata['last_updated_at'] = datetime.now().isoformat()

                # 更新目录大小
                dir_size = self._get_directory_size(template_dir)
                metadata['directory_size'] = dir_size

                self.db.execute_query(
                    "UPDATE secflow_agent_service_templates SET updated_at = NOW(), metadata = %s WHERE name = %s"
                    if self.db.db_type == 'mysql' else
                    "UPDATE secflow_agent_service_templates SET updated_at = datetime('now'), metadata = ? WHERE name = ?",
                    (json.dumps(metadata), name)
                )

                self.logger.info(f"压缩模板 '{name}' 更新成功，新大小: {new_size} 字节")
                return True, f"模板 '{name}' 更新成功，备份文件: {backup_path.name}"

            else:
                return False, f"不支持的模板类型: {template_type}"

        except Exception as e:
            self.logger.error(f"更新YAML内容失败: {str(e)}", exc_info=True)
            return False, f"更新失败: {str(e)}"

    def get_template_file_info(self, name: str) -> Optional[Dict]:
        """获取模板文件详细信息"""
        try:
            template = self.get_template(name)
            if not template:
                return None

            file_path = Path(template['file_path'])

            if not file_path.exists():
                return None

            # 获取文件信息
            stat_info = file_path.stat()
            file_info = {
                'name': name,
                'type': template['type'],
                'file_path': str(file_path),
                'size': stat_info.st_size,
                'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed_time': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'files_in_template': []
            }

            # 如果是压缩类型，获取压缩包内的文件列表
            if template['type'] == 'archive':
                filename = file_path.name.lower()

                if filename.endswith('.zip'):
                    try:
                        with zipfile.ZipFile(file_path, 'r') as zip_ref:
                            file_info['files_in_template'] = zip_ref.namelist()
                            file_info['archive_info'] = {
                                'format': 'zip',
                                'file_count': len(zip_ref.namelist()),
                                'compressed_size': sum(zinfo.compress_size for zinfo in zip_ref.filelist),
                                'uncompressed_size': sum(zinfo.file_size for zinfo in zip_ref.filelist),
                                'compression_ratio': sum(zinfo.compress_size for zinfo in zip_ref.filelist) /
                                                     max(sum(zinfo.file_size for zinfo in zip_ref.filelist), 1)
                            }
                    except Exception as e:
                        self.logger.warning(f"读取ZIP文件信息失败: {e}")

                elif any(filename.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']):
                    try:
                        mode = 'r'
                        if filename.endswith('.gz') or filename.endswith('.tgz'):
                            mode = 'r:gz'
                        elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                            mode = 'r:bz2'
                        elif filename.endswith('.xz') or filename.endswith('.txz'):
                            mode = 'r:xz'

                        with tarfile.open(file_path, mode) as tar_ref:
                            members = tar_ref.getmembers()
                            file_info['files_in_template'] = [m.name for m in members if m.isfile()]
                            file_info['archive_info'] = {
                                'format': 'tar',
                                'file_count': len([m for m in members if m.isfile()]),
                                'compression': mode.replace('r:', '') if ':' in mode else 'none'
                            }
                    except Exception as e:
                        self.logger.warning(f"读取TAR文件信息失败: {e}")

            return file_info

        except Exception as e:
            self.logger.error(f"获取模板文件信息失败: {str(e)}")
            return None

    def get_template_file_content(self, name: str, return_type: str = 'file') -> Tuple[bool, Union[bytes, str, Path], str]:
        """获取模板文件内容"""
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在", "text/plain"

            file_path = Path(template['file_path'])

            if not file_path.exists():
                return False, f"模板文件不存在: {file_path}", "text/plain"

            # 根据模板类型确定内容类型
            if template['type'] == 'yaml':
                content_type = 'text/yaml'
                file_extension = 'yaml'
            elif template['type'] == 'archive':
                # 根据文件扩展名确定内容类型
                filename = file_path.name.lower()
                if filename.endswith('.zip'):
                    content_type = 'application/zip'
                    file_extension = 'zip'
                elif filename.endswith('.tar'):
                    content_type = 'application/x-tar'
                    file_extension = 'tar'
                elif filename.endswith('.gz') or filename.endswith('.tgz'):
                    content_type = 'application/gzip'
                    file_extension = 'tar.gz'
                elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                    content_type = 'application/x-bzip2'
                    file_extension = 'tar.bz2'
                elif filename.endswith('.xz') or filename.endswith('.txz'):
                    content_type = 'application/x-xz'
                    file_extension = 'tar.xz'
                else:
                    content_type = 'application/octet-stream'
                    file_extension = 'bin'
            else:
                content_type = 'application/octet-stream'
                file_extension = 'bin'

            # 根据返回类型处理文件
            if return_type == 'bytes':
                with open(file_path, 'rb') as f:
                    content = f.read()
                return True, content, content_type
            elif return_type == 'stream':
                # 返回文件流
                return True, file_path, content_type
            else:  # 'file' 类型
                return True, file_path, content_type

        except Exception as e:
            self.logger.error(f"获取模板文件内容失败: {str(e)}")
            return False, f"获取文件失败: {str(e)}", "text/plain"

    def get_template_as_zip(self, name: str, include_all_files: bool = True) -> Tuple[bool, Union[bytes, str], str]:
        """将模板打包为ZIP下载"""
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在", "text/plain"

            template_dir = self.templates_root / name

            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}", "text/plain"

            # 创建内存中的ZIP文件
            zip_buffer = io.BytesIO()

            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                if include_all_files:
                    # 添加模板目录下的所有文件
                    for file_path in template_dir.rglob('*'):
                        if file_path.is_file():
                            rel_path = file_path.relative_to(template_dir)
                            zip_file.write(file_path, rel_path)
                else:
                    # 只添加主要模板文件
                    main_file = Path(template['file_path'])
                    if main_file.exists():
                        zip_file.write(main_file, main_file.name)

            zip_content = zip_buffer.getvalue()
            zip_buffer.close()

            return True, zip_content, 'application/zip'

        except Exception as e:
            self.logger.error(f"打包模板为ZIP失败: {str(e)}")
            return False, f"打包失败: {str(e)}", "text/plain"

    def export_template(self, name: str, export_format: str = 'original') -> Tuple[bool, Any, str, str]:
        """导出模板"""
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在", "text/plain", ""

            template_type = template['type']
            file_path = Path(template['file_path'])

            # 确定文件名
            if export_format == 'original':
                if template_type == 'yaml':
                    export_format = 'yaml'
                else:
                    export_format = 'archive'

            # 根据导出格式处理
            if export_format == 'yaml':
                # 导出为YAML
                success, yaml_content, message = self.get_yaml_content(name)
                if success:
                    return True, yaml_content.encode('utf-8'), 'text/yaml', f"{name}.yaml"
                else:
                    return False, message, "text/plain", ""

            elif export_format == 'archive':
                # 导出为压缩文件
                if template_type == 'archive':
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    return True, content, self._get_content_type(file_path.name), f"{name}{Path(file_path).suffix}"
                else:
                    success, archive_content, content_type = self.get_template_as_zip(name, True)
                    if success:
                        return True, archive_content, content_type, f"{name}.zip"
                    else:
                        return False, archive_content, "text/plain", ""

            else:
                return False, f"不支持的导出格式: {export_format}", "text/plain", ""

        except Exception as e:
            self.logger.error(f"导出模板失败: {str(e)}")
            return False, f"导出失败: {str(e)}", "text/plain", ""

    def _get_content_type(self, filename: str) -> str:
        """根据文件名获取Content-Type"""
        filename_lower = filename.lower()

        if filename_lower.endswith('.zip'):
            return 'application/zip'
        elif filename_lower.endswith('.tar'):
            return 'application/x-tar'
        elif filename_lower.endswith('.tar.gz') or filename_lower.endswith('.tgz'):
            return 'application/gzip'
        elif filename_lower.endswith('.tar.bz2') or filename_lower.endswith('.tbz') or filename_lower.endswith('.tbz2'):
            return 'application/x-bzip2'
        elif filename_lower.endswith('.tar.xz') or filename_lower.endswith('.txz'):
            return 'application/x-xz'
        else:
            return 'application/octet-stream'

    def list_templates(self, page: int = 1, per_page: int = 20) -> Tuple[List[Dict], int]:
        """列出所有模板（包含文件大小信息）"""
        offset = (page - 1) * per_page

        if self.db.db_type == 'mysql':
            templates = self.db.fetch_all(
                "SELECT * FROM secflow_agent_service_templates ORDER BY updated_at DESC LIMIT %s OFFSET %s",
                (per_page, offset)
            )
            count_result = self.db.fetch_one("SELECT COUNT(*) as count FROM secflow_agent_service_templates")
        else:
            templates = self.db.fetch_all(
                "SELECT * FROM secflow_agent_service_templates ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (per_page, offset)
            )
            count_result = self.db.fetch_one("SELECT COUNT(*) as count FROM secflow_agent_service_templates")

        total = count_result['count'] if count_result else 0

        # 为每个模板添加文件大小信息
        for template in templates:
            # 解析metadata
            if template.get('metadata'):
                if isinstance(template['metadata'], str):
                    try:
                        template['metadata'] = json.loads(template['metadata'])
                    except:
                        template['metadata'] = {}
            else:
                template['metadata'] = {}

            # 获取文件信息
            file_path = Path(template['file_path'])
            if file_path.exists():
                template['file_size'] = file_path.stat().st_size
            else:
                template['file_size'] = 0

            # 获取目录信息
            template_dir = self.templates_root / template['name']
            if template_dir.exists():
                template['directory_size'] = self._get_directory_size(template_dir)
            else:
                template['directory_size'] = 0

        return templates, total

    def delete_template(self, name: str) -> Tuple[bool, str]:
        """删除模板"""
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在"

            template_dir = self.templates_root / name
            if template_dir.exists():
                shutil.rmtree(template_dir, ignore_errors=True)

            self.db.execute_query(
                "DELETE FROM secflow_agent_service_templates WHERE name = %s"
                if self.db.db_type == 'mysql' else
                "DELETE FROM secflow_agent_service_templates WHERE name = ?",
                (name,)
            )

            self.logger.info(f"模板 '{name}' 删除成功")
            return True, f"模板 '{name}' 删除成功"
        except Exception as e:
            self.logger.error(f"删除模板失败: {str(e)}")
            return False, f"删除模板失败: {str(e)}"

# ===================== Agent管理器（修复分布式锁问题） =====================

class AgentManager:
    """Agent管理器"""
    def __init__(self, nacos_url: str, nacos_namespace: str,
                 agent_api_port: int, agent_auth_token: str,
                 db_manager: DatabaseManager, redis_manager: RedisManager,
                 pod_id: str, agent_api_timeouts: Dict = None,
                 nacos_username: str = None, nacos_password: str = None):  # 新增参数
        self.nacos_url = nacos_url.rstrip('/')
        self.nacos_namespace = nacos_namespace
        self.agent_api_port = agent_api_port
        self.agent_auth_token = agent_auth_token
        self.db = db_manager
        self.redis_manager = redis_manager
        self.pod_id = pod_id

        # 新增：Nacos认证信息
        self.nacos_username = nacos_username
        self.nacos_password = nacos_password
        self.nacos_auth = None
        if self.nacos_username and self.nacos_password:
            self.nacos_auth = (self.nacos_username, self.nacos_password)

        # 设置超时配置
        self.timeouts = agent_api_timeouts or {
            'default': (10, 30),
            'health_check': (5, 10),
            'deploy_create': (10, 60),
            'deploy_start': (10, 300),
            'deploy_stop': (10, 120),
            'deploy_delete': (10, 60),
            'undeploy': (10, 180),
            'file_upload': (10, 600),
            'stream': (10, 3600),
            'proxy': (10, 300),
        }

        self.agents: Dict[str, AgentInfo] = {}
        self.projects: Dict[str, ProjectInfo] = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)

        # 检查Nacos连接
        if not self._test_nacos_connection():
            self.logger.warning("Nacos连接测试失败，Agent刷新功能可能不可用")

        # 从数据库加载Agent状态
        self._load_agents_from_db()
        # 新增：缓存nacos-client的uuid值
        self.nacos_client_uuid_cache = {}
        self.nacos_client_cache_time = 0
        self.nacos_client_cache_ttl = 60  # 缓存60秒


    def _test_nacos_connection(self) -> bool:
        """测试Nacos连接"""
        try:
            result, message = ConnectionChecker.check_nacos(self.nacos_url, self.nacos_namespace)
            if result:
                self.logger.info("Nacos连接测试通过")
                return True
            else:
                self.logger.warning(f"Nacos连接测试失败: {message}")
                return False
        except Exception as e:
            self.logger.error(f"Nacos连接测试异常: {str(e)}")
            return False

    def _load_agents_from_db(self):
        try:
            with self.lock:
                if self.db.db_type == 'mysql':
                    agents_data = self.db.fetch_all(
                        "SELECT * FROM secflow_agent_agent_status WHERE updated_at > NOW() - INTERVAL 5 MINUTE"
                    )
                else:
                    agents_data = self.db.fetch_all(
                        "SELECT * FROM secflow_agent_agent_status WHERE updated_at > datetime('now', '-5 minutes')"
                    )

                for agent_data in agents_data:
                    agent = AgentInfo(
                        key=agent_data['agent_key'],
                        ip_address=agent_data['ip_address'],
                        hostname=agent_data['hostname'],
                        project_id=agent_data['project_id'],
                        full_name=agent_data['full_name'],
                        status=agent_data['status'],
                        pod_id=agent_data['pod_id']
                    )

                    if agent_data['last_seen']:
                        agent.last_seen = datetime.fromisoformat(str(agent_data['last_seen']))

                    if agent_data['system_info']:
                        if isinstance(agent_data['system_info'], str):
                            agent.system_info = json.loads(agent_data['system_info'])
                        else:
                            agent.system_info = agent_data['system_info']

                    if agent_data['services']:
                        if isinstance(agent_data['services'], str):
                            agent.services = json.loads(agent_data['services'])
                        else:
                            agent.services = agent_data['services']

                    self.agents[agent.key] = agent
                    self._update_project(agent.project_id, agent.key)

                self.logger.info(f"从数据库加载了 {len(agents_data)} 个Agent状态")

        except Exception as e:
            self.logger.error(f"从数据库加载Agent状态失败: {str(e)}")

    def _update_project(self, project_id: str, agent_key: str):
        if project_id not in self.projects:
            self.projects[project_id] = ProjectInfo(
                id=project_id,
                last_refresh=datetime.now()
            )

        project = self.projects[project_id]
        if agent_key not in project.agents:
            project.agents.append(agent_key)

        online_count = 0
        for key in project.agents:
            agent = self.agents.get(key)
            if agent and agent.status == 'online':
                online_count += 1

        project.agent_count = len(project.agents)
        project.online_agents = online_count
        project.last_refresh = datetime.now()

    def _parse_agent_name(self, service_name: str) -> Optional[Tuple[str, str, str]]:
        # 找到第一个连字符，它分隔 project_id 和 hostname
        first_dash = service_name.find('-')
        if first_dash == -1:
            return None

        project_id = service_name[:first_dash]

        # 确保 project_id 不为空且不包含连字符
        if not project_id or '-' in project_id:
            return None

        # 找到最后一个连字符，它分隔 hostname 和 IP
        last_dash = service_name.rfind('-')
        if last_dash == -1 or last_dash <= first_dash:
            return None

        ip_address = service_name[last_dash + 1:]
        hostname = service_name[first_dash + 1:last_dash]

        # 确保 hostname 不为空
        if not hostname:
            return None

        # 验证 IP 地址
        if not self._is_ip_address(ip_address):
            return None

        return project_id, hostname, ip_address

    def _get_agent_key(self, hostname: str, ip_address: str, service_name: str) -> Optional[str]:
        """
        从nacos service中获取agent_key
        根据服务名称获取对应的集群，然后从该集群的metadata中获取key为uuid的值
        如果获取不到，则不认为是一个有效的agent，忽略即可
        """
        try:
            # 检查缓存
            current_time = time.time()
            cache_key = f"{service_name}_nacos-client"
            if current_time - self.nacos_client_cache_time < self.nacos_client_cache_ttl:
                uuid_value = self.nacos_client_uuid_cache.get(cache_key)
                if uuid_value:
                    self.logger.debug(f"使用缓存的uuid: {uuid_value} for service: {service_name}")
                    return uuid_value

            # 方法1: 尝试使用新的API路径
            try:
                # 新的API路径: /v3/admin/ns/service
                url = f"{self.nacos_url}/nacos/v3/admin/ns/service"
                params = {
                    'serviceName': service_name,  # 使用agent的服务名称
                    'groupName': 'DEFAULT_GROUP',
                    'namespaceId': self.nacos_namespace
                }

                # 使用认证信息
                response = requests.get(url, params=params, timeout=5, auth=self.nacos_auth)

                if response.status_code == 200:
                    service_data = response.json()
                    self.logger.debug(f"使用新API获取服务 {service_name} 成功")

                    # 尝试解析新的API返回格式，查找名为nacos-client的集群
                    uuid_value = self._parse_nacos_v3_response_for_cluster(service_data, 'nacos-client')
                    if uuid_value:
                        # 更新缓存
                        self.nacos_client_uuid_cache[cache_key] = uuid_value
                        self.nacos_client_cache_time = current_time

                        #self.logger.debug(f"从服务 {service_name} 的nacos-client集群获取到uuid: {uuid_value}")
                        return uuid_value
                    else:
                        self.logger.debug(f"服务 {service_name} 中没有找到名为nacos-client的集群")

            except Exception as e:
                self.logger.debug(f"使用新API获取服务 {service_name} 失败: {str(e)}")

            # 方法2: 尝试使用实例列表API（指定集群名称）
            try:
                # 实例列表API，可以指定集群名称
                url = f"{self.nacos_url}/nacos/v1/ns/instance/list"
                params = {
                    'serviceName': service_name,
                    'groupName': 'DEFAULT_GROUP',
                    'namespaceId': self.nacos_namespace,
                    'clusters': 'nacos-client'  # 指定集群名称
                }

                # 使用认证信息
                response = requests.get(url, params=params, timeout=5, auth=self.nacos_auth)

                if response.status_code == 200:
                    instances_data = response.json()

                    # 查找实例的metadata
                    if 'hosts' in instances_data and instances_data['hosts']:
                        for instance in instances_data['hosts']:
                            if 'metadata' in instance:
                                uuid_value = instance['metadata'].get('uuid')
                                if uuid_value:
                                    # 更新缓存
                                    self.nacos_client_uuid_cache[cache_key] = uuid_value
                                    self.nacos_client_cache_time = current_time

                                    self.logger.debug(f"从服务 {service_name} 的nacos-client集群实例获取到uuid: {uuid_value}")
                                    return uuid_value

                        self.logger.debug(f"服务 {service_name} 的nacos-client集群实例中没有找到uuid")
                    else:
                        self.logger.debug(f"服务 {service_name} 没有nacos-client集群的实例")
                else:
                    self.logger.debug(f"获取服务 {service_name} 的实例列表失败: HTTP {response.status_code}")

            except Exception as e:
                self.logger.debug(f"使用实例列表API获取服务 {service_name} 失败: {str(e)}")

            # 方法3: 尝试使用旧API路径（如果新API不可用）
            try:
                url = f"{self.nacos_url}/v1/ns/service"
                params = {
                    'serviceName': service_name,
                    'groupName': 'DEFAULT_GROUP',
                    'namespaceId': self.nacos_namespace
                }

                # 使用认证信息
                response = requests.get(url, params=params, timeout=5, auth=self.nacos_auth)

                if response.status_code == 200:
                    service_data = response.json()
                    self.logger.debug(f"使用旧API获取服务 {service_name} 成功")

                    # 查找名为nacos-client的集群
                    if 'hosts' in service_data and service_data['hosts']:
                        for host in service_data['hosts']:
                            # 检查集群名称是否为nacos-client
                            cluster_name = host.get('clusterName', '')
                            if cluster_name == 'nacos-client' and 'metadata' in host:
                                metadata = host['metadata']
                                uuid_value = metadata.get('uuid')

                                if uuid_value:
                                    # 更新缓存
                                    self.nacos_client_uuid_cache[cache_key] = uuid_value
                                    self.nacos_client_cache_time = current_time

                                    self.logger.debug(f"从服务 {service_name} 的nacos-client集群获取到uuid: {uuid_value}")
                                    return uuid_value

                        self.logger.debug(f"服务 {service_name} 中没有找到名为nacos-client的集群")
                    else:
                        self.logger.debug(f"服务 {service_name} 没有找到集群信息")
                else:
                    self.logger.debug(f"获取服务 {service_name} 失败: HTTP {response.status_code}")

            except Exception as e:
                self.logger.debug(f"使用旧API获取服务 {service_name} 失败: {str(e)}")

        except requests.exceptions.ConnectionError:
            self.logger.debug("连接Nacos失败，无法获取服务信息")
        except requests.exceptions.Timeout:
            self.logger.debug("获取服务信息超时")
        except Exception as e:
            self.logger.debug(f"获取服务信息异常: {str(e)}")

        # 如果获取不到uuid，打印调试信息并返回None
        self.logger.debug(f"无法从服务 {service_name} 的nacos-client集群获取有效的uuid，忽略agent: {hostname}-{ip_address}")
        return None

    def _parse_nacos_v3_response_for_cluster(self, service_data: Dict, cluster_name: str) -> Optional[str]:
        """
        解析Nacos v3 API的响应，查找指定集群名称的metadata中的uuid
        """
        try:
            # 尝试不同的响应格式
            if isinstance(service_data, dict):
                # 格式1: 直接包含service字段
                if 'service' in service_data:
                    service = service_data['service']
                    if 'clusters' in service and service['clusters']:
                        for cluster in service['clusters']:
                            if cluster.get('name') == cluster_name and 'metadata' in cluster:
                                uuid_value = cluster['metadata'].get('uuid')
                                if uuid_value:
                                    return uuid_value

                # 格式2: 包含data字段
                if 'data' in service_data:
                    data = service_data['data']
                    if isinstance(data, dict) and 'clusters' in data and data['clusters']:
                        for cluster in data['clusters']:
                            if cluster.get('name') == cluster_name and 'metadata' in cluster:
                                uuid_value = cluster['metadata'].get('uuid')
                                if uuid_value:
                                    return uuid_value

                # 格式3: 直接是集群列表
                if 'clusters' in service_data and service_data['clusters']:
                    for cluster in service_data['clusters']:
                        if cluster.get('name') == cluster_name and 'metadata' in cluster:
                            uuid_value = cluster['metadata'].get('uuid')
                            if uuid_value:
                                return uuid_value

                # 格式4: 尝试查找任何包含metadata的字段
                for key, value in service_data.items():
                    if isinstance(value, dict):
                        result = self._parse_nacos_v3_response_for_cluster(value, cluster_name)
                        if result:
                            return result
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                result = self._parse_nacos_v3_response_for_cluster(item, cluster_name)
                                if result:
                                    return result

            self.logger.debug(f"无法从响应中找到集群 {cluster_name} 的uuid，响应格式: {service_data}")
            return None

        except Exception as e:
            self.logger.debug(f"解析Nacos v3响应失败: {str(e)}")
            return None

    def _fetch_nacos_services(self) -> List[Dict]:
        try:
            url = f"{self.nacos_url}/nacos/v1/ns/service/list"
            params = {
                'pageNo': 1,
                'pageSize': 1000000,
                'namespaceId': self.nacos_namespace
            }

            # 使用认证信息
            response = requests.get(url, params=params, timeout=10, auth=self.nacos_auth)
            if response.status_code == 200:
                data = response.json()
                return data.get('doms', [])
            elif response.status_code == 401:
                # 尝试v3 API
                v3_url = f"{self.nacos_url}/nacos/v3/ns/service/list"
                v3_response = requests.get(v3_url, params=params, timeout=10, auth=self.nacos_auth)
                if v3_response.status_code == 200:
                    v3_data = v3_response.json()
                    # 解析v3 API返回格式
                    if 'data' in v3_data and 'list' in v3_data['data']:
                        return [service['name'] for service in v3_data['data']['list']]
                    elif 'list' in v3_data:
                        return [service['name'] for service in v3_data['list']]
                    else:
                        self.logger.error(f"Nacos v3 API返回格式异常: {v3_data}")
                        return []
                else:
                    self.logger.error(f"获取Nacos服务列表失败 (v3): {v3_response.status_code}")
                    return []
            else:
                self.logger.error(f"获取Nacos服务列表失败: {response.status_code}")
                return []

        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"Nacos连接失败: {str(e)}")
            return []
        except requests.exceptions.Timeout as e:
            self.logger.error(f"Nacos请求超时: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"获取Nacos服务列表异常: {str(e)}")
            return []

    def _check_secflow_agent_agent_status(self, agent: AgentInfo) -> bool:
        try:
            # 首先检查是否有有效的agent_key
            if not agent.key:
                self.logger.debug(f"Agent {agent.full_name} 没有有效的agent_key，跳过状态检查")
                agent.status = 'invalid'
                return False

            url = f"http://{agent.ip_address}:{self.agent_api_port}/api/health"
            headers = {'X-Auth-Token': self.agent_auth_token}

            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                agent.status = 'online'
                agent.last_seen = datetime.now()
                agent.pod_id = self.pod_id

                try:
                    sys_url = f"http://{agent.ip_address}:{self.agent_api_port}/api/system/info"
                    sys_response = requests.get(sys_url, headers=headers, timeout=5)
                    if sys_response.status_code == 200:
                        agent.system_info = sys_response.json()
                except:
                    pass

                try:
                    services_url = f"http://{agent.ip_address}:{self.agent_api_port}/api/services"
                    services_response = requests.get(services_url, headers=headers, timeout=5)
                    if services_response.status_code == 200:
                        agent.services = services_response.json()
                except:
                    pass

                return True
            else:
                agent.status = 'error'
                return False

        except requests.exceptions.ConnectionError:
            agent.status = 'offline'
            return False
        except requests.exceptions.Timeout:
            agent.status = 'timeout'
            return False
        except Exception:
            agent.status = 'error'
            return False

    def refresh_agents(self):
        """刷新Agent列表（使用分布式锁确保只有一个POD执行刷新）"""
        lock_key = "agent_refresh_lock"

        try:
            # 获取分布式锁（如果Redis不可用，会返回虚拟锁）
            with self.redis_manager.get_lock(lock_key, timeout=30) as lock:
                if lock.is_acquired():
                    pass
                else:
                    self.logger.warning(f"POD {self.pod_id} 无法获取锁，跳过本次刷新...")
                    return

                services = self._fetch_nacos_services()
                new_agents = {}

                for service in services:
                    result = self._parse_agent_name(service)
                    if result:
                        project_id, hostname, ip_address = result

                        # 使用新方法获取agent_key，传入service_name
                        agent_key = self._get_agent_key(hostname, ip_address, service)

                        # 如果没有获取到有效的agent_key，跳过这个agent
                        if not agent_key:
                            self.logger.debug(f"跳过无效的agent: {hostname} ({ip_address}), 服务: {service}")
                            continue

                        agent = AgentInfo(
                            key=agent_key,
                            ip_address=ip_address,
                            hostname=hostname,
                            project_id=project_id,
                            full_name=service,
                            status='unknown',
                            pod_id=self.pod_id
                        )

                        self._check_secflow_agent_agent_status(agent)
                        self._save_agent_to_db(agent)
                        new_agents[agent_key] = agent

                with self.lock:
                    for key, new_agent in new_agents.items():
                        self.agents[key] = new_agent
                        self._update_project(new_agent.project_id, key)

                    removed_keys = [k for k in self.agents.keys() if k not in new_agents]
                    for key in removed_keys:
                        del self.agents[key]

                self.logger.info(f"Agent列表刷新完成，共 {len(new_agents)} 个有效Agent")

        except Exception as e:
            self.logger.error(f"刷新Agent列表异常: {str(e)}")

    def cleanup_offline_agents(self, project_id: str = None) -> Tuple[bool, str, Dict]:
        """
        清除指定project下掉线的agent

        Args:
            project_id: 项目ID，如果为None则清理所有项目的掉线agent

        Returns:
            (success, message, cleanup_info)
        """
        try:
            # 获取分布式锁，确保只有一个POD执行清理
            lock_key = f"agent_cleanup_lock_{project_id}" if project_id else "agent_cleanup_lock"
            with self.redis_manager.get_lock(lock_key, timeout=60) as lock:
                if lock.is_acquired():
                    self.logger.info(f"成功获取清理锁，开始清除{('project ' + project_id) if project_id else '全部'}掉线agent")
                else:
                    self.logger.warning("无法获取清理锁，跳过本次清理")
                    return False, "其他POD正在执行清理操作，请稍后重试", {}

                # 构建查询条件
                if project_id:
                    where_clause = " WHERE project_id = %s AND status IN ('offline', 'error', 'timeout', 'unknown') AND updated_at < NOW() - INTERVAL 5 MINUTE"
                    where_clause_sqlite = " WHERE project_id = ? AND status IN ('offline', 'error', 'timeout', 'unknown') AND updated_at < datetime('now', '-5 minutes')"
                else:
                    where_clause = " WHERE status IN ('offline', 'error', 'timeout', 'unknown') AND updated_at < NOW() - INTERVAL 5 MINUTE"
                    where_clause_sqlite = " WHERE status IN ('offline', 'error', 'timeout', 'unknown') AND updated_at < datetime('now', '-5 minutes')"

                # 查询所有掉线的agent
                if self.db.db_type == 'mysql':
                    offline_agents = self.db.fetch_all(f'''
                                                       SELECT agent_key, hostname, ip_address, project_id, status,
                                                              last_seen, updated_at
                                                       FROM secflow_agent_agent_status
                                                       {where_clause}
                                                       ORDER BY updated_at ASC
                                                       ''', (project_id,) if project_id else None)
                else:
                    offline_agents = self.db.fetch_all(f'''
                                                       SELECT agent_key, hostname, ip_address, project_id, status,
                                                              last_seen, updated_at
                                                       FROM secflow_agent_agent_status
                                                       {where_clause_sqlite}
                                                       ORDER BY updated_at ASC
                                                       ''', (project_id,) if project_id else None)

                if not offline_agents:
                    return True, "没有需要清理的掉线agent", {
                        'cleaned_count': 0,
                        'offline_count': 0,
                        'timestamp': datetime.now().isoformat()
                    }

                self.logger.info(f"找到 {len(offline_agents)} 个掉线agent需要清理")

                # 记录清理信息
                cleaned_agents = []
                cleaned_count = 0

                with self.lock:
                    # 删除数据库中的掉线agent记录
                    for agent_data in offline_agents:
                        agent_key = agent_data['agent_key']

                        try:
                            # 从数据库中删除
                            if self.db.db_type == 'mysql':
                                self.db.execute_query(
                                    "DELETE FROM secflow_agent_agent_status WHERE agent_key = %s",
                                    (agent_key,)
                                )
                            else:
                                self.db.execute_query(
                                    "DELETE FROM secflow_agent_agent_status WHERE agent_key = ?",
                                    (agent_key,)
                                )

                            # 从内存中移除
                            if agent_key in self.agents:
                                del self.agents[agent_key]

                            # 从工作空间中移除
                            for project in self.projects.values():
                                if agent_key in project.agents:
                                    project.agents.remove(agent_key)

                            # 记录清理的agent信息
                            cleaned_agents.append({
                                'agent_key': agent_key,
                                'hostname': agent_data['hostname'],
                                'ip_address': agent_data['ip_address'],
                                'project_id': agent_data['project_id'],
                                'status': agent_data['status'],
                                'last_seen': agent_data['last_seen'].isoformat() if agent_data['last_seen'] else None,
                                'cleaned_at': datetime.now().isoformat()
                            })
                            cleaned_count += 1

                            self.logger.info(f"已清理掉线agent: {agent_key} ({agent_data['hostname']})")

                        except Exception as e:
                            self.logger.error(f"清理agent {agent_key} 失败: {str(e)}")
                            continue

                # 更新项目统计
                for project_id, project in self.projects.items():
                    # 重新计算在线agent数量
                    online_count = 0
                    for agent_key in project.agents:
                        agent = self.agents.get(agent_key)
                        if agent and agent.status == 'online':
                            online_count += 1

                    project.agent_count = len(project.agents)
                    project.online_agents = online_count
                    project.last_refresh = datetime.now()

                # 准备清理信息
                cleanup_info = {
                    'cleaned_count': cleaned_count,
                    'offline_count': len(offline_agents),
                    'timestamp': datetime.now().isoformat(),
                    'pod_id': self.pod_id,
                    'cleaned_agents': cleaned_agents,
                    'remaining_agents': len(self.agents),
                    'project_count': len(self.projects)
                }

                self.logger.info(f"清理完成: 已清理 {cleaned_count} 个掉线agent")
                return True, f"成功清理 {cleaned_count} 个掉线agent", cleanup_info

        except Exception as e:
            self.logger.error(f"清除掉线agent失败: {str(e)}", exc_info=True)
            return False, f"清理失败: {str(e)}", {}

    def get_offline_agents_count(self, project_id: str = None) -> Tuple[int, int]:
        """
        获取掉线agent的统计信息

        Args:
            project_id: 项目ID，如果为None则统计所有项目

        Returns:
            (offline_count, total_count)
        """
        try:
            # 构建过滤条件
            project_filter = ""
            params = []
            if project_id:
                project_filter = " WHERE project_id = %s"
                params.append(project_id)

            # 获取总agent数
            if self.db.db_type == 'mysql':
                total_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM secflow_agent_agent_status{project_filter}",
                    tuple(params) if params else None
                )
                offline_filter = " WHERE project_id = %s AND status IN ('offline', 'error', 'timeout', 'unknown') AND updated_at < NOW() - INTERVAL 5 MINUTE"
                offline_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM secflow_agent_agent_status{offline_filter}",
                    tuple(params) if params else None
                )
            else:
                placeholders = "?" * len(params) if params else ""
                project_filter_sql = f" WHERE project_id = {placeholders}" if project_id else ""
                total_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM secflow_agent_agent_status{project_filter_sql}",
                    tuple(params) if params else None
                )
                offline_filter_sql = f" WHERE project_id = {placeholders} AND status IN ('offline', 'error', 'timeout', 'unknown') AND updated_at < datetime('now', '-5 minutes')"
                offline_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM secflow_agent_agent_status{offline_filter_sql}",
                    tuple(params) if params else None
                )

            total_count = total_result['count'] if total_result else 0
            offline_count = offline_result['count'] if offline_result else 0

            return offline_count, total_count

        except Exception as e:
            self.logger.error(f"获取掉线agent统计失败: {str(e)}")
            return 0, 0

    def _is_ip_address(self, s: str) -> bool:
        import socket
        try:
            socket.inet_aton(s)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, s)
                return True
            except socket.error:
                return False


    def _save_agent_to_db(self, agent: AgentInfo):
        try:
            system_info_json = json.dumps(agent.system_info) if agent.system_info else '{}'
            services_json = json.dumps(agent.services) if agent.services else '[]'
            last_seen_str = agent.last_seen.isoformat() if agent.last_seen else None

            if self.db.db_type == 'mysql':
                self.db.execute_query('''
                                      INSERT INTO secflow_agent_agent_status
                                      (agent_key, ip_address, hostname, project_id, full_name, status,
                                       last_seen, system_info, services, pod_id, updated_at)
                                      VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                                          ON DUPLICATE KEY UPDATE
                                                               ip_address = VALUES(ip_address),
                                                               hostname = VALUES(hostname),
                                                               project_id = VALUES(project_id),
                                                               full_name = VALUES(full_name),
                                                               status = VALUES(status),
                                                               last_seen = VALUES(last_seen),
                                                               system_info = VALUES(system_info),
                                                               services = VALUES(services),
                                                               pod_id = VALUES(pod_id),
                                                               updated_at = NOW()
                                      ''', (
                                          agent.key,
                                          agent.ip_address,
                                          agent.hostname,
                                          agent.project_id,
                                          agent.full_name,
                                          agent.status,
                                          last_seen_str,
                                          system_info_json,
                                          services_json,
                                          self.pod_id
                                      ))
            else:
                self.db.execute_query('''
                    INSERT OR REPLACE INTO secflow_agent_agent_status 
                    (agent_key, ip_address, hostname, project_id, full_name, status, 
                     last_seen, system_info, services, pod_id, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ''', (
                    agent.key,
                    agent.ip_address,
                    agent.hostname,
                    agent.project_id,
                    agent.full_name,
                    agent.status,
                    last_seen_str,
                    system_info_json,
                    services_json,
                    self.pod_id
                ))

        except Exception as e:
            self.logger.error(f"保存Agent状态到数据库失败: {str(e)}")

    def get_project(self, project_id: str) -> Optional[ProjectInfo]:
        with self.lock:
            return self.projects.get(project_id)

    def list_projects(self) -> List[Dict]:
        with self.lock:
            return [project.to_dict() for project in self.projects.values()]

    def get_project_agents(self, project_id: str) -> List[Dict]:
        with self.lock:
            project = self.projects.get(project_id)
            if not project:
                return []

            agents = []
            for agent_key in project.agents:
                agent = self.agents.get(agent_key)
                if agent:
                    agents.append(agent.to_dict())

            return agents

    def get_agent(self, key: str) -> Optional[AgentInfo]:
        with self.lock:
            return self.agents.get(key)

    def list_agents(self, page: int = 1, per_page: int = 20,
                    project_id: str = None) -> Tuple[List[Dict], int]:
        with self.lock:
            if project_id:
                project = self.projects.get(project_id)
                if not project:
                    return [], 0

                agents_list = []
                for agent_key in project.agents:
                    agent = self.agents.get(agent_key)
                    if agent:
                        agents_list.append(agent)

                total = len(agents_list)
                start_idx = (page - 1) * per_page
                end_idx = start_idx + per_page
                paginated_agents = agents_list[start_idx:end_idx]

                return [agent.to_dict() for agent in paginated_agents], total
            else:
                agents_list = list(self.agents.values())
                total = len(agents_list)
                start_idx = (page - 1) * per_page
                end_idx = start_idx + per_page
                paginated_agents = agents_list[start_idx:end_idx]

                return [agent.to_dict() for agent in paginated_agents], total

    def call_agent_api(self, agent_key: str, method: str, endpoint: str,
                       data: Any = None, params: Dict = None,
                       headers: Dict = None, files: Dict = None,
                       stream: bool = False, timeout_type: str = 'default') -> Tuple[int, Any]:
        """
        调用Agent API（增强版，支持文件上传和可配置超时）

        Args:
            agent_key: Agent标识符
            method: HTTP方法
            endpoint: API端点
            data: 请求数据
            params: 查询参数
            headers: 请求头
            files: 上传的文件
            stream: 是否流式响应
            timeout_type: 超时类型，对应配置中的超时设置
        """
        agent = self.get_agent(agent_key)
        if not agent:
            return 404, {'error': 'Agent not found'}

        try:
            url = f"http://{agent.ip_address}:{self.agent_api_port}{endpoint}"

            # 获取超时设置
            if timeout_type in self.timeouts:
                timeout = self.timeouts[timeout_type]
            else:
                timeout = self.timeouts['default']

            self.logger.debug(f"调用Agent API: {method} {url}, 超时设置: {timeout}, 类型: {timeout_type}")

            # 构建请求头
            request_headers = {
                'X-Auth-Token': self.agent_auth_token,
            }

            # 添加自定义请求头
            if headers:
                request_headers.update(headers)

            # 准备请求参数
            request_kwargs = {
                'headers': request_headers,
                'params': params,
                'timeout': timeout,
                'stream': stream
            }

            # 处理文件上传
            if files:
                # 文件上传时不设置Content-Type，让requests自动设置multipart/form-data
                if 'Content-Type' in request_headers:
                    del request_headers['Content-Type']

                # 处理文件数据
                files_to_send = {}
                for key, file_info in files.items():
                    if isinstance(file_info, tuple) and len(file_info) == 3:
                        # 已经是(filename, content, content_type)格式
                        filename, content, content_type = file_info
                        if isinstance(content, bytes):
                            files_to_send[key] = (filename, content, content_type)
                        else:
                            # 如果是路径，读取文件
                            if isinstance(content, (str, Path)):
                                file_path = Path(content)
                                if file_path.exists():
                                    with open(file_path, 'rb') as f:
                                        file_content = f.read()
                                    files_to_send[key] = (filename, file_content, content_type)
                                else:
                                    self.logger.warning(f"文件不存在: {content}")
                                    continue
                            else:
                                self.logger.warning(f"不支持的文件内容类型: {type(content)}")
                                continue
                    elif isinstance(file_info, dict):
                        # 字典格式
                        filename = file_info.get('filename', 'file')
                        content = file_info.get('content', b'')
                        content_type = file_info.get('content_type', 'application/octet-stream')

                        if isinstance(content, bytes):
                            files_to_send[key] = (filename, content, content_type)
                        else:
                            self.logger.warning(f"文件内容不是字节类型: {type(content)}")
                            continue
                    else:
                        self.logger.warning(f"不支持的文件格式: {type(file_info)}")
                        continue

                if files_to_send:
                    request_kwargs['files'] = files_to_send

                    # 如果有其他数据，作为multipart表单字段
                    if data:
                        request_kwargs['data'] = data
                else:
                    self.logger.warning("没有有效的文件可上传")
                    return 400, {'error': 'No valid files to upload'}

            elif data is not None and method.upper() in ['POST', 'PUT', 'PATCH', 'DELETE']:
                # 非文件上传时，设置JSON内容
                request_kwargs['json'] = data
                if 'Content-Type' not in request_headers:
                    request_headers['Content-Type'] = 'application/json'

            # 发送请求
            if method.upper() == 'GET':
                response = requests.get(url, **request_kwargs)
            elif method.upper() == 'POST':
                response = requests.post(url, **request_kwargs)
            elif method.upper() == 'PUT':
                response = requests.put(url, **request_kwargs)
            elif method.upper() == 'DELETE':
                response = requests.delete(url, **request_kwargs)
            elif method.upper() == 'PATCH':
                response = requests.patch(url, **request_kwargs)
            else:
                return 400, {'error': f'Unsupported method: {method}'}

            # 处理响应
            content_type = response.headers.get('Content-Type', '').lower()

            if stream:
                # 返回原始响应对象，由调用者处理
                return response.status_code, response.raw

            # 解析响应
            if 'application/json' in content_type:
                try:
                    response_data = response.json() if response.content else {}
                except json.JSONDecodeError:
                    response_data = {'raw_response': response.text}
            elif 'text/' in content_type:
                response_data = response.text
            else:
                # 二进制响应
                response_data = response.content

            self.logger.debug(f"Agent API响应: 状态码={response.status_code}, 耗时={response.elapsed.total_seconds():.2f}秒")
            return response.status_code, response_data

        except requests.exceptions.Timeout:
            self.logger.error(f"请求Agent {agent_key} 超时 (超时设置: {timeout})")
            return 504, {'error': f'Request timeout to agent (timeout: {timeout})'}
        except requests.exceptions.ConnectionError:
            self.logger.error(f"连接Agent {agent_key} 失败")
            return 503, {'error': 'Connection failed to agent'}
        except Exception as e:
            self.logger.error(f"调用Agent API失败: {str(e)}", exc_info=True)
            return 500, {'error': f'API call failed: {str(e)}'}

# ===================== 任务管理器（支持多种压缩格式） =====================

class TaskManager:
    """任务管理器（支持多种压缩格式）"""
    def __init__(self, db_manager: DatabaseManager, agent_manager: AgentManager,
                 template_manager: EnhancedTemplateManager, services_root: str,
                 redis_manager: RedisManager, pod_id: str, max_secflow_agent_task_logs: int = 1000,
                 agent_api_timeouts: Dict = None):
        self.db = db_manager
        self.agent_manager = agent_manager
        self.template_manager = template_manager
        self.services_root = Path(services_root)
        self.redis_manager = redis_manager
        self.pod_id = pod_id
        self.max_secflow_agent_task_logs = max_secflow_agent_task_logs

        # 设置超时配置
        self.timeouts = agent_api_timeouts or {
            'default': (10, 30),
            'health_check': (5, 10),
            'deploy_create': (10, 60),
            'deploy_start': (10, 300),
            'deploy_stop': (10, 120),
            'deploy_delete': (10, 60),
            'undeploy': (10, 180),
            'file_upload': (10, 600),
            'stream': (10, 3600),
            'proxy': (10, 300),
        }

        self.services_root.mkdir(parents=True, exist_ok=True)
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.active_tasks: Dict[str, Future] = {}
        self.logger = logging.getLogger(__name__)

        self._cleanup_old_logs()

    def _cleanup_old_logs(self):
        try:
            cutoff_date = (datetime.now() - timedelta(days=7)).isoformat()
            if self.db.db_type == 'mysql':
                self.db.execute_query('''
                                      DELETE FROM secflow_agent_task_logs
                                      WHERE timestamp < %s
                                      ''', (cutoff_date,))
            else:
                self.db.execute_query('''
                                      DELETE FROM secflow_agent_task_logs
                                      WHERE timestamp < ?
                                      ''', (cutoff_date,))

            self.logger.info("已清理过期任务日志")

        except Exception as e:
            self.logger.error(f"清理过期任务日志失败: {str(e)}")

    def create_task(self, task_type: str, service_name: str, agent_key: str,
                    template_name: str = None, extra_params: Dict = None,
                    project_id: str = None) -> str:
        task_id = str(uuid.uuid4())

        # Use provided project_id or get from agent
        if not project_id:
            agent = self.agent_manager.get_agent(agent_key)
            project_id = agent.project_id if agent else ''

        if self.db.db_type == 'mysql':
            self.db.execute_query('''
                                  INSERT INTO tasks
                                  (task_id, task_type, service_name, agent_key, project_id,
                                   status, progress, message, created_at, pod_id)
                                  VALUES (%s, %s, %s, %s, %s, 'pending', 0, '', NOW(), %s)
                                  ''', (task_id, task_type, service_name, agent_key, project_id, self.pod_id))
        else:
            self.db.execute_query('''
                                  INSERT INTO tasks
                                  (task_id, task_type, service_name, agent_key, project_id,
                                   status, progress, message, created_at, pod_id)
                                  VALUES (?, ?, ?, ?, ?, 'pending', 0, '', datetime('now'), ?)
                                  ''', (task_id, task_type, service_name, agent_key, project_id, self.pod_id))

        # 添加任务日志
        self._add_task_log(task_id, 'INFO', f"任务创建: {task_type} {service_name} on agent {agent_key}")

        future = self.executor.submit(
            self._execute_task, task_id, task_type, service_name,
            agent_key, template_name, extra_params
        )

        self.active_tasks[task_id] = future
        future.add_done_callback(lambda f: self.active_tasks.pop(task_id, None))

        return task_id

    def _execute_task(self, task_id: str, task_type: str, service_name: str,
                      agent_key: str, template_name: str, extra_params: Dict):
        if task_type == 'deploy':
            self._deploy_service(task_id, service_name, agent_key, template_name, extra_params)
        elif task_type == 'undeploy':
            self._undeploy_service(task_id, service_name, agent_key)
        else:
            self._update_task_status(task_id, 'failed', 0, f'未知的任务类型: {task_type}')

    def _add_task_log(self, task_id: str, level: str, message: str):
        try:
            log_id = str(uuid.uuid4())

            if self.db.db_type == 'mysql':
                self.db.execute_query('''
                                      INSERT INTO secflow_agent_task_logs
                                          (log_id, task_id, level, message, timestamp, pod_id)
                                      VALUES (%s, %s, %s, %s, NOW(), %s)
                                      ''', (log_id, task_id, level, message, self.pod_id))

                # 限制日志数量
                self.db.execute_query('''
                    DELETE tl FROM secflow_agent_task_logs tl
                    JOIN (
                        SELECT id FROM secflow_agent_task_logs 
                        WHERE task_id = %s 
                        ORDER BY timestamp DESC 
                        LIMIT 1 OFFSET %s
                    ) t ON tl.id = t.id
                ''', (task_id, self.max_secflow_agent_task_logs))

            else:
                self.db.execute_query('''
                                      INSERT INTO secflow_agent_task_logs
                                          (log_id, task_id, level, message, timestamp, pod_id)
                                      VALUES (?, ?, ?, ?, datetime('now'), ?)
                                      ''', (log_id, task_id, level, message, self.pod_id))

                # 限制日志数量
                self.db.execute_query('''
                                      DELETE FROM secflow_agent_task_logs
                                      WHERE id IN (
                                          SELECT id FROM secflow_agent_task_logs
                                          WHERE task_id = ?
                                          ORDER BY timestamp DESC
                                          LIMIT -1 OFFSET ?
                                          )
                                      ''', (task_id, self.max_secflow_agent_task_logs))

        except Exception as e:
            self.logger.error(f"添加任务日志失败: {str(e)}")

    def _update_task_status(self, task_id: str, status: str, progress: int = 0,
                            message: str = ''):
        update_fields = []
        params = []

        if status:
            update_fields.append("status = %s" if self.db.db_type == 'mysql' else "status = ?")
            params.append(status)

        if progress is not None:
            update_fields.append("progress = %s" if self.db.db_type == 'mysql' else "progress = ?")
            params.append(progress)

        if message is not None:
            update_fields.append("message = %s" if self.db.db_type == 'mysql' else "message = ?")
            params.append(message)

        if status == 'running':
            update_fields.append("started_at = NOW()" if self.db.db_type == 'mysql' else "started_at = datetime('now')")
        elif status in ['success', 'failed', 'cancelled']:
            update_fields.append("completed_at = NOW()" if self.db.db_type == 'mysql' else "completed_at = datetime('now')")

        if update_fields:
            query = f"UPDATE tasks SET {', '.join(update_fields)} WHERE task_id = "
            query += "%s" if self.db.db_type == 'mysql' else "?"
            params.append(task_id)
            self.db.execute_query(query, tuple(params))

        log_level = 'INFO'
        if status == 'failed':
            log_level = 'ERROR'
        elif status == 'cancelled':
            log_level = 'WARNING'

        if message:
            self._add_task_log(task_id, log_level, message)

    def _get_content_type(self, filename: str) -> str:
        """根据文件名获取Content-Type"""
        filename_lower = filename.lower()

        if filename_lower.endswith('.zip'):
            return 'application/zip'
        elif filename_lower.endswith('.tar'):
            return 'application/x-tar'
        elif filename_lower.endswith('.tar.gz') or filename_lower.endswith('.tgz'):
            return 'application/gzip'
        elif filename_lower.endswith('.tar.bz2') or filename_lower.endswith('.tbz') or filename_lower.endswith('.tbz2'):
            return 'application/x-bzip2'
        elif filename_lower.endswith('.tar.xz') or filename_lower.endswith('.txz'):
            return 'application/x-xz'
        else:
            return 'application/octet-stream'

    def _deploy_service(self, task_id: str, service_name: str, agent_key: str,
                        template_name: str, extra_params: Dict = None):
        """部署服务（支持多种压缩格式）"""
        try:
            self._update_task_status(task_id, 'running', 10, '开始部署')

            # 1. 检查Agent是否存在
            agent = self.agent_manager.get_agent(agent_key)
            if not agent:
                self._update_task_status(task_id, 'failed', 0, f'Agent {agent_key} 不存在')
                return

            self._add_task_log(task_id, 'INFO', f"目标Agent: {agent.hostname} ({agent.ip_address})")
            self._add_task_log(task_id, 'INFO', f"服务名称: {service_name}")
            self._add_task_log(task_id, 'INFO', f"使用模板: {template_name}")

            # 2. 检查模板是否存在
            if not template_name:
                self._update_task_status(task_id, 'failed', 0, '未指定模板名称')
                return

            self._update_task_status(task_id, 'running', 20, '检查模板')

            template = self.template_manager.get_template(template_name)
            if not template:
                self._update_task_status(task_id, 'failed', 0, f'模板 {template_name} 不存在')
                return

            template_type = template['type']
            self._add_task_log(task_id, 'INFO', f"模板类型: {template_type}")

            # 3. 根据模板类型处理
            if template_type == 'yaml':
                # YAML模板部署
                self._deploy_yaml_template(task_id, service_name, agent_key, template_name, extra_params)

            elif template_type == 'archive':
                # 压缩模板部署（支持多种格式）
                self._deploy_archive_template(task_id, service_name, agent_key, template_name, extra_params)

            else:
                error_msg = f'不支持的模板类型: {template_type}'
                self._update_task_status(task_id, 'failed', 0, error_msg)

        except Exception as e:
            self.logger.error(f"部署服务失败: {str(e)}", exc_info=True)
            self._update_task_status(task_id, 'failed', 0, f'部署失败: {str(e)}')
            self._add_task_log(task_id, 'ERROR', f"异常详情: {traceback.format_exc()}")
    def _deploy_yaml_template(self, task_id: str, service_name: str, agent_key: str,
                              template_name: str, extra_params: Dict = None):
        """部署YAML模板"""
        # 获取YAML内容
        success, yaml_content, error_msg = self.template_manager.get_yaml_content(template_name)
        if not success:
            self._update_task_status(task_id, 'failed', 30, f'获取YAML内容失败: {yaml_content}')
            return

        self._add_task_log(task_id, 'INFO', f"YAML内容大小: {len(yaml_content)} 字符")

        # 准备部署数据
        data = {
            'name': service_name,
            'yaml': yaml_content
        }

        # 添加额外参数（如果有）
        if extra_params:
            data.update(extra_params)

        self._add_task_log(task_id, 'INFO', f"调用Agent API创建服务: {service_name}")

        # 调用Agent API创建服务（使用较长的超时）
        self._add_task_log(task_id, 'INFO', f"创建服务，超时设置: {self.timeouts['deploy_create']}")
        status_code, response = self.agent_manager.call_agent_api(
            agent_key, 'POST', '/api/services/yaml', data,
            timeout_type='deploy_create'
        )

        self._add_task_log(task_id, 'INFO', f"Agent响应状态码: {status_code}")
        self._add_task_log(task_id, 'DEBUG', f"Agent响应内容: {json.dumps(response)[:200]}...")

        # 处理响应
        if status_code == 201:
            self._update_task_status(task_id, 'running', 70, '服务创建成功，正在启动')
            time.sleep(2)

            # 启动服务（使用更长的超时，因为可能需要下载镜像）
            self._add_task_log(task_id, 'INFO', f"启动服务，超时设置: {self.timeouts['deploy_start']}")
            start_status_code, start_response = self.agent_manager.call_agent_api(
                agent_key, 'POST', f'/api/services/{service_name}/start', {},
                timeout_type='deploy_start'
            )

            if start_status_code == 200:
                self._update_task_status(task_id, 'success', 100, '服务部署成功')
                self._add_task_log(task_id, 'INFO', '服务部署完成')
            else:
                error_msg = f'启动服务失败: {start_response}'
                self._update_task_status(task_id, 'failed', 70, error_msg)
                self._add_task_log(task_id, 'ERROR', error_msg)

                # 尝试清理创建的服务
                self._add_task_log(task_id, 'WARN', '尝试清理已创建的服务')
                self._add_task_log(task_id, 'INFO', f"停止服务，超时设置: {self.timeouts['deploy_stop']}")
                self.agent_manager.call_agent_api(
                    agent_key, 'POST', f'/api/services/{service_name}/stop', {},
                    timeout_type='deploy_stop'
                )

                time.sleep(2)

                self._add_task_log(task_id, 'INFO', f"删除服务，超时设置: {self.timeouts['deploy_delete']}")
                self.agent_manager.call_agent_api(
                    agent_key, 'DELETE', f'/api/services/{service_name}', {},
                    timeout_type='deploy_delete'
                )

        elif status_code == 409:
            # 服务已存在，重新创建
            self._update_task_status(task_id, 'running', 70, '服务已存在，尝试重新创建')
            self._add_task_log(task_id, 'INFO', '停止现有服务')

            # 先停止并删除现有服务
            self.agent_manager.call_agent_api(
                agent_key, 'POST', f'/api/services/{service_name}/stop', {},
                timeout_type='deploy_stop'
            )

            time.sleep(3)

            self._add_task_log(task_id, 'INFO', '删除现有服务')
            self.agent_manager.call_agent_api(
                agent_key, 'DELETE', f'/api/services/{service_name}', {},
                timeout_type='deploy_delete'
            )

            time.sleep(2)

            # 重新创建服务
            self._add_task_log(task_id, 'INFO', '重新创建服务')
            status_code, response = self.agent_manager.call_agent_api(
                agent_key, 'POST', '/api/services/yaml', data,
                timeout_type='deploy_create'
            )

            if status_code == 201:
                # 启动服务
                time.sleep(2)
                start_status_code, start_response = self.agent_manager.call_agent_api(
                    agent_key, 'POST', f'/api/services/{service_name}/start', {},
                    timeout_type='deploy_start'
                )

                if start_status_code == 200:
                    self._update_task_status(task_id, 'success', 100, '服务重新部署成功')
                else:
                    error_msg = f'重新部署后启动服务失败: {start_response}'
                    self._update_task_status(task_id, 'failed', 70, error_msg)
            else:
                error_msg = f'重新创建服务失败: {response}'
                self._update_task_status(task_id, 'failed', 70, error_msg)

        else:
            error_msg = f'创建服务失败 (HTTP {status_code}): {response}'
            self._update_task_status(task_id, 'failed', 30, error_msg)
            self._add_task_log(task_id, 'ERROR', error_msg)

    def _deploy_archive_template(self, task_id: str, service_name: str, agent_key: str,
                                 template_name: str, extra_params: Dict = None):
        """部署压缩模板（支持多种格式）"""
        self._update_task_status(task_id, 'running', 30, '处理压缩模板')

        # 获取模板文件路径
        template_file = self.template_manager.get_template_file(template_name)
        if not template_file:
            self._update_task_status(task_id, 'failed', 30, '压缩模板文件不存在')
            return

        self._add_task_log(task_id, 'INFO', f"压缩文件: {template_file}")

        # 读取压缩文件内容
        with open(template_file, 'rb') as f:
            file_content = f.read()

        # 获取文件扩展名
        filename = Path(template_file).name

        # 创建文件字典（符合call_agent_api的文件格式）
        files = {
            'file': (filename, file_content, self._get_content_type(filename))
        }

        data = {
            'name': service_name
        }

        # 添加额外参数
        if extra_params:
            data.update(extra_params)

        self._add_task_log(task_id, 'INFO', f"上传压缩文件到Agent: {filename}")

        # 调用Agent的压缩文件部署接口（使用文件上传的超时）
        self._add_task_log(task_id, 'INFO', f"上传文件，超时设置: {self.timeouts['file_upload']}")
        status_code, response = self.agent_manager.call_agent_api(
            agent_key, 'POST', '/api/services/zip', data=data, files=files,
            timeout_type='file_upload'
        )

        self._add_task_log(task_id, 'INFO', f"Agent响应状态码: {status_code}")
        self._add_task_log(task_id, 'DEBUG', f"Agent响应内容: {json.dumps(response)[:200]}...")

        if status_code == 201:
            self._update_task_status(task_id, 'running', 70, '压缩服务创建成功，正在启动')

            # 等待几秒让服务创建完成
            time.sleep(3)

            self._add_task_log(task_id, 'INFO', f"启动服务: {service_name}")

            # 启动服务（使用较长的超时）
            self._add_task_log(task_id, 'INFO', f"启动服务，超时设置: {self.timeouts['deploy_start']}")
            start_status_code, start_response = self.agent_manager.call_agent_api(
                agent_key, 'POST', f'/api/services/{service_name}/start', {},
                timeout_type='deploy_start'
            )

            if start_status_code == 200:
                self._update_task_status(task_id, 'success', 100, '压缩服务部署成功')
                self._add_task_log(task_id, 'INFO', '压缩服务部署完成')
            else:
                error_msg = f'启动压缩服务失败: {start_response}'
                self._update_task_status(task_id, 'failed', 70, error_msg)
                self._add_task_log(task_id, 'ERROR', error_msg)
        else:
            error_msg = f'创建压缩服务失败 (HTTP {status_code}): {response}'
            self._update_task_status(task_id, 'failed', 30, error_msg)
            self._add_task_log(task_id, 'ERROR', error_msg)

    def _undeploy_service(self, task_id: str, service_name: str, agent_key: str):
        """卸载服务"""
        try:
            self._update_task_status(task_id, 'running', 10, '开始卸载服务')

            agent = self.agent_manager.get_agent(agent_key)
            if not agent:
                self._update_task_status(task_id, 'failed', 0, f'Agent {agent_key} 不存在')
                return

            self._add_task_log(task_id, 'INFO', f"目标Agent: {agent.hostname} ({agent.ip_address})")
            self._add_task_log(task_id, 'INFO', f"服务名称: {service_name}")

            # 停止服务（使用较长的超时）
            self._add_task_log(task_id, 'INFO', '停止服务')
            self._add_task_log(task_id, 'INFO', f"超时设置: {self.timeouts['undeploy']}")
            stop_status_code, stop_response = self.agent_manager.call_agent_api(
                agent_key, 'POST', f'/api/services/{service_name}/stop', {},
                timeout_type='undeploy'
            )

            if stop_status_code not in [200, 404]:
                self._update_task_status(task_id, 'failed', 30, f'停止服务失败: {stop_response}')
                return

            time.sleep(2)

            # 删除服务
            self._add_task_log(task_id, 'INFO', '删除服务')
            delete_status_code, delete_response = self.agent_manager.call_agent_api(
                agent_key, 'DELETE', f'/api/services/{service_name}', {},
                timeout_type='undeploy'
            )

            if delete_status_code in [200, 204, 404]:
                self._update_task_status(task_id, 'success', 100, '服务卸载成功')
                self._add_task_log(task_id, 'INFO', '服务卸载完成')
            else:
                error_msg = f'删除服务失败 (HTTP {delete_status_code}): {delete_response}'
                self._update_task_status(task_id, 'failed', 50, error_msg)
                self._add_task_log(task_id, 'ERROR', error_msg)

        except Exception as e:
            self.logger.error(f"卸载服务失败: {str(e)}")
            self._update_task_status(task_id, 'failed', 0, f'卸载失败: {str(e)}')


    def get_task(self, task_id: str) -> Optional[Dict]:
        task = self.db.fetch_one(
            "SELECT * FROM secflow_agent_tasks WHERE task_id = %s"
            if self.db.db_type == 'mysql' else
            "SELECT * FROM secflow_agent_tasks WHERE task_id = ?",
            (task_id,)
        )

        if task:
            log_count = self.db.fetch_one(
                "SELECT COUNT(*) as count FROM secflow_agent_task_logs WHERE task_id = %s"
                if self.db.db_type == 'mysql' else
                "SELECT COUNT(*) as count FROM secflow_agent_task_logs WHERE task_id = ?",
                (task_id,)
            )
            task['log_count'] = log_count['count'] if log_count else 0

        return task

    def get_secflow_agent_task_logs(self, task_id: str, page: int = 1, per_page: int = 100) -> Tuple[List[Dict], int]:
        offset = (page - 1) * per_page

        if self.db.db_type == 'mysql':
            logs = self.db.fetch_all('''
                                     SELECT * FROM secflow_agent_task_logs
                                     WHERE task_id = %s
                                     ORDER BY timestamp ASC
                                         LIMIT %s OFFSET %s
                                     ''', (task_id, per_page, offset))

            count_result = self.db.fetch_one(
                "SELECT COUNT(*) as count FROM secflow_agent_task_logs WHERE task_id = %s",
                (task_id,)
            )
        else:
            logs = self.db.fetch_all('''
                                     SELECT * FROM secflow_agent_task_logs
                                     WHERE task_id = ?
                                     ORDER BY timestamp ASC
                                         LIMIT ? OFFSET ?
                                     ''', (task_id, per_page, offset))

            count_result = self.db.fetch_one(
                "SELECT COUNT(*) as count FROM secflow_agent_task_logs WHERE task_id = ?",
                (task_id,)
            )

        total = count_result['count'] if count_result else 0
        return logs, total

    def list_tasks(self, page: int = 1, per_page: int = 20,
                   task_type: str = None, status: str = None,
                   project_id: str = None, agent_key: str = None) -> Tuple[List[Dict], int]:
        query = "SELECT * FROM secflow_agent_tasks WHERE 1=1"
        params = []

        if task_type:
            query += " AND task_type = "
            query += "%s" if self.db.db_type == 'mysql' else "?"
            params.append(task_type)

        if status:
            query += " AND status = "
            query += "%s" if self.db.db_type == 'mysql' else "?"
            params.append(status)

        if project_id:
            query += " AND project_id = "
            query += "%s" if self.db.db_type == 'mysql' else "?"
            params.append(project_id)

        if agent_key:
            query += " AND agent_key = "
            query += "%s" if self.db.db_type == 'mysql' else "?"
            params.append(agent_key)

        query += " ORDER BY created_at DESC"

        count_query = query.replace("SELECT *", "SELECT COUNT(*) as count")
        count_result = self.db.fetch_one(count_query, tuple(params))
        total = count_result['count'] if count_result else 0

        query += " LIMIT "
        query += "%s OFFSET %s" if self.db.db_type == 'mysql' else "? OFFSET ?"
        offset = (page - 1) * per_page
        params.extend([per_page, offset])

        tasks = self.db.fetch_all(query, tuple(params))

        for task in tasks:
            log_count = self.db.fetch_one(
                "SELECT COUNT(*) as count FROM secflow_agent_task_logs WHERE task_id = " +
                ("%s" if self.db.db_type == 'mysql' else "?"),
                (task['task_id'],)
            )
            task['log_count'] = log_count['count'] if log_count else 0

        return tasks, total

    def delete_task(self, task_id: str) -> bool:
        try:
            if self.db.db_type == 'mysql':
                self.db.execute_transaction([
                    ("DELETE FROM secflow_agent_task_logs WHERE task_id = %s", (task_id,)),
                    ("DELETE FROM secflow_agent_tasks WHERE task_id = %s", (task_id,))
                ])
            else:
                self.db.execute_transaction([
                    ("DELETE FROM secflow_agent_task_logs WHERE task_id = ?", (task_id,)),
                    ("DELETE FROM secflow_agent_tasks WHERE task_id = ?", (task_id,))
                ])

            future = self.active_tasks.pop(task_id, None)
            if future and not future.done():
                future.cancel()

            self.logger.info(f"任务 {task_id} 删除成功")
            return True
        except Exception as e:
            self.logger.error(f"删除任务失败: {str(e)}")
            return False

# ===================== 代理管理器增强版 =====================

class EnhancedProxyManager:
    """增强版代理管理器"""

    def __init__(self, agent_manager: AgentManager, timeouts: Dict = None):
        self.agent_manager = agent_manager
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.verify = False  # 临时禁用SSL验证

        # 设置超时配置
        self.timeouts = timeouts or {
            'default': (10, 30),
            'health_check': (5, 10),
            'deploy_create': (10, 60),
            'deploy_start': (10, 300),
            'deploy_stop': (10, 120),
            'deploy_delete': (10, 60),
            'undeploy': (10, 180),
            'file_upload': (10, 600),
            'stream': (10, 3600),
            'proxy': (10, 300),
        }

    def proxy_request(self, agent_key: str, method: str, endpoint: str,
                      request_data: Any = None, query_params: Dict = None,
                      headers: Dict = None, files: Dict = None,
                      stream: bool = False, timeout: int = None) -> Tuple[int, Any, Dict]:
        """
        代理请求到指定的Agent（增强版）
        """
        try:
            # 获取Agent信息
            agent = self.agent_manager.get_agent(agent_key)
            if not agent:
                return 404, {'error': f'Agent {agent_key} not found'}, {}

            # 检查Agent状态
            if agent.status != 'online':
                return 503, {'error': f'Agent {agent_key} is {agent.status}'}, {}

            # 构建完整的URL
            url = f"http://{agent.ip_address}:{self.agent_manager.agent_api_port}{endpoint}"

            # 准备请求头
            request_headers = {
                'X-Auth-Token': self.agent_manager.agent_auth_token,
            }

            # 只有当有JSON数据时才添加Content-Type
            if request_data and isinstance(request_data, dict):
                request_headers['Content-Type'] = 'application/json'

            # 添加自定义请求头（过滤敏感头）
            if headers:
                for key, value in headers.items():
                    key_lower = key.lower()
                    if key_lower not in ['host', 'authorization', 'cookie', 'connection']:
                        request_headers[key] = value

            # 确定超时时间
            if timeout is None:
                # 根据端点类型确定默认超时
                if stream:
                    timeout_tuple = self.timeouts.get('stream', (10, 3600))
                elif files:
                    timeout_tuple = self.timeouts.get('file_upload', (10, 600))
                elif 'start' in endpoint.lower():
                    timeout_tuple = self.timeouts.get('deploy_start', (10, 300))
                elif 'stop' in endpoint.lower():
                    timeout_tuple = self.timeouts.get('deploy_stop', (10, 120))
                elif 'delete' in endpoint.lower():
                    timeout_tuple = self.timeouts.get('deploy_delete', (10, 60))
                elif 'health' in endpoint.lower():
                    timeout_tuple = self.timeouts.get('health_check', (5, 10))
                else:
                    timeout_tuple = self.timeouts.get('proxy', (10, 300))
            else:
                # 使用指定的超时时间（秒）
                timeout_tuple = (10, timeout)

            # 准备请求参数
            request_kwargs = {
                'headers': request_headers,
                'params': query_params,
                'timeout': timeout_tuple,
                'stream': stream,
                'verify': False  # 禁用SSL验证
            }

            self.logger.info(f"代理请求: {method} {url} 到Agent {agent.hostname}, 超时: {timeout_tuple}")

            # 发送请求
            response = None
            try:
                if method.upper() == 'GET':
                    response = self.session.get(url, **request_kwargs)
                elif method.upper() == 'POST':
                    if files:
                        request_kwargs['files'] = files
                        if request_data:
                            request_kwargs['data'] = request_data
                    elif request_data:
                        request_kwargs['json'] = request_data
                    response = self.session.post(url, **request_kwargs)
                elif method.upper() == 'PUT':
                    if request_data:
                        request_kwargs['json'] = request_data
                    response = self.session.put(url, **request_kwargs)
                elif method.upper() == 'DELETE':
                    if request_data:
                        request_kwargs['json'] = request_data
                    response = self.session.delete(url, **request_kwargs)
                elif method.upper() == 'PATCH':
                    if request_data:
                        request_kwargs['json'] = request_data
                    response = self.session.patch(url, **request_kwargs)
                elif method.upper() == 'HEAD':
                    response = self.session.head(url, **request_kwargs)
                elif method.upper() == 'OPTIONS':
                    response = self.session.options(url, **request_kwargs)
                else:
                    return 400, {'error': f'Unsupported method: {method}'}, {}
            except requests.exceptions.Timeout:
                return 504, {'error': f'Request timeout to agent {agent.hostname} (timeout: {timeout_tuple})'}, {}
            except requests.exceptions.ConnectionError:
                return 503, {'error': f'Connection failed to agent {agent.hostname}'}, {}
            except Exception as e:
                self.logger.error(f"发送请求失败: {str(e)}")
                return 500, {'error': f'Failed to send request: {str(e)}'}, {}

            if response is None:
                return 500, {'error': 'No response received from agent'}, {}

            # 构建响应头
            response_headers = {
                'Content-Type': response.headers.get('Content-Type', 'application/json'),
                'X-Proxied-From-Agent': agent_key,
                'X-Proxied-Agent-IP': agent.ip_address,
                'X-Proxied-Agent-Name': agent.hostname,
                'X-Proxied-Response-Code': str(response.status_code),
                'X-Proxied-Response-Time': str(response.elapsed.total_seconds() * 1000) + 'ms'
            }

            # 复制所有响应头（除了敏感头）
            for key, value in response.headers.items():
                key_lower = key.lower()
                if key_lower not in ['server', 'date', 'connection', 'transfer-encoding']:
                    response_headers[key] = value

            # 处理响应数据
            try:
                content_type = response.headers.get('Content-Type', '').lower()

                if stream:
                    # 流式响应
                    return response.status_code, response.content, response_headers
                elif 'application/json' in content_type:
                    # JSON响应
                    try:
                        response_data = response.json() if response.content else {}
                    except json.JSONDecodeError as e:
                        self.logger.warning(f"Agent响应JSON解析失败: {e}, 返回文本")
                        response_data = {'raw_response': response.text}
                elif 'text/' in content_type:
                    # 文本响应
                    response_data = response.text
                elif response.content:
                    # 二进制响应
                    try:
                        response_data = json.loads(response.text)
                    except:
                        response_data = {'content': 'binary data', 'size': len(response.content)}
                else:
                    response_data = {}
            except Exception as e:
                self.logger.error(f"处理响应失败: {str(e)}")
                response_data = {'error': 'Failed to process response', 'status_code': response.status_code}

            self.logger.debug(f"代理响应: 状态码={response.status_code}, 耗时={response.elapsed.total_seconds():.2f}秒")
            return response.status_code, response_data, response_headers

        except Exception as e:
            self.logger.error(f"代理请求失败: {str(e)}", exc_info=True)
            return 500, {'error': f'Proxy request failed: {str(e)}'}, {}

# ===================== Flask应用 =====================

class WebAPIServer:
    """WEB API服务器（支持多种压缩格式）"""

    def __init__(self, config: Dict):
        self.config = config
        self.logger = self._setup_logger()

        # 1. 检查所有连接
        self._check_startup_connections()

        # 2. 初始化Flask应用
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = config['secret_key']
        self.app.config['MAX_CONTENT_LENGTH'] = config['upload_max_size']
        CORS(self.app)

        # 4. 初始化Redis管理器
        self.redis_manager = RedisManager(
            config.get('redis_url', 'redis://localhost:6379/0'),
            config.get('redis_enabled', True)
        )

        # 5. 初始化数据库管理器
        self.db_manager = DatabaseManager(config['database'])



        # 7. 初始化模板管理器（传递支持的格式）
        supported_formats = config.get('supported_formats', SUPPORTED_FORMATS)
        self.template_manager = EnhancedTemplateManager(
            config['templates_root'],
            self.db_manager,
            supported_formats
        )

        # 8. 初始化Agent管理器（传递超时配置）
        agent_api_timeouts = config.get('agent_api_timeouts', {
            'default': (10, 30),
            'health_check': (5, 10),
            'deploy_create': (10, 60),
            'deploy_start': (10, 300),
            'deploy_stop': (10, 120),
            'deploy_delete': (10, 60),
            'undeploy': (10, 180),
            'file_upload': (10, 600),
            'stream': (10, 3600),
            'proxy': (10, 300),
        })

        self.agent_manager = AgentManager(
            config['nacos_url'],
            config.get('nacos_namespace', 'public'),
            config.get('agent_api_port', 11187),
            config.get('agent_auth_token', 'default_token_change_me'),
            self.db_manager,
            self.redis_manager,
            config['pod_id'],
            agent_api_timeouts,
            config.get('nacos_username'),  # 新增：Nacos用户名
            config.get('nacos_password')   # 新增：Nacos密码
        )

        # 9. 初始化任务管理器（传递超时配置）
        self.task_manager = TaskManager(
            self.db_manager,
            self.agent_manager,
            self.template_manager,
            config['services_root'],
            self.redis_manager,
            config['pod_id'],
            config.get('max_secflow_agent_task_logs', 1000),
            agent_api_timeouts
        )

        # 10. 初始化代理管理器（新增，传递超时配置）
        self.proxy_manager = EnhancedProxyManager(self.agent_manager, agent_api_timeouts)

        # 11. 注册路由
        self._register_routes()

        # 12. 后台刷新线程
        self.refresh_thread = None
        self.should_stop = False

        self.logger.info(f"当前POD ID: {config['pod_id']}")
        self.logger.info(f"使用数据库: {config['database'].get('type', 'sqlite').upper()}")
        self.logger.info(f"Redis状态: {'已启用' if self.redis_manager.enabled else '已禁用'}")
        self.logger.info(f"支持的压缩格式: {', '.join(supported_formats)}")
        self.logger.info(f"Agent API超时配置: {agent_api_timeouts}")
        self.logger.info(f"代理功能: 已启用")

    def _setup_logger(self) -> logging.Logger:
        """设置日志"""
        logger = logging.getLogger(__name__)
        logger.setLevel(getattr(logging, self.config['log_level'].upper()))

        # 文件处理器
        log_file = self.config.get('log_file', './webapi_server.log')
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, self.config['log_level'].upper()))

        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, self.config['log_level'].upper()))

        # 格式化
        formatter = logging.Formatter(
            f'%(asctime)s - {self.config["pod_id"]} - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        return logger

    def _check_startup_connections(self):
        """检查启动连接"""
        self.logger.info("开始检查启动连接...")

        results = ConnectionChecker.check_all_connections(self.config)

        # 检查数据库连接
        db_success, db_message = results.get('database', (False, '数据库检查失败'))
        if not db_success:
            self.logger.error(f"数据库连接失败: {db_message}")
            raise ConnectionError(f"数据库连接失败: {db_message}")

        self.logger.info(f"✓ {db_message}")

        # 检查Nacos连接
        nacos_success, nacos_message = results.get('nacos', (False, 'Nacos检查失败'))
        if not nacos_success:
            self.logger.error(f"Nacos连接失败: {nacos_message}")
            raise ConnectionError(f"Nacos连接失败: {nacos_message}")

        self.logger.info(f"✓ {nacos_message}")

        # 检查Redis连接
        redis_success, redis_message = results.get('redis', (False, 'Redis检查失败'))
        if redis_success:
            self.logger.info(f"✓ {redis_message}")
        else:
            self.logger.warning(f"⚠ {redis_message}，Redis功能将禁用")

        self.logger.info("所有启动连接检查完成")

    def _register_routes(self):
        """注册路由"""

        @self.app.route('/api/agent/health', methods=['GET'])
        def health_check():
            """健康检查端点"""
            db_ok = False
            try:
                db = self.db_manager.get_connection()
                db.fetch_one("SELECT 1")
                db_ok = True
            except:
                pass

            redis_ok = False
            if self.redis_manager.enabled:
                redis_ok = self.redis_manager.test_connection()

            nacos_ok = False
            try:
                result, _ = ConnectionChecker.check_nacos(
                    self.config['nacos_url'],
                    self.config.get('nacos_namespace', 'public')
                )
                nacos_ok = result
            except:
                pass

            # 计算总体状态
            status = 'healthy' if db_ok and nacos_ok else 'unhealthy'

            return jsonify({
                'status': status,
                'timestamp': datetime.now().isoformat(),
                'pod_id': self.config['pod_id'],
                'database_type': self.config['database'].get('type', 'sqlite'),
                'components': {
                    'database': 'connected' if db_ok else 'disconnected',
                    'redis': 'connected' if redis_ok else 'disconnected',
                    'nacos': 'connected' if nacos_ok else 'disconnected'
                },
                'supported_formats': self.config.get('supported_formats', SUPPORTED_FORMATS)
            })

        @self.app.route('/api/agent/system/connections', methods=['GET'])
        def get_connection():
            """获取连接状态"""
            results = ConnectionChecker.check_all_connections(self.config)

            return jsonify({
                'timestamp': datetime.now().isoformat(),
                'connections': {
                    'database': {
                        'status': 'connected' if results['database'][0] else 'disconnected',
                        'message': results['database'][1],
                        'type': self.config['database'].get('type', 'sqlite')
                    },
                    'nacos': {
                        'status': 'connected' if results['nacos'][0] else 'disconnected',
                        'message': results['nacos'][1]
                    },
                    'redis': {
                        'status': 'connected' if results['redis'][0] else 'disabled',
                        'message': results['redis'][1],
                        'enabled': self.config.get('redis_enabled', True)
                    }
                },
                'supported_formats': self.config.get('supported_formats', SUPPORTED_FORMATS)
            })

        @self.app.route('/api/agent/projects', methods=['GET'])
        def list_projects():
            projects = self.agent_manager.list_projects()
            return jsonify({
                'projects': projects,
                'total': len(projects)
            })

        @self.app.route('/api/agent/agents', methods=['GET'])
        def list_agents():
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 20))
            project_id = request.args.get('project_id')

            # project_id is required
            if not project_id:
                return jsonify({'error': 'project_id parameter is required'}), 400

            agents, total = self.agent_manager.list_agents(page, per_page, project_id)
            return jsonify({
                'agents': agents,
                'page': page,
                'per_page': per_page,
                'total': total,
                'project_id': project_id
            })

        @self.app.route('/api/agent/agents/refresh', methods=['POST'])
        def refresh_agents():
            self.agent_manager.refresh_agents()
            return jsonify({'message': 'Agent列表刷新完成'})

        # 在_register_routes方法中添加以下路由
        @self.app.route('/api/agent/agents/cleanup', methods=['POST'])
        def cleanup_offline_agents():
            """清除指定project下掉线的agent"""
            try:
                # 获取清理参数
                data = request.get_json() or {}
                project_id = data.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                dry_run = data.get('dry_run', False)  # 是否模拟运行
                force = data.get('force', False)      # 是否强制清理（不检查时间）

                # 先获取统计信息（按project过滤）
                offline_count, total_count = self.agent_manager.get_offline_agents_count(project_id)

                if offline_count == 0:
                    return jsonify({
                        'message': '没有需要清理的掉线agent',
                        'offline_count': 0,
                        'total_count': total_count,
                        'project_id': project_id,
                        'timestamp': datetime.now().isoformat()
                    })

                if dry_run:
                    # 模拟运行，只返回统计信息
                    return jsonify({
                        'message': f'模拟清理：找到 {offline_count} 个掉线agent（超过5分钟未更新）',
                        'dry_run': True,
                        'offline_count': offline_count,
                        'total_count': total_count,
                        'would_clean': True,
                        'project_id': project_id,
                        'timestamp': datetime.now().isoformat()
                    })

                # 执行清理操作（按project过滤）
                success, message, cleanup_info = self.agent_manager.cleanup_offline_agents(project_id)

                if success:
                    return jsonify({
                        'message': message,
                        'success': True,
                        'cleanup_info': cleanup_info,
                        'offline_count_before': offline_count,
                        'total_count_before': total_count,
                        'project_id': project_id,
                        'timestamp': datetime.now().isoformat()
                    })
                else:
                    return jsonify({
                        'error': message,
                        'success': False,
                        'project_id': project_id,
                        'timestamp': datetime.now().isoformat()
                    }), 500

            except Exception as e:
                self.logger.error(f"清理掉线agent API失败: {str(e)}", exc_info=True)
                return jsonify({
                    'error': '清理操作失败',
                    'message': str(e),
                    'timestamp': datetime.now().isoformat()
                }), 500

        @self.app.route('/api/agent/agents/stats', methods=['GET'])
        def get_agent_stats():
            """获取agent统计信息"""
            try:
                # Get project_id from query parameter
                project_id = request.args.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400

                # 获取各种状态的agent数量 (filtered by project_id)
                if self.db_manager.db_type == 'mysql':
                    status_stats = self.db_manager.fetch_all('''
                                                             SELECT
                                                                 status,
                                                                 COUNT(*) as count,
                            MAX(last_seen) as last_seen_max,
                            MIN(last_seen) as last_seen_min
                                                             FROM secflow_agent_agent_status
                                                             WHERE project_id = %s
                                                             GROUP BY status
                                                             ORDER BY count DESC
                                                             ''', (project_id,))
                else:
                    status_stats = self.db_manager.fetch_all('''
                                                             SELECT
                                                                 status,
                                                                 COUNT(*) as count,
                            MAX(last_seen) as last_seen_max,
                            MIN(last_seen) as last_seen_min
                                                             FROM secflow_agent_agent_status
                                                             WHERE project_id = ?
                                                             GROUP BY status
                                                             ORDER BY count DESC
                                                             ''', (project_id,))

                # 计算掉线agent（超过5分钟未更新）for this project
                if self.db_manager.db_type == 'mysql':
                    offline_result = self.db_manager.fetch_one('''
                                                               SELECT COUNT(*) as count FROM secflow_agent_agent_status
                                                               WHERE project_id = %s
                                                               AND status IN ('offline', 'error', 'timeout', 'unknown')
                                                               AND updated_at < NOW() - INTERVAL 5 MINUTE
                                                               ''', (project_id,))
                    total_result = self.db_manager.fetch_one(
                        "SELECT COUNT(*) as count FROM secflow_agent_agent_status WHERE project_id = %s",
                        (project_id,)
                    )
                else:
                    offline_result = self.db_manager.fetch_one('''
                                                               SELECT COUNT(*) as count FROM secflow_agent_agent_status
                                                               WHERE project_id = ?
                                                               AND status IN ('offline', 'error', 'timeout', 'unknown')
                                                               AND updated_at < datetime('now', '-5 minutes')
                                                               ''', (project_id,))
                    total_result = self.db_manager.fetch_one(
                        "SELECT COUNT(*) as count FROM secflow_agent_agent_status WHERE project_id = ?",
                        (project_id,)
                    )

                total_count = total_result['count'] if total_result else 0
                offline_count = offline_result['count'] if offline_result else 0

                stats = {
                    'timestamp': datetime.now().isoformat(),
                    'project_id': project_id,
                    'summary': {
                        'total_agents': total_count,
                        'offline_agents': offline_count,
                        'status_distribution': {
                            item['status']: item['count'] for item in status_stats
                        }
                    },
                    'status_details': status_stats,
                    'cleanup_info': {
                        'can_cleanup': offline_count > 0,
                        'offline_count': offline_count,
                        'suggested_action': 'POST /api/agent/agents/cleanup 清理掉线agent'
                    }
                }

                return jsonify(stats)

            except Exception as e:
                self.logger.error(f"获取agent统计信息失败: {str(e)}")
                return jsonify({
                    'error': '获取统计信息失败',
                    'message': str(e)
                }), 500

        @self.app.route('/api/agent/agents/<agent_key>/status', methods=['PUT'])
        def update_secflow_agent_agent_status(agent_key):
            """手动更新agent状态"""
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': '请求体必须为JSON'}), 400

                status = data.get('status')
                if status not in ['online', 'offline', 'error', 'timeout', 'unknown']:
                    return jsonify({'error': '无效的状态值'}), 400

                # Get project_id from request body
                project_id = data.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400

                # 检查agent是否存在
                if self.db_manager.db_type == 'mysql':
                    agent = self.db_manager.fetch_one(
                        "SELECT * FROM secflow_agent_agent_status WHERE agent_key = %s",
                        (agent_key,)
                    )
                else:
                    agent = self.db_manager.fetch_one(
                        "SELECT * FROM secflow_agent_agent_status WHERE agent_key = ?",
                        (agent_key,)
                    )

                if not agent:
                    return jsonify({'error': f'Agent {agent_key} 不存在'}), 404

                # Verify the agent belongs to the requested project
                if agent.get('project_id') != project_id:
                    return jsonify({'error': f'Agent {agent_key} does not belong to project {project_id}'}), 403

                # 更新agent状态
                if self.db_manager.db_type == 'mysql':
                    self.db_manager.execute_query('''
                                                  UPDATE secflow_agent_agent_status
                                                  SET status = %s, updated_at = NOW()
                                                  WHERE agent_key = %s
                                                  ''', (status, agent_key))
                else:
                    self.db_manager.execute_query('''
                                                  UPDATE secflow_agent_agent_status
                                                  SET status = ?, updated_at = datetime('now')
                                                  WHERE agent_key = ?
                                                  ''', (status, agent_key))

                # 更新内存中的agent状态
                agent_info = self.agent_manager.get_agent(agent_key)
                if agent_info:
                    agent_info.status = status
                    agent_info.last_seen = datetime.now()

                self.logger.info(f"手动更新agent {agent_key} 状态为 {status}")

                return jsonify({
                    'message': f'Agent {agent_key} 状态已更新为 {status}',
                    'agent_key': agent_key,
                    'project_id': project_id,
                    'new_status': status,
                    'updated_at': datetime.now().isoformat(),
                    'updated_by': 'system'
                })

            except Exception as e:
                self.logger.error(f"更新agent状态失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/task', methods=['GET'])
        def list_tasks():
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 20))
            task_type = request.args.get('type')
            status = request.args.get('status')
            project_id = request.args.get('project_id')
            agent_key = request.args.get('agent_key')

            # project_id is required
            if not project_id:
                return jsonify({'error': 'project_id parameter is required'}), 400

            tasks, total = self.task_manager.list_tasks(
                page, per_page, task_type, status, project_id, agent_key
            )

            return jsonify({
                'secflow_agent_tasks': tasks,
                'page': page,
                'per_page': per_page,
                'total': total,
                'project_id': project_id
            })

        @self.app.route('/api/agent/task/<task_id>', methods=['GET'])
        def get_task(task_id):
            # Get project_id from query parameter
            project_id = request.args.get('project_id')
            if not project_id:
                return jsonify({'error': 'project_id parameter is required'}), 400

            task = self.task_manager.get_task(task_id)
            if not task:
                return jsonify({'error': '任务不存在'}), 404

            # Verify the task belongs to the requested project
            if task.get('project_id') != project_id:
                return jsonify({'error': f'Task {task_id} does not belong to project {project_id}'}), 403

            # Include project_id in response
            task['requested_project_id'] = project_id
            return jsonify(task)

        @self.app.route('/api/agent/task/<task_id>/logs', methods=['GET'])
        def get_secflow_agent_task_logs(task_id):
            # Get project_id from query parameter
            project_id = request.args.get('project_id')
            if not project_id:
                return jsonify({'error': 'project_id parameter is required'}), 400

            # Verify the task belongs to the requested project
            task = self.task_manager.get_task(task_id)
            if not task:
                return jsonify({'error': '任务不存在'}), 404
            if task.get('project_id') != project_id:
                return jsonify({'error': f'Task {task_id} does not belong to project {project_id}'}), 403

            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 100))

            logs, total = self.task_manager.get_secflow_agent_task_logs(task_id, page, per_page)

            return jsonify({
                'logs': logs,
                'task_id': task_id,
                'project_id': project_id,
                'page': page,
                'per_page': per_page,
                'total': total
            })

        @self.app.route('/api/agent/task/<task_id>', methods=['DELETE'])
        def delete_task(task_id):
            # Get project_id from query parameter
            project_id = request.args.get('project_id')
            if not project_id:
                return jsonify({'error': 'project_id parameter is required'}), 400

            # Verify the task belongs to the requested project
            task = self.task_manager.get_task(task_id)
            if not task:
                return jsonify({'error': '任务不存在'}), 404
            if task.get('project_id') != project_id:
                return jsonify({'error': f'Task {task_id} does not belong to project {project_id}'}), 403

            if self.task_manager.delete_task(task_id):
                return jsonify({
                    'message': '任务删除成功',
                    'task_id': task_id,
                    'project_id': project_id
                })
            else:
                return jsonify({'error': '任务删除失败'}), 500

        @self.app.route('/api/agent/task/deploy', methods=['POST'])
        def deploy_service():
            data = request.get_json()
            if not data or 'service_name' not in data or 'agent_key' not in data or 'template_name' not in data:
                return jsonify({'error': '服务名称、Agent和模板名称不能为空'}), 400

            project_id = data.get('project_id')
            if not project_id:
                return jsonify({'error': 'project_id不能为空'}), 400

            # Validate that agent belongs to the project
            agent = self.agent_manager.get_agent(data['agent_key'])
            if not agent:
                return jsonify({'error': f"Agent {data['agent_key']} 不存在"}), 404
            if agent.project_id != project_id:
                return jsonify({'error': f"Agent {data['agent_key']} 不属于项目 {project_id}"}), 403

            task_id = self.task_manager.create_task(
                'deploy', data['service_name'], data['agent_key'],
                data['template_name'], data.get('extra_params'), project_id
            )

            return jsonify({
                'task_id': task_id,
                'message': '部署任务已创建',
                'project_id': project_id
            }), 202

        @self.app.route('/api/agent/task/undeploy', methods=['POST'])
        def undeploy_service():
            data = request.get_json()
            if not data or 'service_name' not in data or 'agent_key' not in data:
                return jsonify({'error': '服务名称和Agent不能为空'}), 400

            project_id = data.get('project_id')
            if not project_id:
                return jsonify({'error': 'project_id不能为空'}), 400

            # Validate that agent belongs to the project
            agent = self.agent_manager.get_agent(data['agent_key'])
            if not agent:
                return jsonify({'error': f"Agent {data['agent_key']} 不存在"}), 404
            if agent.project_id != project_id:
                return jsonify({'error': f"Agent {data['agent_key']} 不属于项目 {project_id}"}), 403

            task_id = self.task_manager.create_task(
                'undeploy', data['service_name'], data['agent_key'],
                None, None, project_id
            )

            return jsonify({
                'task_id': task_id,
                'message': '卸载任务已创建',
                'project_id': project_id
            }), 202

        # ===================== 代理路由（修复版，支持长超时） =====================
        @self.app.route('/api/agent/proxy/<agent_key>/<path:action_path>',
                        methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
        def proxy_to_agent(agent_key, action_path):
            """将请求代理到指定的Agent（修复版，支持长超时）"""
            try:
                # 获取请求方法
                method = request.method
        
                # 获取查询参数
                query_params = {}
                for key, value in request.args.items():
                    if key not in query_params:
                        query_params[key] = value
                    elif isinstance(query_params[key], list):
                        query_params[key].append(value)
                    else:
                        query_params[key] = [query_params[key], value]
        
                # 获取请求头（过滤敏感头）
                headers_to_forward = {}
                exclude_headers = [
                    'host', 'authorization', 'cookie', 'connection',
                    'content-length', 'content-type', 'accept-encoding',
                    'accept', 'user-agent'
                ]
        
                for key, value in request.headers:
                    key_lower = key.lower()
                    if key_lower not in exclude_headers:
                        headers_to_forward[key] = value
        
                # 处理请求数据 - 修复JSON解析问题
                request_data = None
                files_to_forward = {}
        
                content_type = request.headers.get('Content-Type', '').lower()
        
                # 检查是否是文件上传
                if 'multipart/form-data' in content_type and request.files:
                    # 处理文件上传
                    for key, file_storage in request.files.items():
                        file_content = file_storage.read()
                        files_to_forward[key] = (
                            file_storage.filename,
                            file_content,
                            file_storage.content_type
                        )
                        file_storage.seek(0)
        
                    # 处理普通表单字段
                    if request.form:
                        request_data = dict(request.form)
        
                # 检查是否有JSON数据
                elif 'application/json' in content_type:
                    # 安全地解析JSON，避免空请求体错误
                    if request.data:
                        try:
                            request_data = request.get_json()
                        except Exception as e:
                            self.logger.warning(f"JSON解析失败，使用原始数据: {e}")
                            try:
                                # 尝试直接解析
                                request_data = json.loads(request.data.decode('utf-8'))
                            except:
                                request_data = request.data.decode('utf-8')
        
                # 检查普通表单数据
                elif request.form:
                    request_data = dict(request.form)
        
                # 检查原始数据
                elif request.data:
                    try:
                        request_data = json.loads(request.data.decode('utf-8'))
                    except:
                        request_data = request.data.decode('utf-8')
        
                # 检查是否是流式请求
                stream = request.args.get('stream', '').lower() == 'true'
        
                # 构建endpoint
                if not action_path.startswith('/'):
                    action_path = '/' + action_path
        
                # 设置超时时间（优先使用查询参数中的timeout，否则使用默认）
                timeout = request.args.get('timeout', None)
                if timeout is not None:
                    try:
                        timeout = int(timeout)
                    except:
                        timeout = None
        
                # 调用代理管理器
                status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                    agent_key=agent_key,
                    method=method,
                    endpoint=action_path,
                    request_data=request_data,
                    query_params=query_params,
                    headers=headers_to_forward,
                    files=files_to_forward if files_to_forward else None,
                    stream=stream,
                    timeout=timeout
                )
        
                # 处理流式响应
                if stream and isinstance(response_data, bytes):
                    response = self.app.response_class(
                        response_data,
                        status=status_code,
                        headers=response_headers,
                        mimetype=response_headers.get('Content-Type', 'application/octet-stream')
                    )
                    return response
        
                # 构建普通响应
                if isinstance(response_data, bytes):
                    response = self.app.response_class(
                        response_data,
                        status=status_code,
                        headers=response_headers
                    )
                    return response
                elif isinstance(response_data, str):
                    response = self.app.response_class(
                        response_data,
                        status=status_code,
                        headers=response_headers,
                        content_type='text/plain'
                    )
                    return response
                else:
                    response = jsonify(response_data)
                    response.status_code = status_code
                    for key, value in response_headers.items():
                        if key.lower() == 'Content-Length'.lower():
                            continue
                        response.headers[key] = value
        
                    return response
        
            except Exception as e:
                self.logger.error(f"代理路由处理失败: {str(e)}", exc_info=True)
                return jsonify({
                    'error': 'Proxy request failed',
                    'message': str(e),
                    'timestamp': datetime.now().isoformat(),
                    'agent_key': agent_key,
                    'action_path': action_path
                }), 500
        # 简单代理端点 - 专门用于GET请求
        @self.app.route('/api/agent/proxy_simple/<agent_key>/<path:action_path>', methods=['GET'])
        def proxy_simple_to_agent(agent_key, action_path):
            """简单代理到指定的Agent（仅GET请求）"""
            try:
                # 获取Agent信息
                agent = self.agent_manager.get_agent(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404

                if not action_path.startswith('/'):
                    action_path = '/' + action_path

                # 构建URL
                url = f"http://{agent.ip_address}:{self.agent_manager.agent_api_port}{action_path}"

                # 发送GET请求
                response = requests.get(
                    url,
                    headers={'X-Auth-Token': self.agent_manager.agent_auth_token},
                    params=request.args,
                    timeout=10,
                    verify=False
                )

                # 处理响应
                try:
                    data = response.json()
                except:
                    data = {'content': response.text}

                return jsonify({
                    'status_code': response.status_code,
                    'data': data,
                    'agent': {
                        'key': agent_key,
                        'hostname': agent.hostname,
                        'ip': agent.ip_address
                    }
                })

            except Exception as e:
                self.logger.error(f"简单代理失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/<path:action_path>',
                        methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
        def agent_proxy_simple(agent_key, action_path):
            """简化版代理路由，自动添加/api前缀"""
            # 确保action_path以/开头
            if not action_path.startswith('/'):
                action_path = '/' + action_path

            # 添加/api前缀（如果还没有）
            if not action_path.startswith('/api/'):
                action_path = '/api' + action_path

            # 重定向到通用代理
            return proxy_to_agent(agent_key, action_path)

        @self.app.route('/api/agent/agent/<agent_key>/system/info', methods=['GET'])
        def agent_system_info(agent_key):
            """获取Agent的系统信息（快捷方式）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint='/api/system/info'
            )

            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'Content-Length'.lower():
                    continue
                response.headers[key] = value
            response.status_code = status_code

            return response

        @self.app.route('/api/agent/agent/<agent_key>/services', methods=['GET'])
        def agent_services(agent_key):
            """获取Agent的服务列表（快捷方式）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint='/api/services'
            )

            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'Content-Length'.lower():
                    continue
                response.headers[key] = value
            response.status_code = status_code

            return response

        # 代理调试端点
        @self.app.route('/api/agent/proxy/debug/<agent_key>', methods=['GET'])
        def debug_agent_proxy(agent_key):
            """调试Agent代理连接"""
            try:
                agent = self.agent_manager.get_agent(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404

                # 测试多个端点
                endpoints_to_test = [
                    '/api/health',
                    '/api/system/info',
                    '/api/system/metrics',
                    '/api/services'
                ]

                results = []

                for endpoint in endpoints_to_test:
                    try:
                        url = f"http://{agent.ip_address}:{self.agent_manager.agent_api_port}{endpoint}"
                        response = requests.get(
                            url,
                            headers={'X-Auth-Token': self.agent_manager.agent_auth_token},
                            timeout=5,
                            verify=False
                        )

                        results.append({
                            'endpoint': endpoint,
                            'status_code': response.status_code,
                            'response_time': f"{response.elapsed.total_seconds() * 1000:.2f}ms",
                            'success': response.status_code == 200
                        })
                    except Exception as e:
                        results.append({
                            'endpoint': endpoint,
                            'status_code': 0,
                            'error': str(e),
                            'success': False
                        })

                # 总结
                success_count = sum(1 for r in results if r['success'])

                return jsonify({
                    'agent': {
                        'key': agent_key,
                        'hostname': agent.hostname,
                        'ip_address': agent.ip_address,
                        'status': agent.status,
                        'last_seen': agent.last_seen.isoformat() if agent.last_seen else None
                    },
                    'test_results': results,
                    'summary': {
                        'total_tests': len(results),
                        'successful_tests': success_count,
                        'success_rate': f"{(success_count / len(results)) * 100:.1f}%",
                        'agent_available': success_count > 0
                    }
                })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/health', methods=['GET'])
        def agent_health(agent_key):
            """获取Agent的健康状态（快捷方式）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint='/api/health'
            )

            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'Content-Length'.lower():
                    continue
                response.headers[key] = value
            response.status_code = status_code

            return response

        @self.app.route('/api/agent/proxy/info', methods=['GET'])
        def get_proxy_info():
            """获取代理API信息"""
            # 获取可用的Agent列表
            agents = self.agent_manager.list_agents()[0]

            proxy_info = {
                'available_agents': [
                    {
                        'key': agent['key'],
                        'hostname': agent['hostname'],
                        'ip_address': agent['ip_address'],
                        'project': agent['project_id'],
                        'status': agent['status'],
                        'last_seen': agent.get('last_seen')
                    }
                    for agent in agents
                ],
                'supported_formats': self.config.get('supported_formats', SUPPORTED_FORMATS)
            }

            return jsonify(proxy_info)

        @self.app.route('/api/agent/proxy/test/<agent_key>', methods=['GET'])
        def test_proxy_connection(agent_key):
            """测试代理连接"""
            try:
                # 首先尝试直接调用Agent的健康检查
                status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                    agent_key=agent_key,
                    method='GET',
                    endpoint='/api/health'
                )

                agent = self.agent_manager.get_agent(agent_key)
                agent_info = agent.to_dict() if agent else None

                return jsonify({
                    'agent_key': agent_key,
                    'connection_test': 'success' if status_code == 200 else 'failed',
                    'status_code': status_code,
                    'response': response_data,
                    'agent_info': agent_info,
                    'timestamp': datetime.now().isoformat()
                })

            except Exception as e:
                return jsonify({
                    'agent_key': agent_key,
                    'connection_test': 'failed',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }), 500

        @self.app.route('/api/agent/agents/<agent_key>', methods=['GET'])
        def get_agent_by_key(agent_key):
            """根据agent_key获取Agent信息"""
            try:
                # Get project_id from query parameter
                project_id = request.args.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400

                # 从数据库查询Agent
                if self.db_manager.db_type == 'mysql':
                    agent_data = self.db_manager.fetch_one(
                        "SELECT * FROM secflow_agent_agent_status WHERE agent_key = %s",
                        (agent_key,)
                    )
                else:
                    agent_data = self.db_manager.fetch_one(
                        "SELECT * FROM secflow_agent_agent_status WHERE agent_key = ?",
                        (agent_key,)
                    )

                if not agent_data:
                    # 尝试从内存中获取
                    agent = self.agent_manager.get_agent(agent_key)
                    if agent:
                        agent_data = agent.to_dict()
                    else:
                        return jsonify({'error': f'Agent {agent_key} not found'}), 404
                else:
                    # 转换数据格式
                    agent_data = {
                        'key': agent_data['agent_key'],
                        'ip_address': agent_data['ip_address'],
                        'hostname': agent_data['hostname'],
                        'project_id': agent_data['project_id'],
                        'full_name': agent_data['full_name'],
                        'status': agent_data['status'],
                        'pod_id': agent_data['pod_id']
                    }

                # Verify the agent belongs to the requested project
                if agent_data.get('project_id') != project_id:
                    return jsonify({'error': f'Agent {agent_key} does not belong to project {project_id}'}), 403

                # Add additional fields if from database
                if 'last_seen' in agent_data:
                    pass
                else:
                    # Fetch from database for additional fields
                    if self.db_manager.db_type == 'mysql':
                        full_data = self.db_manager.fetch_one(
                            "SELECT * FROM secflow_agent_agent_status WHERE agent_key = %s",
                            (agent_key,)
                        )
                    else:
                        full_data = self.db_manager.fetch_one(
                            "SELECT * FROM secflow_agent_agent_status WHERE agent_key = ?",
                            (agent_key,)
                        )
                    if full_data:
                        if full_data['last_seen']:
                            if isinstance(full_data['last_seen'], str):
                                agent_data['last_seen'] = full_data['last_seen']
                            else:
                                agent_data['last_seen'] = full_data['last_seen'].isoformat()

                        if full_data['system_info']:
                            if isinstance(full_data['system_info'], str):
                                try:
                                    agent_data['system_info'] = json.loads(full_data['system_info'])
                                except:
                                    agent_data['system_info'] = full_data['system_info']
                            else:
                                agent_data['system_info'] = full_data['system_info']

                        if full_data['services']:
                            if isinstance(full_data['services'], str):
                                try:
                                    agent_data['services'] = json.loads(full_data['services'])
                                except:
                                    agent_data['services'] = full_data['services']
                            else:
                                agent_data['services'] = full_data['services']

                # Include project_id in response
                agent_data['requested_project_id'] = project_id

                return jsonify(agent_data)

            except Exception as e:
                self.logger.error(f"获取Agent信息失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        # 在_register_routes方法中添加示例文档端点
        @self.app.route('/api/agent/proxy/examples', methods=['GET'])
        def get_proxy_examples():
            """获取代理使用示例"""
            examples = {
                'description': '代理API允许通过Server访问Agent的所有API',
                'basic_usage': {
                    'pattern': '/api/proxy/{agent_key}/{action_path}',
                    'methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
                    'note': 'action_path可以是任意路径，包括多层路径'
                },
                'simple_usage': {
                    'pattern': '/api/agent/{agent_key}/{action_path}',
                    'methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
                    'note': '自动添加/api前缀，action_path不需要包含/api'
                },
                'quick_access': {
                    '/api/agent/{agent_key}/system/info': 'GET - 获取Agent系统信息',
                    '/api/agent/{agent_key}/services': 'GET - 获取Agent服务列表',
                    '/api/agent/{agent_key}/health': 'GET - 检查Agent健康状态'
                },
                'examples': [
                    {
                        'description': '获取Agent系统信息',
                        'method': 'GET',
                        'url': '/api/agent/proxy/abc123def456/api/system/info',
                        'curl': 'curl -X GET -H "Authorization: Bearer YOUR_TOKEN" http://server:18080/api/agent/proxy/abc123def456/api/system/info'
                    },
                    {
                        'description': '获取Agent服务列表',
                        'method': 'GET',
                        'url': '/api/agent/proxy/abc123def456/api/services',
                        'curl': 'curl -X GET -H "Authorization: Bearer YOUR_TOKEN" http://server:18080/api/agent/proxy/abc123def456/api/services'
                    },
                    {
                        'description': '启动Agent上的服务',
                        'method': 'POST',
                        'url': '/api/agent/proxy/abc123def456/api/services/myservice/start',
                        'curl': 'curl -X POST -H "Authorization: Bearer YOUR_TOKEN" http://server:18080/api/agent/proxy/abc123def456/api/services/myservice/start'
                    },
                    {
                        'description': '获取服务日志',
                        'method': 'GET',
                        'url': '/api/agent/proxy/abc123def456/api/services/myservice/logs?tail=100',
                        'curl': 'curl -X GET -H "Authorization: Bearer YOUR_TOKEN" "http://server:18080/api/agent/proxy/abc123def456/api/services/myservice/logs?tail=100"'
                    },
                    {
                        'description': '上传压缩文件创建服务',
                        'method': 'POST',
                        'url': '/api/agent/proxy/abc123def456/api/services/zip',
                        'content_type': 'multipart/form-data',
                        'form_data': {
                            'name': 'myapp',
                            'file': 'myapp.zip'  # 支持多种压缩格式
                        },
                        'curl': 'curl -X POST -H "Authorization: Bearer YOUR_TOKEN" -F "name=myapp" -F "file=@myapp.zip" http://server:18080/api/agent/proxy/abc123def456/api/services/zip'
                    },
                    {
                        'description': '从YAML创建服务',
                        'method': 'POST',
                        'url': '/api/agent/proxy/abc123def456/api/services/yaml',
                        'content_type': 'application/json',
                        'body': {
                            'name': 'myservice',
                            'yaml': 'version: "3"\nservices:\n  web:\n    image: nginx:latest'
                        },
                        'curl': 'curl -X POST -H "Authorization: Bearer YOUR_TOKEN" -H "Content-Type: application/json" -d \'{"name":"myservice","yaml":"version: \\"3\\"\\nservices:\\n  web:\\n    image: nginx:latest"}\' http://server:18080/api/agent/proxy/abc123def456/api/services/yaml'
                    }
                ],
                'tips': [
                    '使用 /api/agent/proxy/info 获取所有可用Agent',
                    '使用 /api/agent/proxy/test/{agent_key} 测试代理连接',
                    '文件上传需要设置 Content-Type: multipart/form-data',
                    '支持流式响应，添加 ?stream=true 参数',
                    '所有原始请求头（除敏感头外）都会转发到Agent',
                    f'支持多种压缩格式: {", ".join(self.config.get("supported_formats", SUPPORTED_FORMATS))}'
                ]
            }

            return jsonify(examples)

        # ===================== 模板管理API（完整版，支持多种压缩格式） =====================

        @self.app.route('/api/agent/templates', methods=['GET'])
        def list_templates():
            """列出所有模板（包含文件大小信息）"""
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 20))

            templates, total = self.template_manager.list_templates(page, per_page)
            return jsonify({
                'templates': templates,
                'page': page,
                'per_page': per_page,
                'total': total,
                'supported_formats': self.config.get('supported_formats', SUPPORTED_FORMATS)
            })

        @self.app.route('/api/agent/templates', methods=['POST'])
        def upload_template():
            """上传模板（支持多种压缩格式）"""
            if 'file' not in request.files:
                return jsonify({'error': '未找到文件'}), 400

            file = request.files['file']
            name = request.form.get('name')
            description = request.form.get('description', '')
            template_type = request.form.get('type', 'auto')  # 默认为自动检测

            if not name:
                return jsonify({'error': '模板名称不能为空'}), 400

            if not file.filename:
                return jsonify({'error': '文件名不能为空'}), 400

            # 检查文件扩展名
            filename = file.filename
            file_ext = Path(filename).suffix.lower()

            # 自动检测模板类型
            if template_type == 'auto':
                if file_ext in ['.yaml', '.yml']:
                    template_type = 'yaml'
                elif any(filename.lower().endswith(ext) for ext in self.config.get('supported_formats', SUPPORTED_FORMATS)):
                    template_type = 'archive'
                else:
                    return jsonify({'error': f'不支持的文件格式: {filename}'}), 400

            # 验证压缩格式
            if template_type == 'archive':
                is_supported = False
                for ext in self.config.get('supported_formats', SUPPORTED_FORMATS):
                    if filename.lower().endswith(ext):
                        is_supported = True
                        break

                if not is_supported:
                    return jsonify({
                        'error': f'不支持的压缩格式: {filename}',
                        'supported_formats': self.config.get('supported_formats', SUPPORTED_FORMATS)
                    }), 400

            # 读取文件内容
            file_content = file.read()

            # 获取当前用户
            success, message = self.template_manager.create_template(
                name, description, template_type, file_content, filename,
                'system'
            )

            if success:
                return jsonify({
                    'message': message,
                    'template_name': name,
                    'template_type': template_type,
                    'filename': filename
                }), 201
            else:
                return jsonify({'error': message}), 400

        @self.app.route('/api/agent/templates/<name>', methods=['GET'])
        def get_template_detail(name):
            """获取模板详细信息（包含文件大小）"""
            template = self.template_manager.get_template(name)

            if template:
                # 获取文件详细信息
                file_info = self.template_manager.get_template_file_info(name)
                if file_info:
                    template['file_info'] = file_info

                # 获取目录中的文件列表
                template_dir = self.template_manager.templates_root / name
                if template_dir.exists():
                    files = []
                    for file_path in template_dir.rglob('*'):
                        if file_path.is_file():
                            file_stat = file_path.stat()
                            files.append({
                                'name': file_path.name,
                                'path': str(file_path.relative_to(template_dir)),
                                'size': file_stat.st_size,
                                'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                            })
                    template['directory_files'] = files

                return jsonify(template)
            else:
                return jsonify({'error': '模板不存在'}), 404

        @self.app.route('/api/agent/templates/<name>/yaml', methods=['GET'])
        def get_template_yaml(name):
            """获取模板的YAML内容"""
            success, content, message = self.template_manager.get_yaml_content(name)

            if success:
                return jsonify({
                    'name': name,
                    'yaml_content': content,
                    'status': 'success'
                })
            else:
                return jsonify({
                    'error': content,
                    'details': message,
                    'status': 'failed'
                }), 400

        @self.app.route('/api/agent/templates/<name>/yaml', methods=['PUT'])
        def update_template_yaml(name):
            """更新模板的YAML内容"""
            data = request.get_json()
            if not data:
                return jsonify({'error': '请求体必须为JSON'}), 400

            yaml_content = data.get('yaml_content')
            if not yaml_content:
                return jsonify({'error': 'YAML内容不能为空'}), 400

            success, message = self.template_manager.update_yaml_content(
                name, yaml_content, 'system'
            )

            if success:
                # 返回更新后的模板信息
                template = self.template_manager.get_template(name)
                return jsonify({
                    'message': message,
                    'template': template,
                    'status': 'success'
                })
            else:
                return jsonify({'error': message}), 400

        @self.app.route('/api/agent/templates/<name>/download', methods=['GET'])
        def download_template(name):
            """下载模板文件"""
            try:
                format_param = request.args.get('format', 'original')
                as_zip = request.args.get('as_zip', '').lower() == 'true'
                include_all = request.args.get('include_all', 'true').lower() == 'true'
                disposition = request.args.get('disposition', 'attachment')

                self.logger.info(f"下载模板请求: {name}, format={format_param}, as_zip={as_zip}")

                # 检查模板是否存在
                template = self.template_manager.get_template(name)
                if not template:
                    return jsonify({'error': f'模板 {name} 不存在'}), 404

                # 处理下载请求
                if as_zip:
                    # 下载为ZIP包（包含所有文件）
                    success, content, content_type = self.template_manager.get_template_as_zip(
                        name, include_all
                    )
                    filename = f"{name}.zip"
                else:
                    # 根据指定格式下载
                    export_format = format_param
                    if export_format == 'original':
                        export_format = template['type']

                    success, content, content_type, filename = self.template_manager.export_template(
                        name, export_format
                    )

                if not success:
                    return jsonify({'error': content}), 400

                # 设置响应头
                response_headers = {
                    'Content-Type': content_type,
                    'Content-Disposition': f'{disposition}; filename="{filename}"',
                    'X-Template-Name': name,
                    'X-Template-Type': template['type'],
                    'X-File-Size': str(len(content) if isinstance(content, bytes) else 0)
                }

                # 创建响应
                response = self.app.response_class(
                    response=content,
                    status=200,
                    headers=response_headers
                )

                self.logger.info(f"模板下载成功: {name}, 文件大小: {len(content) if isinstance(content, bytes) else 'N/A'} 字节")

                return response

            except Exception as e:
                self.logger.error(f"模板下载失败: {str(e)}", exc_info=True)
                return jsonify({'error': f'下载失败: {str(e)}'}), 500

        @self.app.route('/api/agent/templates/<name>/file', methods=['GET'])
        def get_template_file(name):
            """获取模板原始文件"""
            try:
                file_info = self.template_manager.get_template_file_info(name)

                if not file_info:
                    return jsonify({'error': f'模板 {name} 不存在或文件已丢失'}), 404

                file_path = Path(file_info['file_path'])

                if not file_path.exists():
                    return jsonify({'error': '模板文件不存在'}), 404

                # 设置内容类型
                if file_info['type'] == 'yaml':
                    mimetype = 'text/yaml'
                    as_attachment = False
                elif file_info['type'] == 'archive':
                    mimetype = self.template_manager._get_content_type(file_path.name)
                    as_attachment = True
                else:
                    mimetype = 'application/octet-stream'
                    as_attachment = True

                # 确定文件名
                if as_attachment:
                    filename = f"{name}{Path(file_path).suffix}"
                else:
                    filename = None

                self.logger.info(f"发送模板文件: {name}, 路径: {file_path}")

                return send_file(
                    file_path,
                    mimetype=mimetype,
                    as_attachment=as_attachment,
                    download_name=filename
                )

            except Exception as e:
                self.logger.error(f"获取模板文件失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/templates/<name>/content', methods=['GET'])
        def get_template_content(name):
            """获取模板内容（JSON格式）"""
            try:
                template = self.template_manager.get_template(name)

                if not template:
                    return jsonify({'error': f'模板 {name} 不存在'}), 404

                success, content, content_type = self.template_manager.get_template_file_content(
                    name, 'bytes'
                )

                if not success:
                    return jsonify({'error': content}), 400

                # 编码内容
                if template['type'] == 'yaml':
                    content_str = content.decode('utf-8')
                    encoded_content = content_str
                    encoding = 'utf-8'
                else:
                    encoded_content = base64.b64encode(content).decode('utf-8')
                    encoding = 'base64'

                return jsonify({
                    'name': name,
                    'type': template['type'],
                    'content_type': content_type,
                    'content_encoding': encoding,
                    'content': encoded_content,
                    'size': len(content),
                    'file_size': template.get('file_size', 0),
                    'directory_size': template.get('directory_size', 0),
                    'created_at': template.get('created_at'),
                    'updated_at': template.get('updated_at')
                })

            except Exception as e:
                self.logger.error(f"获取模板内容失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/templates/<name>/info', methods=['GET'])
        def get_template_info(name):
            """获取模板详细信息（包含文件列表）"""
            try:
                template = self.template_manager.get_template(name)

                if not template:
                    return jsonify({'error': f'模板 {name} 不存在'}), 404

                file_info = self.template_manager.get_template_file_info(name)

                response = dict(template)

                if file_info:
                    response['file_info'] = file_info

                # 获取模板目录中的文件列表
                template_dir = self.template_manager.templates_root / name
                if template_dir.exists():
                    files = []
                    total_size = 0

                    for file_path in template_dir.rglob('*'):
                        if file_path.is_file():
                            file_stat = file_path.stat()
                            files.append({
                                'name': file_path.name,
                                'path': str(file_path.relative_to(template_dir)),
                                'size': file_stat.st_size,
                                'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                            })
                            total_size += file_stat.st_size

                    response['directory_info'] = {
                        'path': str(template_dir),
                        'total_files': len(files),
                        'total_size': total_size,
                        'files': files
                    }

                return jsonify(response)

            except Exception as e:
                self.logger.error(f"获取模板信息失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/templates/<name>', methods=['DELETE'])
        def delete_template(name):
            """删除模板"""
            success, message = self.template_manager.delete_template(name)

            if success:
                return jsonify({'message': message})
            else:
                return jsonify({'error': message}), 400

        @self.app.route('/api/agent/templates/download/batch', methods=['POST'])
        def download_templates_batch():
            """批量下载模板"""
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': '请求体必须为JSON'}), 400

                template_names = data.get('templates', [])
                format_type = data.get('format', 'original')
                include_all = data.get('include_all', True)

                if not template_names:
                    return jsonify({'error': '未指定要下载的模板'}), 400

                # 检查模板是否存在
                missing_templates = []
                for name in template_names:
                    if not self.template_manager.get_template(name):
                        missing_templates.append(name)

                if missing_templates:
                    return jsonify({
                        'error': '以下模板不存在',
                        'missing_templates': missing_templates
                    }), 400

                # 如果只有一个模板，直接下载
                if len(template_names) == 1:
                    return redirect(f'/api/templates/{template_names[0]}/download?format={format_type}&include_all={include_all}')

                # 多个模板，创建ZIP包
                zip_buffer = io.BytesIO()

                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    for name in template_names:
                        template = self.template_manager.get_template(name)
                        template_dir = self.template_manager.templates_root / name

                        if template_dir.exists():
                            for file_path in template_dir.rglob('*'):
                                if file_path.is_file():
                                    rel_path = file_path.relative_to(self.template_manager.templates_root)
                                    zip_file.write(file_path, rel_path)

                zip_content = zip_buffer.getvalue()
                zip_buffer.close()

                # 设置响应头
                response_headers = {
                    'Content-Type': 'application/zip',
                    'Content-Disposition': f'attachment; filename="templates_batch_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip"',
                    'X-Templates-Count': str(len(template_names)),
                    'X-Templates-List': ','.join(template_names)
                }

                response = self.app.response_class(
                    response=zip_content,
                    status=200,
                    headers=response_headers
                )

                self.logger.info(f"批量下载模板成功: {len(template_names)} 个模板")

                return response

            except Exception as e:
                self.logger.error(f"批量下载模板失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        # ===================== 新增：模板文件管理API =====================

        @self.app.route('/api/agent/templates/<name>/files', methods=['GET'])
        def list_template_files(name):
            """列出模板目录下的所有文件和目录"""
            path = request.args.get('path', '')

            success, result = self.template_manager.list_template_files(name, path)

            if success:
                return jsonify({
                    'template_name': name,
                    'path': path,
                    'files': result,
                    'status': 'success'
                })
            else:
                return jsonify({'error': result}), 404

        @self.app.route('/api/agent/templates/<name>/files/content', methods=['GET'])
        def get_template_file_content(name):
            """获取模板目录下指定文件的内容"""
            file_path = request.args.get('path', '')
            encoding = request.args.get('encoding', 'utf-8')
            preview = request.args.get('preview', 'false').lower() == 'true'
            max_size = int(request.args.get('max_size', 1024 * 1024))  # 默认1MB

            if not file_path:
                return jsonify({'error': '文件路径不能为空'}), 400

            success, content, content_type, file_info = self.template_manager.get_template_file_by_path(
                name, file_path, encoding
            )

            if not success:
                return jsonify({'error': content}), 404

            # 如果是预览模式且文件较大，进行截断
            if preview and isinstance(content, str) and len(content) > max_size:
                content = content[:max_size] + f"\n\n... (文件过大，已截断，完整大小: {file_info['size']} 字节)"
                file_info['truncated'] = True
                file_info['original_size'] = file_info['size']
                file_info['preview_size'] = len(content)
            elif preview and isinstance(content, bytes) and len(content) > max_size:
                # 对于二进制文件，只返回基本信息
                content = None
                file_info['binary_preview'] = True
                file_info['original_size'] = file_info['size']

            response_data = {
                'template_name': name,
                'file_info': file_info,
                'content_type': content_type,
                'is_text': file_info.get('is_text', True),
                'status': 'success'
            }

            # 根据内容类型返回不同格式
            if content is not None:
                if isinstance(content, str):
                    response_data['content'] = content
                    response_data['encoding'] = encoding
                else:
                    # 二进制内容进行base64编码
                    response_data['content'] = base64.b64encode(content).decode('ascii')
                    response_data['encoding'] = 'base64'
            else:
                response_data['content'] = None

            return jsonify(response_data)

        @self.app.route('/api/agent/templates/<name>/files/content', methods=['PUT'])
        def update_template_file_content(name):
            """更新模板目录下指定文件的内容"""
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': '请求体必须为JSON'}), 400

                file_path = data.get('path', '')
                content = data.get('content', '')
                encoding = data.get('encoding', 'utf-8')

                if not file_path:
                    return jsonify({'error': '文件路径不能为空'}), 400

                if content is None:
                    return jsonify({'error': '文件内容不能为空'}), 400

                # 处理内容编码
                actual_content = content
                content_encoding = data.get('content_encoding', '')

                if content_encoding == 'base64':
                    try:
                        actual_content = base64.b64decode(content)
                    except Exception as e:
                        return jsonify({'error': f'Base64解码失败: {str(e)}'}), 400

                # 获取当前用户
                updated_by = 'system'

                success, message, update_info = self.template_manager.update_template_file(
                    name, file_path, actual_content, encoding, updated_by
                )

                if success:
                    # 获取更新后的文件信息
                    file_success, file_content, file_content_type, file_info = self.template_manager.get_template_file_by_path(
                        name, file_path, encoding
                    )

                    response_data = {
                        'message': message,
                        'update_info': update_info,
                        'status': 'success'
                    }

                    if file_success:
                        response_data['file_info'] = file_info

                    return jsonify(response_data)
                else:
                    return jsonify({'error': message}), 400

            except Exception as e:
                self.logger.error(f"更新模板文件失败: {str(e)}", exc_info=True)
                return jsonify({'error': f'更新失败: {str(e)}'}), 500

        @self.app.route('/api/agent/templates/<name>/files/download', methods=['GET'])
        def download_template_file(name):
            """下载模板目录下的单个文件"""
            file_path = request.args.get('path', '')

            if not file_path:
                return jsonify({'error': '文件路径不能为空'}), 400

            success, content, content_type, file_info = self.template_manager.get_template_file_by_path(
                name, file_path, 'utf-8'
            )

            if not success:
                return jsonify({'error': content}), 404

            # 构建响应
            if isinstance(content, str):
                # 文本文件
                response = self.app.response_class(
                    response=content,
                    status=200,
                    mimetype=content_type,
                    headers={
                        'Content-Disposition': f'attachment; filename="{file_info["name"]}"',
                        'X-File-Path': file_path,
                        'X-Template-Name': name
                    }
                )
            else:
                # 二进制文件
                response = self.app.response_class(
                    response=content,
                    status=200,
                    mimetype=content_type,
                    headers={
                        'Content-Disposition': f'attachment; filename="{file_info["name"]}"',
                        'X-File-Path': file_path,
                        'X-Template-Name': name,
                        'X-File-Size': str(file_info['size'])
                    }
                )

            return response

        @self.app.route('/api/agent/templates/<name>/files/upload', methods=['POST'])
        def upload_template_file(name):
            """上传文件到模板目录"""
            if 'file' not in request.files:
                return jsonify({'error': '未找到文件'}), 400

            file = request.files['file']
            target_path = request.form.get('path', '')
            overwrite = request.form.get('overwrite', 'false').lower() == 'true'

            if not file.filename:
                return jsonify({'error': '文件名不能为空'}), 400

            # 如果没有指定路径，使用文件名
            if not target_path:
                target_path = file.filename

            # 获取当前用户
            updated_by = 'system'

            # 读取文件内容
            file_content = file.read()

            # 检查文件编码（尝试作为文本文件处理）
            try:
                # 尝试解码为UTF-8
                decoded_content = file_content.decode('utf-8')
                # 如果是文本文件，使用字符串
                content = decoded_content
                encoding = 'utf-8'
            except UnicodeDecodeError:
                # 如果是二进制文件，使用字节
                content = file_content
                encoding = 'binary'

            success, message, update_info = self.template_manager.update_template_file(
                name, target_path, content, encoding, updated_by
            )

            if not success and not overwrite:
                # 检查是否是文件已存在的错误
                if "already exists" in message.lower() or "文件已存在" in message:
                    return jsonify({
                        'error': '文件已存在',
                        'message': message,
                        'suggestion': '使用 overwrite=true 参数覆盖文件'
                    }), 409
                else:
                    return jsonify({'error': message}), 400

            # 如果是覆盖模式，强制更新
            if not success and overwrite:
                # 这里可以添加强制更新的逻辑
                # 目前我们假设update_template_file已经处理了覆盖
                pass

            if success:
                return jsonify({
                    'message': message,
                    'update_info': update_info,
                    'filename': file.filename,
                    'path': target_path,
                    'size': len(file_content),
                    'status': 'success'
                }), 201
            else:
                return jsonify({'error': message}), 400


        @self.app.route('/api/agent/templates/<name>/files', methods=['DELETE'])
        def delete_template_file(name):
            """删除模板目录下的指定文件"""
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': '请求体必须为JSON'}), 400

                file_path = data.get('path', '')
                if not file_path:
                    return jsonify({'error': '文件路径不能为空'}), 400

                # 获取当前用户
                deleted_by = 'system'

                success, message, delete_info = self.template_manager.delete_template_file(
                    name, file_path, deleted_by
                )

                if success:
                    return jsonify({
                        'message': message,
                        'delete_info': delete_info,
                        'status': 'success'
                    })
                else:
                    return jsonify({'error': message}), 400

            except Exception as e:
                self.logger.error(f"删除模板文件失败: {str(e)}", exc_info=True)
                return jsonify({'error': f'删除失败: {str(e)}'}), 500

        @self.app.route('/api/agent/templates/<name>/directories', methods=['DELETE'])
        def delete_template_directory(name):
            """删除模板目录下的指定目录"""
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': '请求体必须为JSON'}), 400

                dir_path = data.get('path', '')
                force = data.get('force', False)

                if len(dir_path) == 0:
                    return jsonify({'error': '目录路径不能为空'}), 400

                # 获取当前用户
                deleted_by = 'system'

                success, message, delete_info = self.template_manager.delete_template_directory(
                    name, dir_path, deleted_by, force
                )

                if success:
                    return jsonify({
                        'message': message,
                        'delete_info': delete_info,
                        'status': 'success'
                    })
                else:
                    return jsonify({'error': message}), 400

            except Exception as e:
                self.logger.error(f"删除模板目录失败: {str(e)}", exc_info=True)
                return jsonify({'error': f'删除失败: {str(e)}'}), 500



    def _refresh_loop(self):
        """后台刷新循环"""
        while not self.should_stop:
            try:
                self.agent_manager.refresh_agents()
            except Exception as e:
                self.logger.error(f"刷新Agent列表失败: {str(e)}")

            # 等待下一次刷新
            for _ in range(self.config['refresh_interval']):
                if self.should_stop:
                    break
                time.sleep(1)

    def start_refresh_thread(self):
        """启动后台刷新线程"""
        self.should_stop = False
        self.refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self.refresh_thread.start()
        self.logger.info("后台刷新线程已启动")

    def stop_refresh_thread(self):
        """停止后台刷新线程"""
        self.should_stop = True
        if self.refresh_thread:
            self.refresh_thread.join(timeout=5)
            self.logger.info("后台刷新线程已停止")

    def run(self):
        """运行服务器"""
        # 启动后台刷新线程
        self.start_refresh_thread()

        # 运行Flask应用
        self.logger.info(f"启动WEB API服务器，监听 {self.config['host']}:{self.config['port']}")
        self.app.run(
            host=self.config['host'],
            port=self.config['port'],
            debug=self.config['debug'],
            use_reloader=False
        )
        
def adjust_timeout_config(config: Dict) -> Dict:
    """调整超时配置以确保合理性"""
    default_timeouts = {
        'default': (10, 30),
        'health_check': (5, 10),
        'deploy_create': (10, 60),
        'deploy_start': (10, 300),
        'deploy_stop': (10, 120),
        'deploy_delete': (10, 60),
        'undeploy': (10, 180),
        'file_upload': (10, 600),
        'stream': (10, 3600),
        'proxy': (10, 300),
    }

    # 获取用户配置的超时设置
    user_timeouts = config.get('agent_api_timeouts', {})

    # 合并配置，用户配置优先
    final_timeouts = default_timeouts.copy()
    for key, value in user_timeouts.items():
        if isinstance(value, (list, tuple)) and len(value) == 2:
            final_timeouts[key] = tuple(value)
        elif isinstance(value, (int, float)):
            final_timeouts[key] = (10, int(value))

    config['agent_api_timeouts'] = final_timeouts
    return config
# ===================== 主函数 =====================

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='WEB API服务器 - Docker Compose服务管理中心')
    parser.add_argument('-c', '--config', help='配置文件路径')
    parser.add_argument('--host', help='监听主机')
    parser.add_argument('--port', type=int, help='监听端口')
    parser.add_argument('--debug', action='store_true', help='调试模式')
    parser.add_argument('--pod-id', help='POD标识符')
    parser.add_argument('--skip-connection-check', action='store_true',
                        help='跳过连接检查（用于测试）')
    parser.add_argument('--timeout', type=int, help='全局超时时间（秒）')
    parser.add_argument('--deploy-timeout', type=int, help='部署超时时间（秒）')

    args = parser.parse_args()

    config = DEFAULT_CONFIG.copy()

    if args.config:
        try:
            with open(args.config, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
                config.update(user_config)
        except Exception as e:
            print(f"加载配置文件失败: {e}")
            sys.exit(1)

    if args.host:
        config['host'] = args.host
    if args.port:
        config['port'] = args.port
    if args.debug:
        config['debug'] = args.debug
    if args.pod_id:
        config['pod_id'] = args.pod_id
    if args.skip_connection_check:
        config['skip_connection_check'] = True

    # 调整超时配置
    config = adjust_timeout_config(config)

    # 命令行参数覆盖配置
    if args.timeout:
        config['agent_api_timeouts']['default'] = (10, args.timeout)
        config['agent_api_timeouts']['proxy'] = (10, args.timeout)

    if args.deploy_timeout:
        config['agent_api_timeouts']['deploy_start'] = (10, args.deploy_timeout)

    # 打印启动信息
    print("=" * 60)
    print("WEB API 服务器 - Docker Compose服务管理中心")
    print(f"版本: 2.0.0 (增强连接检查和分布式锁修复版)")
    print(f"POD ID: {config['pod_id']}")
    print(f"数据库: {config['database'].get('type', 'sqlite').upper()}")
    print(f"Redis: {'启用' if config.get('redis_enabled', True) else '禁用'}")
    print(f"支持的压缩格式: {', '.join(config.get('supported_formats', SUPPORTED_FORMATS))}")
    print(f"监听地址: {config['host']}:{config['port']}")
    print("\n超时配置:")
    for key, value in config['agent_api_timeouts'].items():
        print(f"  {key}: {value}")
    print("=" * 60)

    try:
        server = WebAPIServer(config)
        server.run()
    except ConnectionError as e:
        print(f"\n启动失败: {e}")
        print("请检查配置文件和网络连接后重试")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n正在关闭服务器...")
        if 'server' in locals():
            server.stop_refresh_thread()
        sys.exit(0)
    except Exception as e:
        print(f"\n服务器启动失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()