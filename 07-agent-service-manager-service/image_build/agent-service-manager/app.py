#!/usr/bin/env python3
"""
WEB API服务器 - Docker Compose服务管理中心
增强版本：修复分布式锁问题，增强连接检查
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

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from flask_httpauth import HTTPTokenAuth
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import base64
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
    import sqlite3
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False
    import sqlite3

class DatabaseConnection:
    """数据库连接抽象类"""

    def __init__(self, db_config: Dict):
        self.db_config = db_config
        self.db_type = db_config.get('type', 'sqlite')
        self.connection = None
        self.logger = logging.getLogger(__name__)

    def connect(self) -> bool:
        """建立数据库连接"""
        try:
            if self.db_type == 'mysql':
                if not MYSQL_AVAILABLE:
                    self.logger.error("pymysql未安装，请使用 'pip install pymysql' 安装")
                    return False

                self.connection = pymysql.connect(
                    host=self.db_config.get('host', 'localhost'),
                    port=self.db_config.get('port', 3306),
                    user=self.db_config.get('user', 'root'),
                    password=self.db_config.get('password', ''),
                    database=self.db_config.get('database', 'webapi'),
                    charset='utf8mb4',
                    cursorclass=pymysql.cursors.DictCursor,
                    autocommit=False,
                    connect_timeout=10  # 连接超时10秒
                )
                self.logger.info("MySQL数据库连接成功")
                return True

            elif self.db_type == 'sqlite':
                db_path = self.db_config.get('path', './webapi_server.db')
                # 确保目录存在
                db_dir = os.path.dirname(db_path)
                if db_dir:
                    os.makedirs(db_dir, exist_ok=True)

                self.connection = sqlite3.connect(db_path, check_same_thread=False)
                self.connection.row_factory = sqlite3.Row
                self.logger.info(f"SQLite数据库连接成功: {db_path}")
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
        """测试数据库连接是否正常"""
        try:
            if self.connect():
                # 执行一个简单的查询测试
                cursor = self.connection.cursor()
                if self.db_type == 'mysql':
                    cursor.execute("SELECT 1")
                else:
                    cursor.execute("SELECT 1")
                cursor.close()
                return True
        except Exception as e:
            self.logger.error(f"数据库连接测试失败: {str(e)}")
        finally:
            self.close()
        return False

    def close(self):
        """关闭数据库连接"""
        if self.connection:
            try:
                self.connection.close()
            except:
                pass
            self.connection = None

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
        self.close()

class DatabaseManager:
    """数据库管理器（支持MySQL和SQLite）"""

    def __init__(self, db_config: Dict):
        self.db_config = db_config
        self.db_type = db_config.get('type', 'sqlite')
        self.logger = logging.getLogger(__name__)

        # 测试连接
        if not self.test_connection():
            raise ConnectionError(f"数据库连接失败，请检查配置: {db_config}")

        self.init_database()

    def test_connection(self) -> bool:
        """测试数据库连接"""
        db = DatabaseConnection(self.db_config)
        return db.test_connection()

    def get_connection(self) -> DatabaseConnection:
        """获取数据库连接"""
        return DatabaseConnection(self.db_config)

    def init_database(self):
        """初始化数据库（创建表和索引）"""
        with self.get_connection() as db:
            # 创建用户表
            if self.db_type == 'mysql':
                db.execute('''
                           CREATE TABLE IF NOT EXISTS users (
                                                                id INT AUTO_INCREMENT PRIMARY KEY,
                                                                username VARCHAR(100) UNIQUE NOT NULL,
                               password_hash VARCHAR(255) NOT NULL,
                               role VARCHAR(20) NOT NULL DEFAULT 'user',
                               email VARCHAR(100),
                               full_name VARCHAR(100),
                               is_active TINYINT DEFAULT 1,
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               last_login TIMESTAMP NULL,
                               INDEX idx_users_username (username),
                               INDEX idx_users_role (role)
                               ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:  # sqlite
                db.execute('''
                           CREATE TABLE IF NOT EXISTS users (
                                                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                                username TEXT UNIQUE NOT NULL,
                                                                password_hash TEXT NOT NULL,
                                                                role TEXT NOT NULL DEFAULT 'user',
                                                                email TEXT,
                                                                full_name TEXT,
                                                                is_active INTEGER DEFAULT 1,
                                                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                                last_login TIMESTAMP
                           )
                           ''')

            # 创建服务模板表
            if self.db_type == 'mysql':
                db.execute('''
                           CREATE TABLE IF NOT EXISTS service_templates (
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
                           CREATE TABLE IF NOT EXISTS service_templates (
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
                           CREATE TABLE IF NOT EXISTS tasks (
                                                                id INT AUTO_INCREMENT PRIMARY KEY,
                                                                task_id VARCHAR(36) UNIQUE NOT NULL,
                               task_type VARCHAR(20) NOT NULL,
                               service_name VARCHAR(100) NOT NULL,
                               agent_key VARCHAR(32) NOT NULL,
                               workspace_id VARCHAR(100),
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
                               INDEX idx_tasks_workspace (workspace_id),
                               INDEX idx_tasks_created (created_at)
                               ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:
                db.execute('''
                           CREATE TABLE IF NOT EXISTS tasks (
                                                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                                task_id TEXT UNIQUE NOT NULL,
                                                                task_type TEXT NOT NULL,
                                                                service_name TEXT NOT NULL,
                                                                agent_key TEXT NOT NULL,
                                                                workspace_id TEXT,
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
                db.execute('CREATE INDEX IF NOT EXISTS idx_tasks_task_id ON tasks(task_id)')
                db.execute('CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)')
                db.execute('CREATE INDEX IF NOT EXISTS idx_tasks_agent_key ON tasks(agent_key)')

            # 创建任务日志表
            if self.db_type == 'mysql':
                db.execute('''
                           CREATE TABLE IF NOT EXISTS task_logs (
                                                                    id INT AUTO_INCREMENT PRIMARY KEY,
                                                                    log_id VARCHAR(36) UNIQUE NOT NULL,
                               task_id VARCHAR(36) NOT NULL,
                               level VARCHAR(10) NOT NULL DEFAULT 'INFO',
                               message TEXT NOT NULL,
                               timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               pod_id VARCHAR(100),
                               INDEX idx_logs_task_id (task_id),
                               INDEX idx_logs_timestamp (timestamp),
                               FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
                               ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:
                db.execute('''
                           CREATE TABLE IF NOT EXISTS task_logs (
                                                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                                    log_id TEXT UNIQUE NOT NULL,
                                                                    task_id TEXT NOT NULL,
                                                                    level TEXT NOT NULL DEFAULT 'INFO',
                                                                    message TEXT NOT NULL,
                                                                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                                    pod_id TEXT,
                                                                    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
                               )
                           ''')
                # 为SQLite创建索引
                db.execute('CREATE INDEX IF NOT EXISTS idx_logs_task_id ON task_logs(task_id)')

            # 创建Agent状态表（用于多POD状态同步）
            if self.db_type == 'mysql':
                db.execute('''
                           CREATE TABLE IF NOT EXISTS agent_status (
                                                                       id INT AUTO_INCREMENT PRIMARY KEY,
                                                                       agent_key VARCHAR(32) UNIQUE NOT NULL,
                               ip_address VARCHAR(45) NOT NULL,
                               hostname VARCHAR(100) NOT NULL,
                               workspace_id VARCHAR(100) NOT NULL,
                               full_name VARCHAR(255) NOT NULL,
                               status VARCHAR(20) NOT NULL DEFAULT 'unknown',
                               last_seen TIMESTAMP NULL,
                               system_info JSON,
                               services JSON,
                               pod_id VARCHAR(100),
                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                               INDEX idx_agent_status_key (agent_key),
                               INDEX idx_agent_status_workspace (workspace_id),
                               INDEX idx_agent_status_updated (updated_at)
                               ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:
                db.execute('''
                           CREATE TABLE IF NOT EXISTS agent_status (
                                                                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                                       agent_key TEXT UNIQUE NOT NULL,
                                                                       ip_address TEXT NOT NULL,
                                                                       hostname TEXT NOT NULL,
                                                                       workspace_id TEXT NOT NULL,
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
                db.execute('CREATE INDEX IF NOT EXISTS idx_agent_status_workspace ON agent_status(workspace_id)')

            # 创建默认管理员用户（如果不存在）
            existing = db.fetch_one("SELECT COUNT(*) as count FROM users WHERE username = 'admin'")
            if existing and existing['count'] == 0:
                admin_hash = generate_password_hash('admin123')
                db.execute('''
                           INSERT INTO users (username, password_hash, role, email, full_name)
                           VALUES (%s, %s, 'admin', 'admin@example.com', 'Administrator')
                           ''' if self.db_type == 'mysql' else '''
                                                               INSERT INTO users (username, password_hash, role, email, full_name)
                                                               VALUES (?, ?, 'admin', 'admin@example.com', 'Administrator')
                                                               ''', ('admin', admin_hash))

            self.logger.info(f"数据库初始化完成（使用{self.db_type.upper()}）")

    def execute_query(self, query: str, params: tuple = ()):
        """执行查询"""
        with self.get_connection() as db:
            return db.execute(query, params)

    def execute_transaction(self, queries: List[Tuple[str, tuple]]):
        """执行事务（多个查询）"""
        with self.get_connection() as db:
            try:
                for query, params in queries:
                    db.execute(query, params)
            except Exception as e:
                raise e

    def fetch_one(self, query: str, params: tuple = ()):
        """获取单条记录"""
        with self.get_connection() as db:
            return db.fetch_one(query, params)

    def fetch_all(self, query: str, params: tuple = ()):
        """获取所有记录"""
        with self.get_connection() as db:
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
                self.logger.debug(f"成功释放锁 {self.lock_key}")
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
                self.logger.debug(f"虚拟锁已获取: {self.lock_key}")
                self._acquired = True
                return True

            def release(self) -> bool:
                self.logger.debug(f"虚拟锁已释放: {self.lock_key}")
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
    'refresh_interval': 60,
    'max_workers': 10,
    'upload_max_size': 100 * 1024 * 1024,
    'token_expiration': 24 * 3600,
    'log_level': 'INFO',
    'log_file': './webapi_server.log',
    'pod_id': os.environ.get('POD_NAME', 'webapi-server-1'),
    'lock_timeout': 30,
    'max_task_logs': 1000,
    'task_log_retention_days': 7,
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
    def check_nacos(nacos_url: str, namespace: str = 'public') -> Tuple[bool, str]:
        """检查Nacos连接"""
        try:
            url = f"{nacos_url.rstrip('/')}/nacos/v1/ns/service/list"
            params = {
                'pageNo': 1,
                'pageSize': 10,
                'namespaceId': namespace
            }

            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                return True, "Nacos连接正常"
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
            config.get('nacos_namespace', 'public')
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
class WorkspaceInfo:
    """工作空间信息"""
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
    workspace_id: str
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
    workspace_id: str = ''
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

# ===================== 模板管理器 =====================

class TemplateManager:
    """服务模板管理器"""

    def __init__(self, templates_root: str, db_manager: DatabaseManager):
        self.templates_root = Path(templates_root)
        self.db = db_manager
        self.templates_root.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def create_template(self, name: str, description: str, template_type: str,
                        file_content: bytes, filename: str, created_by: str) -> Tuple[bool, str]:
        try:
            existing = self.db.fetch_one(
                "SELECT id FROM service_templates WHERE name = %s"
                if self.db.db_type == 'mysql' else
                "SELECT id FROM service_templates WHERE name = ?",
                (name,)
            )
            if existing:
                return False, f"模板名称 '{name}' 已存在"

            template_dir = self.templates_root / name
            template_dir.mkdir(parents=True, exist_ok=False)

            file_path = template_dir / filename

            if template_type == 'yaml':
                try:
                    yaml_content = file_content.decode('utf-8')
                    parsed = yaml.safe_load(yaml_content)
                    if not parsed or 'services' not in parsed:
                        shutil.rmtree(template_dir)
                        return False, "YAML文件必须包含services部分"

                    with open(file_path, 'wb') as f:
                        f.write(file_content)

                except yaml.YAMLError as e:
                    shutil.rmtree(template_dir)
                    return False, f"YAML格式错误: {e}"

            elif template_type == 'zip':
                with open(file_path, 'wb') as f:
                    f.write(file_content)

                try:
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        zip_ref.extractall(template_dir)

                    yaml_files = list(template_dir.rglob('service.yaml'))
                    yaml_files.extend(list(template_dir.rglob('docker-compose.yaml')))
                    yaml_files.extend(list(template_dir.rglob('docker-compose.yml')))

                    if not yaml_files:
                        shutil.rmtree(template_dir)
                        return False, "ZIP文件中未找到service.yaml或docker-compose.yaml文件"

                except zipfile.BadZipFile:
                    shutil.rmtree(template_dir)
                    return False, "无效的ZIP文件"

            else:
                shutil.rmtree(template_dir)
                return False, f"不支持的模板类型: {template_type}"

            self.db.execute_query(
                "INSERT INTO service_templates (name, description, type, file_path, created_by, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, NOW(), NOW())"
                if self.db.db_type == 'mysql' else
                "INSERT INTO service_templates (name, description, type, file_path, created_by, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
                (name, description, template_type, str(file_path), created_by)
            )

            self.logger.info(f"模板 '{name}' 创建成功")
            return True, f"模板 '{name}' 创建成功"

        except Exception as e:
            self.logger.error(f"创建模板失败: {str(e)}")
            template_dir = self.templates_root / name
            if template_dir.exists():
                shutil.rmtree(template_dir, ignore_errors=True)
            return False, f"创建模板失败: {str(e)}"

    def get_template(self, name: str) -> Optional[Dict]:
        return self.db.fetch_one(
            "SELECT * FROM service_templates WHERE name = %s"
            if self.db.db_type == 'mysql' else
            "SELECT * FROM service_templates WHERE name = ?",
            (name,)
        )

    def list_templates(self, page: int = 1, per_page: int = 20) -> Tuple[List[Dict], int]:
        offset = (page - 1) * per_page

        if self.db.db_type == 'mysql':
            templates = self.db.fetch_all(
                "SELECT * FROM service_templates ORDER BY updated_at DESC LIMIT %s OFFSET %s",
                (per_page, offset)
            )
            count_result = self.db.fetch_one("SELECT COUNT(*) as count FROM service_templates")
        else:
            templates = self.db.fetch_all(
                "SELECT * FROM service_templates ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (per_page, offset)
            )
            count_result = self.db.fetch_one("SELECT COUNT(*) as count FROM service_templates")

        total = count_result['count'] if count_result else 0
        return templates, total

    def delete_template(self, name: str) -> Tuple[bool, str]:
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在"

            template_dir = self.templates_root / name
            if template_dir.exists():
                shutil.rmtree(template_dir, ignore_errors=True)

            self.db.execute_query(
                "DELETE FROM service_templates WHERE name = %s"
                if self.db.db_type == 'mysql' else
                "DELETE FROM service_templates WHERE name = ?",
                (name,)
            )

            self.logger.info(f"模板 '{name}' 删除成功")
            return True, f"模板 '{name}' 删除成功"
        except Exception as e:
            self.logger.error(f"删除模板失败: {str(e)}")
            return False, f"删除模板失败: {str(e)}"

# ===================== 模板管理器（完整增强版） =====================

class EnhancedTemplateManager:
    """完整增强版模板管理器"""

    def __init__(self, templates_root: str, db_manager: DatabaseManager):
        self.templates_root = Path(templates_root)
        self.db = db_manager
        self.templates_root.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def validate_yaml_content(self, yaml_content: str, template_type: str, filename: str = None) -> Tuple[bool, str]:
        """
        验证YAML内容的有效性

        Args:
            yaml_content: YAML内容字符串
            template_type: 模板类型（yaml或zip）
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
        """创建模板（增强版，包含格式校验和清理逻辑）"""
        template_dir = None
        file_path = None
        db_cleanup_needed = False

        try:
            # 检查模板名称是否已存在
            existing = self.db.fetch_one(
                "SELECT id FROM service_templates WHERE name = %s"
                if self.db.db_type == 'mysql' else
                "SELECT id FROM service_templates WHERE name = ?",
                (name,)
            )
            if existing:
                return False, f"模板名称 '{name}' 已存在"

            # 创建模板目录
            template_dir = self.templates_root / name
            template_dir.mkdir(parents=True, exist_ok=False)

            file_path = template_dir / filename
            # 在YAML部分的验证中：
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

            elif template_type == 'zip':
                # 保存ZIP文件
                with open(file_path, 'wb') as f:
                    f.write(file_content)

                try:
                    # 解压ZIP文件
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        zip_ref.extractall(template_dir)

                    # 查找并验证YAML文件
                    yaml_files = []
                    found_yaml = None

                    # 首先查找特定的YAML文件
                    for yaml_name in ['service.yaml', 'docker-compose.yaml', 'docker-compose.yml']:
                        for yaml_path in template_dir.rglob(yaml_name):
                            if yaml_path.is_file():
                                yaml_files.append(yaml_path)

                    # 检查是否找到YAML文件
                    if not yaml_files:
                        raise ValueError("ZIP文件中未找到service.yaml、docker-compose.yaml或docker-compose.yml文件")

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
                                self.logger.info(f"在ZIP中找到有效的YAML文件: {yaml_file}")
                                break
                            else:
                                self.logger.warning(f"文件 {yaml_file} 验证失败: {error_msg}")
                        except Exception as e:
                            self.logger.warning(f"文件 {yaml_file} 读取失败: {str(e)}")
                            continue

                    # 检查是否找到有效的YAML文件
                    if not yaml_content or not found_yaml:
                        raise ValueError("ZIP文件中未找到包含有效services部分的YAML文件")

                    # 额外验证：确保services部分不为空
                    parsed = yaml.safe_load(yaml_content)
                    services = parsed.get('services', {})
                    if not services or len(services) == 0:
                        raise ValueError("YAML文件中的services部分不能为空")

                    self.logger.info(f"ZIP模板 '{name}' 验证成功，找到有效YAML文件: {found_yaml}")

                except zipfile.BadZipFile:
                    raise ValueError("无效的ZIP文件格式")
                except zipfile.LargeZipFile:
                    raise ValueError("ZIP文件过大")
                except Exception as e:
                    if not str(e).startswith("ZIP文件"):
                        raise ValueError(f"ZIP文件处理失败: {str(e)}")
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
                'template_type': template_type
            }

            if template_type == 'zip':
                # 记录ZIP文件中的YAML文件信息
                if found_yaml:
                    metadata['main_yaml_file'] = str(found_yaml.relative_to(template_dir))

            metadata_json = json.dumps(metadata)

            # 插入数据库记录
            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    "INSERT INTO service_templates (name, description, type, file_path, created_by, created_at, updated_at, metadata) "
                    "VALUES (%s, %s, %s, %s, %s, NOW(), NOW(), %s)",
                    (name, description, template_type, str(file_path), created_by, metadata_json)
                )
            else:
                self.db.execute_query(
                    "INSERT INTO service_templates (name, description, type, file_path, created_by, created_at, updated_at, metadata) "
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
                        "DELETE FROM service_templates WHERE name = %s"
                        if self.db.db_type == 'mysql' else
                        "DELETE FROM service_templates WHERE name = ?",
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
            "SELECT * FROM service_templates WHERE name = %s"
            if self.db.db_type == 'mysql' else
            "SELECT * FROM service_templates WHERE name = ?",
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

            elif template_type == 'zip':
                # 从ZIP文件中提取YAML
                template_dir = self.templates_root / name

                # 查找YAML文件
                yaml_files = []
                for pattern in ['service.yaml', 'docker-compose.yaml', 'docker-compose.yml']:
                    yaml_files.extend(list(template_dir.rglob(pattern)))

                if not yaml_files:
                    return False, "ZIP文件中未找到YAML文件", "no_yaml_in_zip"

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
        对于zip格式：替换解压目录中的yaml文件，并重新打包
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
                    "UPDATE service_templates SET updated_at = NOW(), metadata = %s WHERE name = %s"
                    if self.db.db_type == 'mysql' else
                    "UPDATE service_templates SET updated_at = datetime('now'), metadata = ? WHERE name = ?",
                    (json.dumps(metadata), name)
                )

                self.logger.info(f"YAML模板 '{name}' 更新成功，新大小: {new_size} 字节")
                return True, f"模板 '{name}' 更新成功，备份文件: {backup_path.name}"

            elif template_type == 'zip':
                # 更新ZIP包中的YAML
                zip_path = Path(template['file_path'])

                # 备份原ZIP文件
                backup_path = zip_path.with_suffix(f'.zip.backup.{datetime.now().strftime("%Y%m%d%H%M%S")}')
                shutil.copy2(zip_path, backup_path)

                # 查找解压目录中的YAML文件
                yaml_files = []
                for pattern in ['service.yaml', 'docker-compose.yaml', 'docker-compose.yml']:
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

                # 重新打包ZIP文件
                # 先删除原ZIP文件
                zip_path.unlink()

                # 创建新ZIP文件
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for file_path in template_dir.rglob('*'):
                        if file_path.is_file():
                            # 计算相对路径
                            rel_path = file_path.relative_to(template_dir)
                            # 添加文件到ZIP
                            zipf.write(file_path, rel_path)

                # 更新元数据
                new_size = zip_path.stat().st_size
                metadata = template.get('metadata', {})
                metadata['file_size'] = new_size
                metadata['last_updated_by'] = updated_by
                metadata['last_updated_at'] = datetime.now().isoformat()

                # 更新目录大小
                dir_size = self._get_directory_size(template_dir)
                metadata['directory_size'] = dir_size

                self.db.execute_query(
                    "UPDATE service_templates SET updated_at = NOW(), metadata = %s WHERE name = %s"
                    if self.db.db_type == 'mysql' else
                    "UPDATE service_templates SET updated_at = datetime('now'), metadata = ? WHERE name = ?",
                    (json.dumps(metadata), name)
                )

                self.logger.info(f"ZIP模板 '{name}' 更新成功，新大小: {new_size} 字节")
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

            # 如果是zip类型，获取zip内的文件列表
            if template['type'] == 'zip':
                try:
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        file_info['files_in_template'] = zip_ref.namelist()
                        file_info['zip_info'] = {
                            'file_count': len(zip_ref.namelist()),
                            'compressed_size': sum(zinfo.compress_size for zinfo in zip_ref.filelist),
                            'uncompressed_size': sum(zinfo.file_size for zinfo in zip_ref.filelist),
                            'compression_ratio': sum(zinfo.compress_size for zinfo in zip_ref.filelist) /
                                                 max(sum(zinfo.file_size for zinfo in zip_ref.filelist), 1)
                        }
                except Exception as e:
                    self.logger.warning(f"读取ZIP文件信息失败: {e}")

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
            elif template['type'] == 'zip':
                content_type = 'application/zip'
                file_extension = 'zip'
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
                    export_format = 'zip'

            # 根据导出格式处理
            if export_format == 'yaml':
                # 导出为YAML
                success, yaml_content, message = self.get_yaml_content(name)
                if success:
                    return True, yaml_content.encode('utf-8'), 'text/yaml', f"{name}.yaml"
                else:
                    return False, message, "text/plain", ""

            elif export_format == 'zip':
                # 导出为ZIP
                if template_type == 'zip':
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    return True, content, 'application/zip', f"{name}.zip"
                else:
                    success, zip_content, content_type = self.get_template_as_zip(name, True)
                    if success:
                        return True, zip_content, content_type, f"{name}.zip"
                    else:
                        return False, zip_content, "text/plain", ""

            else:
                return False, f"不支持的导出格式: {export_format}", "text/plain", ""

        except Exception as e:
            self.logger.error(f"导出模板失败: {str(e)}")
            return False, f"导出失败: {str(e)}", "text/plain", ""

    def list_templates(self, page: int = 1, per_page: int = 20) -> Tuple[List[Dict], int]:
        """列出所有模板（包含文件大小信息）"""
        offset = (page - 1) * per_page

        if self.db.db_type == 'mysql':
            templates = self.db.fetch_all(
                "SELECT * FROM service_templates ORDER BY updated_at DESC LIMIT %s OFFSET %s",
                (per_page, offset)
            )
            count_result = self.db.fetch_one("SELECT COUNT(*) as count FROM service_templates")
        else:
            templates = self.db.fetch_all(
                "SELECT * FROM service_templates ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (per_page, offset)
            )
            count_result = self.db.fetch_one("SELECT COUNT(*) as count FROM service_templates")

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
                "DELETE FROM service_templates WHERE name = %s"
                if self.db.db_type == 'mysql' else
                "DELETE FROM service_templates WHERE name = ?",
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
                 pod_id: str):
        self.nacos_url = nacos_url.rstrip('/')
        self.nacos_namespace = nacos_namespace
        self.agent_api_port = agent_api_port
        self.agent_auth_token = agent_auth_token
        self.db = db_manager
        self.redis_manager = redis_manager
        self.pod_id = pod_id

        self.agents: Dict[str, AgentInfo] = {}
        self.workspaces: Dict[str, WorkspaceInfo] = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)

        # 检查Nacos连接
        if not self._test_nacos_connection():
            self.logger.warning("Nacos连接测试失败，Agent刷新功能可能不可用")

        # 从数据库加载Agent状态
        self._load_agents_from_db()

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
                        "SELECT * FROM agent_status WHERE updated_at > NOW() - INTERVAL 5 MINUTE"
                    )
                else:
                    agents_data = self.db.fetch_all(
                        "SELECT * FROM agent_status WHERE updated_at > datetime('now', '-5 minutes')"
                    )

                for agent_data in agents_data:
                    agent = AgentInfo(
                        key=agent_data['agent_key'],
                        ip_address=agent_data['ip_address'],
                        hostname=agent_data['hostname'],
                        workspace_id=agent_data['workspace_id'],
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
                    self._update_workspace(agent.workspace_id, agent.key)

                self.logger.info(f"从数据库加载了 {len(agents_data)} 个Agent状态")

        except Exception as e:
            self.logger.error(f"从数据库加载Agent状态失败: {str(e)}")

    def _update_workspace(self, workspace_id: str, agent_key: str):
        if workspace_id not in self.workspaces:
            self.workspaces[workspace_id] = WorkspaceInfo(
                id=workspace_id,
                last_refresh=datetime.now()
            )

        workspace = self.workspaces[workspace_id]
        if agent_key not in workspace.agents:
            workspace.agents.append(agent_key)

        online_count = 0
        for key in workspace.agents:
            agent = self.agents.get(key)
            if agent and agent.status == 'online':
                online_count += 1

        workspace.agent_count = len(workspace.agents)
        workspace.online_agents = online_count
        workspace.last_refresh = datetime.now()

    def _parse_agent_name(self, service_name: str) -> Optional[Tuple[str, str, str]]:
        # 找到第一个连字符，它分隔 workspace_id 和 hostname
        first_dash = service_name.find('-')
        if first_dash == -1:
            return None

        workspace_id = service_name[:first_dash]

        # 确保 workspace_id 不为空且不包含连字符
        if not workspace_id or '-' in workspace_id:
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

        return workspace_id, hostname, ip_address


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

    def _get_agent_key(self, hostname: str, ip_address: str) -> str:
        key_str = f"{hostname}-{ip_address}"
        return hashlib.md5(key_str.encode()).hexdigest()

    def _fetch_nacos_services(self) -> List[Dict]:
        try:
            url = f"{self.nacos_url}/nacos/v1/ns/service/list"
            params = {
                'pageNo': 1,
                'pageSize': 1000000,
                'namespaceId': self.nacos_namespace
            }

            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('doms', [])
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

    def _check_agent_status(self, agent: AgentInfo) -> bool:
        try:
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

    def _save_agent_to_db(self, agent: AgentInfo):
        try:
            system_info_json = json.dumps(agent.system_info) if agent.system_info else '{}'
            services_json = json.dumps(agent.services) if agent.services else '[]'
            last_seen_str = agent.last_seen.isoformat() if agent.last_seen else None

            if self.db.db_type == 'mysql':
                self.db.execute_query('''
                                      INSERT INTO agent_status
                                      (agent_key, ip_address, hostname, workspace_id, full_name, status,
                                       last_seen, system_info, services, pod_id, updated_at)
                                      VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                                          ON DUPLICATE KEY UPDATE
                                                               ip_address = VALUES(ip_address),
                                                               hostname = VALUES(hostname),
                                                               workspace_id = VALUES(workspace_id),
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
                                          agent.workspace_id,
                                          agent.full_name,
                                          agent.status,
                                          last_seen_str,
                                          system_info_json,
                                          services_json,
                                          self.pod_id
                                      ))
            else:
                self.db.execute_query('''
                    INSERT OR REPLACE INTO agent_status 
                    (agent_key, ip_address, hostname, workspace_id, full_name, status, 
                     last_seen, system_info, services, pod_id, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ''', (
                    agent.key,
                    agent.ip_address,
                    agent.hostname,
                    agent.workspace_id,
                    agent.full_name,
                    agent.status,
                    last_seen_str,
                    system_info_json,
                    services_json,
                    self.pod_id
                ))

        except Exception as e:
            self.logger.error(f"保存Agent状态到数据库失败: {str(e)}")

    def refresh_agents(self):
        """刷新Agent列表（使用分布式锁确保只有一个POD执行刷新）"""
        lock_key = "agent_refresh_lock"

        try:
            # 获取分布式锁（如果Redis不可用，会返回虚拟锁）
            with self.redis_manager.get_lock(lock_key, timeout=60) as lock:
                if lock.is_acquired():
                    self.logger.info(f"POD {self.pod_id} 获取到锁，开始刷新Agent列表...")
                else:
                    self.logger.warning(f"POD {self.pod_id} 无法获取锁，跳过本次刷新...")
                    return

                services = self._fetch_nacos_services()
                new_agents = {}

                for service in services:
                    result = self._parse_agent_name(service)
                    if result:
                        workspace_id, hostname, ip_address = result
                        agent_key = self._get_agent_key(hostname, ip_address)

                        agent = AgentInfo(
                            key=agent_key,
                            ip_address=ip_address,
                            hostname=hostname,
                            workspace_id=workspace_id,
                            full_name=service,
                            status='unknown',
                            pod_id=self.pod_id
                        )

                        self._check_agent_status(agent)
                        self._save_agent_to_db(agent)
                        new_agents[agent_key] = agent

                with self.lock:
                    for key, new_agent in new_agents.items():
                        self.agents[key] = new_agent
                        self._update_workspace(new_agent.workspace_id, key)

                    removed_keys = [k for k in self.agents.keys() if k not in new_agents]
                    for key in removed_keys:
                        del self.agents[key]

                self.logger.info(f"Agent列表刷新完成，共 {len(new_agents)} 个Agent")

        except Exception as e:
            self.logger.error(f"刷新Agent列表异常: {str(e)}")

    def get_workspace(self, workspace_id: str) -> Optional[WorkspaceInfo]:
        with self.lock:
            return self.workspaces.get(workspace_id)

    def list_workspaces(self) -> List[Dict]:
        with self.lock:
            return [workspace.to_dict() for workspace in self.workspaces.values()]

    def get_workspace_agents(self, workspace_id: str) -> List[Dict]:
        with self.lock:
            workspace = self.workspaces.get(workspace_id)
            if not workspace:
                return []

            agents = []
            for agent_key in workspace.agents:
                agent = self.agents.get(agent_key)
                if agent:
                    agents.append(agent.to_dict())

            return agents

    def get_agent(self, key: str) -> Optional[AgentInfo]:
        with self.lock:
            return self.agents.get(key)

    def list_agents(self, page: int = 1, per_page: int = 20,
                    workspace_id: str = None) -> Tuple[List[Dict], int]:
        with self.lock:
            if workspace_id:
                workspace = self.workspaces.get(workspace_id)
                if not workspace:
                    return [], 0

                agents_list = []
                for agent_key in workspace.agents:
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
                       stream: bool = False) -> Tuple[int, Any]:
        """
        调用Agent API（增强版，支持文件上传）
        """
        agent = self.get_agent(agent_key)
        if not agent:
            return 404, {'error': 'Agent not found'}

        try:
            url = f"http://{agent.ip_address}:{self.agent_api_port}{endpoint}"

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
                'timeout': (5, 30),
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

            return response.status_code, response_data

        except requests.exceptions.Timeout:
            self.logger.error(f"请求Agent {agent_key} 超时")
            return 504, {'error': 'Request timeout to agent'}
        except requests.exceptions.ConnectionError:
            self.logger.error(f"连接Agent {agent_key} 失败")
            return 503, {'error': 'Connection failed to agent'}
        except Exception as e:
            self.logger.error(f"调用Agent API失败: {str(e)}", exc_info=True)
            return 500, {'error': f'API call failed: {str(e)}'}

# ===================== 任务管理器 =====================

class TaskManager:
    """任务管理器"""

    def __init__(self, db_manager: DatabaseManager, agent_manager: AgentManager,
                 template_manager: TemplateManager, services_root: str,
                 redis_manager: RedisManager, pod_id: str, max_task_logs: int = 1000):
        self.db = db_manager
        self.agent_manager = agent_manager
        self.template_manager = template_manager
        self.services_root = Path(services_root)
        self.redis_manager = redis_manager
        self.pod_id = pod_id
        self.max_task_logs = max_task_logs

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
                                      DELETE FROM task_logs
                                      WHERE timestamp < %s
                                      ''', (cutoff_date,))
            else:
                self.db.execute_query('''
                                      DELETE FROM task_logs
                                      WHERE timestamp < ?
                                      ''', (cutoff_date,))

            self.logger.info("已清理过期任务日志")

        except Exception as e:
            self.logger.error(f"清理过期任务日志失败: {str(e)}")

    def create_task(self, task_type: str, service_name: str, agent_key: str,
                    template_name: str = None, extra_params: Dict = None) -> str:
        task_id = str(uuid.uuid4())

        agent = self.agent_manager.get_agent(agent_key)
        workspace_id = agent.workspace_id if agent else ''

        if self.db.db_type == 'mysql':
            self.db.execute_query('''
                                  INSERT INTO tasks
                                  (task_id, task_type, service_name, agent_key, workspace_id,
                                   status, progress, message, created_at, pod_id)
                                  VALUES (%s, %s, %s, %s, %s, 'pending', 0, '', NOW(), %s)
                                  ''', (task_id, task_type, service_name, agent_key, workspace_id, self.pod_id))
        else:
            self.db.execute_query('''
                                  INSERT INTO tasks
                                  (task_id, task_type, service_name, agent_key, workspace_id,
                                   status, progress, message, created_at, pod_id)
                                  VALUES (?, ?, ?, ?, ?, 'pending', 0, '', datetime('now'), ?)
                                  ''', (task_id, task_type, service_name, agent_key, workspace_id, self.pod_id))

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
                                      INSERT INTO task_logs
                                          (log_id, task_id, level, message, timestamp, pod_id)
                                      VALUES (%s, %s, %s, %s, NOW(), %s)
                                      ''', (log_id, task_id, level, message, self.pod_id))

                # 限制日志数量
                self.db.execute_query('''
                    DELETE tl FROM task_logs tl
                    JOIN (
                        SELECT id FROM task_logs 
                        WHERE task_id = %s 
                        ORDER BY timestamp DESC 
                        LIMIT 1 OFFSET %s
                    ) t ON tl.id = t.id
                ''', (task_id, self.max_task_logs))

            else:
                self.db.execute_query('''
                                      INSERT INTO task_logs
                                          (log_id, task_id, level, message, timestamp, pod_id)
                                      VALUES (?, ?, ?, ?, datetime('now'), ?)
                                      ''', (log_id, task_id, level, message, self.pod_id))

                # 限制日志数量
                self.db.execute_query('''
                                      DELETE FROM task_logs
                                      WHERE id IN (
                                          SELECT id FROM task_logs
                                          WHERE task_id = ?
                                          ORDER BY timestamp DESC
                                          LIMIT -1 OFFSET ?
                                          )
                                      ''', (task_id, self.max_task_logs))

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

    def _deploy_service(self, task_id: str, service_name: str, agent_key: str,
                        template_name: str, extra_params: Dict = None):
        """部署服务（修复模板文件获取问题）"""
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

            # 3. 根据模板类型获取YAML内容
            self._update_task_status(task_id, 'running', 30, '获取模板内容')

            if template_type == 'yaml':
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

                # 调用Agent API创建服务
                status_code, response = self.agent_manager.call_agent_api(
                    agent_key, 'POST', '/api/services/yaml', data
                )

                self._add_task_log(task_id, 'INFO', f"Agent响应状态码: {status_code}")
                self._add_task_log(task_id, 'DEBUG', f"Agent响应内容: {json.dumps(response)[:200]}...")

                if status_code == 201:
                    self._update_task_status(task_id, 'running', 70, '服务创建成功，正在启动')

                    # 等待几秒让服务创建完成
                    time.sleep(2)

                    self._add_task_log(task_id, 'INFO', f"启动服务: {service_name}")

                    # 启动服务
                    start_status_code, start_response = self.agent_manager.call_agent_api(
                        agent_key, 'POST', f'/api/services/{service_name}/start', {}
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
                        self.agent_manager.call_agent_api(
                            agent_key, 'DELETE', f'/api/services/{service_name}', {}
                        )

                elif status_code == 409:
                    # 服务已存在
                    self._update_task_status(task_id, 'running', 70, '服务已存在，尝试重新创建')

                    # 先停止并删除现有服务
                    self._add_task_log(task_id, 'INFO', '停止现有服务')
                    self.agent_manager.call_agent_api(
                        agent_key, 'POST', f'/api/services/{service_name}/stop', {}
                    )

                    time.sleep(3)

                    self._add_task_log(task_id, 'INFO', '删除现有服务')
                    self.agent_manager.call_agent_api(
                        agent_key, 'DELETE', f'/api/services/{service_name}', {}
                    )

                    time.sleep(2)

                    # 重新创建服务
                    self._add_task_log(task_id, 'INFO', '重新创建服务')
                    status_code, response = self.agent_manager.call_agent_api(
                        agent_key, 'POST', '/api/services/yaml', data
                    )

                    if status_code == 201:
                        # 启动服务
                        time.sleep(2)
                        start_status_code, start_response = self.agent_manager.call_agent_api(
                            agent_key, 'POST', f'/api/services/{service_name}/start', {}
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

            elif template_type == 'zip':
                # ZIP模板部署
                self._update_task_status(task_id, 'running', 30, '处理ZIP模板')

                # 获取模板文件路径
                template_file = self.template_manager.get_template_file(template_name)
                if not template_file:
                    self._update_task_status(task_id, 'failed', 30, 'ZIP模板文件不存在')
                    return

                self._add_task_log(task_id, 'INFO', f"ZIP文件: {template_file}")

                # 准备文件上传
                with open(template_file, 'rb') as f:
                    file_content = f.read()

                # 创建文件字典（符合call_agent_api的文件格式）
                files = {
                    'file': ('template.zip', file_content, 'application/zip')
                }

                data = {
                    'name': service_name
                }

                # 添加额外参数
                if extra_params:
                    data.update(extra_params)

                self._add_task_log(task_id, 'INFO', f"上传ZIP文件到Agent")

                # 调用Agent的ZIP部署接口
                status_code, response = self.agent_manager.call_agent_api(
                    agent_key, 'POST', '/api/services/zip', data=data, files=files
                )

                self._add_task_log(task_id, 'INFO', f"Agent响应状态码: {status_code}")
                self._add_task_log(task_id, 'DEBUG', f"Agent响应内容: {json.dumps(response)[:200]}...")

                if status_code == 201:
                    self._update_task_status(task_id, 'running', 70, 'ZIP服务创建成功，正在启动')

                    # 等待几秒让服务创建完成
                    time.sleep(3)

                    self._add_task_log(task_id, 'INFO', f"启动服务: {service_name}")

                    # 启动服务
                    start_status_code, start_response = self.agent_manager.call_agent_api(
                        agent_key, 'POST', f'/api/services/{service_name}/start', {}
                    )

                    if start_status_code == 200:
                        self._update_task_status(task_id, 'success', 100, 'ZIP服务部署成功')
                        self._add_task_log(task_id, 'INFO', 'ZIP服务部署完成')
                    else:
                        error_msg = f'启动ZIP服务失败: {start_response}'
                        self._update_task_status(task_id, 'failed', 70, error_msg)
                        self._add_task_log(task_id, 'ERROR', error_msg)
                else:
                    error_msg = f'创建ZIP服务失败 (HTTP {status_code}): {response}'
                    self._update_task_status(task_id, 'failed', 30, error_msg)
                    self._add_task_log(task_id, 'ERROR', error_msg)

            else:
                error_msg = f'不支持的模板类型: {template_type}'
                self._update_task_status(task_id, 'failed', 0, error_msg)

        except Exception as e:
            self.logger.error(f"部署服务失败: {str(e)}", exc_info=True)
            self._update_task_status(task_id, 'failed', 0, f'部署失败: {str(e)}')
            self._add_task_log(task_id, 'ERROR', f"异常详情: {traceback.format_exc()}")

    def get_task(self, task_id: str) -> Optional[Dict]:
        task = self.db.fetch_one(
            "SELECT * FROM tasks WHERE task_id = %s"
            if self.db.db_type == 'mysql' else
            "SELECT * FROM tasks WHERE task_id = ?",
            (task_id,)
        )

        if task:
            log_count = self.db.fetch_one(
                "SELECT COUNT(*) as count FROM task_logs WHERE task_id = %s"
                if self.db.db_type == 'mysql' else
                "SELECT COUNT(*) as count FROM task_logs WHERE task_id = ?",
                (task_id,)
            )
            task['log_count'] = log_count['count'] if log_count else 0

        return task

    def get_task_logs(self, task_id: str, page: int = 1, per_page: int = 100) -> Tuple[List[Dict], int]:
        offset = (page - 1) * per_page

        if self.db.db_type == 'mysql':
            logs = self.db.fetch_all('''
                                     SELECT * FROM task_logs
                                     WHERE task_id = %s
                                     ORDER BY timestamp ASC
                                         LIMIT %s OFFSET %s
                                     ''', (task_id, per_page, offset))

            count_result = self.db.fetch_one(
                "SELECT COUNT(*) as count FROM task_logs WHERE task_id = %s",
                (task_id,)
            )
        else:
            logs = self.db.fetch_all('''
                                     SELECT * FROM task_logs
                                     WHERE task_id = ?
                                     ORDER BY timestamp ASC
                                         LIMIT ? OFFSET ?
                                     ''', (task_id, per_page, offset))

            count_result = self.db.fetch_one(
                "SELECT COUNT(*) as count FROM task_logs WHERE task_id = ?",
                (task_id,)
            )

        total = count_result['count'] if count_result else 0
        return logs, total

    def list_tasks(self, page: int = 1, per_page: int = 20,
                   task_type: str = None, status: str = None,
                   workspace_id: str = None, agent_key: str = None) -> Tuple[List[Dict], int]:
        query = "SELECT * FROM tasks WHERE 1=1"
        params = []

        if task_type:
            query += " AND task_type = "
            query += "%s" if self.db.db_type == 'mysql' else "?"
            params.append(task_type)

        if status:
            query += " AND status = "
            query += "%s" if self.db.db_type == 'mysql' else "?"
            params.append(status)

        if workspace_id:
            query += " AND workspace_id = "
            query += "%s" if self.db.db_type == 'mysql' else "?"
            params.append(workspace_id)

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
                "SELECT COUNT(*) as count FROM task_logs WHERE task_id = " +
                ("%s" if self.db.db_type == 'mysql' else "?"),
                (task['task_id'],)
            )
            task['log_count'] = log_count['count'] if log_count else 0

        return tasks, total

    def delete_task(self, task_id: str) -> bool:
        try:
            if self.db.db_type == 'mysql':
                self.db.execute_transaction([
                    ("DELETE FROM task_logs WHERE task_id = %s", (task_id,)),
                    ("DELETE FROM tasks WHERE task_id = %s", (task_id,))
                ])
            else:
                self.db.execute_transaction([
                    ("DELETE FROM task_logs WHERE task_id = ?", (task_id,)),
                    ("DELETE FROM tasks WHERE task_id = ?", (task_id,))
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

    def __init__(self, agent_manager: AgentManager):
        self.agent_manager = agent_manager
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.verify = False  # 临时禁用SSL验证

    def proxy_request(self, agent_key: str, method: str, endpoint: str,
                      request_data: Any = None, query_params: Dict = None,
                      headers: Dict = None, files: Dict = None,
                      stream: bool = False, timeout: int = 30) -> Tuple[int, Any, Dict]:
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

            # 准备请求参数
            request_kwargs = {
                'headers': request_headers,
                'params': query_params,
                'timeout': timeout,
                'stream': stream,
                'verify': False  # 禁用SSL验证
            }

            self.logger.info(f"代理请求: {method} {url} 到Agent {agent.hostname}")

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
                return 504, {'error': f'Request timeout to agent {agent.hostname}'}, {}
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

            return response.status_code, response_data, response_headers

        except Exception as e:
            self.logger.error(f"代理请求失败: {str(e)}", exc_info=True)
            return 500, {'error': f'Proxy request failed: {str(e)}'}, {}

# ===================== Flask应用 =====================

class WebAPIServer:
    """WEB API服务器"""

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

        # 3. 初始化认证
        self.auth = HTTPTokenAuth(scheme='Bearer')

        # 4. 初始化Redis管理器
        self.redis_manager = RedisManager(
            config.get('redis_url', 'redis://localhost:6379/0'),
            config.get('redis_enabled', True)
        )

        # 5. 初始化数据库管理器
        self.db_manager = DatabaseManager(config['database'])


        # 6. 初始化认证管理器
        from werkzeug.security import generate_password_hash
        import jwt

        class AuthManager:
            def __init__(self, db_manager, secret_key, token_expiration=86400):
                self.db = db_manager
                self.secret_key = secret_key
                self.token_expiration = token_expiration

            def authenticate(self, username, password):
                user = self.db.fetch_one(
                    "SELECT * FROM users WHERE username = %s AND is_active = 1"
                    if self.db.db_type == 'mysql' else
                    "SELECT * FROM users WHERE username = ? AND is_active = 1",
                    (username,)
                )

                if user and check_password_hash(user['password_hash'], password):
                    if self.db.db_type == 'mysql':
                        self.db.execute_query(
                            "UPDATE users SET last_login = NOW() WHERE id = %s",
                            (user['id'],)
                        )
                    else:
                        self.db.execute_query(
                            "UPDATE users SET last_login = datetime('now') WHERE id = ?",
                            (user['id'],)
                        )

                    token = jwt.encode({
                        'user_id': user['id'],
                        'username': user['username'],
                        'role': user['role'],
                        'exp': datetime.utcnow().timestamp() + self.token_expiration
                    }, self.secret_key, algorithm='HS256')

                    return {
                        'token': token,
                        'user': {
                            'id': user['id'],
                            'username': user['username'],
                            'role': user['role'],
                            'email': user['email'],
                            'full_name': user['full_name']
                        }
                    }

                return None

            def verify_token(self, token):
                try:
                    payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
                    return payload
                except jwt.ExpiredSignatureError:
                    return None
                except jwt.InvalidTokenError:
                    return None

        self.auth_manager = AuthManager(self.db_manager, config['secret_key'],
                                        config.get('token_expiration', 86400))

        # 7. 初始化模板管理器
        self.template_manager = EnhancedTemplateManager(config['templates_root'], self.db_manager)

        # 8. 初始化Agent管理器
        self.agent_manager = AgentManager(
            config['nacos_url'],
            config.get('nacos_namespace', 'public'),
            config.get('agent_api_port', 11187),
            config.get('agent_auth_token', 'default_token_change_me'),
            self.db_manager,
            self.redis_manager,
            config['pod_id']
        )

        # 9. 初始化任务管理器
        self.task_manager = TaskManager(
            self.db_manager,
            self.agent_manager,
            self.template_manager,
            config['services_root'],
            self.redis_manager,
            config['pod_id'],
            config.get('max_task_logs', 1000)
        )

        # 10. 初始化代理管理器（新增）
        self.proxy_manager = EnhancedProxyManager(self.agent_manager)

        # 11. 注册路由
        self._register_routes()

        # 12. 设置认证回调
        @self.auth.verify_token
        def verify_token(token):
            return self._verify_token(token)

        # 13. 后台刷新线程
        self.refresh_thread = None
        self.should_stop = False

        self.logger.info(f"当前POD ID: {config['pod_id']}")
        self.logger.info(f"使用数据库: {config['database'].get('type', 'sqlite').upper()}")
        self.logger.info(f"Redis状态: {'已启用' if self.redis_manager.enabled else '已禁用'}")
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

    def _verify_token(self, token: str) -> Optional[Dict]:
        payload = self.auth_manager.verify_token(token)
        if payload:
            return payload
        return None

    def _register_routes(self):
        """注册路由"""

        @self.app.route('/api/health', methods=['GET'])
        def health_check():
            """健康检查端点"""
            db_ok = False
            try:
                with self.db_manager.get_connection() as db:
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
                }
            })

        @self.app.route('/api/system/connections', methods=['GET'])
        @self.auth.login_required
        def get_connections():
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
                }
            })

        @self.app.route('/api/auth/login', methods=['POST'])
        def login():
            data = request.get_json()
            if not data or 'username' not in data or 'password' not in data:
                return jsonify({'error': '用户名和密码不能为空'}), 400

            result = self.auth_manager.authenticate(data['username'], data['password'])
            if result:
                return jsonify(result)
            else:
                return jsonify({'error': '用户名或密码错误'}), 401

        @self.app.route('/api/auth/profile', methods=['GET'])
        @self.auth.login_required
        def get_profile():
            return jsonify(self.auth.current_user())

        @self.app.route('/api/workspaces', methods=['GET'])
        @self.auth.login_required
        def list_workspaces():
            workspaces = self.agent_manager.list_workspaces()
            return jsonify({
                'workspaces': workspaces,
                'total': len(workspaces)
            })

        @self.app.route('/api/agents', methods=['GET'])
        @self.auth.login_required
        def list_agents():
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 20))
            workspace_id = request.args.get('workspace_id')

            agents, total = self.agent_manager.list_agents(page, per_page, workspace_id)
            return jsonify({
                'agents': agents,
                'page': page,
                'per_page': per_page,
                'total': total
            })

        @self.app.route('/api/agents/refresh', methods=['POST'])
        @self.auth.login_required
        def refresh_agents():
            self.agent_manager.refresh_agents()
            return jsonify({'message': 'Agent列表刷新完成'})

        @self.app.route('/api/tasks', methods=['GET'])
        @self.auth.login_required
        def list_tasks():
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 20))
            task_type = request.args.get('type')
            status = request.args.get('status')
            workspace_id = request.args.get('workspace_id')
            agent_key = request.args.get('agent_key')

            tasks, total = self.task_manager.list_tasks(
                page, per_page, task_type, status, workspace_id, agent_key
            )

            return jsonify({
                'tasks': tasks,
                'page': page,
                'per_page': per_page,
                'total': total
            })

        @self.app.route('/api/tasks/<task_id>', methods=['GET'])
        @self.auth.login_required
        def get_task(task_id):
            task = self.task_manager.get_task(task_id)
            if task:
                return jsonify(task)
            else:
                return jsonify({'error': '任务不存在'}), 404

        @self.app.route('/api/tasks/<task_id>/logs', methods=['GET'])
        @self.auth.login_required
        def get_task_logs(task_id):
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 100))

            logs, total = self.task_manager.get_task_logs(task_id, page, per_page)

            return jsonify({
                'logs': logs,
                'task_id': task_id,
                'page': page,
                'per_page': per_page,
                'total': total
            })

        @self.app.route('/api/tasks/<task_id>', methods=['DELETE'])
        @self.auth.login_required
        def delete_task(task_id):
            if self.task_manager.delete_task(task_id):
                return jsonify({'message': '任务删除成功'})
            else:
                return jsonify({'error': '任务删除失败'}), 500

        @self.app.route('/api/tasks/deploy', methods=['POST'])
        @self.auth.login_required
        def deploy_service():
            data = request.get_json()
            if not data or 'service_name' not in data or 'agent_key' not in data or 'template_name' not in data:
                return jsonify({'error': '服务名称、Agent和模板名称不能为空'}), 400

            task_id = self.task_manager.create_task(
                'deploy', data['service_name'], data['agent_key'],
                data['template_name'], data.get('extra_params')
            )

            return jsonify({
                'task_id': task_id,
                'message': '部署任务已创建'
            }), 202

        @self.app.route('/api/tasks/undeploy', methods=['POST'])
        @self.auth.login_required
        def undeploy_service():
            data = request.get_json()
            if not data or 'service_name' not in data or 'agent_key' not in data:
                return jsonify({'error': '服务名称和Agent不能为空'}), 400

            task_id = self.task_manager.create_task(
                'undeploy', data['service_name'], data['agent_key']
            )

            return jsonify({
                'task_id': task_id,
                'message': '卸载任务已创建'
            }), 202

        # ===================== 代理路由（修复版） =====================
        @self.app.route('/api/proxy/<agent_key>/<path:action_path>',
                        methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
        @self.auth.login_required
        def proxy_to_agent(agent_key, action_path):
            """将请求代理到指定的Agent（修复版）"""
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

                # 设置超时时间
                timeout = int(request.args.get('timeout', 30))

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
        @self.app.route('/api/proxy_simple/<agent_key>/<path:action_path>', methods=['GET'])
        @self.auth.login_required
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

        @self.app.route('/api/agent/<agent_key>/<path:action_path>',
                        methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
        @self.auth.login_required
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

        @self.app.route('/api/agent/<agent_key>/system/info', methods=['GET'])
        @self.auth.login_required
        def agent_system_info(agent_key):
            """获取Agent的系统信息（快捷方式）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint='/api/system/info'
            )

            response = jsonify(response_data)
            for key, value in response_headers.items():
                response.headers[key] = value
            response.status_code = status_code

            return response

        @self.app.route('/api/agent/<agent_key>/services', methods=['GET'])
        @self.auth.login_required
        def agent_services(agent_key):
            """获取Agent的服务列表（快捷方式）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint='/api/services'
            )

            response = jsonify(response_data)
            for key, value in response_headers.items():
                response.headers[key] = value
            response.status_code = status_code

            return response

        # 代理调试端点
        @self.app.route('/api/proxy/debug/<agent_key>', methods=['GET'])
        @self.auth.login_required
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

        @self.app.route('/api/agent/<agent_key>/health', methods=['GET'])
        @self.auth.login_required
        def agent_health(agent_key):
            """获取Agent的健康状态（快捷方式）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint='/api/health'
            )

            response = jsonify(response_data)
            for key, value in response_headers.items():
                response.headers[key] = value
            response.status_code = status_code

            return response

        @self.app.route('/api/proxy/info', methods=['GET'])
        @self.auth.login_required
        def get_proxy_info():
            """获取代理API信息"""
            proxy_info = self.proxy_manager.get_agent_proxy_info()

            # 获取可用的Agent列表
            agents = self.agent_manager.list_agents()[0]

            proxy_info['available_agents'] = [
                {
                    'key': agent['key'],
                    'hostname': agent['hostname'],
                    'ip_address': agent['ip_address'],
                    'workspace': agent['workspace_id'],
                    'status': agent['status'],
                    'last_seen': agent.get('last_seen')
                }
                for agent in agents
            ]

            return jsonify(proxy_info)

        @self.app.route('/api/proxy/test/<agent_key>', methods=['GET'])
        @self.auth.login_required
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

        @self.app.route('/api/agents/<agent_key>', methods=['GET'])
        @self.auth.login_required
        def get_agent_by_key(agent_key):
            """根据agent_key获取Agent信息"""
            try:
                # 从数据库查询Agent
                if self.db_manager.db_type == 'mysql':
                    agent_data = self.db_manager.fetch_one(
                        "SELECT * FROM agent_status WHERE agent_key = %s",
                        (agent_key,)
                    )
                else:
                    agent_data = self.db_manager.fetch_one(
                        "SELECT * FROM agent_status WHERE agent_key = ?",
                        (agent_key,)
                    )

                if not agent_data:
                    # 尝试从内存中获取
                    agent = self.agent_manager.get_agent(agent_key)
                    if agent:
                        return jsonify(agent.to_dict())
                    else:
                        return jsonify({'error': f'Agent {agent_key} not found'}), 404

                # 转换数据格式
                agent_info = {
                    'key': agent_data['agent_key'],
                    'ip_address': agent_data['ip_address'],
                    'hostname': agent_data['hostname'],
                    'workspace_id': agent_data['workspace_id'],
                    'full_name': agent_data['full_name'],
                    'status': agent_data['status'],
                    'pod_id': agent_data['pod_id']
                }

                if agent_data['last_seen']:
                    if isinstance(agent_data['last_seen'], str):
                        agent_info['last_seen'] = agent_data['last_seen']
                    else:
                        agent_info['last_seen'] = agent_data['last_seen'].isoformat()

                if agent_data['system_info']:
                    if isinstance(agent_data['system_info'], str):
                        try:
                            agent_info['system_info'] = json.loads(agent_data['system_info'])
                        except:
                            agent_info['system_info'] = agent_data['system_info']
                    else:
                        agent_info['system_info'] = agent_data['system_info']

                if agent_data['services']:
                    if isinstance(agent_data['services'], str):
                        try:
                            agent_info['services'] = json.loads(agent_data['services'])
                        except:
                            agent_info['services'] = agent_data['services']
                    else:
                        agent_info['services'] = agent_data['services']

                return jsonify(agent_info)

            except Exception as e:
                self.logger.error(f"获取Agent信息失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        # 在_register_routes方法中添加示例文档端点
        @self.app.route('/api/proxy/examples', methods=['GET'])
        @self.auth.login_required
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
                        'url': '/api/proxy/abc123def456/api/system/info',
                        'curl': 'curl -X GET -H "Authorization: Bearer YOUR_TOKEN" http://server:18080/api/proxy/abc123def456/api/system/info'
                    },
                    {
                        'description': '获取Agent服务列表',
                        'method': 'GET',
                        'url': '/api/proxy/abc123def456/api/services',
                        'curl': 'curl -X GET -H "Authorization: Bearer YOUR_TOKEN" http://server:18080/api/proxy/abc123def456/api/services'
                    },
                    {
                        'description': '启动Agent上的服务',
                        'method': 'POST',
                        'url': '/api/proxy/abc123def456/api/services/myservice/start',
                        'curl': 'curl -X POST -H "Authorization: Bearer YOUR_TOKEN" http://server:18080/api/proxy/abc123def456/api/services/myservice/start'
                    },
                    {
                        'description': '获取服务日志',
                        'method': 'GET',
                        'url': '/api/proxy/abc123def456/api/services/myservice/logs?tail=100',
                        'curl': 'curl -X GET -H "Authorization: Bearer YOUR_TOKEN" "http://server:18080/api/proxy/abc123def456/api/services/myservice/logs?tail=100"'
                    },
                    {
                        'description': '上传ZIP文件创建服务',
                        'method': 'POST',
                        'url': '/api/proxy/abc123def456/api/services/zip',
                        'content_type': 'multipart/form-data',
                        'form_data': {
                            'name': 'myapp',
                            'file': 'myapp.zip'
                        },
                        'curl': 'curl -X POST -H "Authorization: Bearer YOUR_TOKEN" -F "name=myapp" -F "file=@myapp.zip" http://server:18080/api/proxy/abc123def456/api/services/zip'
                    },
                    {
                        'description': '从YAML创建服务',
                        'method': 'POST',
                        'url': '/api/proxy/abc123def456/api/services/yaml',
                        'content_type': 'application/json',
                        'body': {
                            'name': 'myservice',
                            'yaml': 'version: "3"\nservices:\n  web:\n    image: nginx:latest'
                        },
                        'curl': 'curl -X POST -H "Authorization: Bearer YOUR_TOKEN" -H "Content-Type: application/json" -d \'{"name":"myservice","yaml":"version: \\"3\\"\\nservices:\\n  web:\\n    image: nginx:latest"}\' http://server:18080/api/proxy/abc123def456/api/services/yaml'
                    }
                ],
                'tips': [
                    '使用 /api/proxy/info 获取所有可用Agent',
                    '使用 /api/proxy/test/{agent_key} 测试代理连接',
                    '文件上传需要设置 Content-Type: multipart/form-data',
                    '支持流式响应，添加 ?stream=true 参数',
                    '所有原始请求头（除敏感头外）都会转发到Agent'
                ]
            }

            return jsonify(examples)

        # ===================== 模板管理API（完整版） =====================

        @self.app.route('/api/templates', methods=['GET'])
        @self.auth.login_required
        def list_templates():
            """列出所有模板（包含文件大小信息）"""
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 20))

            templates, total = self.template_manager.list_templates(page, per_page)
            return jsonify({
                'templates': templates,
                'page': page,
                'per_page': per_page,
                'total': total
            })

        @self.app.route('/api/templates', methods=['POST'])
        @self.auth.login_required
        def upload_template():
            """上传模板"""
            if 'file' not in request.files:
                return jsonify({'error': '未找到文件'}), 400

            file = request.files['file']
            name = request.form.get('name')
            description = request.form.get('description', '')
            template_type = request.form.get('type', 'yaml')

            if not name:
                return jsonify({'error': '模板名称不能为空'}), 400

            if not file.filename:
                return jsonify({'error': '文件名不能为空'}), 400

            # 读取文件内容
            file_content = file.read()

            # 获取当前用户
            current_user = self.auth.current_user() if hasattr(self.auth, 'current_user') else {'username': 'admin'}

            success, message = self.template_manager.create_template(
                name, description, template_type, file_content, file.filename,
                current_user.get('username', 'admin')
            )

            if success:
                return jsonify({'message': message}), 201
            else:
                return jsonify({'error': message}), 400

        @self.app.route('/api/templates/<name>', methods=['GET'])
        @self.auth.login_required
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

        @self.app.route('/api/templates/<name>/yaml', methods=['GET'])
        @self.auth.login_required
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

        @self.app.route('/api/templates/<name>/yaml', methods=['PUT'])
        @self.auth.login_required
        def update_template_yaml(name):
            """更新模板的YAML内容"""
            data = request.get_json()
            if not data:
                return jsonify({'error': '请求体必须为JSON'}), 400

            yaml_content = data.get('yaml_content')
            if not yaml_content:
                return jsonify({'error': 'YAML内容不能为空'}), 400

            # 获取当前用户
            current_user = self.auth.current_user() if hasattr(self.auth, 'current_user') else {'username': 'admin'}

            success, message = self.template_manager.update_yaml_content(
                name, yaml_content, current_user.get('username', 'admin')
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

        @self.app.route('/api/templates/<name>/download', methods=['GET'])
        @self.auth.login_required
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

        @self.app.route('/api/templates/<name>/file', methods=['GET'])
        @self.auth.login_required
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
                elif file_info['type'] == 'zip':
                    mimetype = 'application/zip'
                    as_attachment = True
                else:
                    mimetype = 'application/octet-stream'
                    as_attachment = True

                # 确定文件名
                if as_attachment:
                    filename = f"{name}.{file_info['type']}"
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

        @self.app.route('/api/templates/<name>/content', methods=['GET'])
        @self.auth.login_required
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

        @self.app.route('/api/templates/<name>/info', methods=['GET'])
        @self.auth.login_required
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

        @self.app.route('/api/templates/<name>', methods=['DELETE'])
        @self.auth.login_required
        def delete_template(name):
            """删除模板"""
            success, message = self.template_manager.delete_template(name)

            if success:
                return jsonify({'message': message})
            else:
                return jsonify({'error': message}), 400

        @self.app.route('/api/templates/download/batch', methods=['POST'])
        @self.auth.login_required
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

        @self.app.route('/api/templates/docs', methods=['GET'])
        @self.auth.login_required
        def get_templates_docs():
            """获取模板API使用文档"""
            docs = {
                'description': '模板管理API，支持创建、查看、更新、删除和下载模板',
                'endpoints': {
                    'GET /api/templates': '列出所有模板（包含文件大小信息）',
                    'POST /api/templates': '上传新模板',
                    'GET /api/templates/{name}': '获取模板详细信息（包含文件大小）',
                    'DELETE /api/templates/{name}': '删除模板',
                    'GET /api/templates/{name}/yaml': '获取模板的YAML内容（支持yaml和zip格式）',
                    'PUT /api/templates/{name}/yaml': '更新模板的YAML内容',
                    'GET /api/templates/{name}/download': '下载模板文件',
                    'GET /api/templates/{name}/file': '获取模板原始文件',
                    'GET /api/templates/{name}/content': '获取模板内容（JSON格式）',
                    'GET /api/templates/{name}/info': '获取模板详细信息（包含文件列表）',
                    'POST /api/templates/download/batch': '批量下载模板'
                },
                'template_types': {
                    'yaml': 'YAML格式的服务定义文件',
                    'zip': 'ZIP压缩包，包含服务定义文件和其他相关文件'
                },
                'yaml_content_requirements': {
                    'must_contain': 'services部分',
                    'format': '标准的Docker Compose YAML格式'
                },
                'examples': {
                    'create_template': {
                        'method': 'POST',
                        'url': '/api/templates',
                        'content_type': 'multipart/form-data',
                        'form_data': {
                            'name': 'my-service',
                            'description': '我的服务模板',
                            'type': 'yaml',
                            'file': 'service.yaml文件'
                        }
                    },
                    'get_yaml_content': {
                        'method': 'GET',
                        'url': '/api/templates/my-service/yaml',
                        'response': {
                            'name': 'my-service',
                            'yaml_content': 'version: "3"\nservices:\n  web:\n    image: nginx:latest',
                            'status': 'success'
                        }
                    },
                    'update_yaml_content': {
                        'method': 'PUT',
                        'url': '/api/templates/my-service/yaml',
                        'content_type': 'application/json',
                        'body': {
                            'yaml_content': 'version: "3"\nservices:\n  web:\n    image: nginx:latest\n    ports:\n      - "80:80"'
                        }
                    },
                    'download_template': {
                        'method': 'GET',
                        'url': '/api/templates/my-service/download',
                        'query_params': {
                            'format': 'original|yaml|zip',
                            'as_zip': 'true|false',
                            'include_all': 'true|false'
                        }
                    }
                },
                'size_information': {
                    'file_size': '原始模板文件的大小（字节）',
                    'directory_size': '模板解压后目录的总大小（字节）',
                    'metadata': '包含文件大小和其他元数据的JSON对象'
                },
                'notes': [
                    '所有API都需要认证，使用Authorization: Bearer {token}',
                    'YAML内容更新会验证格式，确保包含services部分',
                    'ZIP模板更新时会更新解压目录中的YAML并重新打包',
                    '文件下载支持多种格式和打包选项'
                ]
            }

            return jsonify(docs)

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

    # 打印启动信息
    print("=" * 60)
    print("WEB API 服务器 - Docker Compose服务管理中心")
    print(f"版本: 2.0.0 (增强连接检查和分布式锁修复版)")
    print(f"POD ID: {config['pod_id']}")
    print(f"数据库: {config['database'].get('type', 'sqlite').upper()}")
    print(f"Redis: {'启用' if config.get('redis_enabled', True) else '禁用'}")
    print(f"监听地址: {config['host']}:{config['port']}")
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