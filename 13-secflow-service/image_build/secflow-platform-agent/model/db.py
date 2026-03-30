import logging
import os
import threading
from typing import Dict, List, Any, Optional, Tuple, Union

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

    def execute(self, query: str, params: tuple = (), commit: bool = True):
        """执行SQL语句"""
        cursor = self.connection.cursor()
        try:
            cursor.execute(query, params)
            if commit:
                self.connection.commit()
            return cursor
        except Exception as e:
            if commit:
                self.connection.rollback()
            raise e

    def executemany(self, query: str, params_list: List[tuple], commit: bool = True):
        """批量执行SQL语句"""
        cursor = self.connection.cursor()
        try:
            cursor.executemany(query, params_list)
            if commit:
                self.connection.commit()
            return cursor
        except Exception as e:
            if commit:
                self.connection.rollback()
            raise e

    def fetch_one(self, query: str, params: tuple = ()):
        """获取单条记录"""
        cursor = self.connection.cursor()
        try:
            cursor.execute(query, params)
            result = cursor.fetchone()

            if self.db_type == 'sqlite' and result:
                return dict(result)
            return result
        finally:
            cursor.close()

    def fetch_all(self, query: str, params: tuple = ()):
        """获取所有记录"""
        cursor = self.connection.cursor()
        try:
            cursor.execute(query, params)
            results = cursor.fetchall()

            if self.db_type == 'sqlite':
                return [dict(row) for row in results]
            return results
        finally:
            cursor.close()

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
    """数据库管理器（支持MySQL和SQLite）- 使用连接池"""

    def __init__(self, db_config: Dict):
        self.db_config = db_config
        self.db_type = db_config.get('type', 'sqlite')
        self.table_prefix = db_config.get('table_prefix', 'secflow_agent_')
        self.logger = logging.getLogger(__name__)

        # 初始化连接池（但不存储连接）
        # 首次使用时从连接池获取
        self._init_connection_pool()

        # 初始化数据库表结构
        self.init_database()
        self.logger.info(f"数据库连接池已初始化 ({self.db_type})")

    def get_table_name(self, suffix: str) -> str:
        """获取带前缀的完整表名"""
        return f"{self.table_prefix}{suffix}"

    def _init_connection_pool(self):
        """预初始化连接池"""
        conn = DatabaseConnection(self.db_config, use_pool=True)
        conn.connect()  # 这会初始化连接池
        conn.close()    # 立即归还，以后每次从池中获取

    def get_connection(self) -> DatabaseConnection:
        """获取独立的数据库连接（线程安全）"""
        conn = DatabaseConnection(self.db_config, use_pool=True)
        if not conn.connect():
            raise ConnectionError(f"无法从连接池获取{self.db_type}数据库连接")
        return conn

    def close(self):
        """关闭连接池（通常在应用退出时调用）"""
        if DatabaseConnection._mysql_pool:
            DatabaseConnection._mysql_pool.close()
            self.logger.info("数据库连接池已关闭")

    def init_database(self):
        """初始化数据库（创建表和索引）"""
        conn = self.get_connection()
        try:
            db = conn
            prefix = self.table_prefix

            # 创建服务模板表
            table_templates = f"{prefix}service_templates"
            if self.db_type == 'mysql':
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_templates} (
                               id INT AUTO_INCREMENT PRIMARY KEY,
                               name VARCHAR(100) UNIQUE NOT NULL,
                               description TEXT,
                               type VARCHAR(20) NOT NULL,
                               file_path TEXT NOT NULL,
                               visibility VARCHAR(20) NOT NULL DEFAULT 'shared',
                               owner_id VARCHAR(64),
                               owner_name VARCHAR(100),
                               created_by VARCHAR(100),
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                               metadata JSON,
                               INDEX idx_templates_name (name),
                               INDEX idx_templates_updated (updated_at),
                               INDEX idx_templates_visibility (visibility),
                               INDEX idx_templates_owner_id (owner_id)
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_templates} (
                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                               name TEXT UNIQUE NOT NULL,
                               description TEXT,
                               type TEXT NOT NULL,
                               file_path TEXT NOT NULL,
                               visibility TEXT NOT NULL DEFAULT 'shared',
                               owner_id TEXT,
                               owner_name TEXT,
                               created_by TEXT,
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               metadata TEXT
                           )
                           ''')

            # 创建任务表
            table_tasks = f"{prefix}tasks"
            if self.db_type == 'mysql':
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_tasks} (
                               id INT AUTO_INCREMENT PRIMARY KEY,
                               task_id VARCHAR(36) UNIQUE NOT NULL,
                               task_type VARCHAR(20) NOT NULL,
                               service_name VARCHAR(100) NOT NULL,
                               agent_key VARCHAR(32) NOT NULL,
                               project_id VARCHAR(100),
                               template_name VARCHAR(255),
                               extra_params JSON,
                               status VARCHAR(20) NOT NULL DEFAULT 'pending',
                               progress INT DEFAULT 0,
                               message TEXT,
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               started_at TIMESTAMP NULL,
                               completed_at TIMESTAMP NULL,
                               pod_id VARCHAR(100),
                               worker_id VARCHAR(100),
                               worker_pod_id VARCHAR(100),
                               lease_until TIMESTAMP NULL,
                               heartbeat_at TIMESTAMP NULL,
                               attempt_count INT DEFAULT 0,
                               INDEX idx_tasks_task_id (task_id),
                               INDEX idx_tasks_status (status),
                               INDEX idx_tasks_agent_key (agent_key),
                               INDEX idx_tasks_project (project_id),
                               INDEX idx_tasks_created (created_at),
                               INDEX idx_tasks_worker (worker_id),
                               INDEX idx_tasks_lease (lease_until)
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_tasks} (
                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                               task_id TEXT UNIQUE NOT NULL,
                               task_type TEXT NOT NULL,
                               service_name TEXT NOT NULL,
                               agent_key TEXT NOT NULL,
                               project_id TEXT,
                               template_name TEXT,
                               extra_params TEXT,
                               status TEXT NOT NULL DEFAULT 'pending',
                               progress INTEGER DEFAULT 0,
                               message TEXT,
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               started_at TIMESTAMP,
                               completed_at TIMESTAMP,
                               pod_id TEXT,
                               worker_id TEXT,
                               worker_pod_id TEXT,
                               lease_until TIMESTAMP,
                               heartbeat_at TIMESTAMP,
                               attempt_count INTEGER DEFAULT 0
                           )
                           ''')
                # 为SQLite创建索引
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_tasks_task_id ON {table_tasks}(task_id)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_tasks_status ON {table_tasks}(status)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_tasks_agent_key ON {table_tasks}(agent_key)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_tasks_worker ON {table_tasks}(worker_id)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_tasks_lease ON {table_tasks}(lease_until)')

            # 创建任务日志表
            table_task_logs = f"{prefix}task_logs"
            if self.db_type == 'mysql':
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_task_logs} (
                               id INT AUTO_INCREMENT PRIMARY KEY,
                               log_id VARCHAR(36) UNIQUE NOT NULL,
                               task_id VARCHAR(36) NOT NULL,
                               level VARCHAR(10) NOT NULL DEFAULT 'INFO',
                               message TEXT NOT NULL,
                               timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               pod_id VARCHAR(100),
                               INDEX idx_logs_task_id (task_id),
                               INDEX idx_logs_timestamp (timestamp),
                               FOREIGN KEY (task_id) REFERENCES {table_tasks}(task_id) ON DELETE CASCADE
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_task_logs} (
                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                               log_id TEXT UNIQUE NOT NULL,
                               task_id TEXT NOT NULL,
                               level TEXT NOT NULL DEFAULT 'INFO',
                               message TEXT NOT NULL,
                               timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               pod_id TEXT,
                               FOREIGN KEY (task_id) REFERENCES {table_tasks}(task_id) ON DELETE CASCADE
                           )
                           ''')
                # 为SQLite创建索引
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_logs_task_id ON {table_task_logs}(task_id)')

            # 创建Agent状态表（用于多POD状态同步）
            table_agent_status = f"{prefix}agent_status"
            if self.db_type == 'mysql':
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_agent_status} (
                               id INT AUTO_INCREMENT PRIMARY KEY,
                               agent_key VARCHAR(32) UNIQUE NOT NULL,
                               ip_address VARCHAR(45) NOT NULL,
                               hostname VARCHAR(100) NOT NULL,
                               project_id VARCHAR(100) NOT NULL,
                               full_name VARCHAR(255) NOT NULL,
                               status VARCHAR(20) NOT NULL DEFAULT 'unknown',
                               last_seen TIMESTAMP NULL,
                               system_info JSON,
                               daemon_info JSON,
                               services JSON,
                               pod_id VARCHAR(100),
                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                               INDEX idx_agent_status_key (agent_key),
                               INDEX idx_agent_status_project (project_id),
                               INDEX idx_agent_status_updated (updated_at)
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_agent_status} (
                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                               agent_key TEXT UNIQUE NOT NULL,
                               ip_address TEXT NOT NULL,
                               hostname TEXT NOT NULL,
                               project_id TEXT NOT NULL,
                               full_name TEXT NOT NULL,
                               status TEXT NOT NULL DEFAULT 'unknown',
                               last_seen TIMESTAMP,
                               system_info TEXT,
                               daemon_info TEXT,
                               services TEXT,
                               pod_id TEXT,
                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                           )
                           ''')
                # 为SQLite创建索引
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_agent_status_project ON {table_agent_status}(project_id)')

            # 创建Agent服务聚合表（用于全量服务发现）
            table_agent_services = f"{prefix}agent_services"
            if self.db_type == 'mysql':
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_agent_services} (
                               id BIGINT AUTO_INCREMENT PRIMARY KEY,
                               service_uid VARCHAR(256) UNIQUE NOT NULL,
                               project_id VARCHAR(100) NOT NULL,
                               agent_key VARCHAR(64) NOT NULL,
                               agent_hostname VARCHAR(100),
                               agent_ip VARCHAR(64),
                               service_name VARCHAR(200) NOT NULL,
                               image TEXT,
                               status VARCHAR(32) DEFAULT 'unknown',
                               tags_json JSON,
                               ports_json JSON,
                               raw_json JSON,
                               source VARCHAR(32) DEFAULT 'pull',
                               is_stale TINYINT(1) DEFAULT 0,
                               first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                               pod_id VARCHAR(100),
                               INDEX idx_agent_services_project (project_id),
                               INDEX idx_agent_services_agent (agent_key),
                               INDEX idx_agent_services_status (status),
                               INDEX idx_agent_services_name (service_name),
                               INDEX idx_agent_services_seen (last_seen_at)
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_agent_services} (
                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                               service_uid TEXT UNIQUE NOT NULL,
                               project_id TEXT NOT NULL,
                               agent_key TEXT NOT NULL,
                               agent_hostname TEXT,
                               agent_ip TEXT,
                               service_name TEXT NOT NULL,
                               image TEXT,
                               status TEXT DEFAULT 'unknown',
                               tags_json TEXT,
                               ports_json TEXT,
                               raw_json TEXT,
                               source TEXT DEFAULT 'pull',
                               is_stale INTEGER DEFAULT 0,
                               first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               pod_id TEXT
                           )
                           ''')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_agent_services_project ON {table_agent_services}(project_id)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_agent_services_agent ON {table_agent_services}(agent_key)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_agent_services_status ON {table_agent_services}(status)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_agent_services_name ON {table_agent_services}(service_name)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_agent_services_seen ON {table_agent_services}(last_seen_at)')

            # 创建服务同步历史表
            table_sync_logs = f"{prefix}service_sync_logs"
            if self.db_type == 'mysql':
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_sync_logs} (
                               id BIGINT AUTO_INCREMENT PRIMARY KEY,
                               sync_id VARCHAR(64) UNIQUE NOT NULL,
                               scope VARCHAR(32) NOT NULL,
                               project_id VARCHAR(100),
                               agent_key VARCHAR(64),
                               stale_only TINYINT(1) DEFAULT 0,
                               status VARCHAR(20) NOT NULL DEFAULT 'ok',
                               total INT DEFAULT 0,
                               ok_count INT DEFAULT 0,
                               fail_count INT DEFAULT 0,
                               message TEXT,
                               details_json JSON,
                               pod_id VARCHAR(100),
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               INDEX idx_sync_logs_created (created_at),
                               INDEX idx_sync_logs_scope (scope),
                               INDEX idx_sync_logs_project (project_id),
                               INDEX idx_sync_logs_agent (agent_key)
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_sync_logs} (
                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                               sync_id TEXT UNIQUE NOT NULL,
                               scope TEXT NOT NULL,
                               project_id TEXT,
                               agent_key TEXT,
                               stale_only INTEGER DEFAULT 0,
                               status TEXT NOT NULL DEFAULT 'ok',
                               total INTEGER DEFAULT 0,
                               ok_count INTEGER DEFAULT 0,
                               fail_count INTEGER DEFAULT 0,
                               message TEXT,
                               details_json TEXT,
                               pod_id TEXT,
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                           )
                           ''')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_sync_logs_created ON {table_sync_logs}(created_at)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_sync_logs_scope ON {table_sync_logs}(scope)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_sync_logs_project ON {table_sync_logs}(project_id)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_sync_logs_agent ON {table_sync_logs}(agent_key)')

            # 创建服务实例与模板绑定表
            table_service_bindings = f"{prefix}service_template_bindings"
            if self.db_type == 'mysql':
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_service_bindings} (
                               id BIGINT AUTO_INCREMENT PRIMARY KEY,
                               project_id VARCHAR(100) NOT NULL,
                               agent_key VARCHAR(64) NOT NULL,
                               service_name VARCHAR(200) NOT NULL,
                               template_id INT NULL,
                               template_name VARCHAR(255) NOT NULL,
                               source_task_id VARCHAR(64),
                               source VARCHAR(32) DEFAULT 'deploy',
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                               UNIQUE KEY uniq_binding (project_id, agent_key, service_name),
                               INDEX idx_bindings_project (project_id),
                               INDEX idx_bindings_agent (agent_key),
                               INDEX idx_bindings_template (template_name)
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_service_bindings} (
                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                               project_id TEXT NOT NULL,
                               agent_key TEXT NOT NULL,
                               service_name TEXT NOT NULL,
                               template_id INTEGER,
                               template_name TEXT NOT NULL,
                               source_task_id TEXT,
                               source TEXT DEFAULT 'deploy',
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                           )
                           ''')
                db.execute(
                    f'CREATE UNIQUE INDEX IF NOT EXISTS uniq_binding ON {table_service_bindings}(project_id, agent_key, service_name)'
                )
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_bindings_project ON {table_service_bindings}(project_id)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_bindings_agent ON {table_service_bindings}(agent_key)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_bindings_template ON {table_service_bindings}(template_name)')

            table_ai_batches = f"{prefix}ai_agent_session_batches"
            if self.db_type == 'mysql':
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_ai_batches} (
                               id BIGINT AUTO_INCREMENT PRIMARY KEY,
                               batch_id VARCHAR(64) UNIQUE NOT NULL,
                               project_id VARCHAR(100) NOT NULL,
                               created_by VARCHAR(100),
                               status VARCHAR(32) DEFAULT 'pending',
                               request_json JSON,
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                               INDEX idx_ai_batches_project (project_id),
                               INDEX idx_ai_batches_status (status)
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_ai_batches} (
                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                               batch_id TEXT UNIQUE NOT NULL,
                               project_id TEXT NOT NULL,
                               created_by TEXT,
                               status TEXT DEFAULT 'pending',
                               request_json TEXT,
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                           )
                           ''')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_ai_batches_project ON {table_ai_batches}(project_id)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_ai_batches_status ON {table_ai_batches}(status)')

            table_ai_batch_items = f"{prefix}ai_agent_session_batch_items"
            if self.db_type == 'mysql':
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_ai_batch_items} (
                               id BIGINT AUTO_INCREMENT PRIMARY KEY,
                               batch_id VARCHAR(64) NOT NULL,
                               project_id VARCHAR(100) NOT NULL,
                               agent_key VARCHAR(64) NOT NULL,
                               service_name VARCHAR(200) NOT NULL,
                               helper_session_id VARCHAR(128),
                               helper_agent_ids_json JSON,
                               status VARCHAR(32) DEFAULT 'pending',
                               last_error TEXT,
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                               UNIQUE KEY uniq_ai_batch_item (batch_id, agent_key, service_name),
                               INDEX idx_ai_batch_items_project (project_id),
                               INDEX idx_ai_batch_items_status (status)
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_ai_batch_items} (
                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                               batch_id TEXT NOT NULL,
                               project_id TEXT NOT NULL,
                               agent_key TEXT NOT NULL,
                               service_name TEXT NOT NULL,
                               helper_session_id TEXT,
                               helper_agent_ids_json TEXT,
                               status TEXT DEFAULT 'pending',
                               last_error TEXT,
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                           )
                           ''')
                db.execute(f'CREATE UNIQUE INDEX IF NOT EXISTS uniq_ai_batch_item ON {table_ai_batch_items}(batch_id, agent_key, service_name)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_ai_batch_items_project ON {table_ai_batch_items}(project_id)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_ai_batch_items_status ON {table_ai_batch_items}(status)')

            table_ai_batch_messages = f"{prefix}ai_agent_session_batch_messages"
            if self.db_type == 'mysql':
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_ai_batch_messages} (
                               id BIGINT AUTO_INCREMENT PRIMARY KEY,
                               batch_id VARCHAR(64) NOT NULL,
                               round_no INT NOT NULL,
                               role VARCHAR(20) DEFAULT 'user',
                               content TEXT,
                               response_json JSON,
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               UNIQUE KEY uniq_ai_batch_round (batch_id, round_no),
                               INDEX idx_ai_batch_messages_batch (batch_id)
                           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                           ''')
            else:
                db.execute(f'''
                           CREATE TABLE IF NOT EXISTS {table_ai_batch_messages} (
                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                               batch_id TEXT NOT NULL,
                               round_no INTEGER NOT NULL,
                               role TEXT DEFAULT 'user',
                               content TEXT,
                               response_json TEXT,
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                           )
                           ''')
                db.execute(f'CREATE UNIQUE INDEX IF NOT EXISTS uniq_ai_batch_round ON {table_ai_batch_messages}(batch_id, round_no)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_ai_batch_messages_batch ON {table_ai_batch_messages}(batch_id)')

            # 兼容历史数据库：补齐新增列
            self._ensure_agent_status_columns(db, table_agent_status)
            self._ensure_agent_services_columns(db, table_agent_services)
            self._ensure_template_columns(db, table_templates)
            self._ensure_task_columns(db, table_tasks)
            self._ensure_service_template_binding_columns(db, table_service_bindings)

            self.logger.info(f"数据库初始化完成（使用{self.db_type.upper()}, 表前缀: {prefix}）")
        finally:
            conn.close()

    def _ensure_agent_status_columns(self, db: DatabaseConnection, table_name: str):
        """确保 agent_status 表包含新增字段（历史库自动迁移）"""
        try:
            if self.db_type == 'mysql':
                columns = db.fetch_all(
                    """
                    SELECT COLUMN_NAME
                    FROM information_schema.columns
                    WHERE table_schema = DATABASE() AND table_name = %s
                    """,
                    (table_name,)
                )
                existing = {item['COLUMN_NAME'] for item in columns}
                if 'daemon_info' not in existing:
                    db.execute(f"ALTER TABLE {table_name} ADD COLUMN daemon_info JSON NULL")
                    self.logger.info(f"数据库迁移: 已为 {table_name} 添加 daemon_info 列")
            else:
                columns = db.fetch_all(f"PRAGMA table_info({table_name})")
                existing = {item['name'] for item in columns}
                if 'daemon_info' not in existing:
                    db.execute(f"ALTER TABLE {table_name} ADD COLUMN daemon_info TEXT")
                    self.logger.info(f"数据库迁移: 已为 {table_name} 添加 daemon_info 列")
        except Exception as e:
            self.logger.error(f"检查/迁移 {table_name} 表字段失败: {str(e)}")

    def _ensure_template_columns(self, db: DatabaseConnection, table_name: str):
        """确保 service_templates 表包含模板可见性和归属字段（历史库自动迁移）"""
        try:
            if self.db_type == 'mysql':
                columns = db.fetch_all(
                    """
                    SELECT COLUMN_NAME
                    FROM information_schema.columns
                    WHERE table_schema = DATABASE() AND table_name = %s
                    """,
                    (table_name,)
                )
                existing = {item['COLUMN_NAME'] for item in columns}

                if 'visibility' not in existing:
                    db.execute(
                        f"ALTER TABLE {table_name} ADD COLUMN visibility VARCHAR(20) NOT NULL DEFAULT 'shared'"
                    )
                    db.execute(f"ALTER TABLE {table_name} ADD INDEX idx_templates_visibility (visibility)")
                    self.logger.info(f"数据库迁移: 已为 {table_name} 添加 visibility 列")
                if 'owner_id' not in existing:
                    db.execute(f"ALTER TABLE {table_name} ADD COLUMN owner_id VARCHAR(64) NULL")
                    db.execute(f"ALTER TABLE {table_name} ADD INDEX idx_templates_owner_id (owner_id)")
                    self.logger.info(f"数据库迁移: 已为 {table_name} 添加 owner_id 列")
                if 'owner_name' not in existing:
                    db.execute(f"ALTER TABLE {table_name} ADD COLUMN owner_name VARCHAR(100) NULL")
                    self.logger.info(f"数据库迁移: 已为 {table_name} 添加 owner_name 列")
            else:
                columns = db.fetch_all(f"PRAGMA table_info({table_name})")
                existing = {item['name'] for item in columns}

                if 'visibility' not in existing:
                    db.execute(
                        f"ALTER TABLE {table_name} ADD COLUMN visibility TEXT NOT NULL DEFAULT 'shared'"
                    )
                    self.logger.info(f"数据库迁移: 已为 {table_name} 添加 visibility 列")
                if 'owner_id' not in existing:
                    db.execute(f"ALTER TABLE {table_name} ADD COLUMN owner_id TEXT")
                    self.logger.info(f"数据库迁移: 已为 {table_name} 添加 owner_id 列")
                if 'owner_name' not in existing:
                    db.execute(f"ALTER TABLE {table_name} ADD COLUMN owner_name TEXT")
                    self.logger.info(f"数据库迁移: 已为 {table_name} 添加 owner_name 列")
                db.execute(f"CREATE INDEX IF NOT EXISTS idx_templates_visibility ON {table_name}(visibility)")
                db.execute(f"CREATE INDEX IF NOT EXISTS idx_templates_owner_id ON {table_name}(owner_id)")

            # 历史数据默认迁移为共享模板，避免升级后数据不可见
            if self.db_type == 'mysql':
                db.execute(
                    f"UPDATE {table_name} SET visibility = 'shared' "
                    "WHERE visibility IS NULL OR visibility = ''"
                )
            else:
                db.execute(
                    f"UPDATE {table_name} SET visibility = 'shared' "
                    "WHERE visibility IS NULL OR visibility = ''"
                )
        except Exception as e:
            self.logger.error(f"检查/迁移 {table_name} 模板字段失败: {str(e)}")

    def _ensure_agent_services_columns(self, db: DatabaseConnection, table_name: str):
        """确保 agent_services 表包含 tags_json 字段。"""
        try:
            if self.db_type == 'mysql':
                columns = db.fetch_all(
                    """
                    SELECT COLUMN_NAME
                    FROM information_schema.columns
                    WHERE table_schema = DATABASE() AND table_name = %s
                    """,
                    (table_name,)
                )
                existing = {item['COLUMN_NAME'] for item in columns}
                if 'tags_json' not in existing:
                    db.execute(f"ALTER TABLE {table_name} ADD COLUMN tags_json JSON NULL")
                    self.logger.info(f"数据库迁移: 已为 {table_name} 添加 tags_json 列")
            else:
                columns = db.fetch_all(f"PRAGMA table_info({table_name})")
                existing = {item['name'] for item in columns}
                if 'tags_json' not in existing:
                    db.execute(f"ALTER TABLE {table_name} ADD COLUMN tags_json TEXT")
                    self.logger.info(f"数据库迁移: 已为 {table_name} 添加 tags_json 列")
        except Exception as e:
            self.logger.error(f"检查/迁移 {table_name} 服务聚合字段失败: {str(e)}")

    def _ensure_task_columns(self, db: DatabaseConnection, table_name: str):
        """确保 tasks 表包含多副本 worker 调度所需字段。"""
        try:
            required = {
                'template_name': "VARCHAR(255) NULL" if self.db_type == 'mysql' else "TEXT",
                'extra_params': "JSON NULL" if self.db_type == 'mysql' else "TEXT",
                'worker_id': "VARCHAR(100) NULL" if self.db_type == 'mysql' else "TEXT",
                'worker_pod_id': "VARCHAR(100) NULL" if self.db_type == 'mysql' else "TEXT",
                'lease_until': "TIMESTAMP NULL" if self.db_type == 'mysql' else "TIMESTAMP",
                'heartbeat_at': "TIMESTAMP NULL" if self.db_type == 'mysql' else "TIMESTAMP",
                'attempt_count': "INT DEFAULT 0" if self.db_type == 'mysql' else "INTEGER DEFAULT 0",
            }

            if self.db_type == 'mysql':
                columns = db.fetch_all(
                    """
                    SELECT COLUMN_NAME
                    FROM information_schema.columns
                    WHERE table_schema = DATABASE() AND table_name = %s
                    """,
                    (table_name,)
                )
                existing = {item['COLUMN_NAME'] for item in columns}
                for column, ddl in required.items():
                    if column not in existing:
                        db.execute(f"ALTER TABLE {table_name} ADD COLUMN {column} {ddl}")
                        self.logger.info(f"数据库迁移: 已为 {table_name} 添加 {column} 列")
                index_map = {
                    'idx_tasks_worker': 'worker_id',
                    'idx_tasks_lease': 'lease_until',
                }
                existing_indexes = db.fetch_all(
                    """
                    SELECT INDEX_NAME
                    FROM information_schema.statistics
                    WHERE table_schema = DATABASE() AND table_name = %s
                    """,
                    (table_name,)
                )
                existing_index_names = {item['INDEX_NAME'] for item in existing_indexes}
                for idx_name, column in index_map.items():
                    if idx_name not in existing_index_names:
                        db.execute(f"CREATE INDEX {idx_name} ON {table_name}({column})")
            else:
                columns = db.fetch_all(f"PRAGMA table_info({table_name})")
                existing = {item['name'] for item in columns}
                for column, ddl in required.items():
                    if column not in existing:
                        db.execute(f"ALTER TABLE {table_name} ADD COLUMN {column} {ddl}")
                        self.logger.info(f"数据库迁移: 已为 {table_name} 添加 {column} 列")
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_tasks_worker ON {table_name}(worker_id)')
                db.execute(f'CREATE INDEX IF NOT EXISTS idx_tasks_lease ON {table_name}(lease_until)')
        except Exception as e:
            self.logger.error(f"检查/迁移 {table_name} 任务字段失败: {str(e)}")

    def _ensure_service_template_binding_columns(self, db: DatabaseConnection, table_name: str):
        """确保 service_template_bindings 表包含部署快照字段。"""
        try:
            if self.db_type == 'mysql':
                columns = db.fetch_all(
                    """
                    SELECT COLUMN_NAME
                    FROM information_schema.columns
                    WHERE table_schema = DATABASE() AND table_name = %s
                    """,
                    (table_name,)
                )
                existing = {item['COLUMN_NAME'] for item in columns}
                if 'llm_provider_binding_json' not in existing:
                    db.execute(f"ALTER TABLE {table_name} ADD COLUMN llm_provider_binding_json JSON NULL")
                    self.logger.info(f"数据库迁移: 已为 {table_name} 添加 llm_provider_binding_json 列")
            else:
                columns = db.fetch_all(f"PRAGMA table_info({table_name})")
                existing = {item['name'] for item in columns}
                if 'llm_provider_binding_json' not in existing:
                    db.execute(f"ALTER TABLE {table_name} ADD COLUMN llm_provider_binding_json TEXT")
                    self.logger.info(f"数据库迁移: 已为 {table_name} 添加 llm_provider_binding_json 列")
        except Exception as e:
            self.logger.error(f"检查/迁移 {table_name} 服务绑定字段失败: {str(e)}")

    def execute_query(self, query: str, params: tuple = ()):
        """执行查询 - 使用持久化连接"""
        db = self.get_connection()
        try:
            return db.execute(query, params)
        finally:
            db.close()

    def execute_transaction(self, queries: List[Tuple[str, tuple]]):
        """执行事务（多个查询）- 使用持久化连接"""
        db = self.get_connection()
        try:
            cursor = db.connection.cursor()
            try:
                for query, params in queries:
                    cursor.execute(query, params)
                db.connection.commit()
            except Exception:
                db.connection.rollback()
                raise
            finally:
                cursor.close()
        finally:
            db.close()

    def fetch_one(self, query: str, params: tuple = ()):
        """获取单条记录 - 使用持久化连接"""
        db = self.get_connection()
        try:
            return db.fetch_one(query, params)
        finally:
            db.close()

    def fetch_all(self, query: str, params: tuple = ()):
        """获取所有记录 - 使用持久化连接"""
        db = self.get_connection()
        try:
            return db.fetch_all(query, params)
        finally:
            db.close()
