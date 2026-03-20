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
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import base64
import requests
import redis

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

    def __init__(self, redis_url: str, enabled: bool = True, strict_mode: bool = False):
        self.redis_url = redis_url
        self.enabled = enabled
        self.strict_mode = strict_mode
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
            def __init__(self, lock_key: str, acquired: bool):
                self.lock_key = lock_key
                self._acquired = acquired
                self.logger = logging.getLogger(__name__)

            def acquire(self, *args, **kwargs) -> bool:
                return self._acquired

            def release(self) -> bool:
                self._acquired = False
                return True

            def is_acquired(self) -> bool:
                return self._acquired

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                self.release()

        acquired = not self.strict_mode
        if not acquired:
            self.logger.error(f"Redis严格模式已启用，锁不可用: {lock_key}")
        return DummyRedisLock(lock_key, acquired)
