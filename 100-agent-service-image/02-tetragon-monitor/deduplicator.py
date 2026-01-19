#!/usr/bin/env python3
"""
Tetragon事件去重处理器
监控文件访问和进程执行事件，进行5分钟窗口去重
"""

import json
import sys
import time
import hashlib
import logging
from datetime import datetime, timedelta
from collections import OrderedDict
from dataclasses import dataclass, asdict
from typing import Dict, Optional
import cachetools

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class EventKey:
    """事件去重键"""
    process_id: int
    parent_process_id: int
    event_type: str  # 'file_access' 或 'process_exec'
    file_path: Optional[str] = None
    command: Optional[str] = None

    def get_hash(self) -> str:
        """生成事件的唯一哈希"""
        key_str = f"{self.process_id}:{self.parent_process_id}:{self.event_type}"
        if self.file_path:
            key_str += f":{self.file_path}"
        if self.command:
            key_str += f":{self.command}"
        return hashlib.md5(key_str.encode()).hexdigest()

class DeduplicationCache:
    """去重缓存管理"""

    def __init__(self, window_minutes: int = 5, max_size: int = 10000):
        """
        初始化缓存

        Args:
            window_minutes: 去重时间窗口（分钟）
            max_size: 最大缓存数量
        """
        self.window_minutes = window_minutes
        self.window_seconds = window_minutes * 60

        # 使用TTL缓存自动过期
        self.cache = cachetools.TTLCache(
            maxsize=max_size,
            ttl=self.window_seconds
        )
        logger.info(f"初始化去重缓存，窗口={window_minutes}分钟，最大大小={max_size}")

        # 统计信息
        self.stats = {
            'total_events': 0,
            'unique_events': 0,
            'duplicate_events': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }

    def is_duplicate(self, event_key: EventKey) -> bool:
        """检查事件是否为重复事件"""
        self.stats['total_events'] += 1
        event_hash = event_key.get_hash()

        if event_hash in self.cache:
            self.stats['duplicate_events'] += 1
            self.stats['cache_hits'] += 1
            return True
        else:
            self.cache[event_hash] = {
                'timestamp': time.time(),
                'event': asdict(event_key)
            }
            self.stats['unique_events'] += 1
            self.stats['cache_misses'] += 1
            return False

    def get_stats(self) -> Dict:
        """获取统计信息"""
        return {
            **self.stats,
            'cache_size': len(self.cache),
            'window_minutes': self.window_minutes
        }

    def clear_expired(self):
        """清理过期缓存（TTL自动处理）"""
        # TTLCache会自动处理过期，这里只是记录
        logger.debug(f"当前缓存大小: {len(self.cache)}")

class TetragonEventProcessor:
    """Tetragon事件处理器"""

    def __init__(self, dedup_window: int = 5):
        self.dedup_cache = DeduplicationCache(window_minutes=dedup_window)
        self.event_handlers = {
            'process_exec': self._handle_process_exec,
            'file_access': self._handle_file_access
        }

    def _extract_process_info(self, event: Dict) -> Dict:
        """提取进程信息"""
        try:
            process = event.get('process', {})
            parent = event.get('parent', {})

            return {
                'pid': process.get('pid', {}).get('value', 0),
                'parent_pid': parent.get('pid', {}).get('value', 0),
                'executable': process.get('binary', ''),
                'arguments': process.get('arguments', ''),
                'parent_executable': parent.get('binary', ''),
                'cwd': process.get('cwd', ''),
                'uid': process.get('uid', {}).get('value', 0),
                'gid': process.get('gid', {}).get('value', 0)
            }
        except Exception as e:
            logger.error(f"提取进程信息失败: {e}")
            return {}

    def _handle_process_exec(self, event: Dict) -> Optional[EventKey]:
        """处理进程执行事件"""
        try:
            process_info = self._extract_process_info(event)
            exec_args = event.get('process_exec', {}).get('args', '')

            return EventKey(
                process_id=process_info['pid'],
                parent_process_id=process_info['parent_pid'],
                event_type='process_exec',
                command=exec_args
            )
        except Exception as e:
            logger.error(f"处理进程执行事件失败: {e}")
            return None

    def _handle_file_access(self, event: Dict) -> Optional[EventKey]:
        """处理文件访问事件"""
        try:
            process_info = self._extract_process_info(event)
            file_info = event.get('file_access', {})
            file_path = file_info.get('path', '')

            return EventKey(
                process_id=process_info['pid'],
                parent_process_id=process_info['parent_pid'],
                event_type='file_access',
                file_path=file_path
            )
        except Exception as e:
            logger.error(f"处理文件访问事件失败: {e}")
            return None

    def process_event(self, event_line: str) -> Optional[Dict]:
        """处理单个事件行"""
        try:
            event = json.loads(event_line.strip())
            event_type = event.get('type', '')

            if event_type in self.event_handlers:
                event_key = self.event_handlers[event_type](event)

                if event_key:
                    if not self.dedup_cache.is_duplicate(event_key):
                        # 添加时间戳和处理信息
                        event['_processed'] = {
                            'timestamp': datetime.utcnow().isoformat(),
                            'deduplicated': False,
                            'cache_stats': self.dedup_cache.get_stats()
                        }
                        return event
                    else:
                        # 记录去重事件
                        logger.debug(f"事件去重: {event_key}")
                        event['_processed'] = {
                            'timestamp': datetime.utcnow().isoformat(),
                            'deduplicated': True,
                            'event_key': asdict(event_key)
                        }
                        return event
        except json.JSONDecodeError:
            logger.error(f"JSON解析失败: {event_line}")
        except Exception as e:
            logger.error(f"处理事件失败: {e}")

        return None

def main():
    """主函数：从stdin读取事件并处理"""
    import argparse

    parser = argparse.ArgumentParser(description='Tetragon事件去重处理器')
    parser.add_argument('--dedup-window', type=int, default=5,
                        help='去重时间窗口（分钟）')
    parser.add_argument('--log-stats-interval', type=int, default=60,
                        help='统计日志输出间隔（秒）')

    args = parser.parse_args()

    processor = TetragonEventProcessor(dedup_window=args.dedup_window)

    # 定期输出统计信息
    def log_stats():
        stats = processor.dedup_cache.get_stats()
        logger.info(
            f"统计信息 - 总事件: {stats['total_events']}, "
            f"去重事件: {stats['duplicate_events']}, "
            f"唯一事件: {stats['unique_events']}, "
            f"缓存大小: {stats['cache_size']}"
        )

    last_stat_time = time.time()

    # 处理标准输入流
    logger.info("开始处理Tetragon事件...")
    for line in sys.stdin:
        if line.strip():
            processed_event = processor.process_event(line)
            if processed_event:
                # 输出处理后的事件
                print(json.dumps(processed_event))
                sys.stdout.flush()

        # 定期输出统计信息
        current_time = time.time()
        if current_time - last_stat_time >= args.log_stats_interval:
            log_stats()
            last_stat_time = current_time

    log_stats()

if __name__ == "__main__":
    main()