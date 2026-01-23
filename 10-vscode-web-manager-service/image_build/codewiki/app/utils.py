# app/utils.py
import os
import json
import shutil
from datetime import datetime
from typing import Any, Dict, Optional
from pathlib import Path


def ensure_directory(path: str) -> bool:
    """确保目录存在"""
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception as e:
        print(f"Failed to create directory {path}: {e}")
        return False


def save_json(data: Dict[str, Any], filepath: str) -> bool:
    """保存JSON文件"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Failed to save JSON to {filepath}: {e}")
        return False


def load_json(filepath: str) -> Optional[Dict[str, Any]]:
    """加载JSON文件"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to load JSON from {filepath}: {e}")
        return None


def get_file_size(filepath: str) -> int:
    """获取文件大小（字节）"""
    try:
        return os.path.getsize(filepath)
    except:
        return 0


def format_timedelta(start: datetime, end: Optional[datetime] = None) -> str:
    """格式化时间差"""
    if end is None:
        end = datetime.utcnow()

    delta = end - start
    seconds = delta.total_seconds()

    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def clean_old_logs(logs_dir: str, days: int = 7):
    """清理旧日志文件"""
    try:
        now = datetime.now().timestamp()
        cutoff = now - (days * 24 * 3600)

        for filename in os.listdir(logs_dir):
            filepath = os.path.join(logs_dir, filename)
            if os.path.isfile(filepath):
                if os.path.getmtime(filepath) < cutoff:
                    os.remove(filepath)
    except Exception as e:
        print(f"Failed to clean old logs: {e}")


def get_disk_usage(path: str) -> Dict[str, Any]:
    """获取磁盘使用情况"""
    try:
        total, used, free = shutil.disk_usage(path)
        return {
            "total_gb": total / (1024**3),
            "used_gb": used / (1024**3),
            "free_gb": free / (1024**3),
            "percent_used": (used / total) * 100
        }
    except Exception as e:
        return {"error": str(e)}