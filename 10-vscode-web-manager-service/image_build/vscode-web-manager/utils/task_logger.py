"""
任务日志记录器
"""
import os
from datetime import datetime, timezone
from typing import Optional

class TaskLogger:
    """任务日志记录器"""

    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        self.log_buffer = []
        self.start_time = datetime.now(timezone.utc)
        if not os.path.exists(os.path.dirname(log_file_path)):
            os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

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