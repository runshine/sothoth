# app/logs.py
import os
import re
import glob
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
import arrow

class LogManager:
    """日志管理器"""

    def __init__(self, logs_dir: str = "logs"):
        self.logs_dir = logs_dir
        os.makedirs(logs_dir, exist_ok=True)

    def get_log_files(self) -> List[Dict[str, Any]]:
        """获取所有日志文件信息"""
        log_files = []

        # 获取所有日志文件
        for file_path in Path(self.logs_dir).glob("*.log"):
            stat = file_path.stat()
            log_files.append({
                "name": file_path.name,
                "path": str(file_path),
                "size": stat.st_size,
                "size_human": self._format_size(stat.st_size),
                "modified": arrow.get(stat.st_mtime).isoformat(),
                "modified_human": arrow.get(stat.st_mtime).humanize(),
                "created": arrow.get(stat.st_ctime).isoformat(),
                "type": self._get_log_type(file_path.name)
            })

        # 按修改时间倒序排序
        log_files.sort(key=lambda x: x["modified"], reverse=True)
        return log_files

    def get_log_content(
            self,
            log_file: str,
            lines: int = 1000,
            search: Optional[str] = None,
            level: Optional[str] = None
    ) -> Dict[str, Any]:
        """获取日志文件内容"""
        log_path = Path(self.logs_dir) / log_file

        if not log_path.exists():
            raise FileNotFoundError(f"Log file not found: {log_file}")

        content_lines = []
        filtered_lines = []

        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            # 读取所有行
            all_lines = f.readlines()
            total_lines = len(all_lines)

            # 获取最后N行
            start_line = max(0, total_lines - lines)
            for i in range(start_line, total_lines):
                line = all_lines[i].rstrip('\n')
                content_lines.append({
                    "line": i + 1,
                    "content": line,
                    "level": self._extract_log_level(line)
                })

            # 如果有搜索条件，进行过滤
            if search or level:
                for line_info in content_lines:
                    match = True

                    if search and search.lower() not in line_info["content"].lower():
                        match = False

                    if level and level.lower() != line_info["level"].lower():
                        match = False

                    if match:
                        filtered_lines.append(line_info)
            else:
                filtered_lines = content_lines

        return {
            "file": log_file,
            "total_lines": total_lines,
            "returned_lines": len(filtered_lines),
            "lines": lines,
            "search": search,
            "level": level,
            "content": filtered_lines,
            "file_size": log_path.stat().st_size,
            "last_modified": arrow.get(log_path.stat().st_mtime).isoformat()
        }

    def get_server_logs(
            self,
            lines: int = 1000,
            search: Optional[str] = None,
            level: Optional[str] = None,
            time_range: Optional[str] = None
    ) -> Dict[str, Any]:
        """获取服务器运行日志（合并多个日志文件）"""
        # 获取所有服务器日志文件（app_*.log）
        server_logs = []
        for file_path in Path(self.logs_dir).glob("app_*.log"):
            server_logs.append(file_path)

        # 按修改时间排序（最新的在前）
        server_logs.sort(key=lambda x: x.stat().st_mtime, reverse=True)

        if not server_logs:
            return {
                "total_files": 0,
                "total_lines": 0,
                "returned_lines": 0,
                "content": []
            }

        all_content = []

        # 读取每个日志文件的最后N行
        for log_file in server_logs[:5]:  # 限制最多读取5个文件
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines_content = f.readlines()
                    file_lines = len(lines_content)

                    # 获取最后N行
                    start_line = max(0, file_lines - lines)
                    for i in range(start_line, file_lines):
                        line = lines_content[i].rstrip('\n')
                        log_level = self._extract_log_level(line)

                        # 应用过滤条件
                        match = True
                        if search and search.lower() not in line.lower():
                            match = False
                        if level and level.lower() != log_level.lower():
                            match = False

                        if match:
                            all_content.append({
                                "file": log_file.name,
                                "line": i + 1,
                                "content": line,
                                "level": log_level,
                                "timestamp": self._extract_timestamp(line)
                            })
            except Exception as e:
                print(f"Error reading log file {log_file}: {e}")

        return {
            "total_files": len(server_logs),
            "files_read": min(5, len(server_logs)),
            "total_lines": len(all_content),
            "lines": lines,
            "search": search,
            "level": level,
            "content": all_content
        }

    def delete_old_logs(self, days: int = 30) -> Dict[str, Any]:
        """删除旧的日志文件"""
        cutoff_date = arrow.utcnow().shift(days=-days)
        deleted_files = []
        failed_files = []

        for file_path in Path(self.logs_dir).glob("*.log"):
            mtime = arrow.get(file_path.stat().st_mtime)
            if mtime < cutoff_date:
                try:
                    file_path.unlink()
                    deleted_files.append(file_path.name)
                except Exception as e:
                    failed_files.append({
                        "file": file_path.name,
                        "error": str(e)
                    })

        return {
            "deleted": deleted_files,
            "failed": failed_files,
            "cutoff_date": cutoff_date.isoformat(),
            "days_retained": days
        }

    def get_log_stats(self) -> Dict[str, Any]:
        """获取日志统计信息"""
        log_files = self.get_log_files()
        total_size = sum(f["size"] for f in log_files)

        # 按类型统计
        type_stats = {}
        for log_file in log_files:
            log_type = log_file["type"]
            type_stats[log_type] = type_stats.get(log_type, 0) + 1

        # 按级别统计（从服务器日志中提取）
        level_stats = {"ERROR": 0, "WARNING": 0, "INFO": 0, "DEBUG": 0}
        server_log_files = [f for f in log_files if f["type"] == "server"]

        for log_file in server_log_files[:3]:  # 只检查最近的3个服务器日志文件
            try:
                with open(Path(self.logs_dir) / log_file["name"], 'r', encoding='utf-8') as f:
                    for line in f:
                        level = self._extract_log_level(line)
                        if level in level_stats:
                            level_stats[level] += 1
            except:
                pass

        return {
            "total_files": len(log_files),
            "total_size": total_size,
            "total_size_human": self._format_size(total_size),
            "type_stats": type_stats,
            "level_stats": level_stats,
            "oldest_log": min([f["created"] for f in log_files]) if log_files else None,
            "newest_log": max([f["modified"] for f in log_files]) if log_files else None
        }

    def _format_size(self, size_bytes: int) -> str:
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"

    def _get_log_type(self, filename: str) -> str:
        """获取日志类型"""
        if filename.startswith("app_"):
            return "server"
        elif filename.startswith("task_") or filename.endswith(".log") and "_" in filename:
            return "task"
        elif "error" in filename.lower():
            return "error"
        elif "access" in filename.lower():
            return "access"
        else:
            return "other"

    def _extract_log_level(self, line: str) -> str:
        """从日志行中提取日志级别"""
        patterns = {
            "ERROR": r'(?i)\b(ERROR|ERR|FAILED|CRITICAL)\b',
            "WARNING": r'(?i)\b(WARNING|WARN|CAUTION)\b',
            "INFO": r'(?i)\b(INFO|INFORMATION)\b',
            "DEBUG": r'(?i)\b(DEBUG|TRACE)\b'
        }

        for level, pattern in patterns.items():
            if re.search(pattern, line):
                return level

        return "INFO"

    def _extract_timestamp(self, line: str) -> Optional[str]:
        """从日志行中提取时间戳"""
        # 尝试匹配常见的时间戳格式
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
            r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
            r'(\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\])'
        ]

        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)

        return None


# 全局日志管理器实例
log_manager = LogManager()