"""
多架构软件包管理系统 - 后端
使用: Flask + MySQL
功能: 上传、解析、存储、管理、校验软件包
"""

import os
import re
import sys
import json
import hashlib
import threading
import zipfile
import tarfile
import shutil
import asyncio
import atexit
import signal
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import logging
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from flask import Flask, request, jsonify, send_file, send_from_directory, abort, redirect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from flask_cors import CORS
from sqlalchemy import or_, func

# 导入配置和注册服务
from config import load_config, get_config
from registry import get_registry_service


# ==================== 命令行参数解析 ====================
def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='多架构软件包管理系统')
    parser.add_argument(
        '-c', '--config',
        dest='config_path',
        type=str,
        help='配置文件路径 (例如: /path/to/config.yaml)',
        default=None
    )
    return parser.parse_args()


# ==================== 加载配置 ====================
try:
    args = parse_args()
    config = load_config(config_path=args.config_path)
    logger = logging.getLogger(__name__)
    if args.config_path:
        logger.info(f"从指定路径加载配置: {args.config_path}")
    else:
        logger.info("使用默认配置文件")
    logger.info("配置加载成功")
except Exception as e:
    print(f"加载配置失败: {e}", file=sys.stderr)
    sys.exit(1)

# ==================== 日志配置 ====================
logging.basicConfig(
    level=getattr(logging, config.logging.level),
    format=config.logging.format,
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)

# ==================== Flask应用初始化 ====================
# 初始化Flask应用
app = Flask(__name__)
CORS(app)

# 使用配置文件中的值
logger.info("DATABASE_URL: {}".format(config.database.url))
logger.info("STORAGE_FOLDER: {}".format(config.storage.storage_folder))

# 配置
app.config['SECRET_KEY'] = config.app.secret_key

app.config['SQLALCHEMY_DATABASE_URI'] = config.database.url
# 明确设置引擎选项禁用SSL
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'connect_args': {
        'ssl': False,
        'connect_timeout': 10
    }
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = config.storage.upload_folder  # 临时上传目录
app.config['STORAGE_FOLDER'] = config.storage.storage_folder  # 永久存储目录
app.config['ORIGINAL_PACKAGE_FOLDER'] = config.storage.original_package_folder  # 原始包存储目录
app.config['MAX_CONTENT_LENGTH'] = config.storage.max_content_length  # 最大上传限制

# 创建必要的目录
for folder in [app.config['UPLOAD_FOLDER'], app.config['STORAGE_FOLDER'], app.config['ORIGINAL_PACKAGE_FOLDER']]:
    Path(folder).mkdir(parents=True, exist_ok=True)

# 初始化数据库
db = SQLAlchemy(app)

# 包级并发锁：避免校验与删除同时操作同一软件包
_package_locks_guard = threading.Lock()
_package_locks: Dict[str, threading.RLock] = {}

# 定时校验线程控制
_auto_verify_stop_event = threading.Event()
_auto_verify_thread: Optional[threading.Thread] = None
_registry_thread: Optional[threading.Thread] = None
_registry_loop: Optional[asyncio.AbstractEventLoop] = None

# ==================== 数据库模型 ====================

class Package(db.Model):
    """软件包信息表"""
    __tablename__ = 'secflow_static_binary_packages'

    id = db.Column(db.String(64), primary_key=True, comment='MD5哈希值作为唯一ID')
    name = db.Column(db.String(100), nullable=False, index=True, comment='软件包名称')
    version = db.Column(db.String(50), nullable=False, index=True, comment='版本号')
    system = db.Column(db.String(20), nullable=False, default='linux', comment='操作系统')
    architecture = db.Column(db.String(20), nullable=False, index=True, comment='CPU架构')
    original_filename = db.Column(db.String(255), nullable=False, comment='原始文件名')
    storage_path = db.Column(db.String(500), nullable=False, comment='存储路径')
    original_package_path = db.Column(db.String(500), nullable=True, comment='原始包存储路径')
    total_size = db.Column(db.BigInteger, default=0, comment='总文件大小(字节)')
    file_count = db.Column(db.Integer, default=0, comment='文件数量')
    upload_time = db.Column(db.DateTime, default=datetime.utcnow, comment='上传时间')
    last_check_time = db.Column(db.DateTime, nullable=True, comment='最后校验时间')
    check_status = db.Column(db.String(20), default='pending', comment='校验状态: pending, checking, valid, invalid')
    download_count = db.Column(db.Integer, default=0, comment='软件包下载次数')
    last_download_time = db.Column(db.DateTime, nullable=True, comment='最后下载时间')

    # 建立与文件表的一对多关系
    files = db.relationship('PackageFile', backref='package', cascade='all, delete-orphan', lazy='dynamic')

    # 复合唯一约束
    __table_args__ = (
        db.UniqueConstraint('name', 'version', 'system', 'architecture', name='unique_package'),
    )


class PackageFile(db.Model):
    """软件包文件记录表"""
    __tablename__ = 'secflow_static_binary_package_files'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    package_id = db.Column(db.String(64), db.ForeignKey('secflow_static_binary_packages.id', ondelete='CASCADE'), nullable=False, index=True)
    file_path = db.Column(db.String(1000), nullable=False, comment='文件相对路径')
    file_name = db.Column(db.String(255), nullable=False, comment='文件名')
    file_size = db.Column(db.BigInteger, nullable=False, comment='文件大小(字节)')
    storage_path = db.Column(db.String(1500), nullable=False, comment='实际存储路径')
    download_count = db.Column(db.Integer, default=0, comment='文件下载次数')
    last_download_time = db.Column(db.DateTime, nullable=True, comment='文件最后下载时间')

    # 复合索引
    __table_args__ = (
        db.Index('idx_package_path', 'package_id', 'file_path'),
        db.Index('idx_file_name', 'file_name'),
        db.Index('idx_package_file_name', 'package_id', 'file_name'),
    )


# ==================== 工具函数 ====================

def calculate_md5(file_path: str) -> str:
    """计算文件的MD5哈希值"""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def parse_filename(filename: str) -> Dict[str, str]:
    """
    解析文件名格式: 软件包名-版本-linux-架构.压缩包后缀
    例如: nginx-v1.28-linux-armel.tar.gz
    """
    # 移除压缩包后缀
    base_name = re.sub(r'\.(zip|tar\.gz|tar\.bz2|tar|xz|gz|bz2)$', '', filename, flags=re.IGNORECASE)

    # 匹配模式
    pattern = r'^(?P<name>.+?)-(?P<version>.+?)-linux-(?P<arch>.+)$'
    match = re.match(pattern, base_name)

    if not match:
        raise ValueError(f"文件名格式不正确: {filename}")

    return {
        'name': match.group('name'),
        'version': match.group('version'),
        'system': 'linux',
        'architecture': match.group('arch')
    }


def parse_bool_arg(value: Optional[str], default: bool = False) -> bool:
    """解析URL中的布尔参数"""
    if value is None:
        return default
    return str(value).strip().lower() in ('1', 'true', 'yes', 'y', 'on')


def pick_best_file_match(results: List[Tuple["PackageFile", "Package"]],
                         system: str,
                         architecture: str,
                         filename: str,
                         package_name: str) -> Tuple["PackageFile", "Package"]:
    """
    从多个候选中选择“最新且最匹配”的文件
    1) 匹配分数更高优先
    2) upload_time 更新的优先
    3) file id 更大的优先（兜底）
    """
    def _score(item: Tuple["PackageFile", "Package"]) -> Tuple[int, datetime, int]:
        file_record, package = item
        score = 0

        if package_name:
            if package.name == package_name:
                score += 100
            elif package_name.lower() in package.name.lower():
                score += 50

        if package.system == system:
            score += 20
        if package.architecture == architecture:
            score += 20
        if file_record.file_name == filename:
            score += 20

        return score, (package.upload_time or datetime.min), (file_record.id or 0)

    return max(results, key=_score)


def extract_package(source_path: str, package_id: str, package_info: Dict) -> Tuple[str, List[Dict]]:
    """
    解压软件包到存储目录
    返回: (存储路径, 文件信息列表)
    """
    storage_dir = os.path.join(app.config['STORAGE_FOLDER'], package_id)

    # 清空目标目录（如果存在）
    if os.path.exists(storage_dir):
        shutil.rmtree(storage_dir)
    os.makedirs(storage_dir, exist_ok=True)

    files_info = []

    # 根据文件类型解压
    if source_path.endswith('.zip'):
        with zipfile.ZipFile(source_path, 'r') as zip_ref:
            for file_info in zip_ref.infolist():
                # 解压文件
                zip_ref.extract(file_info, storage_dir)

                # 记录文件信息
                file_path = file_info.filename
                full_path = os.path.join(storage_dir, file_path)

                if not file_info.is_dir():
                    files_info.append({
                        'file_path': file_path,
                        'file_name': os.path.basename(file_path),
                        'file_size': file_info.file_size,
                        'storage_path': full_path
                    })

    elif source_path.endswith(('.tar.gz', '.tar.bz2', '.tar.xz', '.tar')):
        mode = 'r:gz' if source_path.endswith('.tar.gz') else \
            'r:bz2' if source_path.endswith('.tar.bz2') else \
                'r:xz' if source_path.endswith('.tar.xz') else 'r'

        with tarfile.open(source_path, mode) as tar_ref:
            for member in tar_ref.getmembers():
                # 解压文件（跳过危险路径）
                if not member.name.startswith(('/', '..')):
                    tar_ref.extract(member, storage_dir)

                    # 记录文件信息
                    full_path = os.path.join(storage_dir, member.name)

                    if member.isfile():
                        files_info.append({
                            'file_path': member.name,
                            'file_name': os.path.basename(member.name),
                            'file_size': member.size,
                            'storage_path': full_path
                        })

    else:
        raise ValueError(f"不支持的压缩格式: {source_path}")

    return storage_dir, files_info


def _get_package_lock(package_id: str) -> threading.RLock:
    """获取单个软件包的进程内锁，避免同一包并发删除/校验冲突。"""
    with _package_locks_guard:
        lock = _package_locks.get(package_id)
        if lock is None:
            lock = threading.RLock()
            _package_locks[package_id] = lock
        return lock


def _release_package_lock_if_unused(package_id: str) -> None:
    """尽可能清理已不再使用的锁对象，避免字典无限增长。"""
    # RLock 不提供可靠的“无持有者”公开判断接口，这里保留为空实现。
    # 该字典仅按 package_id 增长，数量与历史软件包数量同阶，开销可接受。
    _ = package_id


def check_package_integrity(package_id: str) -> Dict[str, any]:
    """
    校验软件包完整性（并发安全）
    检查文件是否存在和大小是否匹配
    """
    package_lock = _get_package_lock(package_id)
    with package_lock:
        package = Package.query.get(package_id)
        if not package:
            raise ValueError("软件包不存在")

        package.check_status = 'checking'
        package.last_check_time = datetime.utcnow()
        db.session.commit()

        files = PackageFile.query.filter_by(package_id=package_id).all()
        missing_files = []
        size_mismatch_files = []

        for file_record in files:
            if not os.path.exists(file_record.storage_path):
                missing_files.append(file_record.file_path)
                continue

            actual_size = os.path.getsize(file_record.storage_path)
            if actual_size != file_record.file_size:
                size_mismatch_files.append({
                    'file': file_record.file_path,
                    'expected': file_record.file_size,
                    'actual': actual_size
                })

        package = Package.query.get(package_id)
        if not package:
            raise ValueError("软件包已被删除")

        is_valid = len(missing_files) == 0 and len(size_mismatch_files) == 0
        package.check_status = 'valid' if is_valid else 'invalid'
        package.last_check_time = datetime.utcnow()
        db.session.commit()

        result = {
            'valid': is_valid,
            'missing_files': missing_files,
            'size_mismatch_files': size_mismatch_files,
            'total_files': package.file_count,
            'checked_files': package.file_count - len(missing_files),
            'check_time': package.last_check_time.isoformat() if package.last_check_time else None
        }

    _release_package_lock_if_unused(package_id)
    return result


def _find_unchecked_package_ids(limit_count: int) -> List[str]:
    """查询待校验软件包（未校验或状态仍为pending）。"""
    packages = (
        db.session.query(Package.id)
        .filter(
            (Package.last_check_time.is_(None)) |
            (Package.check_status == 'pending')
        )
        .order_by(Package.upload_time.asc())
        .limit(limit_count)
        .all()
    )
    return [pkg[0] for pkg in packages]


def auto_verify_packages_loop() -> None:
    """后台线程：定时扫描未校验软件包并执行完整性校验。"""
    enabled = config.auto_verify.enabled
    if not enabled:
        logger.info("自动校验功能已禁用")
        return

    interval_seconds = max(5, int(config.auto_verify.interval_seconds))
    batch_size = max(1, int(config.auto_verify.batch_size))
    logger.info(f"自动校验线程启动: interval={interval_seconds}s, batch_size={batch_size}")

    while not _auto_verify_stop_event.wait(interval_seconds):
        try:
            with app.app_context():
                package_ids = _find_unchecked_package_ids(batch_size)
                if not package_ids:
                    continue

                logger.info(f"自动校验扫描到 {len(package_ids)} 个待处理软件包")
                for package_id in package_ids:
                    if _auto_verify_stop_event.is_set():
                        break
                    try:
                        check_package_integrity(package_id)
                    except ValueError as e:
                        logger.info(f"自动校验跳过 package_id={package_id}: {e}")
                    except Exception as e:
                        db.session.rollback()
                        logger.error(f"自动校验失败 package_id={package_id}: {e}")
        except Exception as e:
            logger.error(f"自动校验线程异常: {e}")

    logger.info("自动校验线程已退出")


# ==================== 新增统计接口 ====================

@app.route('/api/packages/statistics/query', methods=['GET'])
def query_statistics():
    """
    根据查询条件统计软件包信息
    支持按架构、系统、校验状态等条件查询
    """
    try:
        # 获取查询参数
        architecture = request.args.get('architecture', '')
        system = request.args.get('system', '')
        check_status = request.args.get('check_status', '')
        name = request.args.get('name', '')
        version = request.args.get('version', '')

        # 构建查询
        query = Package.query

        if architecture:
            query = query.filter(Package.architecture.ilike(f'%{architecture}%'))
        if system:
            query = query.filter(Package.system.ilike(f'%{system}%'))
        if check_status:
            query = query.filter(Package.check_status == check_status)
        if name:
            query = query.filter(Package.name.ilike(f'%{name}%'))
        if version:
            query = query.filter(Package.version.ilike(f'%{version}%'))

        # 执行查询
        packages = query.all()

        # 计算统计信息
        total_packages = len(packages)
        total_files = sum(pkg.file_count for pkg in packages)
        total_size = sum(pkg.total_size for pkg in packages)
        total_downloads = sum(pkg.download_count for pkg in packages)

        # 按架构分组统计
        arch_stats = {}
        for pkg in packages:
            arch = pkg.architecture
            if arch not in arch_stats:
                arch_stats[arch] = {
                    'package_count': 0,
                    'file_count': 0,
                    'total_size': 0,
                    'download_count': 0
                }
            arch_stats[arch]['package_count'] += 1
            arch_stats[arch]['file_count'] += pkg.file_count
            arch_stats[arch]['total_size'] += pkg.total_size
            arch_stats[arch]['download_count'] += pkg.download_count

        # 按系统分组统计
        system_stats = {}
        for pkg in packages:
            sys = pkg.system
            if sys not in system_stats:
                system_stats[sys] = {
                    'package_count': 0,
                    'file_count': 0,
                    'total_size': 0,
                    'download_count': 0
                }
            system_stats[sys]['package_count'] += 1
            system_stats[sys]['file_count'] += pkg.file_count
            system_stats[sys]['total_size'] += pkg.total_size
            system_stats[sys]['download_count'] += pkg.download_count

        # 按校验状态分组统计
        status_stats = {}
        for pkg in packages:
            status = pkg.check_status
            if status not in status_stats:
                status_stats[status] = {
                    'package_count': 0,
                    'file_count': 0,
                    'total_size': 0,
                    'download_count': 0
                }
            status_stats[status]['package_count'] += 1
            status_stats[status]['file_count'] += pkg.file_count
            status_stats[status]['total_size'] += pkg.total_size
            status_stats[status]['download_count'] += pkg.download_count

        # 计算平均文件大小
        avg_file_size = total_size / max(total_files, 1)

        return jsonify({
            'success': True,
            'statistics': {
                'summary': {
                    'package_count': total_packages,
                    'file_count': total_files,
                    'total_size': total_size,
                    'total_size_human': f"{total_size / (1024**3):.2f} GB",
                    'total_downloads': total_downloads,
                    'avg_file_size': avg_file_size,
                    'avg_file_size_human': f"{avg_file_size / 1024:.2f} KB"
                },
                'by_architecture': [
                    {
                        'architecture': arch,
                        'package_count': stats['package_count'],
                        'file_count': stats['file_count'],
                        'total_size': stats['total_size'],
                        'total_size_human': f"{stats['total_size'] / (1024**3):.2f} GB",
                        'download_count': stats['download_count']
                    }
                    for arch, stats in arch_stats.items()
                ],
                'by_system': [
                    {
                        'system': sys,
                        'package_count': stats['package_count'],
                        'file_count': stats['file_count'],
                        'total_size': stats['total_size'],
                        'total_size_human': f"{stats['total_size'] / (1024**3):.2f} GB",
                        'download_count': stats['download_count']
                    }
                    for sys, stats in system_stats.items()
                ],
                'by_check_status': [
                    {
                        'check_status': status,
                        'package_count': stats['package_count'],
                        'file_count': stats['file_count'],
                        'total_size': stats['total_size'],
                        'total_size_human': f"{stats['total_size'] / (1024**3):.2f} GB",
                        'download_count': stats['download_count']
                    }
                    for status, stats in status_stats.items()
                ]
            },
            'query_conditions': {
                'architecture': architecture if architecture else 'all',
                'system': system if system else 'all',
                'check_status': check_status if check_status else 'all',
                'name': name if name else 'all',
                'version': version if version else 'all'
            }
        })

    except Exception as e:
        return jsonify({'success': False, 'error': f'统计查询失败: {str(e)}'}), 500


@app.route('/api/packages/statistics/detailed', methods=['GET'])
def detailed_statistics():
    """
    获取详细的统计信息，包括维度统计
    支持按多个维度分组统计
    """
    try:
        # 获取查询参数
        group_by = request.args.get('group_by', 'architecture')  # 支持: architecture, system, check_status

        # 定义分组字段
        group_fields = {
            'architecture': Package.architecture,
            'system': Package.system,
            'check_status': Package.check_status
        }

        if group_by not in group_fields:
            return jsonify({'success': False, 'error': f'不支持的group_by参数: {group_by}'}), 400

        group_field = group_fields[group_by]

        # 执行分组统计查询
        stats = db.session.query(
            group_field,
            func.count(Package.id).label('package_count'),
            func.sum(Package.file_count).label('file_count'),
            func.sum(Package.total_size).label('total_size'),
            func.sum(Package.download_count).label('download_count')
        ).group_by(group_field).all()

        # 计算总计
        total_packages = sum(stat.package_count for stat in stats)
        total_files = sum(stat.file_count for stat in stats)
        total_size = sum(stat.total_size for stat in stats)
        total_downloads = sum(stat.download_count for stat in stats)

        # 格式化结果
        result = []
        for stat in stats:
            group_value = getattr(stat, group_by) if getattr(stat, group_by) else 'unknown'
            result.append({
                'group': group_value,
                'package_count': stat.package_count,
                'file_count': stat.file_count,
                'total_size': stat.total_size,
                'total_size_human': f"{stat.total_size / (1024**3):.2f} GB",
                'download_count': stat.download_count,
                'avg_package_size': stat.total_size / max(stat.package_count, 1),
                'avg_package_files': stat.file_count / max(stat.package_count, 1)
            })

        # 按package_count排序
        result.sort(key=lambda x: x['package_count'], reverse=True)

        return jsonify({
            'success': True,
            'group_by': group_by,
            'summary': {
                'total_packages': total_packages,
                'total_files': total_files,
                'total_size': total_size,
                'total_size_human': f"{total_size / (1024**3):.2f} GB",
                'total_downloads': total_downloads
            },
            'details': result
        })

    except Exception as e:
        return jsonify({'success': False, 'error': f'详细统计失败: {str(e)}'}), 500


# ==================== 新增API路由 ====================

@app.route('/api/packages/<package_id>/download', methods=['GET'])
def download_package(package_id):
    """下载原始package文件"""
    package = Package.query.get(package_id)
    if not package:
        return jsonify({'success': False, 'error': '软件包不存在'}), 404

    if not package.original_package_path or not os.path.exists(package.original_package_path):
        return jsonify({'success': False, 'error': '原始package文件不存在'}), 404

    try:
        # 更新下载次数和时间
        package.download_count += 1
        package.last_download_time = datetime.utcnow()
        db.session.commit()

        # 使用send_file发送文件，支持大文件流式传输
        return send_file(
            package.original_package_path,
            as_attachment=True,
            download_name=package.original_filename,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({'success': False, 'error': f'下载失败: {str(e)}'}), 500

@app.route('/api/packages/files/search', methods=['GET'])
def search_files():
    """根据文件名搜索package中的子文件"""
    filename = request.args.get('filename', '')
    if not filename:
        return jsonify({'success': False, 'error': '请提供要搜索的文件名'}), 400

    try:
        # 使用模糊查询搜索文件名
        file_records = PackageFile.query.filter(
            PackageFile.file_name.ilike(f'%{filename}%')
        ).all()

        if not file_records:
            return jsonify({
                'success': True,
                'count': 0,
                'packages': [],
                'total_matches': 0
            })

        # 收集所有涉及的package_id
        package_ids = {record.package_id for record in file_records}

        # 一次性获取所有相关的package信息
        packages = Package.query.filter(Package.id.in_(package_ids)).all()
        package_map = {pkg.id: pkg for pkg in packages}

        # 按package_id分组文件记录
        matched_files_by_package = {}
        for file_record in file_records:
            package_id = file_record.package_id

            # 如果package不存在，跳过
            if package_id not in package_map:
                continue

            if package_id not in matched_files_by_package:
                matched_files_by_package[package_id] = []

            matched_files_by_package[package_id].append({
                'file_path': file_record.file_path,
                'file_name': file_record.file_name,
                'file_size': file_record.file_size,
                'storage_path': file_record.storage_path,
                'download_count': file_record.download_count,
                'last_download_time': file_record.last_download_time.isoformat() if file_record.last_download_time else None,
                'id': file_record.id
            })

        # 构建与search_packages一致的返回结构
        result_packages = []
        for package_id, matched_files in matched_files_by_package.items():
            package = package_map[package_id]

            # 构建与search_packages一致的package信息
            package_info = {
                'id': package.id,
                'name': package.name,
                'version': package.version,
                'system': package.system,
                'architecture': package.architecture,
                'original_filename': package.original_filename,
                'total_size': package.total_size,
                'file_count': package.file_count,
                'upload_time': package.upload_time.isoformat() if package.upload_time else None,
                'last_check_time': package.last_check_time.isoformat() if package.last_check_time else None,
                'check_status': package.check_status,
                'original_package_path': package.original_package_path,
                'download_count': package.download_count,
                'last_download_time': package.last_download_time.isoformat() if package.last_download_time else None,
                # 新增字段：匹配的文件信息
                'matched_files_count': len(matched_files),
                'matched_files': matched_files
            }

            result_packages.append(package_info)

        # 计算总匹配数
        total_matches = len(file_records)

        return jsonify({
            'success': True,
            'count': len(result_packages),
            'total_matches': total_matches,
            'packages': result_packages  # 与search_packages保持一致的字段名
        })

    except Exception as e:
        logger.error(f"搜索文件失败: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'搜索失败: {str(e)}'}), 500


@app.route('/api/packages/download/latest', methods=['GET'])
def download_latest_package():
    """
    根据系统、架构、软件包名下载最新的软件包
    参数：system（必须），architecture（必须），name（必须，精确匹配）
    返回：最新的软件包文件
    """
    try:
        # 获取查询参数
        system = request.args.get('system', '')
        architecture = request.args.get('architecture', '')
        name = request.args.get('name', '')

        # 验证必须参数
        if not system or not architecture or not name:
            return jsonify({
                'success': False,
                'error': 'system, architecture和name都是必须参数'
            }), 400

        # 构建查询 - 精确匹配系统、架构和软件包名
        query = Package.query.filter(
            Package.system == system,
            Package.architecture == architecture,
            Package.name == name
        )

        # 查询所有符合条件的软件包
        packages = query.order_by(Package.upload_time.desc()).all()

        if not packages:
            return jsonify({
                'success': False,
                'error': f'未找到符合条件的软件包: system={system}, architecture={architecture}, name={name}'
            }), 404

        # 选择最新的软件包（按上传时间排序，取第一个）
        latest_package = packages[0]

        # 检查原始包文件是否存在
        if not latest_package.original_package_path or not os.path.exists(latest_package.original_package_path):
            return jsonify({
                'success': False,
                'error': '软件包文件不存在或已损坏'
            }), 404

        # 更新下载次数和时间
        latest_package.download_count += 1
        latest_package.last_download_time = datetime.utcnow()
        db.session.commit()

        # 使用send_file发送文件，支持大文件流式传输
        return send_file(
            latest_package.original_package_path,
            as_attachment=True,
            download_name=latest_package.original_filename,
            mimetype='application/octet-stream'
        )

    except Exception as e:
        logger.error(f"下载最新软件包失败: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'下载失败: {str(e)}'}), 500


@app.route('/api/packages/files/download/by-conditions', methods=['GET'])
def download_file_by_conditions():
    """
    根据系统、架构、文件名下载文件
    参数：system（必须），architecture（必须），filename（必须，不含路径的精确匹配），name（可选，软件包名）
    返回：单个文件或符合条件的文件列表
    """
    try:
        # 获取查询参数
        system = request.args.get('system', '')
        architecture = request.args.get('architecture', '')
        filename = request.args.get('filename', '')
        package_name = request.args.get('name', '')

        # 验证必须参数
        if not system or not architecture or not filename:
            return jsonify({
                'success': False,
                'error': 'system, architecture和filename都是必须参数'
            }), 400

        # 构建查询条件
        query = db.session.query(PackageFile, Package).join(
            Package, PackageFile.package_id == Package.id
        ).filter(
            Package.system == system,
            Package.architecture == architecture,
            PackageFile.file_name == filename  # 精确匹配文件名（不含路径）
        )

        # 如果提供了软件包名，则添加过滤条件
        if package_name:
            query = query.filter(Package.name == package_name)

        # 执行查询
        results = query.all()

        if not results:
            return jsonify({
                'success': False,
                'error': f'未找到符合条件的文件: system={system}, architecture={architecture}, filename={filename}' +
                         (f', name={package_name}' if package_name else '')
            }), 404

        # 如果只有一个匹配结果，直接下载文件
        if len(results) == 1:
            file_record, package = results[0]

            # 检查文件是否存在
            if not os.path.exists(file_record.storage_path):
                return jsonify({
                    'success': False,
                    'error': '文件不存在或已损坏'
                }), 404

            # 检查文件路径安全性
            real_path = os.path.realpath(file_record.storage_path)
            storage_root = os.path.realpath(package.storage_path)

            if not real_path.startswith(storage_root):
                return jsonify({'success': False, 'error': '文件路径不安全'}), 403

            # 更新下载次数和时间
            file_record.download_count += 1
            file_record.last_download_time = datetime.utcnow()
            package.download_count += 1
            package.last_download_time = datetime.utcnow()
            db.session.commit()

            # 发送文件
            directory = os.path.dirname(file_record.storage_path)
            base_filename = os.path.basename(file_record.storage_path)

            return send_from_directory(
                directory=directory,
                path=base_filename,
                as_attachment=True,
                download_name=filename
            )

        # 如果多个匹配结果，返回JSON列表
        else:
            matched_files = []
            for file_record, package in results:
                matched_files.append({
                    'package': {
                        'id': package.id,
                        'name': package.name,
                        'version': package.version,
                        'system': package.system,
                        'architecture': package.architecture,
                        'original_filename': package.original_filename,
                        'upload_time': package.upload_time.isoformat() if package.upload_time else None,
                        'download_count': package.download_count,
                        'last_download_time': package.last_download_time.isoformat() if package.last_download_time else None
                    },
                    'file': {
                        'id': file_record.id,
                        'file_path': file_record.file_path,
                        'file_name': file_record.file_name,
                        'file_size': file_record.file_size,
                        'storage_path': file_record.storage_path,
                        'download_count': file_record.download_count,
                        'last_download_time': file_record.last_download_time.isoformat() if file_record.last_download_time else None
                    }
                })

            return jsonify({
                'success': True,
                'message': f'找到{len(results)}个匹配的文件，请指定具体的软件包或路径',
                'count': len(results),
                'files': matched_files,
                'query_conditions': {
                    'system': system,
                    'architecture': architecture,
                    'filename': filename,
                    'package_name': package_name if package_name else 'all'
                }
            })

    except Exception as e:
        logger.error(f"按条件下载文件失败: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'下载失败: {str(e)}'}), 500


@app.route('/api/packages/download/latest/redirect', methods=['GET'])
def redirect_to_latest_package():
    """
    根据系统、架构、软件包名重定向到最新的软件包
    参数：system（必须），architecture（必须），name（必须，精确匹配）
    返回：302重定向到最新的软件包静态文件路径
    """
    try:
        # 获取查询参数
        system = request.args.get('system', '')
        architecture = request.args.get('architecture', '')
        name = request.args.get('name', '')

        # 验证必须参数
        if not system or not architecture or not name:
            return jsonify({
                'success': False,
                'error': 'system, architecture和name都是必须参数'
            }), 400

        # 构建查询 - 精确匹配系统、架构和软件包名
        query = Package.query.filter(
            Package.system == system,
            Package.architecture == architecture,
            Package.name == name
        )

        # 查询所有符合条件的软件包
        packages = query.order_by(Package.upload_time.desc()).all()

        if not packages:
            return jsonify({
                'success': False,
                'error': f'未找到符合条件的软件包: system={system}, architecture={architecture}, name={name}'
            }), 404

        # 选择最新的软件包（按上传时间排序，取第一个）
        latest_package = packages[0]

        # 检查原始包文件是否存在
        if not latest_package.original_package_path or not os.path.exists(latest_package.original_package_path):
            return jsonify({
                'success': False,
                'error': '软件包文件不存在或已损坏'
            }), 404

        # 更新下载次数和时间
        latest_package.download_count += 1
        latest_package.last_download_time = datetime.utcnow()
        db.session.commit()

        # 构建nginx静态文件路径
        # 原始包文件存储路径：/data/original_packages/{package_id}_{original_filename}
        # nginx访问路径：/packages/original_packages/{package_id}_{original_filename}
        original_filename = latest_package.original_filename
        redirect_url = f"/packages/original_packages/{latest_package.id}_{original_filename}"

        # 返回302重定向
        return redirect(redirect_url, code=302)

    except Exception as e:
        logger.error(f"重定向到最新软件包失败: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'重定向失败: {str(e)}'}), 500


@app.route('/api/packages/files/download/by-conditions/redirect', methods=['GET'])
def redirect_to_file_by_conditions():
    """
    根据系统、架构、文件名重定向到文件
    参数：system（必须），architecture（必须），filename（必须，不含路径的精确匹配），name（可选，软件包名），force（可选，布尔）
    返回：302重定向到文件静态路径或符合条件的文件列表（force=true时多结果也会自动选择并重定向）
    """
    try:
        # 获取查询参数
        system = request.args.get('system', '')
        architecture = request.args.get('architecture', '')
        filename = request.args.get('filename', '')
        package_name = request.args.get('name', '')
        force = parse_bool_arg(request.args.get('force'), default=False)

        # 验证必须参数
        if not system or not architecture or not filename:
            return jsonify({
                'success': False,
                'error': 'system, architecture和filename都是必须参数'
            }), 400

        # 构建查询条件
        query = db.session.query(PackageFile, Package).join(
            Package, PackageFile.package_id == Package.id
        ).filter(
            Package.system == system,
            Package.architecture == architecture,
            PackageFile.file_name == filename  # 精确匹配文件名（不含路径）
        )

        # 如果提供了软件包名，则添加过滤条件
        if package_name:
            query = query.filter(Package.name == package_name)

        # 执行查询
        results = query.all()

        if not results:
            return jsonify({
                'success': False,
                'error': f'未找到符合条件的文件: system={system}, architecture={architecture}, filename={filename}' +
                         (f', name={package_name}' if package_name else '')
            }), 404

        # 单结果，或者 force=true 且多结果时，直接选择目标并重定向
        if len(results) == 1 or force:
            if len(results) == 1:
                file_record, package = results[0]
            else:
                file_record, package = pick_best_file_match(
                    results=results,
                    system=system,
                    architecture=architecture,
                    filename=filename,
                    package_name=package_name
                )
                logger.info(
                    "force=true 命中多候选，自动选择: package_id=%s, package_name=%s, version=%s, file=%s",
                    package.id, package.name, package.version, file_record.file_path
                )

            # 检查文件是否存在
            if not os.path.exists(file_record.storage_path):
                return jsonify({
                    'success': False,
                    'error': '文件不存在或已损坏'
                }), 404

            # 检查文件路径安全性
            real_path = os.path.realpath(file_record.storage_path)
            storage_root = os.path.realpath(package.storage_path)

            if not real_path.startswith(storage_root):
                return jsonify({'success': False, 'error': '文件路径不安全'}), 403

            # 更新下载次数和时间
            file_record.download_count += 1
            file_record.last_download_time = datetime.utcnow()
            package.download_count += 1
            package.last_download_time = datetime.utcnow()
            db.session.commit()

            # 构建nginx静态文件路径
            # 文件存储路径示例：/data/{package_id}/path/to/file
            # nginx访问路径：/packages/{package_id}/path/to/file
            # 需要确保路径安全，不包含../等

            # 获取相对于package存储目录的路径
            storage_dir = package.storage_path
            file_relative_path = os.path.relpath(file_record.storage_path, storage_dir)

            # URL编码路径中的特殊字符
            import urllib.parse
            encoded_path = '/'.join(urllib.parse.quote(part) for part in file_relative_path.split('/'))

            redirect_url = f"/packages/{package.id}/{encoded_path}"

            # 返回302重定向
            return redirect(redirect_url, code=302)

        # 多个匹配结果且未 force，返回JSON列表
        else:
            matched_files = []
            for file_record, package in results:
                # 获取相对于package存储目录的路径
                storage_dir = package.storage_path
                file_relative_path = os.path.relpath(file_record.storage_path, storage_dir)

                # URL编码路径中的特殊字符
                import urllib.parse
                encoded_path = '/'.join(urllib.parse.quote(part) for part in file_relative_path.split('/'))

                nginx_path = f"/packages/{package.id}/{encoded_path}"

                matched_files.append({
                    'package': {
                        'id': package.id,
                        'name': package.name,
                        'version': package.version,
                        'system': package.system,
                        'architecture': package.architecture,
                        'original_filename': package.original_filename,
                        'upload_time': package.upload_time.isoformat() if package.upload_time else None,
                        'download_count': package.download_count,
                        'last_download_time': package.last_download_time.isoformat() if package.last_download_time else None
                    },
                    'file': {
                        'id': file_record.id,
                        'file_path': file_record.file_path,
                        'file_name': file_record.file_name,
                        'file_size': file_record.file_size,
                        'storage_path': file_record.storage_path,
                        'download_count': file_record.download_count,
                        'last_download_time': file_record.last_download_time.isoformat() if file_record.last_download_time else None,
                        'nginx_url': nginx_path  # 添加nginx访问路径
                    }
                })

            return jsonify({
                'success': True,
                'message': f'找到{len(results)}个匹配的文件，请指定具体的软件包或路径',
                'count': len(results),
                'files': matched_files,
                'query_conditions': {
                    'system': system,
                    'architecture': architecture,
                    'filename': filename,
                    'package_name': package_name if package_name else 'all'
                }
            })

    except Exception as e:
        logger.error(f"按条件重定向到文件失败: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'重定向失败: {str(e)}'}), 500


@app.route('/api/packages/<package_id>/files/download', methods=['GET'])
def download_package_file(package_id):
    """下载package中的子文件"""
    file_path = request.args.get('path', '')
    if not file_path:
        return jsonify({'success': False, 'error': '请提供文件路径'}), 400

    package = Package.query.get(package_id)
    if not package:
        return jsonify({'success': False, 'error': '软件包不存在'}), 404

    try:
        # 查找文件记录
        file_record = PackageFile.query.filter_by(
            package_id=package_id,
            file_path=file_path
        ).first()

        if not file_record:
            return jsonify({'success': False, 'error': '文件不存在'}), 404

        # 检查文件是否存在
        if not os.path.exists(file_record.storage_path):
            return jsonify({'success': False, 'error': '文件不存在或已损坏'}), 404

        # 检查是否在package存储目录内（安全校验）
        real_path = os.path.realpath(file_record.storage_path)
        storage_root = os.path.realpath(package.storage_path)

        if not real_path.startswith(storage_root):
            return jsonify({'success': False, 'error': '文件路径不安全'}), 403

        # 更新下载次数和时间
        file_record.download_count += 1
        file_record.last_download_time = datetime.utcnow()

        # 同时更新package的下载次数
        package.download_count += 1
        package.last_download_time = datetime.utcnow()

        db.session.commit()

        # 发送文件
        directory = os.path.dirname(file_record.storage_path)
        filename = os.path.basename(file_record.storage_path)

        return send_from_directory(
            directory=directory,
            path=filename,
            as_attachment=True,
            download_name=os.path.basename(file_path)
        )

    except Exception as e:
        return jsonify({'success': False, 'error': f'下载失败: {str(e)}'}), 500


# ==================== 原有API路由 ====================

@app.route('/api/packages', methods=['GET'])
def get_all_packages():
    """获取所有软件包列表"""
    packages = Package.query.all()

    result = []
    for pkg in packages:
        result.append({
            'id': pkg.id,
            'name': pkg.name,
            'version': pkg.version,
            'system': pkg.system,
            'architecture': pkg.architecture,
            'original_filename': pkg.original_filename,
            'total_size': pkg.total_size,
            'file_count': pkg.file_count,
            'upload_time': pkg.upload_time.isoformat() if pkg.upload_time else None,
            'last_check_time': pkg.last_check_time.isoformat() if pkg.last_check_time else None,
            'check_status': pkg.check_status,
            'original_package_path': pkg.original_package_path,
            'download_count': pkg.download_count,
            'last_download_time': pkg.last_download_time.isoformat() if pkg.last_download_time else None
        })

    return jsonify({
        'success': True,
        'count': len(result),
        'packages': result
    })


@app.route('/api/packages/search', methods=['GET'])
def search_packages():
    """搜索软件包"""
    name = request.args.get('name', '')
    version = request.args.get('version', '')
    architecture = request.args.get('architecture', '')

    query = Package.query

    if name:
        query = query.filter(Package.name.ilike(f'%{name}%'))
    if version:
        query = query.filter(Package.version.ilike(f'%{version}%'))
    if architecture:
        query = query.filter(Package.architecture.ilike(f'%{architecture}%'))

    packages = query.all()

    result = []
    for pkg in packages:
        result.append({
            'id': pkg.id,
            'name': pkg.name,
            'version': pkg.version,
            'system': pkg.system,
            'architecture': pkg.architecture,
            'original_filename': pkg.original_filename,
            'total_size': pkg.total_size,
            'file_count': pkg.file_count,
            'upload_time': pkg.upload_time.isoformat() if pkg.upload_time else None,
            'last_check_time': pkg.last_check_time.isoformat() if pkg.last_check_time else None,
            'check_status': pkg.check_status,
            'original_package_path': pkg.original_package_path,
            'download_count': pkg.download_count,
            'last_download_time': pkg.last_download_time.isoformat() if pkg.last_download_time else None
        })

    return jsonify({
        'success': True,
        'count': len(result),
        'packages': result
    })


@app.route('/api/packages/upload', methods=['POST'])
def upload_package():
    """上传软件包"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': '没有文件被上传'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': '没有选择文件'}), 400

    try:
        # 保存上传的文件
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(temp_path)

        # 解析文件名
        package_info = parse_filename(filename)

        # 计算MD5作为唯一ID
        package_id = calculate_md5(temp_path)

        # 检查是否已存在相同的MD5
        existing_by_md5 = Package.query.get(package_id)
        if existing_by_md5:
            os.remove(temp_path)
            return jsonify({
                'success': False,
                'error': '相同的软件包已存在（文件内容相同）',
                'package_id': package_id
            }), 409

        # 检查是否已存在相同的name, version, system, architecture
        existing_by_composite = Package.query.filter_by(
            name=package_info['name'],
            version=package_info['version'],
            system=package_info['system'],
            architecture=package_info['architecture']
        ).first()

        if existing_by_composite:
            os.remove(temp_path)
            return jsonify({
                'success': False,
                'error': f'已存在相同名称、版本、系统和架构的软件包。请先删除现有软件包（ID: {existing_by_composite.id}），或使用不同的版本号',
                'existing_package_id': existing_by_composite.id,
                'existing_package_name': f"{existing_by_composite.name}-{existing_by_composite.version}",
                'conflict_details': {
                    'name': package_info['name'],
                    'version': package_info['version'],
                    'system': package_info['system'],
                    'architecture': package_info['architecture']
                }
            }), 409

        # 保存原始包文件
        original_package_path = os.path.join(app.config['ORIGINAL_PACKAGE_FOLDER'], f"{package_id}_{filename}")
        shutil.copy2(temp_path, original_package_path)

        # 解压软件包
        storage_path, files_info = extract_package(temp_path, package_id, package_info)

        # 计算总大小和文件数
        total_size = sum(f['file_size'] for f in files_info)
        file_count = len(files_info)

        # 创建软件包记录
        package = Package(
            id=package_id,
            name=package_info['name'],
            version=package_info['version'],
            system=package_info['system'],
            architecture=package_info['architecture'],
            original_filename=filename,
            storage_path=storage_path,
            original_package_path=original_package_path,
            total_size=total_size,
            file_count=file_count,
            download_count=0
        )
        db.session.add(package)

        # 创建文件记录
        for file_info in files_info:
            file_record = PackageFile(
                package_id=package_id,
                file_path=file_info['file_path'],
                file_name=file_info['file_name'],
                file_size=file_info['file_size'],
                storage_path=file_info['storage_path'],
                download_count=0
            )
            db.session.add(file_record)

        db.session.commit()

        # 清理临时文件
        os.remove(temp_path)

        return jsonify({
            'success': True,
            'package_id': package_id,
            'package_info': {
                'name': package.name,
                'version': package.version,
                'system': package.system,
                'architecture': package.architecture
            },
            'storage_path': storage_path,
            'original_package_path': original_package_path,
            'total_size': total_size,
            'file_count': file_count
        })

    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        # 清理可能已创建的文件
        if 'original_package_path' in locals() and os.path.exists(original_package_path):
            os.remove(original_package_path)
        if 'storage_path' in locals() and os.path.exists(storage_path):
            shutil.rmtree(storage_path)
        return jsonify({'success': False, 'error': f'上传失败: {str(e)}'}), 500


@app.route('/api/packages/<package_id>', methods=['GET'])
def get_package_detail(package_id):
    """获取软件包详情"""
    package = Package.query.get(package_id)
    if not package:
        return jsonify({'success': False, 'error': '软件包不存在'}), 404

    # 获取文件列表
    files = []
    for file_record in package.files.limit(10000):  # 限制返回数量
        files.append({
            'path': file_record.file_path,
            'name': file_record.file_name,
            'size': file_record.file_size,
            'download_count': file_record.download_count,
            'last_download_time': file_record.last_download_time.isoformat() if file_record.last_download_time else None
        })

    return jsonify({
        'success': True,
        'package': {
            'id': package.id,
            'name': package.name,
            'version': package.version,
            'system': package.system,
            'architecture': package.architecture,
            'original_filename': package.original_filename,
            'storage_path': package.storage_path,
            'original_package_path': package.original_package_path,
            'total_size': package.total_size,
            'file_count': package.file_count,
            'upload_time': package.upload_time.isoformat() if package.upload_time else None,
            'last_check_time': package.last_check_time.isoformat() if package.last_check_time else None,
            'check_status': package.check_status,
            'download_count': package.download_count,
            'last_download_time': package.last_download_time.isoformat() if package.last_download_time else None
        },
        'files': files,
        'total_files': package.file_count
    })


@app.route('/api/packages/<package_id>/files', methods=['GET'])
def get_package_files(package_id):
    """获取软件包文件列表（分页）"""
    package = Package.query.get(package_id)
    if not package:
        return jsonify({'success': False, 'error': '软件包不存在'}), 404

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    files_query = package.files
    total = files_query.count()
    files_paginated = files_query.paginate(page=page, per_page=per_page, error_out=False)

    files = []
    for file_record in files_paginated.items:
        files.append({
            'path': file_record.file_path,
            'name': file_record.file_name,
            'size': file_record.file_size,
            'storage_path': file_record.storage_path,
            'download_count': file_record.download_count,
            'last_download_time': file_record.last_download_time.isoformat() if file_record.last_download_time else None
        })

    return jsonify({
        'success': True,
        'files': files,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': files_paginated.pages
        }
    })


@app.route('/api/packages/<package_id>/check', methods=['GET'])
def check_package(package_id):
    """校验软件包完整性"""
    package = Package.query.get(package_id)
    if not package:
        return jsonify({'success': False, 'error': '软件包不存在'}), 404

    try:
        result = check_package_integrity(package_id)
    except ValueError as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'校验失败: {str(e)}'}), 500

    package = Package.query.get(package_id)
    result['success'] = True
    result['package_id'] = package_id
    result['package_name'] = f"{package.name}-{package.version}" if package else package_id
    result['last_check_time'] = package.last_check_time.isoformat() if package and package.last_check_time else None
    return jsonify(result)


@app.route('/api/packages/check-all', methods=['POST'])
def check_all_packages():
    """批量校验所有软件包"""
    package_ids = [pkg_id for (pkg_id,) in Package.query.with_entities(Package.id).all()]
    results = []

    for package_id in package_ids:
        try:
            result = check_package_integrity(package_id)
            package = Package.query.get(package_id)
            result['package_id'] = package_id
            result['package_name'] = f"{package.name}-{package.version}" if package else package_id
            result['last_check_time'] = package.last_check_time.isoformat() if package and package.last_check_time else None
            results.append(result)
        except ValueError:
            # 删除并发导致不存在，跳过
            continue
        except Exception as e:
            db.session.rollback()
            results.append({
                'package_id': package_id,
                'valid': False,
                'error': str(e)
            })

    return jsonify({
        'success': True,
        'total': len(results),
        'results': results
    })


@app.route('/api/packages/<package_id>', methods=['DELETE'])
def delete_package(package_id):
    """删除单个软件包"""
    package_lock = _get_package_lock(package_id)
    with package_lock:
        package = Package.query.get(package_id)
        if not package:
            return jsonify({'success': False, 'error': '软件包不存在'}), 404

        try:
            # 删除存储的文件
            if os.path.exists(package.storage_path):
                shutil.rmtree(package.storage_path)

            # 删除原始包文件
            if package.original_package_path and os.path.exists(package.original_package_path):
                os.remove(package.original_package_path)

            # 删除数据库记录（级联删除文件记录）
            db.session.delete(package)
            db.session.commit()

            return jsonify({
                'success': True,
                'message': '软件包删除成功',
                'package_id': package_id
            })

        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': f'删除失败: {str(e)}'}), 500
        finally:
            _release_package_lock_if_unused(package_id)


# ==================== 解决数据库锁超时问题 ====================

@app.route('/api/packages/batch-delete', methods=['POST'])
def batch_delete_packages():
    """批量删除软件包 - 优化版本，避免锁超时"""
    data = request.get_json()
    if not data or 'package_ids' not in data:
        return jsonify({'success': False, 'error': '请提供要删除的软件包ID列表'}), 400

    package_ids = data['package_ids']
    if not isinstance(package_ids, list):
        return jsonify({'success': False, 'error': 'package_ids必须是数组'}), 400

    success_count = 0
    error_count = 0
    errors = []

    # 限制批量删除的数量，避免长时间锁定
    MAX_BATCH_SIZE = 1000
    if len(package_ids) > MAX_BATCH_SIZE:
        return jsonify({
            'success': False,
            'error': f'批量删除数量超过限制，最多允许{MAX_BATCH_SIZE}个',
            'current_count': len(package_ids)
        }), 400

    try:
        for package_id in package_ids:
            package_lock = _get_package_lock(package_id)
            with package_lock:
                package = Package.query.get(package_id)
                if not package:
                    errors.append(f"软件包 {package_id} 不存在")
                    error_count += 1
                    continue
                logger.info("start delete package: {}-{}-{}-{}".format(package.name,package.version,package.system,package.architecture))
                try:
                    # 使用独立的事务处理每个删除，避免长事务
                    with db.session.begin_nested():
                        # 删除存储的文件
                        if os.path.exists(package.storage_path):
                            shutil.rmtree(package.storage_path)

                        # 删除原始包文件
                        if package.original_package_path and os.path.exists(package.original_package_path):
                            os.remove(package.original_package_path)

                        # 删除数据库记录
                        db.session.delete(package)
                        success_count += 1

                        # 立即提交这个嵌套事务
                        db.session.flush()

                except Exception as e:
                    db.session.rollback()  # 回滚嵌套事务
                    errors.append(f"删除软件包 {package_id} 失败: {str(e)}")
                    error_count += 1
                    continue
                finally:
                    _release_package_lock_if_unused(package_id)
                db.session.commit()

        # 提交所有更改
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'批量删除失败: {str(e)}'}), 500

    return jsonify({
        'success': True,
        'message': f'批量删除完成，成功: {success_count}, 失败: {error_count}',
        'success_count': success_count,
        'error_count': error_count,
        'errors': errors if errors else None
    })


@app.route('/api/packages/delete-all', methods=['DELETE'])
def delete_all_packages():
    """删除所有软件包"""
    try:
        # 获取所有软件包
        packages = Package.query.all()
        deleted_count = 0

        for package in packages:
            package_lock = _get_package_lock(package.id)
            with package_lock:
                # 删除存储的文件
                if os.path.exists(package.storage_path):
                    shutil.rmtree(package.storage_path)

                # 删除原始包文件
                if package.original_package_path and os.path.exists(package.original_package_path):
                    os.remove(package.original_package_path)

                deleted_count += 1
            _release_package_lock_if_unused(package.id)

        # 清空数据库（使用原生SQL确保效率）
        db.session.execute(db.text('DELETE FROM secflow_static_binary_package_files'))
        db.session.execute(db.text('DELETE FROM secflow_static_binary_packages'))
        db.session.commit()

        # 清空原始包目录
        original_dir = app.config['ORIGINAL_PACKAGE_FOLDER']
        for filename in os.listdir(original_dir):
            file_path = os.path.join(original_dir, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)

        return jsonify({
            'success': True,
            'message': f'已删除所有软件包，共 {deleted_count} 个'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'清除失败: {str(e)}'}), 500


@app.route('/api/packages/architectures', methods=['GET'])
def get_architectures():
    """获取所有支持的CPU架构列表"""
    architectures = db.session.query(Package.architecture).distinct().all()
    arch_list = [arch[0] for arch in architectures if arch[0]]

    return jsonify({
        'success': True,
        'architectures': sorted(arch_list)
    })


@app.route('/api/packages/statistics', methods=['GET'])
def get_statistics():
    """获取统计信息"""
    total_packages = Package.query.count()
    total_size = db.session.query(db.func.sum(Package.total_size)).scalar() or 0
    total_files = db.session.query(db.func.sum(Package.file_count)).scalar() or 0
    total_downloads = db.session.query(db.func.sum(Package.download_count)).scalar() or 0

    # 获取下载次数最多的软件包
    most_downloaded = Package.query.order_by(Package.download_count.desc()).first()

    # 按架构统计
    arch_stats = db.session.query(
        Package.architecture,
        db.func.count(Package.id),
        db.func.sum(Package.total_size),
        db.func.sum(Package.download_count)
    ).group_by(Package.architecture).all()

    # 按系统统计
    system_stats = db.session.query(
        Package.system,
        db.func.count(Package.id),
        db.func.sum(Package.total_size),
        db.func.sum(Package.download_count)
    ).group_by(Package.system).all()

    # 按校验状态统计
    status_stats = db.session.query(
        Package.check_status,
        db.func.count(Package.id),
        db.func.sum(Package.download_count)
    ).group_by(Package.check_status).all()

    return jsonify({
        'success': True,
        'statistics': {
            'summary': {
                'total_packages': total_packages,
                'total_size': total_size,
                'total_size_human': f"{total_size / (1024**3):.2f} GB",
                'total_files': total_files,
                'total_downloads': total_downloads,
                'avg_file_size': total_size / max(total_files, 1),
                'avg_package_size': total_size / max(total_packages, 1)
            },
            'most_downloaded': {
                'package_id': most_downloaded.id if most_downloaded else None,
                'name': most_downloaded.name if most_downloaded else None,
                'version': most_downloaded.version if most_downloaded else None,
                'download_count': most_downloaded.download_count if most_downloaded else 0,
                'architecture': most_downloaded.architecture if most_downloaded else None
            },
            'by_architecture': [
                {
                    'architecture': arch,
                    'package_count': count,
                    'total_size': size,
                    'total_size_human': f"{size / (1024**3):.2f} GB",
                    'download_count': downloads
                }
                for arch, count, size, downloads in arch_stats
            ],
            'by_system': [
                {
                    'system': system,
                    'package_count': count,
                    'total_size': size,
                    'total_size_human': f"{size / (1024**3):.2f} GB",
                    'download_count': downloads
                }
                for system, count, size, downloads in system_stats
            ],
            'by_status': [
                {
                    'status': status,
                    'package_count': count,
                    'download_count': downloads
                }
                for status, count, downloads in status_stats
            ]
        }
    })


@app.route('/api/packages/health', methods=['GET'])
@app.route('/api/static-binary/health', methods=['GET'])
def health_check():
    """健康检查接口"""
    try:
        # 检查数据库连接
        db.session.execute(db.text('SELECT 1'))

        # 检查存储目录
        storage_dir = app.config['STORAGE_FOLDER']
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir, exist_ok=True)

        # 检查原始包目录
        original_dir = app.config['ORIGINAL_PACKAGE_FOLDER']
        if not os.path.exists(original_dir):
            os.makedirs(original_dir, exist_ok=True)

        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'storage': 'available',
            'original_storage': 'available',
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': '请求的资源不存在'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'error': '服务器内部错误'}), 500


# ==================== 初始化应用 ====================

def init_database():
    """初始化数据库"""
    with app.app_context():
        db.create_all()
        print("数据库表创建完成")


def start_auto_verify_worker():
    """启动后台自动校验线程。"""
    global _auto_verify_thread
    if _auto_verify_thread and _auto_verify_thread.is_alive():
        return

    _auto_verify_stop_event.clear()
    _auto_verify_thread = threading.Thread(
        target=auto_verify_packages_loop,
        name="static-binary-auto-verify",
        daemon=True
    )
    _auto_verify_thread.start()


def stop_auto_verify_worker(timeout_seconds: int = 5):
    """停止后台自动校验线程。"""
    global _auto_verify_thread
    _auto_verify_stop_event.set()
    if _auto_verify_thread and _auto_verify_thread.is_alive():
        _auto_verify_thread.join(timeout=timeout_seconds)
    _auto_verify_thread = None


def verify_auth_service_or_exit():
    """启动时校验Auth服务连通性与机机Token有效性。"""
    cfg = config.auth_service
    machine_token = getattr(cfg, "service_machine_token", None)
    if not machine_token:
        logger.error("未配置auth_service.service_machine_token，拒绝启动")
        sys.exit(1)

    base_url = f"http://{cfg.host}:{cfg.port}"
    health_url = f"{base_url}/api/auth/health"
    validate_url = cfg.validate_url

    try:
        with urlopen(health_url, timeout=cfg.timeout) as resp:
            if resp.status != 200:
                logger.error(f"Auth服务健康检查失败: status={resp.status}")
                sys.exit(1)
    except Exception as e:
        logger.error(f"Auth服务不可达: {e}")
        sys.exit(1)

    try:
        req = Request(validate_url, method="POST")
        req.add_header("Authorization", f"Bearer {machine_token}")
        with urlopen(req, timeout=cfg.timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            if resp.status != 200:
                logger.error(f"机机Token校验失败: status={resp.status}, body={body}")
                sys.exit(1)
            payload = json.loads(body or "{}")
            if payload.get("token_type") != "machine":
                logger.error(f"机机Token类型异常: token_type={payload.get('token_type')}")
                sys.exit(1)
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
        logger.error(f"机机Token校验失败: status={e.code}, body={body}")
        sys.exit(1)
    except URLError as e:
        logger.error(f"机机Token校验失败，Auth服务不可达: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"机机Token校验失败: {e}")
        sys.exit(1)


# ==================== 菜单注册服务 ====================

async def setup_registry():
    """设置Menu注册中心"""
    try:
        registry_service = get_registry_service()
        await registry_service.start()
        logger.info("Menu注册服务启动成功")
    except Exception as e:
        logger.warning(f"Menu注册服务启动失败: {e}，服务将继续运行")


async def shutdown_registry():
    """关闭Menu注册中心"""
    try:
        registry_service = get_registry_service()
        await registry_service.stop()
        logger.info("Menu注册服务已停止")
    except Exception as e:
        logger.warning(f"Menu注册服务停止失败: {e}")


def start_registry_background():
    """在独立事件循环中启动Menu注册心跳，避免主线程关闭loop后任务丢失。"""
    global _registry_thread, _registry_loop

    if _registry_thread and _registry_thread.is_alive():
        return

    def _worker():
        global _registry_loop
        loop = asyncio.new_event_loop()
        _registry_loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(setup_registry())
            loop.run_forever()
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()

    _registry_thread = threading.Thread(target=_worker, name="menu-registry-loop", daemon=True)
    _registry_thread.start()


def stop_registry_background():
    """停止后台Menu注册心跳循环。"""
    global _registry_thread, _registry_loop

    if _registry_loop is None:
        return

    try:
        future = asyncio.run_coroutine_threadsafe(shutdown_registry(), _registry_loop)
        future.result(timeout=10)
    except Exception as e:
        logger.warning(f"停止Menu注册后台线程失败: {e}")
    finally:
        _registry_loop.call_soon_threadsafe(_registry_loop.stop)

    if _registry_thread and _registry_thread.is_alive():
        _registry_thread.join(timeout=5)

    _registry_thread = None
    _registry_loop = None


# 注册程序退出时的清理操作
def cleanup(signum=None, frame=None):
    """清理操作"""
    logger.info("正在执行清理操作...")
    try:
        stop_auto_verify_worker()
        stop_registry_background()
    except Exception as e:
        logger.error(f"清理操作失败: {e}")
    sys.exit(0)


# 注册信号处理
signal.signal(signal.SIGTERM, cleanup)
signal.signal(signal.SIGINT, cleanup)
atexit.register(lambda: stop_registry_background())
atexit.register(lambda: stop_auto_verify_worker())


# ==================== 启动应用 ====================

if __name__ == '__main__':
    verify_auth_service_or_exit()
    logger.info("Auth服务连通性与机机Token校验通过")

    # 初始化数据库
    init_database()
    start_auto_verify_worker()

    # 启动Menu注册服务
    try:
        start_registry_background()
    except Exception as e:
        logger.warning(f"注册服务启动失败: {e}，服务将继续运行")

    # 启动Flask应用
    app.run(host=config.app.host, port=config.app.port, debug=config.app.debug)
