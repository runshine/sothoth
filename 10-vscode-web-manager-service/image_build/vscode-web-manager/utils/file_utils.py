"""
文件操作工具类
"""
import os
import time
import shutil
import zipfile
import tarfile
import hashlib
import mimetypes
from datetime import datetime
from typing import List, Dict, Any, Optional

from config import Config

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
            import logging
            logger = logging.getLogger(__name__)
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
            import logging
            logger = logging.getLogger(__name__)
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
        """
        try:
            # 检查路径安全性
            if not FileUtils.is_safe_path(project_extract_path, file_path):
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"路径不安全: {file_path}")
                return None

            # 构建完整文件路径
            full_path = os.path.join(project_extract_path, file_path)

            # 检查文件是否存在
            if not os.path.exists(full_path) or not os.path.isfile(full_path):
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"文件不存在: {full_path}")
                return None

            # 检查文件大小
            file_size = os.path.getsize(full_path)
            if file_size > Config.MAX_DOWNLOAD_SIZE:
                import logging
                logger = logging.getLogger(__name__)
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
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"下载文件失败: {e}")
            return None

    @staticmethod
    def download_directory(project_extract_path: str, dir_path: str, user_id: int) -> Optional[str]:
        """
        下载目录（打包为zip）
        """
        try:
            # 检查路径安全性
            if not FileUtils.is_safe_path(project_extract_path, dir_path):
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"路径不安全: {dir_path}")
                return None

            # 构建完整目录路径
            full_path = os.path.join(project_extract_path, dir_path)

            # 检查目录是否存在
            if not os.path.exists(full_path) or not os.path.isdir(full_path):
                import logging
                logger = logging.getLogger(__name__)
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
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"下载目录失败: {e}")
            return None

    @staticmethod
    def download_project_files(project_extract_path: str, file_paths: List[str], user_id: int) -> Optional[str]:
        """
        下载多个文件（打包为zip）
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
                        import logging
                        logger = logging.getLogger(__name__)
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
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"下载多个文件失败: {e}")
            return None