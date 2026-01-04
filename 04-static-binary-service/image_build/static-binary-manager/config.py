"""
配置文件
"""

import os

class Config:
    # Flask配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # 数据库配置
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'mysql://package_user:package_password@localhost/package_manager'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 文件存储配置
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or '/tmp/package_uploads'
    STORAGE_FOLDER = os.environ.get('STORAGE_FOLDER') or '/data/packages'

    # 上传限制
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024 * 1024  # 2GB

    # 支持的压缩格式
    ALLOWED_EXTENSIONS = {
        '.zip', '.tar.gz', '.tar.bz2', '.tar.xz', '.tar',
        '.gz', '.bz2'
    }

    # 支持的CPU架构
    SUPPORTED_ARCHITECTURES = {
        'x86_64', 'x86', 'amd64', 'i386', 'i686',
        'arm64', 'armhf', 'armel', 'aarch64',
        'ppc64le', 'ppc64', 's390x', 'mips', 'mips64'
    }