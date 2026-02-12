"""
数据库初始化脚本
"""

import sys
# 导入app模块会自动解析命令行参数并加载配置
from app import app, db

with app.app_context():
    # 创建所有表
    db.create_all()

    # 可选：创建索引
    from sqlalchemy import text

    # 为常用查询字段创建索引
    index_statements = [
        "CREATE INDEX IF NOT EXISTS idx_packages_name ON secflow_static_binary_packages(name)",
        "CREATE INDEX IF NOT EXISTS idx_packages_version ON secflow_static_binary_packages(version)",
        "CREATE INDEX IF NOT EXISTS idx_packages_arch ON secflow_static_binary_packages(architecture)",
        "CREATE INDEX IF NOT EXISTS idx_packages_status ON secflow_static_binary_packages(check_status)",
        "CREATE INDEX IF NOT EXISTS idx_files_package ON secflow_static_binary_package_files(package_id)",
        "CREATE INDEX IF NOT EXISTS idx_files_path ON secflow_static_binary_package_files(file_path(255))"
    ]

    for stmt in index_statements:
        try:
            db.session.execute(text(stmt))
        except Exception as e:
            print(f"创建索引时出错: {e}")

    db.session.commit()
    print("数据库初始化完成！")
    print(f"使用配置文件: {app.config.get('CONFIG_PATH', '默认配置')}")