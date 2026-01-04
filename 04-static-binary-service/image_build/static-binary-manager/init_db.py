"""
数据库初始化脚本
"""

from app import app, db

with app.app_context():
    # 创建所有表
    db.create_all()

    # 可选：创建索引
    from sqlalchemy import text

    # 为常用查询字段创建索引
    index_statements = [
        "CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name)",
        "CREATE INDEX IF NOT EXISTS idx_packages_version ON packages(version)",
        "CREATE INDEX IF NOT EXISTS idx_packages_arch ON packages(architecture)",
        "CREATE INDEX IF NOT EXISTS idx_packages_status ON packages(check_status)",
        "CREATE INDEX IF NOT EXISTS idx_files_package ON package_files(package_id)",
        "CREATE INDEX IF NOT EXISTS idx_files_path ON package_files(file_path(255))"
    ]

    for stmt in index_statements:
        try:
            db.session.execute(text(stmt))
        except Exception as e:
            print(f"创建索引时出错: {e}")

    db.session.commit()
    print("数据库初始化完成！")