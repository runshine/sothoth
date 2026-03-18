#!/usr/bin/env python3
"""为admin用户配置管理员权限"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.database import get_db
from app.model import User, Role


def configure_admin_permissions():
    """为admin用户配置管理员权限"""
    print("=" * 60)
    print("配置admin用户管理员权限")
    print("=" * 60)
    
    db = next(get_db())
    
    # 查找admin用户
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        print("错误: 未找到admin用户!")
        return False
    
    print(f"\n用户信息:")
    print(f"  ID: {admin_user.id}")
    print(f"  用户名: {admin_user.username}")
    print(f"  当前角色: {admin_user.get_all_role_names()}")
    
    # 查找或创建admin角色
    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        print("\n创建admin角色...")
        admin_role = Role(
            name="admin",
            description="系统管理员角色，拥有所有权限"
        )
        db.add(admin_role)
        db.commit()
        db.refresh(admin_role)
        print(f"  已创建角色: {admin_role.name}")
    else:
        print(f"\n已存在admin角色: {admin_role.name}")
    
    # 检查用户是否已有admin角色
    if admin_role in admin_user.roles:
        print("\nadmin用户已经拥有admin角色，无需重复添加")
    else:
        print("\n为admin用户添加admin角色...")
        admin_user.roles.append(admin_role)
        db.commit()
        print("  已添加admin角色")
    
    # 验证权限
    print(f"\n权限验证:")
    print(f"  角色列表: {admin_user.get_all_role_names()}")
    
    from app.router.org import is_admin, get_manageable_department_ids, get_department_structure_manageable_ids
    
    print(f"  is_admin: {is_admin(admin_user)}")
    
    manageable_ids = get_manageable_department_ids(db, admin_user)
    print(f"  manageable_department_ids: {manageable_ids}")
    
    dept_structure_ids = get_department_structure_manageable_ids(db, admin_user)
    print(f"  department_structure_manageable_ids: {dept_structure_ids}")
    
    print("\n" + "=" * 60)
    print("配置完成!")
    print("=" * 60)
    
    return True


if __name__ == "__main__":
    configure_admin_permissions()
