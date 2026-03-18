#!/usr/bin/env python3
"""详细检查admin用户权限"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.database import get_db
from app.model import User, Department, DepartmentMember
from app.router.org import (
    is_admin,
    get_user_department_ids,
    get_manageable_department_ids,
    get_accessible_department_ids
)


def check_admin_user():
    """详细检查admin用户权限"""
    print("=" * 60)
    print("检查admin用户权限")
    print("=" * 60)
    
    db = next(get_db())
    
    # 查找admin用户
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        print("未找到admin用户!")
        return
    
    print(f"\n用户信息:")
    print(f"  ID: {admin_user.id}")
    print(f"  用户名: {admin_user.username}")
    print(f"  是否激活: {admin_user.is_active}")
    
    # 检查角色
    role_names = admin_user.get_all_role_names()
    print(f"\n角色信息:")
    print(f"  角色列表: {role_names}")
    print(f"  是否管理员(通过角色判断): {is_admin(admin_user)}")
    
    # 检查部门成员关系
    print(f"\n部门成员关系:")
    memberships = db.query(DepartmentMember).filter(
        DepartmentMember.user_id == admin_user.id
    ).all()
    
    for m in memberships:
        dept = db.query(Department).filter(Department.id == m.department_id).first()
        print(f"  - 部门: {dept.name if dept else '未知'} (ID: {m.department_id}), 角色: {m.role}")
    
    # 检查可管理部门
    manageable_ids = get_manageable_department_ids(db, admin_user)
    print(f"\n可管理部门（包含下级部门）:")
    if manageable_ids is None:
        print("  所有部门（管理员）")
    else:
        print(f"  ID列表: {manageable_ids}")
        for dept_id in manageable_ids:
            dept = db.query(Department).filter(Department.id == dept_id).first()
            parent_name = "无"
            if dept and dept.parent_id:
                parent = db.query(Department).filter(Department.id == dept.parent_id).first()
                if parent:
                    parent_name = parent.name
            print(f"    - {dept.name if dept else '未知'} (ID: {dept_id}, 上级: {parent_name})")
    
    # 检查可访问部门
    accessible_ids = get_accessible_department_ids(db, admin_user)
    print(f"\n可访问部门:")
    if accessible_ids is None:
        print("  所有部门（管理员）")
    else:
        print(f"  ID列表: {accessible_ids}")
    
    # 模拟API返回
    print(f"\n模拟API返回 (UserPermissionInfo):")
    print(f"  is_admin: {is_admin(admin_user)}")
    print(f"  department_ids: {get_user_department_ids(db, admin_user.id)}")
    print(f"  manageable_department_ids: {manageable_ids if manageable_ids is not None else []}")
    print(f"  role_names: {role_names}")


if __name__ == "__main__":
    check_admin_user()
