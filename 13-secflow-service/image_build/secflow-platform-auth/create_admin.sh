#!/bin/bash
# 向数据库中添加管理员用户

cd "$(dirname "$0")"

# 激活虚拟环境
#source /home/runshine/miniconda3/etc/profile.d/conda.sh
#conda activate sothoth

python -c "
from app.database import SessionLocal, init_db
from app.model import User, Role
from app.auth import get_password_hash

# 初始化数据库
init_db()
db = SessionLocal()

# 检查是否已存在 admin 角色
role = db.query(Role).filter(Role.name == 'admin').first()
if not role:
    role = Role(name='admin', description='Administrator')
    db.add(role)
    db.commit()
    print(f'Created role: admin (id={role.id})')
else:
    print(f'Role admin already exists (id={role.id})')

# 检查是否已存在 admin 用户
user = db.query(User).filter(User.username == 'admin').first()
if user:
    print(f'User admin already exists (id={user.id})')
else:
    user = User(
        username='admin',
        hashed_password=get_password_hash('Huawei12#$'),
        is_active=True
    )
    # 绑定 admin 角色
    user.roles = [role]
    db.add(user)
    db.commit()
    db.refresh(user)
    print(f'Created user: admin (id={user.id})')

print('Done!')
"