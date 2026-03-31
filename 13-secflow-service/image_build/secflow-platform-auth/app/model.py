"""SQLAlchemy数据库模型"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db_base import Base  # 从 db_base 导入 Base，确保使用同一个


# 用户角色关联表（多对多）- 放在最前面
secflow_user_user_role = Table(
    'secflow_user_user_role',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('secflow_user_users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('secflow_user_role.id'), primary_key=True)
)


class User(Base):
    """用户模型"""
    __tablename__ = "secflow_user_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # 关系 - roles 对应 Role.users，back_populates 应该是 "users"
    roles = relationship("Role", secondary=secflow_user_user_role, back_populates="users")

    def get_all_role_names(self) -> list:
        """获取所有角色名称"""
        return [role.name for role in self.roles]


class Role(Base):
    """角色模型"""
    __tablename__ = "secflow_user_role"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(String(500))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # 关系 - users 对应 User.roles，back_populates 应该是 "roles"
    users = relationship("User", secondary=secflow_user_user_role, back_populates="roles")


class MachineToken(Base):
    """机机Token模型"""
    __tablename__ = "secflow_user_machine_token"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(500), unique=True, index=True, nullable=False)
    machine_code = Column(String(100), unique=True, nullable=False)
    description = Column(String(500))
    token_scope = Column(String(32), nullable=False, default="global")
    project_id = Column(String(64), nullable=True, index=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    expires_at = Column(DateTime(timezone=True), nullable=True)  # null表示永不过期


class UserSession(Base):
    """用户会话模型 - 用于追踪在线用户"""
    __tablename__ = "secflow_user_session"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("secflow_user_users.id"), nullable=False, index=True)
    token_jti = Column(String(100), unique=True, index=True, nullable=True)  # JWT的jti标识
    ip_address = Column(String(45))  # 支持IPv6
    user_agent = Column(String(500))
    status = Column(String(20), default="active")  # active, expired, revoked
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_active_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)

    # 关联用户
    user = relationship("User", backref="sessions")


class Department(Base):
    """部门模型"""
    __tablename__ = "secflow_org_department"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(500))
    parent_id = Column(Integer, ForeignKey("secflow_org_department.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # 关联关系
    parent = relationship("Department", remote_side=[id], backref="children")


class DepartmentMember(Base):
    """部门成员模型"""
    __tablename__ = "secflow_org_department_member"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("secflow_user_users.id"), nullable=False)
    department_id = Column(Integer, ForeignKey("secflow_org_department.id"), nullable=False)
    role = Column(String(20), nullable=False)  # leader, member
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # 关联关系
    user = relationship("User", backref="department_memberships")
    department = relationship("Department", backref="members")


class Project(Base):
    """项目模型"""
    __tablename__ = "secflow_org_project"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(500))
    is_public = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ProjectDepartment(Base):
    """项目-部门关联模型"""
    __tablename__ = "secflow_org_project_department"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("secflow_org_project.id"), nullable=False)
    department_id = Column(Integer, ForeignKey("secflow_org_department.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # 关联关系
    project = relationship("Project", backref="departments")
    department = relationship("Department", backref="projects")
