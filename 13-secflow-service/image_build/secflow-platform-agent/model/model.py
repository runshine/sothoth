from datetime import datetime
from typing import Dict, List, Optional


from dataclasses import dataclass, asdict, field

@dataclass
class ProjectInfo:
    """项目信息"""
    id: str
    agent_count: int = 0
    online_agents: int = 0
    services_count: int = 0
    last_refresh: Optional[datetime] = None
    agents: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        data = asdict(self)
        if self.last_refresh:
            data['last_refresh'] = self.last_refresh.isoformat()
        return data

@dataclass
class AgentInfo:
    """Agent信息"""
    key: str
    ip_address: str
    hostname: str
    project_id: str
    full_name: str
    status: str = 'unknown'
    last_seen: Optional[datetime] = None
    system_info: Optional[Dict] = None
    services: List[Dict] = field(default_factory=list)
    pod_id: str = ''

    def to_dict(self) -> Dict:
        data = asdict(self)
        if self.last_seen:
            data['last_seen'] = self.last_seen.isoformat()
        return data

@dataclass
class ServiceTemplate:
    """服务模板"""
    name: str
    description: str = ''
    type: str = 'yaml'
    file_path: str = ''
    created_by: str = ''
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        return data

@dataclass
class TaskInfo:
    """任务信息"""
    task_id: str
    task_type: str
    service_name: str
    agent_key: str
    project_id: str = ''
    status: str = 'pending'
    progress: int = 0
    message: str = ''
    logs: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    pod_id: str = ''

    def to_dict(self) -> Dict:
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        if self.started_at:
            data['started_at'] = self.started_at.isoformat()
        if self.completed_at:
            data['completed_at'] = self.completed_at.isoformat()
        return data
