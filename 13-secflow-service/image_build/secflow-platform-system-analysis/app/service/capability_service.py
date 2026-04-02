"""Capabilities discovery service."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.schemas import AnalysisCapabilityNodeItem, AnalysisCapabilitySummary, ProjectAnalysisCapabilitiesResponse
from app.service.agent_gateway import AgentGateway, AgentGatewayError, get_agent_gateway

logger = logging.getLogger(__name__)


class CapabilityService:
    def __init__(self, agent_gateway: Optional[AgentGateway] = None):
        self.agent_gateway = agent_gateway or get_agent_gateway()

    async def list_capabilities(self, project_id: str, token: Optional[str] = None) -> ProjectAnalysisCapabilitiesResponse:
        agents = await self.agent_gateway.list_agents(project_id, token=token)
        helpers = await self.agent_gateway.list_ai_helpers(project_id, token=token)

        helper_by_agent: Dict[str, Dict[str, Any]] = {}
        for helper in helpers:
            agent_key = str(helper.get("agent_key") or "").strip()
            service_name = str(helper.get("service_name") or "").strip()
            if not agent_key or not service_name:
                continue
            helper_agents = []
            health_status = helper.get("health_status") or "unknown"
            try:
                helper_agents_payload = await self.agent_gateway.get_helper_agents(
                    project_id,
                    agent_key,
                    service_name,
                    token=token,
                )
                for item in helper_agents_payload:
                    aid = str(item.get("agent_id") or "").strip()
                    aname = str(item.get("name") or aid).strip() or aid
                    if aid:
                        helper_agents.append({"agent_id": aid, "agent_name": aname})
            except AgentGatewayError:
                # Degrade single helper failure to node-level unavailable, but keep
                # capability API responsive for other nodes.
                logger.warning(
                    "helper agent discovery failed, project_id=%s agent_key=%s service_name=%s",
                    project_id,
                    agent_key,
                    service_name,
                )
                health_status = "error"
            candidate = {
                "service_name": service_name,
                "health_status": health_status,
                "ai_agents": helper_agents,
            }
            existing = helper_by_agent.get(agent_key)
            if existing is None:
                helper_by_agent[agent_key] = candidate
            else:
                # Prefer healthy helper; if same health, prefer more AI agents.
                existing_healthy = str(existing.get("health_status") or "").lower() == "healthy"
                candidate_healthy = str(candidate.get("health_status") or "").lower() == "healthy"
                if (candidate_healthy and not existing_healthy) or (
                    candidate_healthy == existing_healthy and len(candidate["ai_agents"]) > len(existing.get("ai_agents", []))
                ):
                    helper_by_agent[agent_key] = candidate

        items: List[AnalysisCapabilityNodeItem] = []
        online_count = 0
        helper_ready_count = 0
        analyzable_count = 0

        for agent in agents:
            status = str(agent.get("status") or "unknown")
            if status.lower() == "online":
                online_count += 1

            agent_key = str(agent.get("key") or agent.get("agent_key") or "").strip()
            helper = helper_by_agent.get(agent_key)
            helper_installed = helper is not None
            helper_ready_count += 1 if helper_installed else 0

            available_ai_agents = helper.get("ai_agents", []) if helper else []
            analyzable = bool(helper_installed and available_ai_agents)
            analyzable_count += 1 if analyzable else 0

            items.append(
                AnalysisCapabilityNodeItem(
                    agent_key=agent_key,
                    agent_hostname=agent.get("hostname") or agent.get("agent_hostname"),
                    agent_ip=agent.get("ip_address") or agent.get("ip") or agent.get("agent_ip"),
                    agent_status=status,
                    helper_installed=helper_installed,
                    helper_service_name=helper.get("service_name") if helper else None,
                    helper_status=helper.get("health_status") if helper else None,
                    available_ai_agents=available_ai_agents,
                )
            )

        summary = AnalysisCapabilitySummary(
            total_nodes=len(items),
            online_nodes=online_count,
            helper_ready_nodes=helper_ready_count,
            analyzable_nodes=analyzable_count,
        )
        return ProjectAnalysisCapabilitiesResponse(project_id=project_id, summary=summary, items=items)


_capability_service: Optional[CapabilityService] = None


def get_capability_service() -> CapabilityService:
    global _capability_service
    if _capability_service is None:
        _capability_service = CapabilityService()
    return _capability_service
