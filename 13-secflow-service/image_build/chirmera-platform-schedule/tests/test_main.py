from __future__ import annotations

from unittest.mock import patch

from app.api.routes import ready_check


def test_ready_route_returns_503_when_checks_fail():
    async def fake_collect():
        return {"status": "not_ready", "checks": {"database": {"ok": False}}}

    with patch("app.api.routes.collect_readiness", side_effect=fake_collect):
        response = __import__("asyncio").run(ready_check())
    assert response.status_code == 503


def test_ready_route_returns_200_when_checks_pass():
    async def fake_collect():
        return {"status": "ready", "checks": {"database": {"ok": True}}}

    with patch("app.api.routes.collect_readiness", side_effect=fake_collect):
        response = __import__("asyncio").run(ready_check())
    assert response.status_code == 200
