from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parent.parent
if str(SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVICE_ROOT))

from app.config import load_config
from app.model import EvolutionTask, EvolutionTaskRound
from app.schemas import EvolutionMemoryModePatchRequest
from app.service.task_service import TaskService


@pytest.fixture()
def configured_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TaskService:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "database": {"url": f"sqlite:///{tmp_path / 'service.db'}", "table_prefix": "test_binary_evo_"},
                "auth_service": {"enabled": False, "service_machine_token": "token"},
                "project_service": {"enabled": False},
                "fileserver_service": {
                    "data_mount_path": str(tmp_path / "data"),
                    "project_files_dirname": "files",
                    "dataflow_subproject_name": "DATAFLOW_VULN_SCANNER",
                    "evolution_subproject_name": "secflow-app-binary-evolution-center",
                },
                "registry": {"enabled": False},
                "scheduler": {"enabled": False},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CONFIG_PATH", str(config_path))
    import app.config as config_module
    import app.model as model_module
    import app.service.task_service as task_service_module

    config_module._config = None
    model_module._engine = None
    model_module._SessionFactory = None
    task_service_module._task_service = None
    load_config()
    model_module.init_database()
    return TaskService()


def _task(project_id: str = "p1", task_id: str = "evo-1") -> EvolutionTask:
    return EvolutionTask(
        id=task_id,
        project_id=project_id,
        title="demo",
        status="running",
        objective="lower false positives",
        metrics_json={},
        source_case_ids_json=["case-1"],
        source_task_ids_json=["source-1"],
        preview_payload_json={},
        agent_state_roots_json={},
        default_agent_source_dirs_json={},
        config_json={"evolve_agents": ["pi-worker", "pi-advisor"]},
        created_by="tester",
    )


def test_prepare_candidate_roots_are_per_round_and_inherit_previous(configured_service: TaskService):
    service = configured_service
    task = _task()
    seed_worker = service._dataflow_agent_state_root(task.project_id) / "evolution" / task.id / "seed" / "pi-worker"
    seed_advisor = service._dataflow_agent_state_root(task.project_id) / "evolution" / task.id / "seed" / "pi-advisor"
    (seed_worker / "memory").mkdir(parents=True, exist_ok=True)
    (seed_advisor / "memory").mkdir(parents=True, exist_ok=True)
    (seed_worker / "memory" / "seed.md").write_text("seed", encoding="utf-8")
    task.agent_state_roots_json = {"pi-worker": str(seed_worker), "pi-advisor": str(seed_advisor)}

    round1 = service._prepare_candidate_roots(task, 1)
    Path(round1["pi-worker"], "memory", "round1.md").write_text("round1", encoding="utf-8")
    round2 = service._prepare_candidate_roots(task, 2)

    assert round1["pi-worker"].endswith("/rounds/round-1/pi-worker")
    assert round2["pi-worker"].endswith("/rounds/round-2/pi-worker")
    assert Path(round2["pi-worker"], "memory", "seed.md").is_file()
    assert Path(round2["pi-worker"], "memory", "round1.md").is_file()
    assert Path(round1["pi-worker"], "memory", "evolution-candidate-round-1.md").is_file()
    assert Path(round1["pi-advisor"], "memory", "evolution-candidate-round-1.md").read_text(encoding="utf-8").find("Advisor-specific guardrails") >= 0
    assert round1["pi-worker"] != round2["pi-worker"]


def test_write_adjustment_files_only_writes_memory(configured_service: TaskService):
    service = configured_service
    task = _task()
    candidate_root = service._candidate_round_root(task.project_id, task.id, 1) / "pi-worker"

    service._write_adjustment_files(
        task,
        1,
        {"expected_case_count": 1, "reported_case_count": 1},
        "rule score",
        candidate_roots={"pi-worker": str(candidate_root)},
        meta_evaluation={"isolated_from_candidate_agent_memory": True},
    )

    assert (candidate_root / "memory" / "evolution-round-1.md").is_file()
    assert not (candidate_root / "skills").exists()


def test_meta_evaluator_isolated_when_advisor_evolves(configured_service: TaskService):
    service = configured_service
    task = _task()
    report = service._meta_evaluate_round(
        task=task,
        round_no=1,
        metrics={"expected_case_count": 1, "reported_case_count": 0, "false_negative_rate": 1.0, "false_positive_rate": 0.0},
        score=500,
        score_reason="rule score",
        candidate_roots={"pi-advisor": "/tmp/advisor"},
    )

    assert report["isolated_from_candidate_agent_memory"] is True
    assert report["advisor_memory_evolved"] is True
    assert report["decision"] == "continue"
    assert any("not used" in item for item in report["guardrails"])


def test_metrics_use_derived_result_counts_when_replay_does_not_report_cases(configured_service: TaskService):
    service = configured_service
    preview = {
        "project_id": "p1",
        "requested_case_ids": ["case-1", "case-2"],
        "effective_case_ids": ["case-1", "case-2"],
        "can_create": True,
        "sources": [
            {
                "source_task_id": "source-1",
                "selected_case_ids": ["case-1"],
                "all_case_ids": ["case-1", "case-2"],
                "replay_ready": True,
            }
        ],
    }
    from app.schemas import EvolutionPreviewResponse

    metrics = service._compute_round_metrics(
        EvolutionPreviewResponse.model_validate(preview),
        [],
        derived_tasks=[{"source_task_id": "source-1", "result_count": 2}],
    )

    assert metrics["formal_evolution_case_count"] == 0
    assert metrics["reported_case_count"] == 2
    assert metrics["false_negative_count"] == 0


def test_memory_mode_writes_project_config_and_promoted_roots(configured_service: TaskService):
    service = configured_service
    import app.model as model_module

    db = model_module.get_session_factory()()
    try:
        task = _task()
        db.add(task)
        db.add(EvolutionTaskRound(id="rnd-1", task_id=task.id, round_no=1, status="succeeded"))
        db.commit()
        promoted = service._promoted_root(task.project_id, task.id, 1) / "pi-worker"
        (promoted / "memory").mkdir(parents=True, exist_ok=True)

        response = service.save_memory_mode(
            db,
            project_id=task.project_id,
            payload=EvolutionMemoryModePatchRequest(
                mode="evolution",
                enabled_agents=["pi-worker"],
                promoted_task_id=task.id,
                promoted_round=1,
            ),
        )

        config_path = Path(response.config_path or "")
        assert response.mode == "evolution"
        assert response.agent_state_roots == {"pi-worker": str(promoted)}
        assert config_path.is_file()
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        assert payload["mode"] == "evolution"
        assert payload["agent_state_roots"]["pi-worker"] == str(promoted)
    finally:
        db.close()
