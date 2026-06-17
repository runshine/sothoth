import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.model import Base
from app.schemas import TaskCreate, TokenUser
from app.service.config_service import get_service_config, save_service_config
from app.service.task_service import create_task


class VulnVerifyConfigServiceTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    def test_save_and_clear_service_default_model(self):
        db = self.SessionLocal()
        try:
            config, row = get_service_config(db)
            self.assertIsNone(row)
            self.assertIsNone(config["default_model"])

            saved, row = save_service_config(
                db,
                {"default_model": " local_minimax/MiniMax/MiniMax-M2.5 "},
                TokenUser(user_id="u1", username="alice"),
            )
            self.assertEqual("local_minimax/MiniMax/MiniMax-M2.5", saved["default_model"])
            self.assertEqual("alice", row.updated_by)

            saved, row = save_service_config(db, {"default_model": ""}, "bob")
            self.assertIsNone(saved["default_model"])
            self.assertEqual("bob", row.updated_by)
        finally:
            db.close()

    def test_create_task_uses_service_default_model_when_request_model_omitted(self):
        db = self.SessionLocal()
        try:
            save_service_config(db, {"default_model": "local_codex/zai-org/GLM-5"}, "tester")
            cfg = SimpleNamespace(worker=SimpleNamespace(default_concurrency=2, max_concurrency=16))
            req = TaskCreate(
                name="verify",
                reports_dir="/project/reports",
                source_root="/project/source",
                binary_root="/project/binary",
                threat_path="/project/threat.md",
            )
            with patch("app.service.task_service.get_config", return_value=cfg):
                with patch("app.service.task_service.ensure_path_in_project", side_effect=lambda _project_id, path, **_kwargs: path):
                    with patch("app.service.task_service.safe_output_dir", return_value="/project/output/task1"):
                        response = asyncio.run(create_task(db, "p1", req, "tester"))
            self.assertEqual("local_codex/zai-org/GLM-5", response.model)
            self.assertEqual(2, response.concurrency)
        finally:
            db.close()

    def test_create_task_request_model_overrides_service_default_model(self):
        db = self.SessionLocal()
        try:
            save_service_config(db, {"default_model": "local_codex/zai-org/GLM-5"}, "tester")
            cfg = SimpleNamespace(worker=SimpleNamespace(default_concurrency=2, max_concurrency=16))
            req = TaskCreate(
                name="verify",
                reports_dir="/project/reports",
                source_root="/project/source",
                binary_root="/project/binary",
                threat_path="/project/threat.md",
                model="gaiasec/auto",
            )
            with patch("app.service.task_service.get_config", return_value=cfg):
                with patch("app.service.task_service.ensure_path_in_project", side_effect=lambda _project_id, path, **_kwargs: path):
                    with patch("app.service.task_service.safe_output_dir", return_value="/project/output/task2"):
                        response = asyncio.run(create_task(db, "p1", req, "tester"))
            self.assertEqual("gaiasec/auto", response.model)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
