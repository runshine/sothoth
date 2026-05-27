import os
import tempfile
import unittest
from pathlib import Path

import yaml

from app.config import reload_config
from app.start import build_gunicorn_argv


class StartScriptTests(unittest.TestCase):
    def test_build_gunicorn_argv_defaults_to_128_threads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.yaml"
            config_path.write_text(
                yaml.safe_dump(
                    {
                        "app": {
                            "host": "127.0.0.1",
                            "port": 18080,
                        }
                    }
                ),
                encoding="utf-8",
            )
            reload_config(str(config_path))
            old_value = os.environ.pop("GUNICORN_THREADS", None)
            try:
                argv = build_gunicorn_argv()
            finally:
                if old_value is not None:
                    os.environ["GUNICORN_THREADS"] = old_value

        self.assertEqual("128", argv[argv.index("--threads") + 1])

    def test_build_gunicorn_argv_uses_gthread_wsgi_entrypoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.yaml"
            config_path.write_text(
                yaml.safe_dump(
                    {
                        "app": {
                            "host": "127.0.0.1",
                            "port": 18080,
                        }
                    }
                ),
                encoding="utf-8",
            )
            reload_config(str(config_path))
            old_env = {key: os.environ.get(key) for key in (
                "GUNICORN_WORKERS",
                "GUNICORN_THREADS",
                "GUNICORN_TIMEOUT",
                "GUNICORN_KEEPALIVE",
            )}
            os.environ["GUNICORN_WORKERS"] = "1"
            os.environ["GUNICORN_THREADS"] = "12"
            os.environ["GUNICORN_TIMEOUT"] = "321"
            os.environ["GUNICORN_KEEPALIVE"] = "22"
            try:
                argv = build_gunicorn_argv()
            finally:
                for key, value in old_env.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

        self.assertIn("gthread", argv)
        self.assertIn("app.wsgi:app", argv)
        self.assertNotIn("uvicorn.workers.UvicornWorker", argv)
        self.assertNotIn("app.main:app", argv)
        self.assertEqual("127.0.0.1:18080", argv[argv.index("--bind") + 1])
        self.assertEqual("12", argv[argv.index("--threads") + 1])
        self.assertEqual("321", argv[argv.index("--timeout") + 1])
        self.assertEqual("22", argv[argv.index("--keep-alive") + 1])
