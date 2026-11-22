from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main
from app.inference import ModelArtifacts
from app.version import SEMVER, VERSION_FILE, __version__, read_version

LABELS = ["BENIGN", "BOTNET", "DOS_DDOS", "OTHER_ATTACK"]


class VersionFileTests(unittest.TestCase):
    def test_the_shipped_version_is_semantic(self) -> None:
        self.assertRegex(__version__, SEMVER)
        self.assertEqual(read_version(), __version__)
        self.assertEqual(VERSION_FILE.parent.name, "app")

    def test_malformed_versions_are_refused(self) -> None:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / "VERSION"
        for text in ("", "1.9", "v1.9.0", "01.9.0", "1.9.0.1", "1.9.0 beta"):
            with self.subTest(text=text):
                path.write_text(text + "\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "semantic version"):
                    read_version(path)
        for text in ("1.10.0", "2.0.0-rc.1", "1.9.0+sha.0123456"):
            with self.subTest(text=text):
                path.write_text(text + "\n", encoding="utf-8")
                self.assertEqual(read_version(path), text)


class VersionApiTests(unittest.TestCase):
    def setUp(self) -> None:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        settings = replace(main.settings, db_path=Path(temp_dir.name) / "nids.sqlite3", ingest_token="test-token")
        self.enterContext(patch.object(main, "settings", settings))
        self.enterContext(patch.object(main.classifier, "load", return_value=ModelArtifacts(LABELS, [])))
        self.client = self.enterContext(TestClient(main.app))

    def test_health_summary_and_openapi_report_the_version(self) -> None:
        self.assertEqual(self.client.get("/healthz").json()["version"], __version__)
        self.assertEqual(self.client.get("/readyz").json()["version"], __version__)
        self.assertEqual(self.client.get("/api/public/summary").json()["version"], __version__)
        self.assertEqual(self.client.get("/openapi.json").json()["info"]["version"], __version__)


if __name__ == "__main__":
    unittest.main()
