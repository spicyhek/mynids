"""Tree candidate: separate artifacts, honest reporting, and refusal paths."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import joblib

from tools.train_tree_model import MODEL_FILE, train
from tools.training_data import ROOT, model_matrix, prepare, sha256

LABELS = ["BENIGN", "BOTNET", "BRUTE_FORCE", "DOS_DDOS", "OTHER_ATTACK"]
PORTS = {"BENIGN": 443, "BOTNET": 6667, "BRUTE_FORCE": 22, "DOS_DDOS": 80, "OTHER_ATTACK": 445}


class TreeCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        base = json.loads((ROOT / "tools/fixtures/smoke_conn.json").read_text())
        self.base = {**base, "id.orig_h": "10.0.0.15", "id.resp_h": "10.0.0.25", "conn_state": "SF", "duration": 0}
        labels = self.root / "labels.json"
        labels.write_text(json.dumps(dict(enumerate(LABELS))))
        self.label_map = {"path": labels.name, "sha256": sha256(labels)}

    def capture(self, name, split):
        log = [{**self.base, "uid": f"{name}-first", "ts": 1600000000}]
        reviewed = []
        for i in range(25):
            label = LABELS[i % 5]
            row = {**self.base, "uid": f"{name}-{i}", "ts": 1600000100 + i, "id.resp_p": PORTS[label]}
            log.append(row)
            reviewed.append({"source": "synthetic", "label": label, "conn": row})
        paths = {}
        for suffix, rows in (("conn.log", log), ("jsonl", reviewed), ("evidence.json", [{"purpose": "test"}])):
            path = self.root / f"{name}.{suffix}"
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            paths[suffix] = path
        return {"path": paths["jsonl"].name, "sha256": sha256(paths["jsonl"]),
                "provenance_path": paths["evidence.json"].name, "provenance_sha256": sha256(paths["evidence.json"]),
                "origin": "synthetic-unit-test", "label_basis": "Synthetic fixture.", "group": name, "split": split,
                "conn_log_path": paths["conn.log"].name, "conn_log_sha256": sha256(paths["conn.log"])}

    def dataset(self):
        recipe = self.root / "recipe.json"
        recipe.write_text(json.dumps({"schema_version": 1, "name": "synthetic-tree", "label_map": self.label_map,
                                      "feature_contract": "zeek-conn-window-v2",
                                      "sources": [self.capture("cap-a", "train"), self.capture("cap-b", "train"),
                                                  self.capture("cap-c", "validation")]}))
        output = self.root / "prepared"
        prepare(recipe, output)
        return output

    def test_candidate_artifacts_report_and_alert_volume(self):
        dataset = self.dataset()
        output = self.root / "candidate"
        report = train(dataset, output, iterations=20, alert_captures=(self.root / "cap-c.conn.log",))
        for name in (MODEL_FILE, "feature_order.json", "label_map.json", "feature_contract.json", "training-report.json"):
            self.assertTrue((output / name).exists(), name)
        self.assertEqual(report["feature_contract"], "zeek-conn-window-v2")
        self.assertFalse(report["deployment_approved"])
        self.assertFalse(report["configuration"]["early_stopping"])
        self.assertEqual(report["metrics"]["validation"]["per_class"]["BRUTE_FORCE"]["recall"], 1.0)
        self.assertEqual(set(report["leave_one_source_out"]), {"cap-a", "cap-b", "cap-c"})
        volume = report["unlabeled_alert_volume"][(self.root / "cap-c.conn.log").as_posix()]
        self.assertEqual(volume["classified"], 25)  # The cold first record is not classified.
        self.assertEqual(volume["alerts"], 20)
        model = joblib.load(output / MODEL_FILE)
        feature_order = json.loads((output / "feature_order.json").read_text())
        self.assertEqual(len(feature_order), model.n_features_in_)

    def test_training_is_deterministic(self):
        dataset = self.dataset()
        first = train(dataset, self.root / "one", iterations=20, leave_one_source_out=False)
        second = train(dataset, self.root / "two", iterations=20, leave_one_source_out=False)
        self.assertEqual(first["metrics"], second["metrics"])
        rows = [json.loads(line)["flow"] for line in (dataset / "records.jsonl").read_text().splitlines()]
        matrix = model_matrix(rows, json.loads((self.root / "one/feature_order.json").read_text()))
        self.assertEqual(joblib.load(self.root / "one" / MODEL_FILE).predict(matrix).tolist(),
                         joblib.load(self.root / "two" / MODEL_FILE).predict(matrix).tolist())

    def test_existing_output_and_v1_alert_volume_are_refused(self):
        dataset = self.dataset()
        existing = self.root / "existing"
        existing.mkdir()
        with self.assertRaisesRegex(ValueError, "already exists"):
            train(dataset, existing)
        v1_recipe = self.root / "v1.json"
        source = {key: value for key, value in self.capture("cap-v1", "train").items()
                  if not key.startswith("conn_log")}
        validation = {key: value for key, value in self.capture("cap-v1v", "validation").items()
                      if not key.startswith("conn_log")}
        v1_recipe.write_text(json.dumps({"schema_version": 1, "name": "v1", "label_map": self.label_map,
                                         "sources": [source, validation]}))
        prepare(v1_recipe, self.root / "v1-prepared")
        with self.assertRaisesRegex(ValueError, "window-v2 contract only"):
            train(self.root / "v1-prepared", self.root / "v1-candidate", alert_captures=(self.root / "cap-v1.conn.log",))
        self.assertFalse((self.root / "v1-candidate").exists())


if __name__ == "__main__":
    unittest.main()
