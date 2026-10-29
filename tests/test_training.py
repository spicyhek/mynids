"""Data provenance, split isolation, and production preprocessing for retraining."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np

from tools.training_data import (ROOT, contract, fit_preprocessing, load_prepared, model_matrix,
                                 prepare, require_training_coverage, sha256)
from tools.train_model import train


class TrainingDataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.schema = contract()
        self.conn = json.loads((ROOT / "tools/fixtures/smoke_conn.json").read_text())
        self.sequence = 0

    def row(self, label="BENIGN", **changes):
        self.sequence += 1
        conn = {**deepcopy(self.conn), "ts": 1600000000 + self.sequence, "uid": f"unit-test-{self.sequence}", **changes}
        return {"source": "synthetic-unit-fixture", "label": label, "conn": conn}

    def recipe(self, entries):
        sources = []
        for number, (split, group, rows) in enumerate(entries):
            path = self.directory / f"source-{number}.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            proof = self.directory / f"source-{number}.evidence.json"
            proof.write_text(json.dumps({"purpose": "synthetic test fixture, not attack evidence"}))
            sources.append({"path": path.name, "sha256": sha256(path), "provenance_path": proof.name,
                            "provenance_sha256": sha256(proof), "origin": "synthetic-unit-test",
                            "label_basis": "Synthetic fixture labels for structural testing only.",
                            "group": group, "split": split})
        recipe = self.directory / "recipe.json"
        recipe.write_text(json.dumps({"schema_version": 1, "name": "synthetic-test-only", "sources": sources}))
        return recipe

    def complete_recipe(self):
        return self.recipe([
            ("train", "train-capture", [self.row(label) for label in self.schema["labels"]]),
            ("validation", "validation-capture", [self.row(label, orig_ip_bytes=10000000) for label in self.schema["labels"]]),
            ("test", "test-capture", [self.row("BENIGN", orig_ip_bytes=100000000)]),
            ("regression", "regression-capture", [self.row()]),
        ])

    def test_seed_preserves_observation_but_is_not_trainable(self):
        recipe = self.recipe([("regression", "known-capture", [self.row()])])
        output = self.directory / "prepared"
        manifest = prepare(recipe, output)
        records, _ = load_prepared(output)
        self.assertFalse(manifest["ready_for_four_class_training"])
        self.assertEqual(records[0]["flow"]["features"]["timestamp"], 1600000001000000)
        self.assertIn("2020-09-13", records[0]["flow"]["event_time"])
        matrix = model_matrix([records[0]["flow"]], self.schema["feature_order"])
        self.assertEqual(matrix.shape, (1, 80))
        self.assertEqual(matrix.dtype, np.float32)
        self.assertEqual(matrix[0, self.schema["feature_order"].index("timestamp")], 0)
        self.assertNotEqual(records[0]["flow"]["features"]["timestamp"], 0)
        with self.assertRaisesRegex(ValueError, "every class in both train and validation"):
            require_training_coverage(records, self.schema["labels"])
        with self.assertRaisesRegex(ValueError, "every class in both train and validation"):
            train(output, self.directory / "candidate", epochs=1)
        self.assertFalse((self.directory / "candidate").exists())

    def test_scaler_uses_training_only_and_keeps_timestamp_constant_zero(self):
        output = self.directory / "prepared"
        prepare(self.complete_recipe(), output)
        records, manifest = load_prepared(output)
        scaler, encoder, matrix, targets = fit_preprocessing(records, manifest["contract"])
        train_matrix = matrix[[i for i, row in enumerate(records) if row["split"] == "train"]]
        np.testing.assert_allclose(scaler.mean_, train_matrix.mean(axis=0, dtype=np.float64))
        index = self.schema["feature_order"].index("totlen_fwd_pkts")
        self.assertLess(scaler.mean_[index], matrix[:, index].mean())
        index = self.schema["feature_order"].index("timestamp")
        self.assertEqual(scaler.mean_[index], 0)
        self.assertEqual(scaler.var_[index], 0)
        self.assertEqual(list(encoder.classes_), self.schema["labels"])
        self.assertEqual(set(targets), {0, 1, 2, 3})

    def test_group_cannot_cross_splits_even_with_different_observations(self):
        recipe = self.recipe([("train", "same-capture", [self.row()]),
                              ("validation", "same-capture", [self.row()])])
        with self.assertRaisesRegex(ValueError, "multiple splits"):
            prepare(recipe, self.directory / "prepared")
        self.assertFalse((self.directory / "prepared").exists())

    def test_source_alias_cannot_hide_duplicate_observation(self):
        row = self.row()
        alias = {**deepcopy(row), "source": "another-alias"}
        recipe = self.recipe([("train", "capture-a", [row]), ("validation", "capture-b", [alias])])
        with self.assertRaisesRegex(ValueError, "Duplicate flow ID"):
            prepare(recipe, self.directory / "prepared")

    def test_unreviewed_unknown_and_operational_labels_are_rejected(self):
        for label in (None, "UNVALIDATED", "predicted-BENIGN"):
            with self.subTest(label=label):
                recipe = self.recipe([("train", "capture", [self.row(label)])])
                with self.assertRaisesRegex(ValueError, "Missing/unreviewed/unknown label"):
                    prepare(recipe, self.directory / "prepared")

    def test_precomputed_flow_cannot_bypass_zeek_extraction(self):
        recipe = self.recipe([("regression", "capture", [{"label": "BENIGN", "source": "fixture", "flow": {}}])])
        with self.assertRaisesRegex(ValueError, "reviewed Zeek conn records"):
            prepare(recipe, self.directory / "prepared")

    def test_modified_reviewed_source_and_modified_evidence_are_rejected(self):
        for target in ("source-0.jsonl", "source-0.evidence.json"):
            with self.subTest(target=target):
                recipe = self.recipe([("regression", "capture", [self.row()])])
                with (self.directory / target).open("a") as handle:
                    handle.write(" ")
                with self.assertRaisesRegex(ValueError, "hash mismatch"):
                    prepare(recipe, self.directory / "prepared")

    def test_prepared_data_tampering_and_contract_changes_are_detected(self):
        output = self.directory / "prepared"
        prepare(self.complete_recipe(), output)
        original = (output / "records.jsonl").read_bytes()
        with (output / "records.jsonl").open("a") as handle:
            handle.write(" ")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            load_prepared(output)
        (output / "records.jsonl").write_bytes(original)
        manifest = json.loads((output / "manifest.json").read_text())
        manifest["contract"]["feature_order"].reverse()
        (output / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "contract is incompatible"):
            load_prepared(output)

    def test_existing_dataset_and_model_outputs_are_preserved(self):
        output = self.directory / "existing"
        output.mkdir()
        sentinel = output / "sentinel"
        sentinel.write_text("preserve")
        with self.assertRaisesRegex(ValueError, "already exists"):
            prepare(self.recipe([("regression", "capture", [self.row()])]), output)
        with self.assertRaisesRegex(ValueError, "already exists"):
            train(self.directory / "unused", output)
        self.assertEqual(sentinel.read_text(), "preserve")

    def test_overflow_is_rejected_before_timestamp_normalization(self):
        output = self.directory / "prepared"
        prepare(self.recipe([("regression", "capture", [self.row()])]), output)
        records, _ = load_prepared(output)
        flow = deepcopy(records[0]["flow"])
        flow["features"]["timestamp"] = 1e100
        with self.assertRaisesRegex(ValueError, "finite float32"):
            model_matrix([flow], self.schema["feature_order"])

    def test_five_class_recipe_does_not_change_production_label_map(self):
        labels = ["BENIGN", "BOTNET", "BRUTE_FORCE", "DOS_DDOS", "OTHER_ATTACK"]
        original_hash = sha256(ROOT / "label_map.json")
        custom = self.directory / "labels.five-class.json"
        custom.write_text(json.dumps({str(i): label for i, label in enumerate(labels)}))
        recipe_path = self.recipe([
            ("train", "capture-five-train", [self.row(label) for label in labels]),
            ("validation", "capture-five-validation", [self.row(label) for label in labels]),
        ])
        recipe = json.loads(recipe_path.read_text())
        recipe["label_map"] = {"path": custom.name, "sha256": sha256(custom)}
        recipe_path.write_text(json.dumps(recipe))
        output = self.directory / "prepared-five"
        manifest = prepare(recipe_path, output)
        rows, loaded = load_prepared(output)
        self.assertEqual(loaded["contract"]["labels"], labels)
        self.assertTrue(manifest["ready_for_training"])
        self.assertFalse(manifest["ready_for_four_class_training"])
        _, encoder, _, _ = fit_preprocessing(rows, loaded["contract"])
        self.assertEqual(list(encoder.classes_), labels)
        self.assertEqual(sha256(ROOT / "label_map.json"), original_hash)

    def test_sampling_is_reproducible_and_does_not_move_capture_between_splits(self):
        recipe_path = self.recipe([("regression", "capture", [self.row() for _ in range(20)])])
        recipe = json.loads(recipe_path.read_text())
        recipe["sources"][0].update(max_records_per_label=3, sample_seed=71)
        recipe_path.write_text(json.dumps(recipe))
        first, second = self.directory / "first", self.directory / "second"
        report = prepare(recipe_path, first)
        prepare(recipe_path, second)
        self.assertEqual((first / "records.jsonl").read_bytes(), (second / "records.jsonl").read_bytes())
        records, _ = load_prepared(first)
        self.assertEqual(len(records), 3)
        self.assertEqual({row["split"] for row in records}, {"regression"})
        self.assertEqual(report["sources"][0]["source_class_counts_before_sampling"], {"BENIGN": 20})


class WindowContractDatasetTests(unittest.TestCase):
    """zeek-conn-window-v2 preparation: complete-log context, exclusions, and contract isolation."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        base = json.loads((ROOT / "tools/fixtures/smoke_conn.json").read_text())
        self.base = {**base, "id.orig_h": "10.0.0.15", "id.resp_h": "10.0.0.25", "conn_state": "SF", "duration": 0}

    def conn(self, second, **changes):
        return {**self.base, "uid": f"v2-{second}", "ts": 1600000000 + second, **changes}

    def recipe(self, log_records, reviewed, *, split="regression", name="capture"):
        log = self.directory / f"{name}.conn.log"
        log.write_text("".join(json.dumps(record) + "\n" for record in log_records))
        path = self.directory / f"{name}.jsonl"
        path.write_text("".join(json.dumps({"source": "synthetic", "label": label, "conn": record}) + "\n"
                                for label, record in reviewed))
        proof = self.directory / f"{name}.evidence.json"
        proof.write_text(json.dumps({"purpose": "synthetic test fixture"}))
        recipe = self.directory / "recipe.json"
        recipe.write_text(json.dumps({"schema_version": 1, "name": "synthetic-v2", "feature_contract": "zeek-conn-window-v2",
                                      "sources": [{"path": path.name, "sha256": sha256(path), "provenance_path": proof.name,
                                                   "provenance_sha256": sha256(proof), "origin": "synthetic-unit-test",
                                                   "label_basis": "Synthetic fixture.", "group": name, "split": split,
                                                   "conn_log_path": log.name, "conn_log_sha256": sha256(log)}]}))
        return recipe

    def test_unreviewed_log_records_are_window_context_only(self):
        context = [self.conn(60 + i, uid=f"context-{i}", conn_state="REJ") for i in range(5)]
        target = self.conn(70)
        log = [self.conn(0, uid="first"), *context, target, self.conn(71, uid="later")]
        output = self.directory / "prepared"
        manifest = prepare(self.recipe(log, [("BENIGN", target)]), output)
        records, loaded = load_prepared(output)
        self.assertEqual(loaded["contract"]["feature_contract"], "zeek-conn-window-v2")
        self.assertEqual(len(records), 1)
        features = records[0]["flow"]["features"]
        self.assertEqual(features["src_conns"], 6)  # Five unreviewed earlier records plus itself; not "later".
        self.assertAlmostEqual(features["src_failed_frac"], 5 / 6)
        self.assertNotIn("timestamp", features)
        self.assertEqual(manifest["sources"][0]["window_context"]["records"], 8)
        matrix = model_matrix([records[0]["flow"]], loaded["contract"]["feature_order"])
        self.assertEqual(matrix.shape, (1, len(loaded["contract"]["feature_order"])))

    def test_cold_window_and_tunnel_carriers_are_excluded_and_counted(self):
        cold = self.conn(10)
        carrier = self.conn(80, uid="carrier", proto="udp", **{"id.resp_p": 8472})
        warm = self.conn(90)
        log = [self.conn(0, uid="first"), cold, carrier, warm]
        manifest = prepare(self.recipe(log, [("BENIGN", cold), ("BENIGN", carrier), ("BENIGN", warm)]),
                           self.directory / "prepared")
        self.assertEqual(manifest["records"], 1)
        self.assertEqual(manifest["sources"][0]["excluded_before_sampling"],
                         {"window_not_warm": 1, "tunnel_carrier": 1})
        self.assertEqual(manifest["sources"][0]["window_context"]["tunnel_carriers"], 1)

    def test_reviewed_rows_must_match_the_pinned_complete_log(self):
        target = self.conn(90)
        log = [self.conn(0, uid="first"), target]
        cases = {"absent from": {**target, "uid": "never-logged"}, "differs from": {**target, "orig_pkts": 99}}
        for message, reviewed in cases.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    prepare(self.recipe(log, [("BENIGN", reviewed)]), self.directory / "prepared")
        recipe = self.recipe(log, [("BENIGN", target)])
        with (self.directory / "capture.conn.log").open("a") as handle:
            handle.write("\n")
        with self.assertRaisesRegex(ValueError, "conn.log hash mismatch"):
            prepare(recipe, self.directory / "prepared")
        self.assertFalse((self.directory / "prepared").exists())

    def test_contracts_do_not_reconcile_with_each_other(self):
        self.assertNotIn("feature_contract", contract())
        self.assertEqual(len(contract()["feature_order"]), 80)
        self.assertNotEqual(contract(feature_contract="zeek-conn-window-v2")["feature_order"], contract()["feature_order"])
        with self.assertRaisesRegex(ValueError, "Unknown feature contract"):
            contract(feature_contract="zeek-conn-v9")
        output = self.directory / "prepared"
        prepare(self.recipe([self.conn(0, uid="first"), self.conn(90)], [("BENIGN", self.conn(90))]), output)
        manifest = json.loads((output / "manifest.json").read_text())
        del manifest["contract"]["feature_contract"]
        (output / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "contract is incompatible"):
            load_prepared(output)


if __name__ == "__main__":
    unittest.main()
