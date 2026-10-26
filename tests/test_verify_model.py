import csv
import json
from pathlib import Path
import tempfile
import unittest

from tools.verify_model import prepare_records, sample_csv


class VerificationInputTests(unittest.TestCase):
    def setUp(self):
        self.names = json.loads((Path(__file__).resolve().parents[1] / "feature_order.json").read_text())

    def row(self, label="Bot"):
        row = {name.replace("_", " ").title(): "0" for name in self.names
               if name not in ("src_port", "timestamp")}
        row.update(Label=label, Timestamp="02/03/2018 12:00:00")
        row["Init Fwd Win Byts"] = "-1"
        return row

    def test_label_mapping_timestamp_and_missing_port_are_explicit(self):
        labels = {"Benign": "BENIGN", "Bot": "BOTNET", "FTP-BruteForce": "OTHER_ATTACK",
                  "SSH-Bruteforce": "OTHER_ATTACK", "DoS attacks-GoldenEye": "DOS_DDOS",
                  "DoS attacks-Slowloris": "DOS_DDOS", "DDOS attack-HOIC": "DOS_DDOS",
                  "DDOS attack-LOIC-UDP": "DOS_DDOS"}
        records, kept, rejected = prepare_records(
            {label: [("source-row-1", self.row(label))] for label in labels}, self.names)
        self.assertFalse(rejected)
        self.assertEqual(sum(kept.values()), len(labels))
        for label, record in zip(sorted(labels), records):
            self.assertEqual(record["label"], labels[label])
            self.assertEqual(record["flow"]["features"]["timestamp"], 0)
            self.assertEqual(record["flow"]["features"]["src_port"], 0)
            self.assertEqual(record["flow"]["features"]["init_fwd_win_byts"], -1)
            self.assertIsNotNone(record["flow"]["event_time"].tzinfo)

    def test_duplicate_and_nonfinite_samples_are_excluded(self):
        row = self.row()
        invalid = dict(row, **{"Flow Byts S": "Infinity"})
        records, _, rejected = prepare_records(
            {"Bot": [("1", row), ("2", dict(row)), ("3", invalid)]}, self.names)
        self.assertEqual(len(records), 1)
        self.assertEqual(rejected["duplicate sampled CSV row"], 1)
        self.assertEqual(sum(rejected.values()), 2)

    def test_unknown_labels_and_missing_columns_fail(self):
        with self.assertRaisesRegex(RuntimeError, "Unreviewed source label"):
            prepare_records({"unknown": [("1", self.row("unknown"))]}, self.names)
        row = self.row()
        del row["Flow Duration"]
        with self.assertRaisesRegex(RuntimeError, "columns disagree"):
            prepare_records({"Bot": [("1", row)]}, self.names)

    def test_sampling_is_repeatable_and_ids_distinguish_files(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("a.csv", "b.csv")]
            for path in paths:
                with path.open("w", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=["Label", "value"])
                    writer.writeheader()
                    writer.writerows({"Label": "Bot", "value": i} for i in range(10))
            first = sample_csv(paths, 7, 42)
            self.assertEqual(first, sample_csv(paths, 7, 42))
            self.assertEqual(first[1]["Bot"], 20)
            self.assertEqual(len(first[2]["Bot"]), 7)
            self.assertEqual(len({key for key, _ in first[2]["Bot"]}), 7)
