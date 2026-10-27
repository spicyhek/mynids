import unittest
from types import SimpleNamespace
from unittest.mock import Mock

import numpy as np

from app.inference import ModelArtifacts
from app.storage import PredictionRow, utcnow
from tools.evaluate_replay import evaluate


class EvaluationTests(unittest.TestCase):
    def test_confusion_metrics_and_feature_moments(self):
        classifier = Mock()
        classifier.load.return_value = ModelArtifacts(["BENIGN", "ATTACK"], ["tot_fwd_pkts", "tot_bwd_pkts"])
        classifier._scaler = SimpleNamespace(mean_=np.zeros(2), scale_=np.ones(2))
        classifier.classify_batch.side_effect = lambda flows: [
            PredictionRow(utcnow(), "ATTACK" if flow["features"]["tot_fwd_pkts"] > 1 else "BENIGN", 0.95)
            for flow in flows
        ]
        records = [
            {"label": actual, "flow": {"flow_id": str(i), "event_time": utcnow().isoformat(),
                                      "features": {"tot_fwd_pkts": i, "tot_bwd_pkts": 0}}}
            for i, actual in enumerate(["BENIGN", "ATTACK", "BENIGN", "ATTACK"])
        ]
        report = evaluate(records, classifier, batch_size=2)
        self.assertEqual(report["accuracy"], 0.5)
        self.assertEqual(report["benign_false_positive_rate"], 0.5)
        self.assertEqual(report["errors_with_score_at_least_0_9"], 2)
        self.assertEqual(report["per_class"]["ATTACK"]["precision"], 0.5)
        self.assertEqual(report["features"]["tot_fwd_pkts"]["mean"], 1.5)
        self.assertAlmostEqual(report["features"]["tot_fwd_pkts"]["std"], np.std([0, 1, 2, 3]))
        self.assertEqual(report["operational_counts"], {"BENIGN": 2, "ATTACK": 2, "UNVALIDATED": 0})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            evaluate([records[0], records[0]], classifier)
        with self.assertRaisesRegex(ValueError, "empty"):
            evaluate([], classifier)

    def test_unvalidated_status_does_not_rewrite_raw_model_metrics(self):
        classifier = Mock()
        classifier.load.return_value = ModelArtifacts(["BENIGN", "ATTACK"], ["tot_fwd_pkts", "tot_bwd_pkts", "protocol"])
        classifier._scaler = SimpleNamespace(mean_=np.zeros(3), scale_=np.ones(3))
        classifier.classify_batch.return_value = [PredictionRow(utcnow(), "ATTACK", 0.999, protocol=58)]
        record = {"label": "BENIGN", "flow": {"flow_id": "icmpv6", "event_time": utcnow().isoformat(),
                  "features": {"tot_fwd_pkts": 2, "tot_bwd_pkts": 2, "protocol": 58}}}
        report = evaluate([record], classifier)
        self.assertEqual(report["confusion_matrix"]["BENIGN"]["ATTACK"], 1)
        self.assertEqual(report["accuracy"], 0)
        self.assertEqual(report["operational_counts"], {"BENIGN": 0, "ATTACK": 0, "UNVALIDATED": 1})
