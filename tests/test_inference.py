import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import numpy as np

from app.inference import FlowClassifier
from app.storage import utcnow


class InferenceValidationTests(unittest.TestCase):
    def classifier(self):
        classifier = FlowClassifier(**{name: Path("unused") for name in (
            "model_path", "scaler_path", "feature_order_path", "label_map_path", "label_encoder_path")})
        classifier._np = np
        classifier._labels = ["BENIGN", "ATTACK"]
        classifier._feature_order = ["tot_fwd_pkts", "tot_bwd_pkts", "flow_duration"]
        classifier._scaler = Mock(transform=lambda matrix: matrix)
        classifier._model = Mock()
        classifier._model.predict.return_value = np.array([[0.8, 0.2]])
        return classifier

    def flow(self):
        return {"event_time": utcnow(), "features": {"tot_fwd_pkts": 2, "tot_bwd_pkts": 3, "flow_duration": 10}}

    def test_valid_prediction(self):
        row = self.classifier().classify_batch([self.flow()])[0]
        self.assertEqual(row.predicted_label, "BENIGN")
        self.assertEqual(row.confidence, 0.8)

    def test_invalid_model_outputs_are_rejected(self):
        for scores in ([[np.nan, 1]], [[np.inf, 0]], [[-0.1, 1.1]], [[0.1, 0.1]],
                       [[1, 0, 0]], [], [[1, 0], [0, 1]], [1, 0]):
            with self.subTest(scores=scores):
                classifier = self.classifier()
                classifier._model.predict.return_value = np.array(scores)
                with self.assertRaises(RuntimeError):
                    classifier.classify_batch([self.flow()])
                self.assertIsNotNone(classifier.load_error)

    def test_scaler_corruption_and_overflow(self):
        classifier = self.classifier()
        classifier._scaler.transform = lambda matrix: matrix * np.inf
        with self.assertRaises(RuntimeError):
            classifier.classify_batch([self.flow()])
        classifier._model.predict.assert_not_called()
        classifier = self.classifier()
        flow = self.flow()
        flow["features"]["flow_duration"] = 1e100
        with self.assertRaises(ValueError):
            classifier.classify_batch([flow])
        classifier._model.predict.assert_not_called()

    def test_busy_slot_is_bounded_and_released_after_failure(self):
        classifier = self.classifier()
        classifier._inference_slot.acquire()
        with self.assertRaisesRegex(RuntimeError, "busy"):
            classifier.classify_batch([self.flow()])
        classifier._inference_slot.release()
        classifier._model.predict.side_effect = ValueError("broken runtime")
        with self.assertRaises(RuntimeError):
            classifier.classify_batch([self.flow()])
        classifier._model.predict.side_effect = None
        self.assertEqual(len(classifier.classify_batch([self.flow()])), 1)
        self.assertIsNone(classifier.load_error)

    def test_artifacts_are_validated_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "features.json").write_text(json.dumps(["tot_fwd_pkts", "tot_bwd_pkts"]))
            (root / "labels.json").write_text(json.dumps({"0": "BENIGN", "1": "ATTACK"}))
            classifier = FlowClassifier(model_path=root / "model", scaler_path=root / "scaler",
                feature_order_path=root / "features.json", label_map_path=root / "labels.json",
                label_encoder_path=root / "encoder")
            scaler = SimpleNamespace(n_features_in_=2)
            encoder = SimpleNamespace(classes_=["ATTACK", "BENIGN"])
            model = SimpleNamespace(input_shape=(None, 2), output_shape=(None, 2))
            tf = SimpleNamespace(keras=SimpleNamespace(models=SimpleNamespace(load_model=lambda *a, **kw: model)))
            with patch.dict("sys.modules", {"tensorflow": tf}), patch("joblib.load", side_effect=lambda p: scaler if p.name == "scaler" else encoder):
                with self.assertRaisesRegex(RuntimeError, "encoder"):
                    classifier.load()
                self.assertFalse(classifier.loaded)
                encoder.classes_ = ["BENIGN", "ATTACK"]
                model.output_shape = (None, 3)
                with self.assertRaisesRegex(RuntimeError, "output dimensions"):
                    classifier.load()
                model.output_shape = (None, 2)
                self.assertEqual(classifier.load().labels, encoder.classes_)
                self.assertTrue(classifier.loaded)
