"""Offline labeled JSONL replay: detection metrics and feature-distribution diagnostics."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Iterable

import numpy as np

from app.schemas import FlowRecord
from app.storage import UNVALIDATED
from sensor.zeek_to_cicids import conn_record_to_flow
from tools.smoke_model import make_classifier


def evaluate(records: Iterable[dict], classifier, batch_size: int = 100) -> dict:
    if not 1 <= batch_size <= 1000:
        raise ValueError("batch_size must be between 1 and 1000.")
    artifacts = classifier.load()
    labels, names = artifacts.labels, artifacts.feature_order
    confusion = {actual: dict.fromkeys(labels, 0) for actual in labels}
    operational_counts = dict.fromkeys([*labels, UNVALIDATED], 0)
    total = 0
    confidence_sum = 0.0
    confident_errors = 0
    mean = np.zeros(len(names))
    m2 = np.zeros(len(names))
    minima = np.full(len(names), np.inf)
    maxima = np.full(len(names), -np.inf)
    zeros = np.zeros(len(names), dtype=np.int64)
    far_from_training = np.zeros(len(names), dtype=np.int64)
    seen = set()
    batch = []

    def consume():
        nonlocal total, mean, m2, minima, maxima, zeros, confidence_sum, confident_errors
        flows = [flow for _, flow in batch]
        predictions = classifier.classify_batch(flows)
        if len(predictions) != len(batch):
            raise RuntimeError("Classifier returned the wrong number of predictions.")
        matrix = np.asarray([[flow["features"][name] for name in names] for flow in flows], dtype=np.float64)
        size = len(batch)
        batch_mean = matrix.mean(axis=0)
        delta = batch_mean - mean
        m2 += ((matrix - batch_mean) ** 2).sum(axis=0) + delta**2 * total * size / (total + size)
        mean += delta * size / (total + size)
        minima = np.minimum(minima, matrix.min(axis=0))
        maxima = np.maximum(maxima, matrix.max(axis=0))
        zeros += (matrix == 0).sum(axis=0)
        # StandardScaler stores training moments; this is a diagnostic, not a calibrated OOD detector.
        scaler = classifier._scaler
        if hasattr(scaler, "mean_") and hasattr(scaler, "scale_"):
            scale = np.where(np.asarray(scaler.scale_) > 0, scaler.scale_, 1)
            far_from_training[:] += (np.abs((matrix - scaler.mean_) / scale) > 5).sum(axis=0)
        for (actual, _), predicted in zip(batch, predictions):
            confusion[actual][predicted.predicted_label] += 1
            operational_counts[predicted.summary_label] += 1
            confidence_sum += predicted.confidence
            confident_errors += int(actual != predicted.predicted_label and predicted.confidence >= 0.9)
        total += size
        batch.clear()

    for number, record in enumerate(records, 1):
        actual = record.get("label")
        if actual not in labels:
            raise ValueError(f"Record {number}: label must be one of {labels}.")
        if ("conn" in record) == ("flow" in record):
            raise ValueError(f"Record {number}: supply exactly one of conn or flow.")
        flow = FlowRecord.model_validate(
            conn_record_to_flow(record["conn"]) if "conn" in record else record["flow"]
        ).model_dump()
        # Reject duplicate evaluation observations instead of inflating apparent support.
        key = (record.get("source", "evaluation"), flow["flow_id"])
        if key in seen:
            raise ValueError(f"Record {number}: duplicate evaluation flow ID.")
        seen.add(key)
        batch.append((actual, flow))
        if len(batch) >= batch_size:
            consume()
    if batch:
        consume()
    if not total:
        raise ValueError("Evaluation dataset is empty.")

    metrics = {}
    for label in labels:
        tp = confusion[label][label]
        support = sum(confusion[label].values())
        predicted = sum(confusion[actual][label] for actual in labels)
        precision = tp / predicted if predicted else 0.0
        recall = tp / support if support else 0.0
        metrics[label] = {"support": support, "precision": precision, "recall": recall,
                          "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0}
    benign = confusion.get("BENIGN", {})
    benign_support = sum(benign.values())
    false_positives = benign_support - benign.get("BENIGN", 0)
    return {
        "records": total, "confusion_matrix": confusion, "per_class": metrics,
        "operational_counts": operational_counts,
        "accuracy": sum(confusion[label][label] for label in labels) / total,
        "macro_f1": sum(metric["f1"] for metric in metrics.values()) / len(labels),
        "weighted_f1": sum(metric["f1"] * metric["support"] for metric in metrics.values()) / total,
        "benign_false_positives": false_positives,
        "benign_false_positive_rate": false_positives / benign_support if benign_support else None,
        "mean_winning_score": confidence_sum / total,
        "errors_with_score_at_least_0_9": confident_errors,
        "features": {
            name: {"mean": float(mean[i]), "std": float(np.sqrt(m2[i] / total)),
                   "min": float(minima[i]), "max": float(maxima[i]), "zero_fraction": float(zeros[i] / total),
                   "fraction_beyond_5_training_std": float(far_from_training[i] / total)}
            for i, name in enumerate(names)
        },
        "limitations": [
            "Results apply only to this labeled dataset; absent classes have zero support.",
            "Accuracy and confusion metrics describe raw model labels; operational_counts separates unvalidated ICMPv6.",
            "Feature diagnostics describe submitted values before classifier preprocessing (timestamp is zeroed for this model).",
            "Winning scores are not calibrated probabilities of correctness.",
            "Training-standard-deviation comparisons are heuristic distribution diagnostics.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path, help="JSONL rows: label, source, and either conn or flow.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()
    if args.output.resolve() == args.dataset.resolve():
        parser.error("Output must not overwrite the evaluation dataset.")
    classifier = make_classifier()
    with args.dataset.open(encoding="utf-8") as handle:
        report = evaluate((json.loads(line) for line in handle if line.strip()), classifier, args.batch_size)
    with args.dataset.open("rb") as handle:
        report["dataset_sha256"] = hashlib.file_digest(handle, "sha256").hexdigest()
    report["artifacts_sha256"] = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (classifier._model_path, classifier._scaler_path, classifier._feature_order_path,
                     classifier._label_map_path, classifier._label_encoder_path)
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(f"Evaluated {report['records']} labeled flows; report written to {args.output}")


if __name__ == "__main__":
    main()
