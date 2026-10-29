"""Train a separate gradient-boosted tree candidate for a prepared dataset; never touches deployed artifacts.

Validation is not used for any fitting or model choice here (fixed iteration count, no early
stopping), so its metrics are less biased than the dense baseline's. It is still not a final test.
"""
from __future__ import annotations

import argparse
from collections import Counter
from importlib.metadata import version
import json
from pathlib import Path

import joblib
import numpy as np

from tools.training_data import (extract_v2_log, load_prepared, model_matrix, require_training_coverage, sha256,
                                 write_json)

MODEL_FILE = "tree_model.joblib"


def fit(matrix: np.ndarray, targets: np.ndarray, classes: int, *, iterations: int, seed: int):
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.utils.class_weight import compute_sample_weight

    present = sorted(set(targets.tolist()))
    # Balanced weights from these training rows only; reported so their scale can be audited.
    weights = compute_sample_weight("balanced", targets)
    per_class = {int(c): float(weights[targets == c][0]) for c in present}
    model = HistGradientBoostingClassifier(max_iter=iterations, learning_rate=0.1, early_stopping=False,
                                           random_state=seed)
    model.fit(matrix, targets, sample_weight=weights)
    if list(model.classes_) != present or len(present) > classes:
        raise ValueError("Fitted classes do not match the training targets.")
    return model, per_class


def metrics(predicted: np.ndarray, actual: np.ndarray, labels: list[str]) -> dict:
    benign = labels.index("BENIGN")
    per_class = {}
    for index, name in enumerate(labels):
        support = int((actual == index).sum())
        flagged = int((predicted == index).sum())
        hits = int(((predicted == index) & (actual == index)).sum())
        if support or flagged:
            precision = hits / flagged if flagged else 0.0
            recall = hits / support if support else None
            f1 = (2 * precision * recall / (precision + recall)) if recall and precision else 0.0
            per_class[name] = {"support": support, "predicted": flagged, "precision": round(precision, 4),
                               "recall": None if recall is None else round(recall, 4), "f1": round(f1, 4)}
    attacks = actual != benign
    supported = [v["f1"] for v in per_class.values() if v["support"]]
    return {
        "records": int(len(actual)), "per_class": per_class,
        "macro_f1_supported_classes": round(float(np.mean(supported)), 4) if supported else None,
        "attack_detected_as_any_attack": round(float((predicted[attacks] != benign).mean()), 4) if attacks.any() else None,
        "benign_false_positives": int((predicted[~attacks] != benign).sum()),
        "benign_false_positive_rate": round(float((predicted[~attacks] != benign).mean()), 4) if (~attacks).any() else None,
        "confusion": {labels[a]: {labels[p]: int(((actual == a) & (predicted == p)).sum())
                                  for p in sorted(set(predicted.tolist()))} for a in sorted(set(actual.tolist()))},
    }


def alert_volume(model, path: Path, feature_order: list[str], labels: list[str]) -> dict:
    """Operational alerts on an unlabeled capture, counting only flows serving would classify."""
    observations, counts = extract_v2_log(path)
    flows = [flow for item in observations.values() if item and (flow := item[1])
             and flow["window_warm"] and not flow["window_degraded"]]
    if not flows:
        return {"conn_log_sha256": sha256(path), "classified": 0, "window_context": counts}
    times = [float(item[0]["ts"]) for item in observations.values() if item]
    hours = max((max(times) - min(times)) / 3600, 1 / 3600)
    predicted = model.predict(model_matrix(flows, feature_order))
    alerts = predicted != labels.index("BENIGN")
    ports = Counter(int(flow["features"]["dst_port"]) for flow, alert in zip(flows, alerts) if alert)
    return {"conn_log_sha256": sha256(path), "window_context": counts, "classified": len(flows),
            "capture_hours": round(hours, 3), "alerts": int(alerts.sum()),
            "alerts_per_hour": round(float(alerts.sum()) / hours, 1),
            "alerts_by_label": {labels[k]: int(v) for k, v in Counter(predicted[alerts].tolist()).items()},
            "alert_top_destination_ports": ports.most_common(10)}


def train(dataset: Path, output: Path, *, iterations: int = 300, seed: int = 20261029,
          alert_captures: tuple[Path, ...] = (), leave_one_source_out: bool = True) -> dict:
    if output.exists():
        raise ValueError("Candidate output already exists; choose a new directory.")
    if not 1 <= iterations <= 10000:
        raise ValueError("Invalid iteration count.")
    records, manifest = load_prepared(dataset)
    schema = manifest["contract"]
    labels, feature_order = schema["labels"], schema["feature_order"]
    if alert_captures and schema.get("feature_contract") != "zeek-conn-window-v2":
        raise ValueError("Unlabeled alert volume is implemented for the zeek-conn-window-v2 contract only.")
    require_training_coverage(records, labels)
    matrix = model_matrix([row["flow"] for row in records], feature_order)
    targets = np.asarray([labels.index(row["label"]) for row in records])
    split = np.asarray([row["split"] for row in records])
    group = np.asarray([row["group"] for row in records])
    train_rows = split == "train"

    model, class_weights = fit(matrix[train_rows], targets[train_rows], len(labels), iterations=iterations, seed=seed)
    evaluation = {name: metrics(model.predict(matrix[split == name]), targets[split == name], labels)
                  for name in ("validation", "regression") if (split == name).any()}

    loso = {}
    if leave_one_source_out:
        pool = np.isin(split, ("train", "validation"))
        for held in sorted(set(group[pool].tolist())):
            test, rest = pool & (group == held), pool & (group != held)
            fold, _ = fit(matrix[rest], targets[rest], len(labels), iterations=iterations, seed=seed)
            result = metrics(fold.predict(matrix[test]), targets[test], labels)
            result["classes_absent_from_fold_training"] = sorted(
                {labels[c] for c in set(targets[test].tolist())} - {labels[c] for c in set(targets[rest].tolist())})
            loso[held] = result

    volumes = {path.as_posix(): alert_volume(model, path, feature_order, labels) for path in alert_captures}
    output.mkdir(parents=True)
    joblib.dump(model, output / MODEL_FILE)
    (output / "feature_order.json").write_text(json.dumps(feature_order, indent=2) + "\n")
    (output / "label_map.json").write_text(json.dumps(dict(enumerate(labels)), indent=2) + "\n")
    write_json(output / "feature_contract.json", {key: schema[key] for key in
                                                  ("feature_contract", "window_seconds", "feature_order", "files_sha256")
                                                  if key in schema})
    artifacts = (MODEL_FILE, "feature_order.json", "label_map.json", "feature_contract.json")
    report = {
        "dataset_manifest_sha256": sha256(dataset / "manifest.json"), "dataset_name": manifest["name"],
        "feature_contract": schema.get("feature_contract", "zeek-conn-v1"),
        "configuration": {"estimator": "sklearn HistGradientBoostingClassifier", "max_iter": iterations,
                          "learning_rate": 0.1, "early_stopping": False, "seed": seed,
                          "sample_weights": "balanced, from training rows only",
                          "class_weights": {labels[c]: round(w, 4) for c, w in class_weights.items()}},
        "training_label_tiers": dict(Counter(row.get("label_tier", "reviewed") for row in records
                                             if row["split"] == "train")),
        "class_counts": manifest["class_counts"], "metrics": evaluation, "leave_one_source_out": loso,
        "unlabeled_alert_volume": volumes,
        "artifacts_sha256": {name: sha256(output / name) for name in artifacts},
        "training_code_sha256": {path.name: sha256(path) for path in
                                 (Path(__file__), Path(__file__).with_name("training_data.py"))},
        "versions": {name: version(name) for name in ("numpy", "scikit-learn", "joblib")},
        "test_evaluated": False, "deployment_approved": False,
        "limitations": [
            "No untouched final-test set exists; validation and regression are development checks.",
            "Leave-one-source-out folds whose held-out class has one other source are fragile.",
            "Serving cannot load this candidate: FlowClassifier expects a Keras model and the v1 contract.",
            "Unlabeled alert volume counts predictions, not confirmed attacks or confirmed false alarms.",
            "Allowlist-benign rows are a weaker label tier than per-flow review.",
        ],
    }
    write_json(output / "training-report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="New candidate artifact directory.")
    parser.add_argument("--iterations", type=int, default=300)
    parser.add_argument("--seed", type=int, default=20261029)
    parser.add_argument("--alert-capture", type=Path, action="append", default=[],
                        help="Complete conn.log of an unlabeled capture not used in training; repeatable.")
    parser.add_argument("--skip-loso", action="store_true")
    args = parser.parse_args()
    try:
        report = train(args.dataset, args.output, iterations=args.iterations, seed=args.seed,
                       alert_captures=tuple(args.alert_capture), leave_one_source_out=not args.skip_loso)
    except (ValueError, KeyError, OSError) as exc:
        parser.exit(2, f"Training refused/failed: {exc}\n")
    print(json.dumps({"validation": report["metrics"].get("validation", {}).get("per_class"),
                      "regression_benign_false_positives":
                          report["metrics"].get("regression", {}).get("benign_false_positives")}, indent=2))
    print(f"Saved separate candidate to {args.output}. Test set not evaluated; not deployable.")


if __name__ == "__main__":
    main()
