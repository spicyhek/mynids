"""Train a separate candidate with the dataset's feature contract and class map; preserve deployed artifacts."""
from __future__ import annotations

import argparse
from importlib.metadata import version
import json
from pathlib import Path

import joblib
import numpy as np

from app.inference import FlowClassifier
from tools.evaluate_replay import evaluate
from tools.training_data import fit_preprocessing, load_prepared, require_training_coverage, sha256, write_json


def train(dataset: Path, output: Path, *, epochs: int = 50, batch_size: int = 256,
          patience: int = 5, seed: int = 20261029) -> dict:
    if output.exists():
        raise ValueError("Candidate output already exists; choose a new directory.")
    if not 1 <= epochs <= 10000 or not 1 <= batch_size <= 1000 or not 1 <= patience <= 10000:
        raise ValueError("Invalid epochs, batch size, or patience.")
    records, manifest = load_prepared(dataset)
    schema = manifest["contract"]
    classes, width = len(schema["labels"]), len(schema["feature_order"])
    require_training_coverage(records, schema["labels"])
    scaler, encoder, matrix, targets = fit_preprocessing(records, schema)
    indices = {split: np.asarray([i for i, row in enumerate(records) if row["split"] == split], dtype=int)
               for split in ("train", "validation", "regression")}
    scaled = {}
    for split, positions in indices.items():
        if len(positions):
            values = scaler.transform(matrix[positions]).astype(np.float32)
            if not np.isfinite(values).all():
                raise ValueError("Scaling produced nonfinite model inputs.")
            scaled[split] = values

    # TensorFlow is loaded only after provenance and class-coverage checks pass.
    import tensorflow as tf
    from sklearn.utils.class_weight import compute_class_weight

    tf.keras.utils.set_random_seed(seed)
    tf.config.experimental.enable_op_determinism()
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(width,)),
        tf.keras.layers.Dense(128, activation="relu"), tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(64, activation="relu"), tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(classes, activation="softmax"),
    ])
    model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
                  loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    class_weights = compute_class_weight("balanced", classes=np.arange(classes), y=targets[indices["train"]])
    history = model.fit(scaled["train"], targets[indices["train"]],
                        validation_data=(scaled["validation"], targets[indices["validation"]]),
                        epochs=epochs, batch_size=batch_size, shuffle=True,
                        class_weight={i: float(weight) for i, weight in enumerate(class_weights)},
                        callbacks=[tf.keras.callbacks.EarlyStopping(monitor="val_loss", patience=patience,
                                                                   restore_best_weights=True)], verbose=2)
    output.mkdir(parents=True)
    model_path = output / "cicids2018_dense_model.keras"
    model.save(model_path)
    joblib.dump(scaler, output / "scaler.joblib")
    joblib.dump(encoder, output / "label_encoder.joblib")
    (output / "feature_order.json").write_text(json.dumps(schema["feature_order"], indent=2) + "\n")
    (output / "label_map.json").write_text(json.dumps(dict(enumerate(schema["labels"])), indent=2) + "\n")
    classifier = FlowClassifier(model_path=model_path, scaler_path=output / "scaler.joblib",
                                feature_order_path=output / "feature_order.json", label_map_path=output / "label_map.json",
                                label_encoder_path=output / "label_encoder.joblib")
    classifier.load()  # Enforce the actual production artifact/preprocessing compatibility checks.
    metrics = {}
    for split in ("validation", "regression"):
        subset = [row for row in records if row["split"] == split]
        if subset:
            metrics[split] = evaluate(subset, classifier, batch_size=min(batch_size, 1000))
    artifacts = ("cicids2018_dense_model.keras", "scaler.joblib", "label_encoder.joblib", "feature_order.json", "label_map.json")
    report = {"dataset_manifest_sha256": sha256(dataset / "manifest.json"), "contract": schema,
              "dataset_limitations": manifest.get("source_limitations", []),
              "configuration": {"seed": seed, "epochs_limit": epochs, "batch_size": batch_size, "patience": patience,
                                "architecture": [width, 128, 64, classes], "dropout": 0.2,
                                "class_weights_from_training_only": class_weights.tolist()},
              "epochs_run": len(history.history["loss"]),
              "history": {name: [float(value) for value in values] for name, values in history.history.items()},
              "metrics": metrics, "class_counts": manifest["class_counts"],
              "artifacts_sha256": {name: sha256(output / name) for name in artifacts},
              "training_code_sha256": {path.name: sha256(path) for path in
                                       (Path(__file__), Path(__file__).with_name("training_data.py"))},
              "versions": {name: version(name) for name in ("numpy", "scikit-learn", "tensorflow", "keras", "joblib")},
              "test_evaluated": False, "deployment_approved": False,
              "limitations": ["Validation influences early stopping; it is not an untouched final test.",
                              "Regression captures were previously inspected and cannot establish generalization.",
                              "Test records are not used for fitting, early stopping, class weights, or reported metrics.",
                              "Deterministic settings and seeds do not guarantee identical results across hardware/library versions.",
                              "Class coverage is necessary but does not establish sufficient data or accurate labels.",
                              "ICMPv6 remains operationally unvalidated in the existing server policy."]}
    write_json(output / "training-report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="New candidate artifact directory.")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--patience", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20261029)
    args = parser.parse_args()
    try:
        report = train(args.dataset, args.output, epochs=args.epochs, batch_size=args.batch_size,
                       patience=args.patience, seed=args.seed)
    except (ValueError, KeyError, OSError) as exc:
        parser.exit(2, f"Training refused/failed: {exc}\n")
    print(f"Saved separate candidate to {args.output}; {report['epochs_run']} epochs. Test set not evaluated.")


if __name__ == "__main__":
    main()
