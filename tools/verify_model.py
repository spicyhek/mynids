"""Reproducible partial CSV benchmark and isolated real-model integration checks.

This is not a held-out accuracy certification or a packet-capture replay.
Run with: python -m tools.verify_model --csv data/evaluation/cic.csv
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import random
import re
import csv
import tempfile
import time
from unittest.mock import patch

import numpy as np
from fastapi.testclient import TestClient

from app import main
from app.schemas import FlowRecord
from sensor.zeek_to_cicids import conn_record_to_flow, export_log_once
from tools.evaluate_replay import evaluate


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sample_csv(paths, per_label, seed):
    rng = random.Random(seed)
    counts = Counter()
    samples = {}
    columns = None
    for file_index, path in enumerate(paths):
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            require(reader.fieldnames and "Label" in reader.fieldnames, "CSV has no Label column")
            if columns is None:
                columns = reader.fieldnames
            require(reader.fieldnames == columns, "Input CSV schemas differ")
            for number, row in enumerate(reader, 2):
                label = row["Label"]
                counts[label] += 1
                bucket = samples.setdefault(label, [])
                identity = f"file-{file_index}-row-{number}"
                if len(bucket) < per_label:
                    bucket.append((identity, row))
                else:
                    position = rng.randrange(counts[label])
                    if position < per_label:
                        bucket[position] = (identity, row)
    return columns, counts, samples


def prepare_records(samples, feature_names):
    # Explicit mapping for the selected Kaggle files, consistent with config.json.
    label_map = {"Benign": "BENIGN", "FTP-BruteForce": "OTHER_ATTACK",
                 "SSH-Bruteforce": "OTHER_ATTACK", "Bot": "BOTNET",
                 "DoS attacks-GoldenEye": "DOS_DDOS", "DoS attacks-Slowloris": "DOS_DDOS",
                 "DDOS attack-LOIC-UDP": "DOS_DDOS", "DDOS attack-HOIC": "DOS_DDOS"}
    records = []
    seen = set()
    rejected = Counter()
    kept = Counter()
    for label, bucket in sorted(samples.items()):
        require(label in label_map, f"Unreviewed source label: {label}")
        for number, row in sorted(bucket):
            fingerprint = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
            if fingerprint in seen:
                rejected["duplicate sampled CSV row"] += 1
                continue
            seen.add(fingerprint)
            try:
                # The CSV does not specify timezone; UTC is a documented assumption.
                observed = datetime.strptime(row["Timestamp"], "%d/%m/%Y %H:%M:%S").replace(tzinfo=UTC)
                features = {
                    re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_"): float(value)
                    for key, value in row.items() if key not in ("Label", "Timestamp")
                }
                # This dataset has no source ports. Zero is an evaluation imputation,
                # not a claim about the original flows or training preprocessing.
                features["src_port"] = 0.0
                features["timestamp"] = 0.0
                require(set(features) == set(feature_names), "CSV/model feature columns disagree")
                flow = FlowRecord.model_validate({
                    "flow_id": f"kaggle-cic-row-{number}", "event_time": observed,
                    "features": features,
                }).model_dump()
                if not np.isfinite(np.asarray(list(features.values()), dtype=np.float32)).all():
                    raise ValueError("Feature exceeds float32 range")
            except (ValueError, OverflowError) as exc:
                rejected[type(exc).__name__ + ": " + str(exc).splitlines()[0]] += 1
                continue
            records.append({"label": label_map[label], "source": "kaggle-cic", "flow": flow})
            kept[label] += 1
    return records, kept, rejected


def runtime_checks(classifier):
    fixture = json.loads((Path(__file__).parent / "fixtures/smoke_conn.json").read_text())
    # Runtime scenarios are synthetic and deliberately have no assigned truth labels.
    records = []
    for protocol in ("tcp", "udp", "icmp"):
        for packets, duration in ((1, 0.0), (20, 1.5), (100000, 0.1)):
            row = dict(fixture, uid=f"verify-{protocol}-{packets}", proto=protocol,
                       ts=datetime.now(UTC).timestamp() - 60, duration=duration,
                       orig_pkts=packets, resp_pkts=0, orig_bytes=0,
                       orig_ip_bytes=packets * 40, resp_bytes=0, resp_ip_bytes=0,
                       history="S" if protocol == "tcp" else "")
            records.append(row)
    flows = [FlowRecord.model_validate(conn_record_to_flow(row)).model_dump() for row in records]
    started = time.perf_counter()
    predictions = classifier.classify_batch(flows)
    batch_seconds = time.perf_counter() - started
    for flow, expected in zip(flows, predictions):
        actual = classifier.classify_batch([flow])[0]
        require(actual.predicted_label == expected.predicted_label
                and abs(actual.confidence - expected.confidence) <= 1e-5,
                "Single/batch predictions disagree")

    with tempfile.TemporaryDirectory(prefix="nids-verification-") as directory:
        root = Path(directory)
        log = root / "conn.log"
        log.write_text("".join(json.dumps(row) + "\n" for row in records))
        token = "isolated-local-verification"
        settings = replace(main.settings, db_path=root / "test.sqlite3", ingest_token=token)
        acknowledgments = []
        with patch.object(main, "settings", settings), TestClient(main.app) as client:
            require(client.get("/readyz").status_code == 200, "Real model is not ready")
            require(client.get("/").status_code == 200, "Dashboard route failed")

            def send(endpoint, provided_token, source, batch):
                response = client.post(endpoint, json={"source": source, "flows": batch},
                                       headers={"X-Ingest-Token": provided_token})
                response.raise_for_status()
                acknowledgment = response.json()
                acknowledgments.append(acknowledgment)
                return acknowledgment

            # Only transport is adapted to an in-process ASGI client. Conversion,
            # exporter checkpointing, inference, API validation and storage are real.
            with patch("sensor.zeek_to_cicids.send_payload", side_effect=send):
                for checkpoint in ("first.json", "replay.json"):
                    count = export_log_once(log_path=log, endpoint="/api/internal/flows",
                        state_file=root / checkpoint, source_name="verification", token=token,
                        batch_size=100)
                    require(count == len(records), "Exporter did not acknowledge every flow")
            summary = client.get("/api/public/summary").json()
            expected_counts = dict.fromkeys(classifier.labels, 0)
            expected_counts.update(Counter(row.predicted_label for row in predictions))
            require(acknowledgments[0]["inserted"] == len(records), "Initial insertion mismatch")
            require(acknowledgments[1]["inserted"] == 0
                    and acknowledgments[1]["duplicates"] == len(records), "Replay was not deduplicated")
            require(summary["lifetime_flows"] == len(records), "Stored flow count mismatch")
            require(summary["lifetime_packets"] == sum(r["orig_pkts"] for r in records),
                    "Stored packet count mismatch")
            require(summary["retained_counts"] == expected_counts, "Stored predictions mismatch")
    return {"status": "passed", "synthetic_flows": len(flows), "batch_seconds": batch_seconds,
            "prediction_counts": expected_counts, "summary": summary,
            "scope": "In-process exporter/API/real model/temporary SQLite; no live Zeek, network transport or browser."}


def main_cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, nargs="+", required=True)
    parser.add_argument("--dataset-url", action="append", default=[])
    parser.add_argument("--output-dir", type=Path, default=Path("data/evaluation/results"))
    parser.add_argument("--per-label", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20261025)
    args = parser.parse_args()
    if args.per_label < 1:
        parser.error("--per-label must be positive")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    classifier = main.classifier
    artifacts = classifier.load()
    columns, counts, samples = sample_csv(args.csv, args.per_label, args.seed)
    records, kept, rejected = prepare_records(samples, artifacts.feature_order)
    require(records, "No valid sampled records")
    datasets = []
    for path in args.csv:
        with path.open("rb") as handle:
            datasets.append({"path": str(path), "sha256": hashlib.file_digest(handle, "sha256").hexdigest()})
    missing_classes = sorted(set(artifacts.labels) - {record["label"] for record in records})
    manifest = {
        "generated_at": datetime.now(UTC).isoformat(),
        "dataset_urls": args.dataset_url,
        "datasets": datasets, "dataset_rows_by_label": counts,
        "csv_columns": columns, "sampling": "Uniform reservoir per original label, then validation and exact sampled-row deduplication",
        "seed": args.seed, "requested_per_label": args.per_label,
        "evaluated_by_original_label": kept, "excluded_sample_rows": rejected,
        "missing_model_classes": missing_classes,
        "artifacts_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (
            classifier._model_path, classifier._scaler_path, classifier._feature_order_path,
            classifier._label_map_path, classifier._label_encoder_path)},
        "limitations": [
            "Training/test overlap is unknown; this is not a held-out accuracy claim.",
            "Coverage is limited to the listed source labels; unrepresented attack subtypes remain untested.",
            "Source port is missing and explicitly imputed as zero; original training preprocessing is unavailable.",
            "CSV timestamps are assumed UTC; timestamp-zero matches the scaler's observed constant training feature.",
            "Stratified sample proportions differ from full dataset and live traffic.",
            "CSV features are CIC features, not features reconstructed from Zeek or packet captures.",
        ],
    }
    timestamp_index = artifacts.feature_order.index("timestamp")
    manifest["training_timestamp"] = {"mean": float(classifier._scaler.mean_[timestamp_index]),
                                      "variance": float(classifier._scaler.var_[timestamp_index])}
    require(manifest["training_timestamp"] == {"mean": 0.0, "variance": 0.0},
            "Timestamp-zero diagnostic requires a constant-zero training feature")
    for mode in ("timestamp_zero", "timestamp_epoch_us"):
        selected = deepcopy(records)
        if mode == "timestamp_epoch_us":
            for record in selected:
                flow = record["flow"]
                flow["features"]["timestamp"] = flow["event_time"].timestamp() * 1_000_000
        # Preserve inputs for the existing evaluation CLI, including row identities.
        with (args.output_dir / f"{mode}.jsonl").open("w", encoding="utf-8") as handle:
            for record in selected:
                serializable = dict(record, flow=FlowRecord.model_validate(record["flow"]).model_dump(mode="json"))
                handle.write(json.dumps(serializable, allow_nan=False) + "\n")
        started = time.perf_counter()
        report = evaluate(selected, classifier, batch_size=1000)
        report["elapsed_seconds"] = time.perf_counter() - started
        report["scenario"] = mode
        report["limitations"].extend(manifest["limitations"])
        write_json(args.output_dir / f"{mode}.json", report)
        print(json.dumps({"scenario": mode, "records": report["records"],
                          "accuracy": report["accuracy"], "confusion_matrix": report["confusion_matrix"]}), flush=True)
    manifest["runtime"] = runtime_checks(classifier)
    write_json(args.output_dir / "manifest.json", manifest)
    print(f"Verification reports: {args.output_dir.resolve()}", flush=True)


if __name__ == "__main__":
    main_cli()
