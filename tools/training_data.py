"""Versioned, reviewed Zeek datasets for the existing 80-feature production contract."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import random

import numpy as np

from app.schemas import FlowRecord
from sensor import zeek_features_v2
from sensor.zeek_to_cicids import conn_record_to_flow, parse_zeek_json_line

ROOT = Path(__file__).resolve().parent.parent
SPLITS = ("train", "validation", "test", "regression")
V1_CONTRACT = "zeek-conn-v1"
CONTRACT_FILES = ("feature_order.json", "label_map.json", "sensor/zeek_to_cicids.py",
                  "app/validation.py", "app/schemas.py", "app/inference.py")
V2_CONTRACT_FILES = ("sensor/zeek_features_v2.py", "sensor/zeek_to_cicids.py",
                     "app/validation.py", "app/schemas.py", "app/inference.py")


def sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def contract(training_label_map: dict | None = None, feature_contract: str = V1_CONTRACT) -> dict:
    mapping = training_label_map if training_label_map is not None else json.loads((ROOT / "label_map.json").read_text())
    if not isinstance(mapping, dict) or set(mapping) != {str(i) for i in range(len(mapping))}:
        raise ValueError("Training label map must have contiguous string class indices.")
    labels = [mapping[str(i)] for i in range(len(mapping))]
    if len(labels) < 2 or len(set(labels)) != len(labels):
        raise ValueError("Training requires at least two unique labels.")
    if any(not isinstance(label, str) or not label or label == "UNVALIDATED" for label in labels):
        raise ValueError("Class names must be nonempty strings; UNVALIDATED is an operational status.")
    if labels != sorted(labels):
        raise ValueError("Class indices must match LabelEncoder's alphabetic ordering.")
    if feature_contract == zeek_features_v2.CONTRACT_ID:
        result = {"feature_contract": feature_contract, "window_seconds": zeek_features_v2.WINDOW_SECONDS,
                  "feature_order": list(zeek_features_v2.FEATURE_ORDER), "labels": labels,
                  "files_sha256": {name: sha256(ROOT / name) for name in V2_CONTRACT_FILES}}
        if training_label_map is not None:
            result["training_label_map"] = training_label_map
        return result
    if feature_contract != V1_CONTRACT:
        raise ValueError(f"Unknown feature contract: {feature_contract!r}")
    names = json.loads((ROOT / "feature_order.json").read_text())
    if len(names) != 80 or len(set(names)) != 80:
        raise ValueError("This baseline requires 80 production features and unique training labels.")
    # The v1 result deliberately has no contract key, so existing manifests still reconcile.
    result = {"feature_order": names, "labels": labels, "timestamp_preprocessing": "constant_zero",
              "files_sha256": {name: sha256(ROOT / name) for name in CONTRACT_FILES}}
    if training_label_map is not None:
        result["training_label_map"] = training_label_map
    return result


def jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if line.strip():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path.name}:{number}: invalid JSON") from exc
                if not isinstance(record, dict):
                    raise ValueError(f"{path.name}:{number}: record must be an object")
                yield number, record


def model_matrix(flows: list[dict], feature_order: list[str]) -> np.ndarray:
    with np.errstate(over="ignore", invalid="ignore"):
        matrix = np.asarray([[flow["features"][name] for name in feature_order] for flow in flows], dtype=np.float32)
    if matrix.shape != (len(flows), len(feature_order)) or not np.isfinite(matrix).all():
        raise ValueError("Model features must be finite float32 values with the complete feature order.")
    if "timestamp" in feature_order:  # v1 only; v2 has no timestamp input.
        matrix[:, feature_order.index("timestamp")] = 0
    return matrix


def extract_v2_log(path: Path) -> tuple[dict, dict]:
    """Replay a complete conn.log in file order; every valid record is window context.

    Returns uid -> (conn record, v2 flow or None for a tunnel carrier), and counts. Invalid
    records are skipped without touching window state, as the online exporter quarantines them.
    """
    extractor = zeek_features_v2.Extractor()
    observations, duplicates = {}, set()
    counts = Counter()
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                record = parse_zeek_json_line(line)
                if record is None:
                    continue
                flow = extractor.process(record)
            except (ValueError, KeyError, TypeError, OverflowError):
                counts["invalid_skipped"] += 1
                continue
            counts["records"] += 1
            if flow is None:
                counts["tunnel_carriers"] += 1
            uid = record["uid"]
            if uid in observations:
                duplicates.add(uid)
            observations[uid] = record, flow
    for uid in duplicates:
        observations[uid] = None  # Ambiguous: a reviewed row cannot be joined to one record.
    counts["duplicate_uids"] = len(duplicates)
    return observations, dict(counts)


def validate_flow(value: dict, feature_order: list[str]) -> dict:
    flow = FlowRecord.model_validate(value).model_dump(mode="json")
    if set(flow["features"]) != set(feature_order):
        raise ValueError("Features differ from the production feature contract.")
    model_matrix([flow], feature_order)  # Check range before zeroing timestamp, as production does.
    return flow


def validate_records(records: list[dict], schema: dict) -> None:
    groups = {}
    seen_ids = set()
    for record in records:
        if record.get("label") not in schema["labels"]:
            raise ValueError("Every record requires an independently reviewed, known class label.")
        group, split = record.get("group"), record.get("split")
        if not isinstance(group, str) or not group or len(group) > 200 or any(c.isspace() for c in group):
            raise ValueError("Every record requires a nonempty group ID without whitespace.")
        if split not in SPLITS:
            raise ValueError(f"Split must be one of {SPLITS}.")
        if groups.setdefault(group, split) != split:
            raise ValueError(f"Capture group {group!r} occurs in multiple splits.")
        flow = validate_flow(record["flow"], schema["feature_order"])
        # A source alias must not allow the same observation to cross capture groups/splits.
        if flow["flow_id"] in seen_ids:
            raise ValueError("Duplicate flow ID across dataset sources/groups.")
        seen_ids.add(flow["flow_id"])


def coverage(records: list[dict], labels: list[str]) -> dict:
    counts = {split: dict.fromkeys(labels, 0) for split in SPLITS}
    groups = {split: set() for split in SPLITS}
    for record in records:
        counts[record["split"]][record["label"]] += 1
        groups[record["split"]].add(record["group"])
    missing = {split: [label for label, count in counts[split].items() if not count]
               for split in ("train", "validation")}
    ready = not any(missing.values())
    return {"class_counts": counts, "group_counts": {split: len(values) for split, values in groups.items()},
            "missing_training_or_validation_classes": missing, "ready_for_training": ready,
            "ready_for_four_class_training": len(labels) == 4 and ready}


def require_training_coverage(records: list[dict], labels: list[str]) -> None:
    result = coverage(records, labels)
    if not result["ready_for_training"]:
        raise ValueError("Training requires every class in both train and validation; missing "
                         + json.dumps(result["missing_training_or_validation_classes"]))


def prepare(recipe_path: Path, output: Path) -> dict:
    """Convert reviewed conn JSONL only; preserve observation metadata and explicit capture splits."""
    if output.exists():
        raise ValueError("Dataset output already exists; choose a new dataset version.")
    recipe = json.loads(recipe_path.read_text(encoding="utf-8"))
    if recipe.get("schema_version") != 1 or not recipe.get("name") or not recipe.get("sources"):
        raise ValueError("Recipe requires schema_version 1, a name, and reviewed sources.")
    training_labels = None
    if "label_map" in recipe:
        specification = recipe["label_map"]
        label_path = (recipe_path.parent / specification["path"]).resolve()
        if sha256(label_path) != specification["sha256"]:
            raise ValueError("Training label map hash mismatch.")
        training_labels = json.loads(label_path.read_text(encoding="utf-8"))
    feature_contract = recipe.get("feature_contract", V1_CONTRACT)
    schema = contract(training_labels, feature_contract)
    v2 = feature_contract != V1_CONTRACT
    records, sources = [], []
    seen_reviewed_ids = set()
    for entry in recipe["sources"]:
        path = (recipe_path.parent / entry["path"]).resolve()
        provenance = (recipe_path.parent / entry["provenance_path"]).resolve()
        if sha256(path) != entry["sha256"] or sha256(provenance) != entry["provenance_sha256"]:
            raise ValueError("Reviewed input/provenance hash mismatch; review changes before updating the recipe.")
        if not isinstance(entry.get("label_basis"), str) or not entry["label_basis"].strip():
            raise ValueError("A reviewed source must document its independent label basis.")
        if not isinstance(entry.get("origin"), str) or not entry["origin"].strip():
            raise ValueError("A reviewed source must identify its dataset/capture origin.")
        start = len(records)
        tier = entry.get("label_tier")
        if tier is not None and (not isinstance(tier, str) or not tier.strip()):
            raise ValueError("label_tier must be a nonempty string when present.")
        observations, window_context, excluded = None, None, Counter()
        if v2:
            # Window inputs need every connection in the capture, not just the reviewed rows.
            if not entry.get("conn_log_path") or not entry.get("conn_log_sha256"):
                raise ValueError(f"{feature_contract} sources require conn_log_path and conn_log_sha256.")
            conn_log = (recipe_path.parent / entry["conn_log_path"]).resolve()
            if sha256(conn_log) != entry["conn_log_sha256"]:
                raise ValueError("Complete conn.log hash mismatch; review changes before updating the recipe.")
            observations, window_context = extract_v2_log(conn_log)
        maximum = entry.get("max_records_per_label")
        sampling, buckets, original_counts = None, {}, Counter()
        if maximum is not None:
            seed = entry.get("sample_seed", 20261029)
            if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= 1000000:
                raise ValueError("max_records_per_label must be an integer between 1 and 1000000.")
            if isinstance(seed, bool) or not isinstance(seed, int):
                raise ValueError("sample_seed must be an integer.")
            rng = random.Random(seed)
            sampling = {"method": "per-label reservoir within an already assigned whole-capture split",
                        "max_records_per_label": maximum, "seed": seed}
        for number, row in jsonl(path):
            try:
                if "flow" in row or not isinstance(row.get("conn"), dict):
                    raise ValueError("Training sources must contain reviewed Zeek conn records, not precomputed CIC features.")
                if row.get("label") not in schema["labels"]:
                    raise ValueError("Missing/unreviewed/unknown label; do not infer labels from predictions.")
                source = row.get("source")
                if not isinstance(source, str) or not source.strip() or len(source) > 128:
                    raise ValueError("Reviewed rows require a source name of 1–128 characters.")
                if row.get("label_tier") != tier:
                    # A weaker tier must be declared in the recipe, never mixed in silently.
                    raise ValueError("Row label_tier differs from the recipe source's declared label_tier.")
                if v2:
                    observed = observations.get(row["conn"].get("uid"))
                    if observed is None:
                        raise ValueError("Reviewed connection is absent from, or ambiguous in, the complete conn.log.")
                    if observed[0] != row["conn"]:
                        raise ValueError("Reviewed conn record differs from the complete conn.log record.")
                    v2_flow = observed[1]
                    if v2_flow is None:
                        reason = "tunnel_carrier"
                    elif v2_flow["window_degraded"]:
                        reason = "window_degraded"
                    else:
                        reason = None if v2_flow["window_warm"] else "window_not_warm"
                    if reason:
                        # Serving never classifies these operationally, so they are not training rows.
                        excluded[reason] += 1
                        continue
                    flow = validate_flow({key: v2_flow[key] for key in ("flow_id", "event_time", "features")},
                                         schema["feature_order"])
                else:
                    flow = validate_flow(conn_record_to_flow(row["conn"]), schema["feature_order"])
                if flow["flow_id"] in seen_reviewed_ids:
                    raise ValueError("Duplicate flow ID across reviewed inputs, before any sampling.")
                seen_reviewed_ids.add(flow["flow_id"])
                prepared = {"label": row["label"], "source": source, "group": entry["group"],
                            "split": entry["split"], "origin": entry["origin"], "flow": flow}
                if tier is not None:  # Absent for strictly reviewed sources, keeping older outputs identical.
                    prepared["label_tier"] = tier
                original_counts[row["label"]] += 1
                if maximum is None:
                    records.append(prepared)
                else:
                    bucket = buckets.setdefault(row["label"], [])
                    if len(bucket) < maximum:
                        bucket.append((number, prepared))
                    else:
                        choice = rng.randrange(original_counts[row["label"]])
                        if choice < maximum:
                            bucket[choice] = number, prepared
            except (ValueError, KeyError, TypeError, OverflowError) as exc:
                raise ValueError(f"{path.name}:{number}: {exc}") from exc
        if not original_counts:
            raise ValueError("A reviewed source is empty." if not excluded
                             else f"Every reviewed row was excluded: {dict(excluded)}")
        if maximum is not None:
            records.extend(row for _, row in sorted(item for bucket in buckets.values() for item in bucket))
        summary = {"name": path.name, "sha256": entry["sha256"],
                   "provenance_name": provenance.name, "provenance_sha256": entry["provenance_sha256"],
                   "label_basis": entry["label_basis"], "group": entry["group"], "split": entry["split"],
                   "origin": entry["origin"], "records": len(records) - start,
                   "source_class_counts_before_sampling": dict(original_counts), "sampling": sampling}
        if tier is not None:
            summary["label_tier"] = tier
        if v2:
            summary.update(conn_log_sha256=entry["conn_log_sha256"], window_context=window_context,
                           excluded_before_sampling=dict(excluded))
        sources.append(summary)
    validate_records(records, schema)
    # Validate the entire recipe before creating output. Never silently discard invalid observations.
    output.mkdir(parents=True)
    (output / "splits").mkdir()
    files = {"records.jsonl": records, **{f"splits/{split}.jsonl": [row for row in records if row["split"] == split]
                                         for split in SPLITS}}
    for name, rows in files.items():
        (output / name).write_text("".join(json.dumps(row, allow_nan=False) + "\n" for row in rows), encoding="utf-8")
    write_json(output / "recipe.json", recipe)
    origin_labels = {}
    for row in records:
        origin_labels.setdefault(row["origin"], Counter())[row["label"]] += 1
    manifest = {"schema_version": 2, "name": recipe["name"], "records": len(records), "contract": schema,
                "sources": sources, **coverage(records, schema["labels"]), "origin_class_counts": origin_labels,
                "source_limitations": recipe.get("limitations", []),
                "files_sha256": {name: sha256(output / name) for name in (*files, "recipe.json")},
                "limitations": ["Labels come from reviewed source evidence, not model predictions.",
                                "Explicit capture groups are never randomly split into individual rows.",
                                "Regression data has already been inspected and is not an untouched final test.",
                                "Class coverage checks do not certify label quality, sample adequacy, or generalization."]}
    write_json(output / "manifest.json", manifest)
    return manifest


def load_prepared(directory: Path) -> tuple[list[dict], dict]:
    manifest = json.loads((directory / "manifest.json").read_text())
    stored = manifest.get("contract", {})
    if (manifest.get("schema_version") not in (1, 2)
            or stored != contract(stored.get("training_label_map"), stored.get("feature_contract", V1_CONTRACT))):
        raise ValueError("Prepared dataset contract is incompatible; reprepare from reviewed sources.")
    expected = {"records.jsonl", "recipe.json", *(f"splits/{split}.jsonl" for split in SPLITS)}
    if set(manifest["files_sha256"]) != expected:
        raise ValueError("Prepared dataset file manifest is incomplete.")
    for name, expected_hash in manifest["files_sha256"].items():
        if sha256(directory / name) != expected_hash:
            raise ValueError(f"Prepared dataset hash mismatch: {name}")
    records = [row for _, row in jsonl(directory / "records.jsonl")]
    validate_records(records, manifest["contract"])
    summary = coverage(records, manifest["contract"]["labels"])
    if manifest["schema_version"] == 1:
        summary.pop("ready_for_training")  # Read previously prepared four-class seed manifests.
    if len(records) != manifest["records"] or any(manifest.get(key) != value for key, value in summary.items()):
        raise ValueError("Prepared dataset counts do not reconcile.")
    for split in SPLITS:
        if [row for _, row in jsonl(directory / f"splits/{split}.jsonl")] != [row for row in records if row["split"] == split]:
            raise ValueError("Split file differs from the canonical dataset.")
    return records, manifest


def fit_preprocessing(records: list[dict], schema: dict):
    """Fit moments on training only; validation, test, and regression cannot influence the scaler."""
    from sklearn.preprocessing import LabelEncoder, StandardScaler

    require_training_coverage(records, schema["labels"])
    matrix = model_matrix([record["flow"] for record in records], schema["feature_order"])
    train = np.asarray([row["split"] == "train" for row in records])
    scaler = StandardScaler().fit(matrix[train])
    encoder = LabelEncoder().fit(schema["labels"])
    if list(encoder.classes_) != schema["labels"]:
        raise ValueError("Label encoder ordering differs from the production label map.")
    targets = encoder.transform([row["label"] for row in records])
    return scaler, encoder, matrix, targets
