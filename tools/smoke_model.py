"""Smoke test of the shipped app with a tiny real v2 bundle, and the bundle writer the release smoke test uses.

The production v2 bundle is private and staged on the node, never in the image, so CI and the release build a
throwaway one: a small tree that answers BENIGN for port 443 and DOS_DDOS for port 80.

  python -m tools.smoke_model                    # build a bundle, classify converter flows, check labels
  python -m tools.smoke_model --write-bundle DIR # only write the bundle to DIR and print its SHA-256
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

LABELS = ["BENIGN", "BOTNET", "BRUTE_FORCE", "DOS_DDOS", "OTHER_ATTACK"]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def write_bundle(directory: Path) -> str:
    """Write a zeek-conn-window-v2 bundle to directory (created if needed); return the model's SHA-256."""
    import joblib
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier

    from app.shadow import CONTRACT_ID, MODEL_FILE
    from sensor.zeek_features_v2 import FEATURE_ORDER

    directory.mkdir(parents=True, exist_ok=True)
    port = list(FEATURE_ORDER).index("dst_port")
    matrix = np.zeros((40, len(FEATURE_ORDER)), dtype=np.float32)
    matrix[:20, port], matrix[20:, port] = 443, 80
    model = HistGradientBoostingClassifier(max_iter=10, random_state=0).fit(matrix, [0] * 20 + [3] * 20)
    joblib.dump(model, directory / MODEL_FILE)
    (directory / "feature_order.json").write_text(json.dumps(list(FEATURE_ORDER)))
    (directory / "label_map.json").write_text(json.dumps(dict(enumerate(LABELS))))
    (directory / "feature_contract.json").write_text(json.dumps(
        {"feature_contract": CONTRACT_ID, "feature_order": list(FEATURE_ORDER)}))
    return hashlib.sha256((directory / MODEL_FILE).read_bytes()).hexdigest()


def smoke() -> None:
    """Classify converter output for the fixture with a smoke bundle, through the app's own validation and model."""
    from app.config import ROOT_DIR
    from app.flow_rows import load_feature_order, unlabeled_rows
    from app.schemas import FlowRecord
    from app.shadow import CONTRACT_ID, ShadowClassifier
    from sensor.zeek_to_cicids import FeatureV2Stream, conn_record_to_flow

    with tempfile.TemporaryDirectory() as temp:
        bundle = Path(temp) / "smoke-v2"
        model = ShadowClassifier(bundle, write_bundle(bundle))
        model.load()
        conn = json.loads((FIXTURES / "smoke_conn.json").read_text())
        stream, flows = FeatureV2Stream(), []
        # Warm the 60 s window, then one HTTPS and one HTTP connection.
        for offset, port in ((0, 443), (61, 443), (62, 80)):
            record = {**conn, "uid": f"Csmoke{offset}", "ts": conn["ts"] + offset, "id.resp_p": port,
                      "id.orig_h": "10.0.0.15", "id.resp_h": "10.0.0.25", "conn_state": "SF"}
            v2 = stream.process("smoke", offset + 1, record)
            flow = {**conn_record_to_flow(record), "features_v2": v2["features"],
                    "window_warm": v2["window_warm"], "window_degraded": v2["window_degraded"]}
            flows.append(FlowRecord.model_validate(flow).model_dump())
        rows = unlabeled_rows(flows, load_feature_order(ROOT_DIR / "feature_order.json"))
        predictions = model.classify(CONTRACT_ID, flows)
    got = [p.validation_reason or p.predicted_label for p in predictions]
    expected = ["window_not_warm", "BENIGN", "DOS_DDOS"]
    if got != expected or len(rows) != 3 or len({row.payload_hash for row in rows}) != 3:
        raise SystemExit(f"Smoke test failed: {got}, expected {expected}.")
    print(f"Smoke test passed: {expected}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write-bundle", type=Path, help="Only write a smoke bundle here and print its SHA-256.")
    args = parser.parse_args()
    if args.write_bundle:
        print(write_bundle(args.write_bundle))
    else:
        smoke()
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    raise SystemExit(main())
