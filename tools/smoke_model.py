"""Load the shipped artifacts and exercise the production converter and classifier."""
import json
from pathlib import Path

from app.config import settings
from app.inference import FlowClassifier
from app.schemas import FlowRecord
from sensor.zeek_to_cicids import conn_record_to_flow


def make_classifier() -> FlowClassifier:
    return FlowClassifier(
        model_path=settings.model_path, scaler_path=settings.scaler_path,
        feature_order_path=settings.feature_order_path, label_map_path=settings.label_map_path,
        label_encoder_path=settings.label_encoder_path,
    )


def main() -> None:
    classifier = make_classifier()
    artifacts = classifier.load()
    conn = json.loads((Path(__file__).parent / "fixtures" / "smoke_conn.json").read_text())
    flow = FlowRecord.model_validate(conn_record_to_flow(conn)).model_dump()
    shifted = FlowRecord.model_validate(conn_record_to_flow({**conn, "ts": conn["ts"] + 86400})).model_dump()
    first = classifier.classify_batch([flow, shifted])
    second = classifier.classify_batch([flow])
    if len(first) != 2 or any(
        row.predicted_label != second[0].predicted_label or abs(row.confidence - second[0].confidence) > 1e-5
        for row in first
    ):
        raise RuntimeError("Model smoke test produced inconsistent predictions.")
    if first[0].observed_at == first[1].observed_at:
        raise RuntimeError("Model preprocessing lost the real observation time.")
    icmpv6_conn = json.loads((Path(__file__).parent / "fixtures" / "smoke_icmpv6_conn.json").read_text())
    icmpv6_flow = FlowRecord.model_validate(conn_record_to_flow(icmpv6_conn)).model_dump()
    if icmpv6_flow["features"]["protocol"] != 58.0:
        raise RuntimeError("Converter did not preserve the ICMPv6 IP protocol.")
    icmpv6_predictions = classifier.classify_batch([icmpv6_flow])
    if len(icmpv6_predictions) != 1:
        raise RuntimeError("Model did not return an ICMPv6 prediction.")
    print(json.dumps({"status": "ok", "features": len(artifacts.feature_order),
                      "classes": artifacts.labels, "prediction": second[0].predicted_label,
                      "confidence": second[0].confidence,
                      "timestamp_preprocessing": "constant zero; observation time preserved",
                      "icmpv6_protocol": icmpv6_flow["features"]["protocol"],
                      "icmpv6_prediction": icmpv6_predictions[0].predicted_label,
                      "note": "Runtime validation only; this fixture has no ground-truth label."}))


if __name__ == "__main__":
    main()
