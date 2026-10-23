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
    first = classifier.classify_batch([flow, flow])
    second = classifier.classify_batch([flow])
    if len(first) != 2 or any(
        row.predicted_label != second[0].predicted_label or abs(row.confidence - second[0].confidence) > 1e-5
        for row in first
    ):
        raise RuntimeError("Model smoke test produced inconsistent predictions.")
    print(json.dumps({"status": "ok", "features": len(artifacts.feature_order),
                      "classes": artifacts.labels, "prediction": second[0].predicted_label,
                      "confidence": second[0].confidence,
                      "note": "Runtime validation only; this fixture has no ground-truth label."}))


if __name__ == "__main__":
    main()
