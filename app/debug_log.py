from __future__ import annotations

import json
import os
from pathlib import Path
from time import time
from uuid import uuid4


LOG_PATH = Path("debug-812840.log")
SESSION_ID = "812840"


def agent_log(location: str, message: str, data: dict | None = None, *, hypothesis_id: str, run_id: str = "initial") -> None:
    payload = {
        "sessionId": SESSION_ID,
        "id": f"log_{int(time() * 1000)}_{uuid4().hex[:8]}",
        "timestamp": int(time() * 1000),
        "location": location,
        "message": message,
        "data": data or {},
        "runId": os.getenv("DEBUG_RUN_ID", run_id),
        "hypothesisId": hypothesis_id,
    }
    try:
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, separators=(",", ":")) + "\n")
    except Exception:
        pass
