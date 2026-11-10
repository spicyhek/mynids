"""Web-probe detection from Zeek http.log, exported by the same converter process as conn.log.

A probe is an HTTP request for a path that only an attacker looking for secrets or a vulnerable application
asks for: dotfiles with credentials (.env, .git, .aws, .docker, .ssh, ...), WordPress, PHP, admin panels,
backups and database dumps. The flow model cannot see these: a reverse proxy pools scanner requests into
keep-alive connections shared with real visitors, so the connection looks ordinary. The request does not.

On 70 h of live traffic (2026-11-07 to 11-10) the pattern matched 1,023 requests from about 20 clients, all to
the personal site, 1,022 of them answered 404; it matched nothing on any other host. Events carry the client
address (the right-most forwarded address, the one the trusted proxy added), so they stay on the private API.
"""
from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import re
from typing import Any
from urllib import error, request

PROBE_RULE = "probe-path-v1"
PROBE = re.compile(
    r"(^|/)\.(env|git|aws|docker|ssh|claude|cursor|boto|npmrc|vscode|htpasswd|DS_Store|amplifyrc)"
    r"|wp-(login|admin|content|includes|json)|xmlrpc\.php|phpmyadmin|\.sql($|\?)"
    r"|config\.(env|json|php|yml)|/(cgi-bin|actuator|vendor/phpunit|server-status|HNAP1|boaform)"
    r"|\.php($|\?)|/admin|\.bak($|\?)", re.I)
_FORWARDED_FOR = re.compile(r"for=\"?\[?([0-9A-Fa-f:.]+)", re.I)


def client_address(record: dict[str, Any]) -> str:
    """The client as the nearest trusted proxy saw it, else the connection's originator.

    Zeek's `proxied` holds entries like "X-FORWARDED-FOR -> a, b". A client can send its own
    X-Forwarded-For; the proxy appends the real address, so the right-most entry is the trustworthy one.
    """
    for entry in record.get("proxied") or ():
        name, _, value = str(entry).partition(" -> ")
        name = name.strip().upper()
        if name == "X-FORWARDED-FOR" and value.strip():
            return value.split(",")[-1].strip()[:64]
        if name == "FORWARDED" and (found := _FORWARDED_FOR.findall(value)):
            return found[-1][:64]
    return str(record.get("id.orig_h") or "")[:64]


def probe_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """An event for one http.log request whose URI matches PROBE, else None."""
    uri = record.get("uri")
    if not isinstance(uri, str) or not PROBE.search(uri):
        return None
    uid, ts = record.get("uid"), record.get("ts")
    if not isinstance(uid, str) or not uid or isinstance(ts, bool) or not isinstance(ts, (int, float)):
        raise ValueError("http.log record lacks uid/ts.")
    status = record.get("status_code")
    return {
        "event_id": f"{uid}:{int(record.get('trans_depth') or 0)}"[:200],
        "event_time": datetime.fromtimestamp(float(ts), UTC).isoformat(),
        "client": client_address(record),
        "host": str(record.get("host") or "")[:255],
        "method": str(record.get("method") or "")[:16],
        "uri": uri[:512],
        "status_code": status if type(status) is int and 0 <= status <= 999 else None,
        "user_agent": str(record.get("user_agent") or "")[:256],
        "rule": PROBE_RULE,
    }


def web_probe_endpoint(flow_endpoint: str) -> str:
    """The probe endpoint beside the flow endpoint (…/api/internal/flows -> …/api/internal/web-probes)."""
    base, separator, _ = flow_endpoint.rstrip("/").rpartition("/")
    if not separator:
        raise ValueError("Cannot derive the web-probe endpoint; set it explicitly.")
    return f"{base}/web-probes"


def send_probes(endpoint: str, token: str, source: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    body = json.dumps({"source": source, "events": events}, allow_nan=False).encode("utf-8")
    req = request.Request(endpoint, data=body, method="POST",
                          headers={"Content-Type": "application/json", "X-Ingest-Token": token})
    with request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def deliver_probes(endpoint: str, token: str, source: str, events: list[dict], state_file: Path) -> int:
    """deliver()-shaped: send a batch, verify the acknowledgment, split and quarantine on 409/413/422."""
    from sensor.zeek_to_cicids import quarantine  # Avoids a circular import.

    try:
        response = send_probes(endpoint, token, source, events)
    except error.HTTPError as exc:
        if exc.code not in (409, 413, 422):
            raise
        if len(events) > 1:
            middle = len(events) // 2
            return (deliver_probes(endpoint, token, source, events[:middle], state_file)
                    + deliver_probes(endpoint, token, source, events[middle:], state_file))
        quarantine(state_file, f"Web-probe ingest rejected event with HTTP {exc.code}", events[0])
        return 0
    if (not isinstance(response, dict) or response.get("source") != source
            or response.get("event_ids") != [event["event_id"] for event in events]
            or type(response.get("inserted")) is not int or type(response.get("duplicates")) is not int
            or response["inserted"] + response["duplicates"] != len(events)):
        raise ValueError("Web-probe acknowledgment does not account for the complete batch")
    return len(events)
