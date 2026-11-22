"""Group web-probe events (sensor/web_probes.py) into scans: one client's burst of suspicious HTTP requests.

The flow model sees scanners badly. Behind the reverse proxy every visitor arrives from the proxy's address, and a
scanner that packs its requests into one keep-alive connection looks like an ordinary connection: on 2026-11-21 one
scanner's 163 secret-file requests over 9 connections raised a single BRUTE_FORCE alert, and another's 162 over one
connection raised none. The requests themselves are unmistakable, so the app groups them per client instead.

A scan is a run of a client's events with no gap longer than `gap_seconds`, holding at least `min_requests` events
for at least `min_distinct_uris` different URIs. Events are probe-path requests (any answer) and other 4xx answers,
so a scanner guessing paths the probe list does not know still counts. The distinct-URI floor keeps out a client
retrying one missing URL (the operator polling a /healthz the site does not serve sent 36 in 43 s).

Calibrated on 121 h of live http.log (data/evaluation/analyses/live-alert-20261121/calibrate_scans.py): 28 groups
reach 10 requests; all but that /healthz poller are scanners, so the defaults give 27 scans. Below 10 they are still
mostly scanners, but small (wp-login and backup-dir guesses); they stay counted as probes, not scans.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Iterable

from sensor.web_probes import PROBE

DEFAULT_GAP_SECONDS = 60
DEFAULT_MIN_REQUESTS = 10
DEFAULT_MIN_DISTINCT_URIS = 5
SAMPLE_LIMIT = 10


def _succeeded(event: dict[str, Any]) -> bool:
    """A 2xx answer to a request whose path, not just its query, is a probe path.

    "/?phpinfo=1" answered 200 is the home page ignoring its query string (seen 2026-11-09); "/.env" answered 200
    would be a real file handed to the scanner.
    """
    status = event.get("status_code")
    path = str(event.get("uri") or "").partition("?")[0]
    return isinstance(status, int) and 200 <= status <= 299 and bool(PROBE.search(path))


def _summarize(client: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    started, ended = events[0]["observed_at"], events[-1]["observed_at"]
    statuses = [event.get("status_code") for event in events]
    probes = [event for event in events if str(event.get("rule", "")).startswith("probe-path")]
    # A probe path answered 2xx may have handed the scanner a real file: the one result worth waking up for.
    succeeded = [event["uri"] for event in probes if _succeeded(event)]
    return {
        "client": client,
        "started_at": started,
        "ended_at": ended,
        "duration_seconds": round((ended - started).total_seconds(), 3),
        "requests": len(events),
        "distinct_uris": len({event.get("uri") for event in events}),
        "probe_paths": len(probes),
        "not_found": sum(status == 404 for status in statuses),
        "client_errors": sum(isinstance(status, int) and 400 <= status <= 499 for status in statuses),
        "succeeded": len(succeeded),
        # event_id is "<zeek uid>:<trans_depth>": distinct uids are distinct connections.
        "connections": len({str(event.get("event_id", "")).rpartition(":")[0] for event in events}),
        "hosts": sorted({str(event.get("host") or "") for event in events}),
        "user_agents": [agent for agent, _ in Counter(str(event.get("user_agent") or "")
                                                      for event in events).most_common(3)],
        "sample_uris": [event["uri"] for event in events[:SAMPLE_LIMIT]],
        "succeeded_uris": succeeded[:SAMPLE_LIMIT],
    }


def group_scans(events: Iterable[dict[str, Any]], *, gap_seconds: float = DEFAULT_GAP_SECONDS,
                min_requests: int = DEFAULT_MIN_REQUESTS,
                min_distinct_uris: int = DEFAULT_MIN_DISTINCT_URIS) -> list[dict[str, Any]]:
    """Scans in `events` (dicts with client, observed_at as an aware datetime, uri, status_code, rule, event_id,
    host, user_agent), newest first."""
    if gap_seconds <= 0 or min_requests < 1 or min_distinct_uris < 1:
        raise ValueError("gap_seconds must be positive and min_requests, min_distinct_uris at least 1.")

    def close(client: str, run: list[dict[str, Any]]) -> None:
        if len(run) >= min_requests and len({event.get("uri") for event in run}) >= min_distinct_uris:
            scans.append(_summarize(client, run))

    scans: list[dict[str, Any]] = []
    by_client: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        by_client.setdefault(str(event.get("client") or ""), []).append(event)
    for client, client_events in by_client.items():
        client_events.sort(key=lambda event: event["observed_at"])
        run: list[dict[str, Any]] = []
        previous: datetime | None = None
        for event in client_events:
            if previous is not None and (event["observed_at"] - previous).total_seconds() > gap_seconds:
                close(client, run)
                run = []
            run.append(event)
            previous = event["observed_at"]
        close(client, run)
    scans.sort(key=lambda scan: (scan["started_at"], scan["client"]), reverse=True)
    return scans
