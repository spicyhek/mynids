"""SSH login results from Zeek ssh.log, attached to conn.log flows by the same converter process.

The flow model sees connection sizes and counts, not whether a login worked, so a burst of the operator's own
logins looks like password guessing to it: live, a handful of key-authenticated sessions to the control plane
within a minute raised BRUTE_FORCE, and those that ended in a reset raised DOS_DDOS. Zeek's SSH analyzer infers
the result from the encrypted exchange and sets `auth_success`. It was true for 139 of the 140 live sessions from
2026-11-12 to 11-25 (all the operator's) and for none of the ~96,000 guessing sessions in the training data
(the homelab hydra drills and the CIC-IDS2017/2018 patator runs: false or undetermined).

The converter reads new ssh.log lines into a bounded in-memory index before each conn.log pass, and flows whose
uid had a successful login carry `ssh_auth_success: true`; the app decides what to do with it
(app/alert_rules.py). Zeek writes the ssh.log line when the login result is known, before the connection ends
and its conn.log line is written. A line that is not on disk yet only means no flag, so the flow is judged as
before; the failure is never silent suppression.
"""
from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import Any

FIELD = "ssh_auth_success"
MAX_ENTRIES = 50_000  # Far above the ~10 SSH sessions a day seen live; old uids fall out first.


class SshAuthIndex:
    """Zeek uids whose SSH login succeeded, newest last, capped at max_entries."""

    def __init__(self, max_entries: int = MAX_ENTRIES) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive.")
        self.max_entries = max_entries
        self._uids: OrderedDict[str, None] = OrderedDict()

    def __contains__(self, uid: object) -> bool:
        return uid in self._uids

    def __len__(self) -> int:
        return len(self._uids)

    def add(self, uid: str) -> None:
        self._uids[uid] = None
        self._uids.move_to_end(uid)
        while len(self._uids) > self.max_entries:
            self._uids.popitem(last=False)

    def deliver(self, endpoint: str, token: str, source: str, events: list[str], state_file: Path) -> int:
        """deliver()-shaped sink for export_log_once: index the batch instead of posting it."""
        for uid in events:
            self.add(uid)
        return len(events)

    def annotate(self, record: dict[str, Any], flow: dict[str, Any]) -> None:
        """Mark a conn.log flow whose SSH login succeeded."""
        if record.get("uid") in self._uids:
            flow[FIELD] = True


def successful_login_uid(record: dict[str, Any]) -> str | None:
    """The uid of an ssh.log record whose login Zeek saw succeed, else None."""
    uid = record.get("uid")
    if record.get("auth_success") is True and isinstance(uid, str) and uid and len(uid) <= 160:
        return uid
    return None
