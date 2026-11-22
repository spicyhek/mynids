"""The app's semantic version, read from app/VERSION.

The version names what the app does for its callers: the sensor posting to /api/internal/*, the dashboard and
anyone reading /api/public/summary or /healthz. Bump MAJOR when a caller that worked before would now fail (the
strict ingest contract of 1.0.0 rejected older sensors), MINOR for a new feature or a changed default that keeps
callers working, PATCH for a fix. Changes to CI, docs or training tools alone need no bump.

The file sits in app/ so the image gets it through `COPY app ./app`, and it is outside the release workflow's
CONVERTER_PATHS, so a version bump does not restart the Zeek converter. A malformed file stops the app at import,
which fails the release's smoke test before anything is published.
"""
from __future__ import annotations

import re
from pathlib import Path

VERSION_FILE = Path(__file__).resolve().parent / "VERSION"
# MAJOR.MINOR.PATCH without leading zeros, with an optional pre-release (1.10.0-rc.1) or build (+sha.0123456).
SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?")


def read_version(path: Path = VERSION_FILE) -> str:
    version = path.read_text(encoding="utf-8").strip()
    if not SEMVER.fullmatch(version):
        raise ValueError(f"{path} must hold a semantic version such as 1.9.0, not {version!r}.")
    return version


__version__ = read_version()
