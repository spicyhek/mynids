"""Release identity on /healthz for mybuilds' public check.

/healthz answers with the deployed release's ID in X-Release-ID, read from the RELEASE_ID environment
variable that the release workflow sets in homelab-infra, and with Cache-Control: no-store so Cloudflare
never serves a stale header. It is a middleware rather than code in the handler because /readyz calls
healthz() directly, and only the /healthz response should carry them.
"""
from __future__ import annotations

from collections.abc import Callable

from starlette.datastructures import MutableHeaders

HEALTH_PATH = "/healthz"


class ReleaseHeaders:
    def __init__(self, app, release_id: Callable[[], str]):
        self.app = app
        # Read per request, so tests that replace the settings see the new value.
        self.release_id = release_id

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != HEALTH_PATH:
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Cache-Control"] = "no-store"
                release_id = self.release_id()
                if release_id:
                    headers["X-Release-ID"] = release_id
            await send(message)

        return await self.app(scope, receive, send_with_headers)
