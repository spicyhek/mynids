"""Bound ingestion bodies before JSON parsing, including chunked requests."""
from starlette.responses import JSONResponse


class IngestBodyLimit:
    def __init__(self, app, max_bytes: int = 8 * 1024 * 1024):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != "/api/internal/flows":
            return await self.app(scope, receive, send)
        chunks = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            size += len(body)
            if size > self.max_bytes:
                response = JSONResponse({"detail": "Ingestion body exceeds 8 MiB."}, status_code=413)
                return await response(scope, receive, send)
            chunks.append(body)
            if not message.get("more_body", False):
                break
        buffered = b"".join(chunks)
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": buffered, "more_body": False}
            return await receive()

        return await self.app(scope, replay, send)
