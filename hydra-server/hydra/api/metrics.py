from __future__ import annotations

import time
from typing import Any, cast

from fastapi import FastAPI, Request
from fastapi.responses import Response


class MetricsMiddleware:
    """Minimal Prometheus-compatible metrics collection."""

    def __init__(self) -> None:
        self._request_count = 0
        self._crack_count = 0
        self._total_duration = 0.0

    async def __call__(self, request: Request, call_next: Any) -> Response:
        self._request_count += 1
        start = time.monotonic()
        response = cast(Response, await call_next(request))
        duration = time.monotonic() - start
        self._total_duration += duration
        if request.url.path == "/crack" and request.method == "POST":
            pass
        return response

    def record_crack(self, cracked: int) -> None:
        self._crack_count += cracked

    def metrics_text(self) -> str:
        return (
            "# HELP hydra_requests_total Total HTTP requests\n"
            f"# TYPE hydra_requests_total counter\n"
            f"hydra_requests_total {self._request_count}\n"
            "\n"
            "# HELP hydra_cracked_total Passwords cracked\n"
            f"# TYPE hydra_cracked_total counter\n"
            f"hydra_cracked_total {self._crack_count}\n"
            "\n"
            "# HELP hydra_request_duration_seconds Request duration\n"
            f"# TYPE hydra_request_duration_seconds gauge\n"
            f"hydra_request_duration_seconds {self._total_duration:.3f}\n"
        )


def setup_metrics(app: FastAPI) -> MetricsMiddleware:
    middleware = MetricsMiddleware()
    app.state.metrics = middleware

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(
            content=middleware.metrics_text(),
            media_type="text/plain",
        )

    return middleware
