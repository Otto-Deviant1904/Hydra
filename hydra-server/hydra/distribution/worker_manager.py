from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


@dataclass
class WorkerState:
    id: str
    hostname: str
    connected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    current_chunk: str | None = None
    chunks_completed: int = 0
    total_speed: float = 0.0
    devices: list[str] = field(default_factory=list)
    alive: bool = True


class WorkerManager:
    def __init__(self):
        self._workers: dict[str, WorkerState] = {}
        self._max_concurrent_per_worker = 1

    def register(
        self, worker_id: str, hostname: str,
        devices: list[str] | None = None,
    ) -> WorkerState:
        worker = WorkerState(
            id=worker_id,
            hostname=hostname,
            devices=devices or [],
        )
        self._workers[worker_id] = worker
        logger.info("Worker registered: %s (%s)", worker_id, hostname)
        return worker

    def unregister(self, worker_id: str) -> None:
        self._workers.pop(worker_id, None)
        logger.info("Worker unregistered: %s", worker_id)

    def heartbeat(self, worker_id: str) -> bool:
        worker = self._workers.get(worker_id)
        if worker is None:
            return False
        worker.last_seen = datetime.now(UTC)
        return True

    def get_available(self) -> list[WorkerState]:
        now = datetime.now(UTC)
        return [
            w for w in self._workers.values()
            if w.alive and (now - w.last_seen).total_seconds() < 30
            and w.current_chunk is None
        ]

    def assign_chunk(self, worker_id: str, chunk_id: str) -> bool:
        worker = self._workers.get(worker_id)
        if worker is None or worker.current_chunk is not None:
            return False
        worker.current_chunk = chunk_id
        return True

    def complete_chunk(self, worker_id: str, cracked_count: int, speed: float) -> None:
        worker = self._workers.get(worker_id)
        if worker is None:
            return
        worker.current_chunk = None
        worker.chunks_completed += 1
        worker.total_speed = speed

    def worker_count(self) -> int:
        return len(self.get_available())

    def total_workers(self) -> int:
        return len(self._workers)
