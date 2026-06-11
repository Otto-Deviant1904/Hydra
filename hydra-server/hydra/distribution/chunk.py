from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class Chunk:
    id: str
    session_id: str
    phase_name: str
    hashes: list[str]
    hash_type: str
    index: int
    total_chunks: int
    assigned_worker: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    cracked: dict[str, str] = field(default_factory=dict)
    speed: float = 0.0


class ChunkManager:
    def __init__(self, chunk_size: int = 1000):
        self.chunk_size = chunk_size
        self._chunks: dict[str, Chunk] = {}

    def split(
        self, session_id: str, phase_name: str,
        hashes: list[str], hash_type: str,
    ) -> list[Chunk]:
        total = len(hashes)
        num_chunks = max(1, math.ceil(total / self.chunk_size))
        chunks: list[Chunk] = []
        for i in range(num_chunks):
            start = i * self.chunk_size
            end = min(start + self.chunk_size, total)
            chunk = Chunk(
                id=f"{session_id}/{phase_name}/{i}",
                session_id=session_id,
                phase_name=phase_name,
                hashes=hashes[start:end],
                hash_type=hash_type,
                index=i,
                total_chunks=num_chunks,
            )
            chunks.append(chunk)
            self._chunks[chunk.id] = chunk
        return chunks

    def get_pending(self) -> list[Chunk]:
        return [c for c in self._chunks.values() if c.assigned_worker is None]

    def mark_assigned(self, chunk_id: str, worker_id: str) -> bool:
        chunk = self._chunks.get(chunk_id)
        if chunk is None or chunk.assigned_worker is not None:
            return False
        chunk.assigned_worker = worker_id
        chunk.started_at = datetime.now(UTC)
        return True

    def complete_chunk(self, chunk_id: str, cracked: dict[str, str], speed: float) -> Chunk | None:
        chunk = self._chunks.get(chunk_id)
        if chunk is None:
            return None
        chunk.cracked = cracked
        chunk.speed = speed
        chunk.finished_at = datetime.now(UTC)
        return chunk

    def pending_count(self) -> int:
        return len(self.get_pending())

    def merge_results(self, chunks: list[Chunk]) -> dict[str, str]:
        merged: dict[str, str] = {}
        for c in chunks:
            merged.update(c.cracked)
        return merged
