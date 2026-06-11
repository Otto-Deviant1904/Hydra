from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from hydra.models.base import AttackMode, HashType


@dataclass
class EngineResult:
    cracked: dict[str, str]
    speed: float
    progress: float
    duration: float
    command: list[str]
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    finished_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class EngineCapabilities:
    name: str
    version: str
    supported_hash_modes: list[int]
    supported_attack_modes: list[AttackMode]
    max_wordlist_size: int
    supports_rules: bool
    supports_mask: bool
    supports_opencl: bool
    supports_cuda: bool
    supports_distribution: bool
    max_devices: int


class Engine(ABC):
    name: str = "base"

    def __init__(self, binary: str | Path | None = None):
        self.binary = binary or self._default_binary()
        self._hash_mode_cache: dict[HashType, int] = {}

    @abstractmethod
    def _default_binary(self) -> str: ...

    @abstractmethod
    async def detect(self) -> EngineCapabilities: ...

    @abstractmethod
    async def identify_hashes(self, hashes: list[str]) -> list[tuple[str, HashType]]: ...

    @abstractmethod
    async def run(
        self,
        hash_type: HashType,
        hashes: list[str],
        wordlist: str | Path | None = None,
        rules: str | Path | None = None,
        mask: str | None = None,
        attack_mode: AttackMode = AttackMode.STRAIGHT,
        session_dir: str | Path | None = None,
        devices: list[int] | None = None,
        timeout: int = 3600,
    ) -> EngineResult: ...
