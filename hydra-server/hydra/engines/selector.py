from __future__ import annotations

from hydra.engines.base import Engine
from hydra.engines.hashcat import HashcatEngine
from hydra.engines.jtr import JtrEngine
from hydra.models.base import HashType


async def select_engine(hash_type: HashType) -> list[Engine]:
    engines: list[Engine] = []
    for engine_cls in [HashcatEngine, JtrEngine]:
        candidate = engine_cls()
        try:
            caps = await candidate.detect()
            modes = caps.supported_hash_modes
            if hash_type.hashcat_mode() in modes or hash_type == HashType.UNKNOWN:
                engines.append(candidate)
        except (FileNotFoundError, OSError):
            continue
    return engines


def format_engine_table(engines: list[Engine]) -> str:
    lines = ["Available engines:"]
    for e in engines:
        lines.append(f"  {e.__class__.__name__}: binary={e.binary!r}")
    return "\n".join(lines)
