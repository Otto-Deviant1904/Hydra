from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class HydraConfig:
    data_dir: str = field(default_factory=lambda: os.getenv("HYDRA_DATA_DIR", "/data"))
    wordlist_dir: str = field(default_factory=lambda: os.getenv("HYDRA_WORDLIST_DIR", "/wordlists"))
    rules_dir: str = field(default_factory=lambda: os.getenv("HYDRA_RULES_DIR", "/rules"))
    db_url: str = field(default_factory=lambda: os.getenv("HYDRA_DB_URL", "sqlite:////data/hydra.db"))
    server_host: str = "0.0.0.0"
    server_port: int = 8080
    log_level: str = "INFO"
    chunk_size: int = 1000
    max_workers: int = 10
    plugin_dir: str = "/plugins"
    prometheus_enabled: bool = True

    @classmethod
    def load(cls, path: str | Path | None = None) -> HydraConfig:
        config = cls()
        if path and Path(path).exists():
            raw = json.loads(Path(path).read_text())
            for k, v in raw.items():
                if hasattr(config, k):
                    setattr(config, k, v)
        return config

    def ensure_dirs(self) -> None:
        for d in [self.data_dir, self.plugin_dir]:
            Path(d).mkdir(parents=True, exist_ok=True)
