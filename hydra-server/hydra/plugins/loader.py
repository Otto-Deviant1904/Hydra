from __future__ import annotations

import importlib.util
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class Plugin(ABC):
    name: str = "unnamed"
    version: str = "0.1.0"

    @abstractmethod
    def on_startup(self, app: Any) -> None: ...

    @abstractmethod
    def on_shutdown(self, app: Any) -> None: ...

    def on_phase_start(self, phase_name: str, config: dict[str, Any]) -> dict[str, Any]:
        return config

    def on_result(self, result: dict[str, Any]) -> dict[str, Any]:
        return result


class PluginLoader:
    def __init__(self, plugin_dir: str | Path = "/plugins"):
        self.plugin_dir = Path(plugin_dir)
        self._plugins: dict[str, Plugin] = {}

    def discover(self) -> list[Plugin]:
        if not self.plugin_dir.exists():
            logger.info("Plugin directory %s not found", self.plugin_dir)
            return []

        plugins: list[Plugin] = []
        for pyfile in self.plugin_dir.glob("*.py"):
            try:
                spec = importlib.util.spec_from_file_location(pyfile.stem, pyfile)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    for attr in dir(mod):
                        obj = getattr(mod, attr)
                        if isinstance(obj, type) and issubclass(obj, Plugin) and obj is not Plugin:
                            instance = obj()
                            self._plugins[instance.name] = instance
                            plugins.append(instance)
                            logger.info("Loaded plugin: %s v%s", instance.name, instance.version)
            except Exception:
                logger.exception("Failed to load plugin %s", pyfile)
        return plugins

    def get(self, name: str) -> Plugin | None:
        return self._plugins.get(name)

    def get_all(self) -> list[Plugin]:
        return list(self._plugins.values())
