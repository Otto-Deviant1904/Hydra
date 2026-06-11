from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class RuleClassifier:
    """ADaMs-style rule classifier.

    Predicts which hashcat rules are worth applying for a given word.
    Supports ONNX model inference when a trained model is available,
    and falls back to heuristic scoring when no model is loaded.
    """

    def __init__(self, model_path: str | Path | None = None):
        self.model_path = Path(model_path) if model_path else None
        self._session: Any = None
        self._rules: list[str] = []
        self._loaded = False
        self._load_model()

    def _load_model(self) -> None:
        if self.model_path and self.model_path.exists():
            try:
                import onnxruntime
                self._session = onnxruntime.InferenceSession(
                    str(self.model_path),
                )
                self._loaded = True
                logger.info("Loaded ONNX model from %s", self.model_path)
            except ImportError:
                logger.warning(
                    "onnxruntime not installed, using heuristic fallback",
                )
            except Exception:
                logger.exception("Failed to load ONNX model")

    def predict(self, word: str, top_k: int = 10) -> list[str]:
        if self._loaded and self._session:
            return self._predict_onnx(word, top_k)
        return self._predict_heuristic(word, top_k)

    def _predict_onnx(self, word: str, top_k: int) -> list[str]:
        try:
            assert self._session is not None
            input_name = self._session.get_inputs()[0].name
            import numpy as np
            input_data = np.array(
                [[ord(c) for c in word.ljust(32, "\x00")[:32]]],
                dtype=np.int64,
            )
            outputs = self._session.run(None, {input_name: input_data})
            scores = outputs[0][0]
            top_indices = scores.argsort()[-top_k:][::-1]
            return [self._rules[i] if i < len(self._rules) else f"rule_{i}" for i in top_indices]
        except Exception:
            logger.exception("ONNX inference failed")
            return self._predict_heuristic(word, top_k)

    def _predict_heuristic(self, word: str, top_k: int) -> list[str]:
        rules = []
        if word and word[-1].isalpha():
            rules.append("$$")
        if word and word[-1].isdigit():
            rules.append("$!")
        if len(word) > 3:
            rules.append("l")
            rules.append("u")
        if any(c.isupper() for c in word):
            rules.append("l")
        if any(c.isdigit() for c in word):
            rules.append("$1")
            rules.append("$2")
            rules.append("$3")
        if len(word) > 6:
            rules.append("d")
        return rules[:top_k]

    def set_rules(self, rules: list[str]) -> None:
        self._rules = rules
