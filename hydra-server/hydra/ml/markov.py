from __future__ import annotations

import random
from collections import defaultdict
from pathlib import Path


class MarkovGenerator:
    """Character-level Markov chain password generator.

    Builds a transition matrix from training passwords and generates
    new candidates by walking the chain.
    """

    def __init__(self, order: int = 3, min_length: int = 4, max_length: int = 32):
        self.order = order
        self.min_length = min_length
        self.max_length = max_length
        self._start: dict[str, int] = defaultdict(int)
        self._transitions: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._trained = False

    def train(self, passwords: list[str]) -> None:
        for pw in passwords:
            pw = pw.strip()
            if len(pw) < self.order + 1:
                continue

            prefix = pw[:self.order]
            self._start[prefix] += 1

            for i in range(len(pw) - self.order):
                state = pw[i:i + self.order]
                next_char = pw[i + self.order]
                self._transitions[state][next_char] += 1

            for i in range(self.order):
                state = pw[-(self.order - i):] if i > 0 else pw[-self.order:]
                if state:
                    self._transitions[state][""] += 1

        self._trained = True

    def train_from_file(self, path: str | Path) -> None:
        passwords = Path(path).read_text().splitlines()
        self.train(passwords)

    def generate(self, count: int = 100) -> list[str]:
        if not self._trained:
            return []

        passwords: set[str] = set()
        attempts = 0
        max_attempts = count * 10

        while len(passwords) < count and attempts < max_attempts:
            attempts += 1
            pw = self._walk()
            if pw and len(pw) >= self.min_length:
                passwords.add(pw)

        return list(passwords)[:count]

    def _walk(self) -> str:
        if not self._start:
            return ""

        start_states = list(self._start.keys())
        weights = [self._start[s] for s in start_states]
        state = random.choices(start_states, weights=weights, k=1)[0]
        pw = state

        for _ in range(self.max_length - self.order):
            if state not in self._transitions:
                break

            next_chars = self._transitions[state]
            char_list = list(next_chars.keys())
            char_weights = [next_chars[c] for c in char_list]
            next_char = random.choices(char_list, weights=char_weights, k=1)[0]

            if next_char == "":
                break

            pw += next_char
            state = (state + next_char)[-self.order:]

        return pw
