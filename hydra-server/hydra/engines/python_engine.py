from __future__ import annotations

import asyncio
import hashlib
import re
from itertools import product
from pathlib import Path

from hydra.engines.base import Engine, EngineCapabilities, EngineResult
from hydra.models.base import AttackMode, HashType


class PythonEngine(Engine):
    """Pure-Python engine. Slow (~50K H/s for MD5) but has zero dependencies."""
    name = "python"

    HASH_PATTERNS: list[tuple[re.Pattern[str], HashType]] = [
        (re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"), HashType.BCRYPT),
        (re.compile(r"^\$scrypt\$.+"), HashType.SCRYPT),
        (re.compile(r"^[a-fA-F0-9]{32}$"), HashType.MD5),
        (re.compile(r"^[a-fA-F0-9]{40}$"), HashType.SHA1),
        (re.compile(r"^[a-fA-F0-9]{64}$"), HashType.SHA256),
        (re.compile(r"^[a-fA-F0-9]{128}$"), HashType.SHA512),
        (re.compile(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]+$"), HashType.NTLM),
    ]

    def _default_binary(self) -> str:
        return "python"

    async def detect(self) -> EngineCapabilities:
        return EngineCapabilities(
            name="python",
            version="1.0",
            supported_hash_modes=[0, 100, 1400, 1700, 3200],
            supported_attack_modes=list(AttackMode),
            max_wordlist_size=10_000_000,
            supports_rules=True,
            supports_mask=True,
            supports_opencl=False,
            supports_cuda=False,
            supports_distribution=False,
            max_devices=1,
        )

    async def identify_hashes(self, hashes: list[str]) -> list[tuple[str, HashType]]:
        results: list[tuple[str, HashType]] = []
        for h in hashes:
            identified = False
            for pattern, ht in self.HASH_PATTERNS:
                if pattern.match(h.strip()):
                    results.append((h, ht))
                    identified = True
                    break
            if not identified:
                results.append((h, HashType.UNKNOWN))
        return results

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
    ) -> EngineResult:
        start = asyncio.get_event_loop().time()
        cracked: dict[str, str] = {}
        hash_set = set(h.strip() for h in hashes)

        if wordlist:
            candidates = await self._load_wordlist(wordlist)
            if rules:
                candidates = await self._apply_rules(candidates, rules)
        elif mask:
            candidates = self._expand_mask(mask)
        else:
            candidates = []

        speed_counter = 0
        checked = 0
        for candidate in candidates:
            h = await self._compute(hash_type, candidate.encode())
            if h in hash_set:
                cracked[h] = candidate
                hash_set.discard(h)
                if len(cracked) >= len(hashes):
                    break
            checked += 1
            speed_counter += 1
            if speed_counter >= 1000:
                elapsed = asyncio.get_event_loop().time() - start
                if elapsed > timeout:
                    break
                speed_counter = 0

        duration = asyncio.get_event_loop().time() - start
        speed = checked / duration if duration > 0 else 0

        return EngineResult(
            cracked=cracked,
            speed=speed,
            progress=len(cracked) / max(len(hashes), 1),
            duration=duration,
            command=["python"],
            exit_code=0,
        )

    async def _load_wordlist(self, path: str | Path) -> list[str]:
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(None, Path(path).read_bytes)
        return data.decode(errors="replace").splitlines()

    async def _apply_rules(self, words: list[str], rules_path: str | Path) -> list[str]:
        loop = asyncio.get_running_loop()
        rules_text = await loop.run_in_executor(
            None, Path(rules_path).read_text
        )
        rules_lines = rules_text.splitlines()
        result: list[str] = []
        for word in words:
            result.append(word)
            for rule in rules_lines[:50]:
                rule = rule.strip()
                if not rule or rule.startswith("#"):
                    continue
                transformed = self._apply_rule(word, rule)
                if transformed:
                    result.append(transformed)
        return result

    def _apply_rule(self, word: str, rule: str) -> str | None:
        """Apply a simplified hashcat-style rule to a word."""
        chars: list[str] = list(word)
        i = 0
        while i < len(rule):
            c = rule[i]
            match c:
                case "l":
                    chars = [ch.lower() for ch in chars]
                case "u":
                    chars = [ch.upper() for ch in chars]
                case "d":
                    chars = chars + chars
                case "t":
                    chars = [ch.swapcase() for ch in chars]
                case "r":
                    chars = chars[::-1]
                case "c":
                    if chars:
                        chars[0] = chars[0].upper()
                case "$":
                    if i + 1 < len(rule):
                        chars.append(rule[i + 1])
                        i += 1
                case "^":
                    if i + 1 < len(rule):
                        chars.insert(0, rule[i + 1])
                        i += 1
                case "s":
                    if i + 2 < len(rule):
                        chars = [rule[i + 2] if ch == rule[i + 1] else ch for ch in chars]
                        i += 2
                case "p":
                    if chars:
                        last = chars[-1]
                        for _ in range(len(chars)):
                            chars.append(last)
                case _:
                    pass
            i += 1
        return "".join(chars)

    def _expand_mask(self, mask: str) -> list[str]:
        """Expand a hashcat-style mask into concrete candidates."""
        charsets = {
            "?a": (
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
            ),
            "?d": "0123456789",
            "?l": "abcdefghijklmnopqrstuvwxyz",
            "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "?s": "!@#$%^&*()-_=+[]{}|;:',.<>?/`~",
            "?b": "\x00-\xff",
        }
        tokens: list[list[str]] = []
        i = 0
        while i < len(mask):
            if i + 1 < len(mask) and mask[i:i+2] in charsets:
                tokens.append(list(charsets[mask[i:i+2]]))
                i += 2
            else:
                tokens.append([mask[i]])
                i += 1
        if not tokens:
            return []
        candidates: list[str] = []
        for combo in product(*tokens):
            candidates.append("".join(combo))
        # Limit total candidates to avoid memory explosion
        return candidates[:500_000]

    async def _compute(self, hash_type: HashType, data: bytes) -> str:
        match hash_type:
            case HashType.MD5:
                return hashlib.md5(data).hexdigest()
            case HashType.SHA1:
                return hashlib.sha1(data).hexdigest()
            case HashType.SHA256:
                return hashlib.sha256(data).hexdigest()
            case HashType.SHA512:
                return hashlib.sha512(data).hexdigest()
            case _:
                return hashlib.md5(data).hexdigest()
