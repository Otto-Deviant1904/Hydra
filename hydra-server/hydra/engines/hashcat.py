from __future__ import annotations

import asyncio
import re
import tempfile
from pathlib import Path

from hydra.engines.base import Engine, EngineCapabilities, EngineResult
from hydra.models.base import AttackMode, HashType


class HashcatEngine(Engine):
    name = "hashcat"

    MODE_MAP: dict[HashType, int] = {
        HashType.MD5: 0,
        HashType.SHA1: 100,
        HashType.SHA256: 1400,
        HashType.SHA512: 1700,
        HashType.BCRYPT: 3200,
        HashType.SCRYPT: 8900,
        HashType.NTLM: 1000,
        HashType.LM: 3000,
        HashType.MD4: 900,
    }

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
        return "hashcat"

    async def detect(self) -> EngineCapabilities:
        proc = await asyncio.create_subprocess_exec(
            self.binary, "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        version = stdout.decode().strip() or "unknown"

        proc2 = await asyncio.create_subprocess_exec(
            self.binary, "--backend-ignore-cuda", "-I",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout2, _ = await proc2.communicate()
        devices = stdout2.decode()
        opencl = "OpenCL" in devices
        cuda = "CUDA" in devices
        max_devices = len([line for line in devices.splitlines() if "Device #" in line])

        return EngineCapabilities(
            name="hashcat",
            version=version,
            supported_hash_modes=list(self.MODE_MAP.values()),
            supported_attack_modes=list(AttackMode),
            max_wordlist_size=2**63,
            supports_rules=True,
            supports_mask=True,
            supports_opencl=opencl,
            supports_cuda=cuda,
            supports_distribution=True,
            max_devices=max_devices or 1,
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
        hash_mode = self.MODE_MAP.get(hash_type)
        if hash_mode is None:
            raise ValueError(f"Unsupported hash type: {hash_type}")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as hf:
            hash_file = Path(hf.name)
            hf.write("\n".join(hashes))

        session_path = Path(session_dir) if session_dir else Path(tempfile.mkdtemp())
        session_path.mkdir(parents=True, exist_ok=True)
        outfile = session_path / "cracked.txt"

        cmd = [
            str(self.binary),
            "-m", str(hash_mode),
            "--outfile", str(outfile),
            "--outfile-format", "1,2",
            "--status", "--status-timer", "1",
            "--potfile-disable",
            "--self-test-disable",
            "--backend-ignore-cuda",
            "--force",
            str(hash_file),
        ]

        if wordlist:
            cmd.extend(["-a", str(attack_mode.value), str(wordlist)])
        elif mask:
            cmd.extend(["-a", "3", mask])
        else:
            cmd.extend(["-a", "3", "?a?a?a?a?a?a?a?a"])

        if rules:
            cmd.extend(["-r", str(rules)])

        if devices:
            cmd.extend(["-d", ",".join(str(d) for d in devices)])

        start = asyncio.get_event_loop().time()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except TimeoutError:
            proc.kill()
            stdout_bytes, stderr_bytes = await proc.communicate()

        duration = asyncio.get_event_loop().time() - start
        stdout = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
        stderr = stderr_bytes.decode(errors="replace") if stderr_bytes else ""

        cracked: dict[str, str] = {}
        if outfile.exists():
            for line in outfile.read_text().splitlines():
                parts = line.strip().split(":", 1)
                if len(parts) >= 2:
                    hash_str, password = parts[0], parts[1]
                    cracked[hash_str] = password

        speed = self._parse_speed(stderr)
        progress = self._parse_progress(stderr, len(hashes))

        hash_file.unlink(missing_ok=True)

        return EngineResult(
            cracked=cracked,
            speed=speed,
            progress=progress,
            duration=duration,
            command=cmd,
            exit_code=proc.returncode if proc.returncode is not None else 0,
            stdout=stdout,
            stderr=stderr,
        )

    def _parse_speed(self, stderr: str) -> float:
        for line in stderr.splitlines():
            m = re.search(r"Speed\.[^:]+:\s+([\d.]+)\s*([kMGTP]?)H/s", line)
            if m:
                val = float(m.group(1))
                suffix = m.group(2)
                multipliers = {"k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15}
                return val * multipliers.get(suffix, 1)
        return 0.0

    def _parse_progress(self, stderr: str, total_hashes: int) -> float:
        for line in stderr.splitlines():
            m = re.search(r"Recovered\.+: (\d+)/(\d+)", line)
            if m:
                return int(m.group(1)) / max(int(m.group(2)), 1)
        return 0.0
