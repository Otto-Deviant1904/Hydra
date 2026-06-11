from __future__ import annotations

import asyncio
import re
import tempfile
from pathlib import Path

from hydra.engines.base import Engine, EngineCapabilities, EngineResult
from hydra.models.base import AttackMode, HashType


class JtrEngine(Engine):
    name = "john"

    def _default_binary(self) -> str:
        return "john"

    async def detect(self) -> EngineCapabilities:
        proc = await asyncio.create_subprocess_exec(
            self.binary, "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        version = stdout.decode().strip() or "unknown"

        proc2 = await asyncio.create_subprocess_exec(
            self.binary, "--list=formats",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout2, stderr2 = await proc2.communicate()
        out = stdout2.decode() + stderr2.decode()

        return EngineCapabilities(
            name="john",
            version=version,
            supported_hash_modes=list(range(400)),
            supported_attack_modes=[AttackMode.STRAIGHT, AttackMode.MASK],
            max_wordlist_size=2**63,
            supports_rules=True,
            supports_mask=True,
            supports_opencl="OpenCL" in out,
            supports_cuda="CUDA" in out,
            supports_distribution=False,
            max_devices=1,
        )

    async def identify_hashes(self, hashes: list[str]) -> list[tuple[str, HashType]]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
            f.write("\n".join(hashes))
            tmp = f.name

        proc = await asyncio.create_subprocess_exec(
            self.binary, tmp,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        err = stderr.decode()

        Path(tmp).unlink(missing_ok=True)

        results: list[tuple[str, HashType]] = []
        hash_type_map: dict[str, HashType] = {
            "MD5": HashType.MD5, "SHA1": HashType.SHA1, "SHA256": HashType.SHA256,
            "SHA512": HashType.SHA512, "bcrypt": HashType.BCRYPT, "scrypt": HashType.SCRYPT,
            "NTLM": HashType.NTLM, "LM": HashType.LM, "MD4": HashType.MD4,
            "Raw-MD5": HashType.RAW_MD5, "Raw-SHA1": HashType.RAW_SHA1,
            "Raw-SHA256": HashType.RAW_SHA256, "Raw-SHA512": HashType.RAW_SHA512,
        }
        for h in hashes:
            htype = HashType.UNKNOWN
            for line in err.splitlines():
                if h[:16] in line and "unknown" not in line.lower():
                    for jtr_name, ht in hash_type_map.items():
                        if jtr_name.lower() in line.lower():
                            htype = ht
                            break
                    break
            results.append((h, htype))
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
        session_path = Path(session_dir) if session_dir else Path(tempfile.mkdtemp())
        session_path.mkdir(parents=True, exist_ok=True)
        pot = session_path / "john.pot"
        hash_file = session_path / "hashes.txt"
        hash_file.write_text("\n".join(hashes))

        cmd = [
            str(self.binary),
            f"--pot={pot}",
            f"--session={session_path / 'john'}",
            "--verbosity=6",
            str(hash_file),
        ]

        if wordlist:
            cmd.extend([f"--wordlist={wordlist}"])
            if rules:
                cmd.append(f"--rules={rules}")
        elif mask:
            cmd.extend([f"--mask={mask}", "--incremental=off"])
        else:
            cmd.extend(["--incremental"])

        if devices:
            cmd.extend([f"--devices={','.join(str(d) for d in devices)}"])

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
        if pot.exists():
            for line in pot.read_text().splitlines():
                if ":" in line:
                    parts = line.split(":", 1)
                    cracked[parts[0]] = parts[1]

        return EngineResult(
            cracked=cracked,
            speed=self._parse_speed(stderr),
            progress=self._parse_progress(stderr),
            duration=duration,
            command=cmd,
            exit_code=proc.returncode if proc.returncode is not None else 0,
            stdout=stdout,
            stderr=stderr,
        )

    def _parse_speed(self, stderr: str) -> float:
        for line in stderr.splitlines():
            m = re.search(r"(\d+\.?\d*)\s*([kKMGTP]?)\s*p/s", line)
            if m:
                val = float(m.group(1))
                suffix = m.group(2).upper()
                multipliers = {"K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15}
                return val * multipliers.get(suffix, 1)
        return 0.0

    def _parse_progress(self, stderr: str) -> float:
        for line in stderr.splitlines():
            m = re.search(r"(\d+)g\s+(\d+)s", line)
            if m:
                g = int(m.group(1))
                s = int(m.group(2))
                total = g + s
                return g / total if total > 0 else 0.0
        return 0.0
