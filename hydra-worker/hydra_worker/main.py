from __future__ import annotations

import asyncio
import json
import logging
import platform
import tempfile
import uuid
from pathlib import Path

import click

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("hydra-worker")


class WorkerAgent:
    def __init__(self, server_url: str, worker_id: str):
        self.server_url = server_url
        self.worker_id = worker_id
        self.ws = None
        self._running = False
        self._hashcat_bin = self._find_hashcat()

    def _find_hashcat(self) -> str | None:
        for p in ["/usr/bin/hashcat", "/usr/local/bin/hashcat", "hashcat"]:
            path = Path(p)
            if path.exists() or (p == "hashcat" and self._which("hashcat")):
                return p
        return None

    def _which(self, name: str) -> bool:
        try:
            import shutil
            return shutil.which(name) is not None
        except Exception:
            return False

    async def run(self) -> None:
        self._running = True
        try:
            import websockets
            async for ws in websockets.connect(self.server_url):
                self.ws = ws
                logger.info("Connected to %s", self.server_url)
                try:
                    await self._register(ws)
                    while self._running:
                        msg = await ws.recv()
                        await self._handle(ws, json.loads(msg))
                except websockets.ConnectionClosed:
                    logger.warning("Connection lost, reconnecting...")
                    await asyncio.sleep(2)
        except ImportError:
            logger.error("websockets package not installed")
        except Exception:
            logger.exception("Worker agent error")

    async def _register(self, ws) -> None:
        devices = []
        if self._hashcat_bin:
            devices.append("hashcat")
        else:
            devices.append("python")

        await ws.send(json.dumps({
            "type": "register",
            "worker_id": self.worker_id,
            "hostname": platform.node(),
            "devices": devices,
        }))
        resp = json.loads(await ws.recv())
        logger.info("Registered: %s", resp)

    async def _handle(self, ws, msg: dict) -> None:
        match msg.get("type"):
            case "registered":
                logger.info("Server confirmed registration")

            case "heartbeat_ack":
                await ws.send(json.dumps({"type": "ready"}))

            case "ready_ack":
                chunk = msg.get("chunk")
                if chunk:
                    await self._process_chunk(ws, chunk)
                else:
                    await asyncio.sleep(5)
                    await ws.send(json.dumps({"type": "ready"}))

            case "chunk_assigned":
                chunk = msg.get("chunk")
                if chunk:
                    await self._process_chunk(ws, chunk)

            case "chunk_ack":
                logger.info("Server acknowledged chunk result")
                await ws.send(json.dumps({"type": "ready"}))

    async def _process_chunk(self, ws, chunk: dict) -> None:
        chunk_id = chunk["id"]
        hashes = chunk["hashes"]
        wordlist_path = chunk.get("wordlist", "")
        rules_path = chunk.get("rules", "")
        hash_type = chunk.get("hash_type", "MD5")
        mask = chunk.get("mask", "")
        logger.info("Processing chunk %s (%d hashes)", chunk_id, len(hashes))

        cracked = {}
        speed = 0.0

        if self._hashcat_bin:
            cracked, speed = await self._run_hashcat(
                hashes, wordlist_path, rules_path, hash_type, mask
            )
        else:
            logger.warning("hashcat not found, using Python fallback")
            cracked, speed = self._run_python_fallback(hashes)

        await ws.send(json.dumps({
            "type": "chunk_result",
            "chunk_id": chunk_id,
            "cracked": cracked,
            "speed": speed,
        }))

    async def _run_hashcat(
        self,
        hashes: list[str],
        wordlist_path: str,
        rules_path: str,
        hash_type: str,
        mask: str,
    ) -> tuple[dict[str, str], float]:
        hash_mode = self._hash_type_to_mode(hash_type)
        if hash_mode is None:
            logger.warning("Unsupported hash type %s for hashcat", hash_type)
            return {}, 0.0

        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as hf:
            hash_file = Path(hf.name)
            hf.write("\n".join(hashes))

        outfile = Path(tempfile.mkstemp(suffix=".out")[1])

        cmd = [
            self._hashcat_bin,
            "-m", str(hash_mode),
            "--outfile", str(outfile),
            "--outfile-format", "1,2",
            "--potfile-disable",
            "--self-test-disable",
            "--backend-ignore-cuda",
            "--force",
            str(hash_file),
        ]

        if wordlist_path and Path(wordlist_path).exists():
            cmd.extend(["-a", "0", wordlist_path])
            if rules_path and Path(rules_path).exists():
                cmd.extend(["-r", rules_path])
        elif mask:
            cmd.extend(["-a", "3", mask])
        else:
            cmd.extend(["-a", "3", "?a?a?a?a?a?a?a?a"])

        logger.info("Running: %s", " ".join(str(c) for c in cmd))
        start = asyncio.get_event_loop().time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=3600
            )
            duration = asyncio.get_event_loop().time() - start
            stderr = stderr_bytes.decode(errors="replace") if stderr_bytes else ""
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            duration = asyncio.get_event_loop().time() - start
            stderr = ""

        cracked = {}
        if outfile.exists():
            for line in outfile.read_text().splitlines():
                parts = line.strip().split(":", 1)
                if len(parts) >= 2:
                    cracked[parts[0]] = parts[1]

        speed = 0.0
        for line in stderr.splitlines():
            m = __import__("re").search(r"Speed\.[^:]+:\s+([\d.]+)\s*([kMGTP]?)H/s", line)
            if m:
                val = float(m.group(1))
                suffix = m.group(2)
                multipliers = {"k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15}
                speed = val * multipliers.get(suffix, 1)
                break

        hash_file.unlink(missing_ok=True)
        outfile.unlink(missing_ok=True)
        logger.info("Chunk done: %d cracked, %.1f H/s in %.1fs", len(cracked), speed, duration)
        return cracked, speed

    def _run_python_fallback(self, hashes: list[str]) -> tuple[dict[str, str], float]:
        import hashlib
        import time
        cracked: dict[str, str] = {}
        candidates = ["password", "123456", "admin", "letmein", "welcome",
                        "monkey", "dragon", "master", "qwerty", "login"]
        hash_set = set(hashes)
        start = time.time()
        for candidate in candidates:
            h = hashlib.md5(candidate.encode()).hexdigest()
            if h in hash_set:
                cracked[h] = candidate
        duration = time.time() - start
        return cracked, len(candidates) / max(duration, 0.001)

    @staticmethod
    def _hash_type_to_mode(hash_type: str) -> int | None:
        mapping = {
            "MD5": 0, "SHA1": 100, "SHA256": 1400, "SHA512": 1700,
            "BCRYPT": 3200, "SCRYPT": 8900, "NTLM": 1000, "LM": 3000, "MD4": 900,
        }
        return mapping.get(hash_type.upper())


@click.command()
@click.option("--server", default="ws://localhost:8080/ws", help="HYDRA server WebSocket URL")
@click.option("--worker-id", default="", help="Unique worker ID (auto-generated if empty)")
def main(server: str, worker_id: str) -> None:
    wid = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
    logger.info("Starting worker %s -> %s", wid, server)
    agent = WorkerAgent(server, wid)
    asyncio.run(agent.run())


if __name__ == "__main__":
    main()
