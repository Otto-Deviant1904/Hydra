from __future__ import annotations

import asyncio
from pathlib import Path

import click

from hydra.engines.hashcat import HashcatEngine
from hydra.engines.jtr import JtrEngine
from hydra.engines.selector import format_engine_table, select_engine
from hydra.models.base import HashType


@click.group()
def cli() -> None:
    """HYDRA — next-generation password security research framework."""


@cli.command()
def detect() -> None:
    """Detect available cracking engines."""
    async def _detect() -> None:
        engines = await select_engine(HashType.UNKNOWN)
        click.echo(format_engine_table(engines))
    asyncio.run(_detect())


@cli.command()
@click.option("--hash", "-h", "hash_str", required=True, help="Hash to crack")
@click.option("--wordlist", "-w", type=click.Path(exists=True), help="Wordlist path")
@click.option("--rules", "-r", type=click.Path(exists=True), help="Rules file")
@click.option("--engine", "-e", default="hashcat", help="Engine to use (hashcat/john)")
def crack(hash_str: str, wordlist: str | None, rules: str | None, engine: str) -> None:
    """Crack a single hash."""
    async def _crack() -> None:
        engine_map = {"hashcat": HashcatEngine, "john": JtrEngine}
        eng = engine_map.get(engine, HashcatEngine)()
        caps = await eng.detect()
        click.echo(f"Using: {caps.name} v{caps.version}")

        result = await eng.identify_hashes([hash_str])
        htype: HashType = result[0][1] if result else HashType.UNKNOWN
        click.echo(f"Identified: {htype.value if isinstance(htype, HashType) else htype}")

        res = await eng.run(
            hash_type=htype,
            hashes=[hash_str],
            wordlist=Path(wordlist) if wordlist else None,
            rules=Path(rules) if rules else None,
        )
        click.echo(f"Cracked: {len(res.cracked)} hashes in {res.duration:.2f}s")
        for h, pw in res.cracked.items():
            click.echo(f"  {h[:16]}...:{pw}")

    asyncio.run(_crack())


if __name__ == "__main__":
    cli()
