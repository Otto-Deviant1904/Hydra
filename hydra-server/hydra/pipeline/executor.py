from __future__ import annotations

import asyncio
import logging
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from hydra.engines.base import EngineResult
from hydra.models.base import AttackPhase, AttackResult, Session
from hydra.planner.heuristic import AttackPlan, PhaseConfig

logger = logging.getLogger(__name__)


@dataclass
class PhaseResult:
    phase: AttackPhase
    cracked: dict[str, str]
    total_before: int
    total_after: int
    duration: float
    speed: float
    yield_pct: float
    label: str


class PipelineExecutor:
    """Executes an AttackPlan phase by phase with diminishing returns detection."""

    def __init__(self, plan: AttackPlan, session: Session, workdir: str | Path = "/tmp/hydra"):
        self.plan = plan
        self.session = session
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        prefix = f"session_{session.id}_"
        self._session_dir = Path(tempfile.mkdtemp(dir=self.workdir, prefix=prefix))
        self._uncracked_hashes: list[str] = list(session.config.hashes)
        self._phase_results: list[PhaseResult] = []
        self._start_time: float = 0.0

    async def run(self) -> Session:
        self._start_time = asyncio.get_event_loop().time()
        logger.info(
            "Starting pipeline: %d phases for %s (%d hashes)",
            len(self.plan.phases), self.plan.hash_type.value, len(self._uncracked_hashes),
        )

        for i, phase_cfg in enumerate(self.plan.phases):
            if not self._uncracked_hashes:
                logger.info("All hashes cracked, stopping pipeline")
                break

            if self._check_timeout():
                logger.warning("Session timeout reached, stopping pipeline")
                break

            result = await self._execute_phase(phase_cfg, i + 1)
            self._phase_results.append(result)

            if result.yield_pct < phase_cfg.min_yield:
                logger.info(
                    "Phase '%s' yielded %.2f%% (threshold %.2f%%) — stopping remaining phases",
                    phase_cfg.label(), result.yield_pct * 100, phase_cfg.min_yield * 100,
                )
                break

        self.session.finished_at = datetime.now(UTC)
        self.session.cracked_count = len(self.session.results)
        logger.info(
            "Pipeline complete: %d/%d hashes cracked in %.1fs",
            self.session.cracked_count, self.session.total_hashes,
            asyncio.get_event_loop().time() - self._start_time,
        )
        return self.session

    async def _execute_phase(self, phase_cfg: PhaseConfig, phase_num: int) -> PhaseResult:
        total_before = len(self._uncracked_hashes)
        logger.info(
            "Phase %d/%d: %s (%d uncracked hashes, timeout=%ds)",
            phase_num, len(self.plan.phases), phase_cfg.label(),
            total_before, phase_cfg.timeout,
        )

        engine = self.plan.engines.get(phase_cfg.engine_name)
        if not engine:
            logger.warning("Engine '%s' not available, skipping phase", phase_cfg.engine_name)
            return self._empty_result(phase_cfg)

        result = await engine.run(
            hash_type=self.plan.hash_type,
            hashes=self._uncracked_hashes,
            wordlist=phase_cfg.wordlist,
            rules=phase_cfg.rules,
            mask=phase_cfg.mask,
            attack_mode=phase_cfg.attack_mode,
            session_dir=self._session_dir,
            timeout=phase_cfg.timeout,
        )

        if not result.cracked and result.exit_code != 0 and len(self.plan.engines) > 1:
            logger.warning("Engine '%s' failed (exit=%d), trying fallback", engine.name, result.exit_code)
            for eng_name, fallback_eng in self.plan.engines.items():
                if eng_name == phase_cfg.engine_name or eng_name == engine.name:
                    continue
                logger.info("Retrying phase with engine '%s'", eng_name)
                result = await fallback_eng.run(
                    hash_type=self.plan.hash_type,
                    hashes=self._uncracked_hashes,
                    wordlist=phase_cfg.wordlist,
                    rules=phase_cfg.rules,
                    mask=phase_cfg.mask,
                    attack_mode=phase_cfg.attack_mode,
                    session_dir=self._session_dir,
                    timeout=phase_cfg.timeout,
                )
                if result.cracked or result.exit_code == 0:
                    break

        self._record_results(result, phase_cfg.phase)

        total_after = len(self._uncracked_hashes)
        cracked_count = total_before - total_after
        yield_pct = cracked_count / total_before if total_before > 0 else 0.0

        phase_result = PhaseResult(
            phase=phase_cfg.phase,
            cracked=result.cracked,
            total_before=total_before,
            total_after=total_after,
            duration=result.duration,
            speed=result.speed,
            yield_pct=yield_pct,
            label=phase_cfg.label(),
        )

        logger.info(
            "Phase %d done: %d cracked (%.2f%%), %.1fs, %.1f H/s",
            phase_num, cracked_count, yield_pct * 100, result.duration, result.speed,
        )

        return phase_result

    def _record_results(self, result: EngineResult, phase: AttackPhase) -> None:
        for hash_str, pw in result.cracked.items():
            if hash_str in self._uncracked_hashes:
                self._uncracked_hashes.remove(hash_str)
                self.session.results.append(AttackResult(
                    password=pw,
                    hash_=hash_str,
                    hash_type=self.plan.hash_type,
                    phase=phase,
                    cost=result.duration,
                ))

    def _check_timeout(self) -> bool:
        elapsed = asyncio.get_event_loop().time() - self._start_time
        return elapsed > self.session.config.timeout_seconds

    def _empty_result(self, phase_cfg: PhaseConfig) -> PhaseResult:
        return PhaseResult(
            phase=phase_cfg.phase, cracked={},
            total_before=len(self._uncracked_hashes),
            total_after=len(self._uncracked_hashes),
            duration=0, speed=0, yield_pct=0.0, label=phase_cfg.label(),
        )

    @property
    def phase_count(self) -> int:
        """Return the number of phases executed."""
        return len(self._phase_results)

    @property
    def phase_summary(self) -> str:
        lines = ["Pipeline Summary:"]
        for pr in self._phase_results:
            cracked = len(pr.cracked)
            lines.append(
                f"  {pr.label}: {cracked} cracked ({pr.yield_pct*100:.1f}%), "
                f"{pr.duration:.1f}s @ {pr.speed:.0f} H/s"
            )
        lines.append(f"  Total: {self.session.cracked_count}/{self.session.total_hashes}")
        return "\n".join(lines)
