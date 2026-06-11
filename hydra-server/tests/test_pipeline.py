import tempfile
from pathlib import Path

import pytest

from hydra.engines.base import Engine, EngineCapabilities, EngineResult
from hydra.models.base import AttackMode, AttackPhase, HashType, Session, SessionConfig
from hydra.pipeline.executor import PipelineExecutor
from hydra.planner.heuristic import AttackPlan, HeuristicPlanner, PhaseConfig


class FakeEngine(Engine):
    name = "fake"
    def _default_binary(self) -> str:
        return "fake"
    async def detect(self) -> EngineCapabilities:
        return EngineCapabilities(
            name="fake", version="1.0",
            supported_hash_modes=[0, 100], supported_attack_modes=[AttackMode.STRAIGHT],
            max_wordlist_size=0, supports_rules=False, supports_mask=False,
            supports_opencl=False, supports_cuda=False,
            supports_distribution=False, max_devices=0,
        )
    async def identify_hashes(self, hashes: list[str]) -> list[tuple[str, HashType]]:
        return [(h, HashType.MD5) for h in hashes]
    async def run(self, **kwargs) -> EngineResult:
        return EngineResult(
            cracked={"hash1": "password123"},
            speed=1000.0, progress=1.0, duration=1.0,
            command=["fake"], exit_code=0,
        )


class TestPipelineExecutor:
    def setup_method(self):
        self.engine = FakeEngine()
        self.planner = HeuristicPlanner({"fake": self.engine})
        self.workdir = Path(tempfile.mkdtemp())

    @pytest.mark.asyncio
    async def test_executor_runs_phases(self):
        config = SessionConfig(
            hash_type=HashType.MD5,
            hashes=["hash1", "hash2"],
            wordlists=["/tmp/test.txt"],
        )
        session = Session(id="test-1", config=config, total_hashes=2)
        plan = self.planner.plan(config)
        executor = PipelineExecutor(plan, session, workdir=self.workdir)
        result = await executor.run()

        assert result.cracked_count >= 1
        assert len(result.results) >= 1

    @pytest.mark.asyncio
    async def test_executor_stops_when_all_cracked(self):
        config = SessionConfig(
            hash_type=HashType.MD5,
            hashes=["hash1"],
            wordlists=["/tmp/test.txt"],
        )
        session = Session(id="test-2", config=config, total_hashes=1)
        plan = self.planner.plan(config)
        executor = PipelineExecutor(plan, session, workdir=self.workdir)
        result = await executor.run()

        assert result.cracked_count == 1

    @pytest.mark.asyncio
    async def test_executor_phase_summary(self):
        config = SessionConfig(
            hash_type=HashType.MD5,
            hashes=["hash1"],
            wordlists=["/tmp/test.txt"],
        )
        session = Session(id="test-3", config=config, total_hashes=1)
        plan = AttackPlan(hash_type=HashType.MD5, total_hashes=1, engines={"fake": self.engine})
        plan.phases.append(PhaseConfig(
            phase=AttackPhase.DICTIONARY, engine_name="fake",
            attack_mode=AttackMode.STRAIGHT, wordlist="/tmp/test.txt",
            priority=1, timeout=60,
        ))
        executor = PipelineExecutor(plan, session, workdir=self.workdir)
        await executor.run()
        summary = executor.phase_summary
        assert "password123" not in summary  # shouldn't leak passwords
        assert "DICTIONARY" in summary
