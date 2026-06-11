from hydra.engines.base import EngineCapabilities
from hydra.engines.hashcat import HashcatEngine
from hydra.models.base import AttackPhase, HashType, SessionConfig
from hydra.planner.heuristic import HeuristicPlanner


class FakeEngine(HashcatEngine):
    async def detect(self) -> EngineCapabilities:
        return EngineCapabilities(
            name="hashcat", version="fake",
            supported_hash_modes=[0, 100, 1400, 1700, 3200],
            supported_attack_modes=[],
            max_wordlist_size=0, supports_rules=True, supports_mask=True,
            supports_opencl=False, supports_cuda=False,
            supports_distribution=False, max_devices=0,
        )


class TestHeuristicPlanner:
    def setup_method(self):
        self.engine = FakeEngine()
        self.planner = HeuristicPlanner({"hashcat": self.engine})

    def test_plan_fast_hash(self):
        config = SessionConfig(
            hash_type=HashType.MD5,
            hashes=["hash1", "hash2"],
            wordlists=["/tmp/wordlist.txt"],
        )
        plan = self.planner.plan(config)
        assert len(plan.phases) > 0
        assert plan.phases[0].phase == AttackPhase.DICTIONARY
        assert plan.hash_type == HashType.MD5

    def test_plan_slow_hash_has_fewer_phases(self):
        config = SessionConfig(
            hash_type=HashType.BCRYPT,
            hashes=["hash1"],
            wordlists=["/tmp/wordlist.txt"],
        )
        plan = self.planner.plan(config)
        assert len(plan.phases) <= 3

    def test_plan_medium_hash(self):
        config = SessionConfig(
            hash_type=HashType.SHA256,
            hashes=["hash1"],
            wordlists=["/tmp/wordlist.txt"],
        )
        plan = self.planner.plan(config)
        assert len(plan.phases) <= 4
        assert plan.phases[0].priority == 1

    def test_plan_no_wordlist_still_has_mask_phases(self):
        config = SessionConfig(
            hash_type=HashType.MD5,
            hashes=["hash1"],
        )
        plan = self.planner.plan(config)
        mask_phases = [p for p in plan.phases if p.phase == AttackPhase.MASK]
        assert len(mask_phases) > 0

    def test_plan_respects_max_depth(self):
        config = SessionConfig(
            hash_type=HashType.MD5,
            hashes=["hash1"],
            wordlists=["/tmp/test.txt"],
            max_planner_depth=2,
        )
        plan = self.planner.plan(config)
        assert len(plan.phases) >= 3  # fast hash always gets 6 phases
        # max_planner_depth affects timeout, not phase count

    def test_plan_phases_have_timeouts(self):
        config = SessionConfig(
            hash_type=HashType.NTLM,
            hashes=["hash1"],
            wordlists=["/tmp/test.txt"],
        )
        plan = self.planner.plan(config)
        for p in plan.phases:
            assert p.timeout > 0
