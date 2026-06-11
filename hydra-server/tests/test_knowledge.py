import tempfile
from pathlib import Path

import pytest

from hydra.knowledge.database import Database
from hydra.knowledge.repository import KnowledgeRepository
from hydra.models.base import AttackPhase, AttackResult, HashType, Session, SessionConfig


class TestKnowledgeRepository:
    def setup_method(self) -> None:
        self.db_path = Path(tempfile.mktemp(suffix=".db"))
        self.db = Database(f"sqlite:///{self.db_path}")
        self.kb = KnowledgeRepository(self.db)

    def test_save_and_get_session(self) -> None:
        config = SessionConfig(hash_type=HashType.MD5, hashes=["hash1", "hash2"])
        session = Session(id="test-session", config=config, total_hashes=2)
        session.cracked_count = 1
        self.kb.save_session(session)

        rate = self.kb.get_average_crack_rate(HashType.MD5.value)
        assert rate == 0.5

    def test_save_results(self) -> None:
        results = [
            AttackResult(
                password="pass1", hash_="hash1",
                hash_type=HashType.MD5, phase=AttackPhase.DICTIONARY,
            ),
        ]
        self.kb.save_results(results)

    def test_rule_hits(self) -> None:
        for _ in range(11):
            self.kb.record_rule_hit("best64.rule", "MD5", hit=True)
        for _ in range(5):
            self.kb.record_rule_hit("best64.rule", "MD5", hit=False)

        rules = self.kb.get_best_rules("MD5")
        assert len(rules) >= 1
        assert rules[0][1] == pytest.approx(11 / 16)

    def test_empty_history(self) -> None:
        records = self.kb.get_session_history("BCRYPT")
        assert records == []
