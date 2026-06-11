from __future__ import annotations

from hydra.knowledge.repository import KnowledgeRepository
from hydra.models.base import AttackPhase, HashType


class StrategySelector:
    """Selects optimal attack strategy based on KB history and hash type."""

    def __init__(self, kb: KnowledgeRepository | None = None):
        self.kb = kb

    def select_phases(self, hash_type: HashType) -> list[AttackPhase]:
        speed = hash_type.speed_class
        match speed:
            case "fast":
                return [
                    AttackPhase.DICTIONARY,
                    AttackPhase.RULE_BASED,
                    AttackPhase.MASK,
                    AttackPhase.HYBRID,
                    AttackPhase.PRINCE,
                ]
            case "medium":
                return [
                    AttackPhase.DICTIONARY,
                    AttackPhase.RULE_BASED,
                    AttackPhase.MASK,
                ]
            case "slow":
                return [
                    AttackPhase.DICTIONARY,
                    AttackPhase.RULE_BASED,
                ]
        return [AttackPhase.DICTIONARY]

    def get_preferred_engine(self, hash_type: HashType) -> str:
        speed = hash_type.speed_class
        if speed == "slow" and hash_type in {
            HashType.BCRYPT, HashType.SCRYPT, HashType.PBKDF2,
        }:
            return "john"
        return "hashcat"

    def should_use_markov(self, hash_type: HashType, known_passwords: int) -> bool:
        return hash_type.speed_class == "slow" and known_passwords > 1000

    def should_use_classifier(self, hash_type: HashType) -> bool:
        return hash_type.speed_class != "slow"

    def get_chunk_size(self, hash_type: HashType, total_hashes: int) -> int:
        speed = hash_type.speed_class
        if speed == "fast":
            return min(50000, max(1000, total_hashes // 10))
        if speed == "medium":
            return min(10000, max(500, total_hashes // 5))
        return min(1000, max(100, total_hashes // 2))
