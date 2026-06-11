from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from hydra.engines.base import Engine
from hydra.models.base import AttackMode, AttackPhase, HashType, SessionConfig


@dataclass
class PhaseConfig:
    phase: AttackPhase
    engine_name: str
    attack_mode: AttackMode
    wordlist: str | Path | None = None
    rules: str | Path | None = None
    mask: str | None = None
    priority: int = 0
    timeout: int = 600
    min_yield: float = 0.01

    def label(self) -> str:
        parts = [self.phase.name]
        if self.wordlist:
            parts.append(f"wl={Path(str(self.wordlist)).name}")
        if self.rules:
            parts.append(f"rules={Path(str(self.rules)).name}")
        if self.mask:
            parts.append(f"mask={self.mask}")
        return " ".join(parts)


@dataclass
class AttackPlan:
    hash_type: HashType
    total_hashes: int
    phases: list[PhaseConfig] = field(default_factory=list)
    engines: dict[str, Engine] = field(default_factory=dict)

    @property
    def estimated_max_duration(self) -> int:
        return sum(p.timeout for p in self.phases)


class HeuristicPlanner:
    """Generates attack plans based on hash type and available resources."""

    def __init__(self, engines: dict[str, Engine]):
        self.engines = engines

    def plan(self, config: SessionConfig) -> AttackPlan:
        plan = AttackPlan(
            hash_type=config.hash_type,
            total_hashes=len(config.hashes),
            engines=self.engines,
        )

        speed = config.hash_type.speed_class

        match speed:
            case "fast":
                self._build_fast_plan(plan, config)
            case "medium":
                self._build_medium_plan(plan, config)
            case "slow":
                self._build_slow_plan(plan, config)
            case _:
                self._build_fast_plan(plan, config)

        return plan

    def _build_fast_plan(self, plan: AttackPlan, config: SessionConfig) -> None:
        engine = self._pick_engine("hashcat")
        depth = min(config.max_planner_depth, 6)

        # Phase 1: Straight dictionary with best64 rules
        if config.wordlists:
            plan.phases.append(PhaseConfig(
                phase=AttackPhase.DICTIONARY,
                engine_name=engine.name,
                attack_mode=AttackMode.STRAIGHT,
                wordlist=config.wordlists[0],
                rules=Path("/usr/share/hashcat/rules/best64.rule") if Path(
                    "/usr/share/hashcat/rules/best64.rule"
                ).exists() else None,
                priority=1,
                timeout=min(config.timeout_seconds // depth, 300),
            ))

        # Phase 2: Mask attack for short passwords
        plan.phases.append(PhaseConfig(
            phase=AttackPhase.MASK,
            engine_name=engine.name,
            attack_mode=AttackMode.MASK,
            mask="?a?a?a?a?a?a",
            priority=2,
            timeout=min(config.timeout_seconds // depth, 600),
        ))

        # Phase 3: Dictionary with more aggressive rules
        if config.wordlists:
            plan.phases.append(PhaseConfig(
                phase=AttackPhase.RULE_BASED,
                engine_name=engine.name,
                attack_mode=AttackMode.STRAIGHT,
                wordlist=config.wordlists[0],
                rules=Path("/usr/share/hashcat/rules/rockyou-30000.rule") if Path(
                    "/usr/share/hashcat/rules/rockyou-30000.rule"
                ).exists() else None,
                priority=3,
                timeout=min(config.timeout_seconds // depth, 900),
            ))

        # Phase 4: Hybrid wordlist+mask
        if config.wordlists:
            plan.phases.append(PhaseConfig(
                phase=AttackPhase.HYBRID,
                engine_name=engine.name,
                attack_mode=AttackMode.HYBRID_WORDLIST_MASK,
                wordlist=config.wordlists[0],
                mask="?d?d?d?d",
                priority=4,
                timeout=min(config.timeout_seconds // depth, 600),
            ))

        # Phase 5: PRINCE attack
        if config.wordlists:
            plan.phases.append(PhaseConfig(
                phase=AttackPhase.PRINCE,
                engine_name=engine.name,
                attack_mode=AttackMode.PRINCE,
                wordlist=config.wordlists[0],
                priority=5,
                timeout=min(config.timeout_seconds // depth, 1200),
            ))

        # Phase 6: Wider mask
        plan.phases.append(PhaseConfig(
            phase=AttackPhase.MASK,
            engine_name=engine.name,
            attack_mode=AttackMode.MASK,
            mask="?a?a?a?a?a?a?a?a",
            priority=6,
            timeout=min(config.timeout_seconds // depth, 1800),
        ))

    def _build_medium_plan(self, plan: AttackPlan, config: SessionConfig) -> None:
        engine = self._pick_engine("hashcat")
        depth = min(config.max_planner_depth, 4)

        if config.wordlists:
            plan.phases.append(PhaseConfig(
                phase=AttackPhase.DICTIONARY,
                engine_name=engine.name,
                attack_mode=AttackMode.STRAIGHT,
                wordlist=config.wordlists[0],
                rules=Path("/usr/share/hashcat/rules/best64.rule") if Path(
                    "/usr/share/hashcat/rules/best64.rule"
                ).exists() else None,
                priority=1,
                timeout=min(config.timeout_seconds // depth, 600),
            ))

        if config.wordlists:
            plan.phases.append(PhaseConfig(
                phase=AttackPhase.RULE_BASED,
                engine_name=engine.name,
                attack_mode=AttackMode.STRAIGHT,
                wordlist=config.wordlists[0],
                priority=2,
                timeout=min(config.timeout_seconds // depth, 1200),
            ))

        plan.phases.append(PhaseConfig(
            phase=AttackPhase.MASK,
            engine_name=engine.name,
            attack_mode=AttackMode.MASK,
            mask="?a?a?a?a?a?a?a",
            priority=3,
            timeout=min(config.timeout_seconds // depth, 1800),
        ))

    def _build_slow_plan(self, plan: AttackPlan, config: SessionConfig) -> None:
        engine = self._pick_engine("hashcat")
        depth = min(config.max_planner_depth, 2)

        if config.wordlists:
            plan.phases.append(PhaseConfig(
                phase=AttackPhase.DICTIONARY,
                engine_name=engine.name,
                attack_mode=AttackMode.STRAIGHT,
                wordlist=config.wordlists[0],
                priority=1,
                timeout=min(config.timeout_seconds // depth, 3600),
                min_yield=0.001,
            ))

        if config.wordlists:
            plan.phases.append(PhaseConfig(
                phase=AttackPhase.RULE_BASED,
                engine_name=engine.name,
                attack_mode=AttackMode.STRAIGHT,
                wordlist=config.wordlists[0],
                rules=Path("/usr/share/hashcat/rules/best64.rule") if Path(
                    "/usr/share/hashcat/rules/best64.rule"
                ).exists() else None,
                priority=2,
                timeout=min(config.timeout_seconds // depth, 7200),
                min_yield=0.001,
            ))

    def _pick_engine(self, preferred: str = "hashcat") -> Engine:
        if preferred in self.engines:
            return self.engines[preferred]
        for name in ("python", "hashcat", "john"):
            if name in self.engines:
                return self.engines[name]
        for eng in self.engines.values():
            return eng
        raise RuntimeError("No engines available")
