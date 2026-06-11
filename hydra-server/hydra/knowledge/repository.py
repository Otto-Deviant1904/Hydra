from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from sqlalchemy import func

from hydra.knowledge.database import Database
from hydra.knowledge.models import CrackRecord, RuleHitRecord, SessionRecord
from hydra.models.base import AttackResult, Session

logger = logging.getLogger(__name__)


class KnowledgeRepository:
    """Persists and queries cracking knowledge."""

    def __init__(self, db: Database):
        self.db = db
        db.create_tables()

    def save_session(self, session: Session) -> None:
        with self.db.get_session() as s:
            record = s.get(SessionRecord, session.id)
            if record is None:
                record = SessionRecord(
                    id=session.id,
                    hash_type=session.config.hash_type.value,
                    total_hashes=session.total_hashes,
                    config_json=json.dumps({
                        "wordlists": [str(w) for w in session.config.wordlists],
                        "timeout": session.config.timeout_seconds,
                    }),
                )
                s.add(record)

            record.cracked_count = session.cracked_count
            record.finished_at = session.finished_at or datetime.now(UTC)
            s.commit()
            logger.debug(
                "Saved session %s (%d/%d)",
                session.id, session.cracked_count, session.total_hashes,
            )

    def save_results(self, results: list[AttackResult], session_id: str = "") -> None:
        with self.db.get_session() as s:
            for r in results:
                record = CrackRecord(
                    session_id=session_id,
                    hash_value=r.hash_,
                    password=r.password,
                    hash_type=r.hash_type.value,
                    phase=r.phase.name,
                    rule=r.rule,
                    cost=r.cost,
                )
                s.add(record)
            s.commit()
            logger.debug("Saved %d crack results", len(results))

    def record_rule_hit(self, rule: str, hash_type_value: str, hit: bool = True) -> None:
        with self.db.get_session() as s:
            record = s.query(RuleHitRecord).filter_by(
                rule=rule, hash_type=hash_type_value
            ).first()
            if record is None:
                record = RuleHitRecord(
                    rule=rule, hash_type=hash_type_value,
                    hits=1 if hit else 0, attempts=1,
                )
                s.add(record)
            else:
                record.hits += 1 if hit else 0
                record.attempts += 1
                record.last_seen = datetime.now(UTC)
            s.commit()

    def get_best_rules(self, hash_type_value: str, limit: int = 20) -> list[tuple[str, float]]:
        with self.db.get_session() as s:
            records = (
                s.query(RuleHitRecord)
                .filter(RuleHitRecord.hash_type == hash_type_value, RuleHitRecord.attempts > 10)
                .all()
            )
            scored = [
                (r.rule, r.hits / max(r.attempts, 1))
                for r in records
            ]
            scored.sort(key=lambda x: x[1], reverse=True)
            return scored[:limit]

    def get_session_history(self, hash_type_value: str, limit: int = 10) -> list[SessionRecord]:
        with self.db.get_session() as s:
            return (
                s.query(SessionRecord)
                .filter(SessionRecord.hash_type == hash_type_value)
                .order_by(SessionRecord.started_at.desc())
                .limit(limit)
                .all()
            )

    def get_all_sessions(self, limit: int = 50) -> list[SessionRecord]:
        with self.db.get_session() as s:
            return (
                s.query(SessionRecord)
                .order_by(SessionRecord.started_at.desc())
                .limit(limit)
                .all()
            )

    def get_average_crack_rate(self, hash_type_value: str) -> float:
        with self.db.get_session() as s:
            numerator = SessionRecord.cracked_count * 1.0
            denominator = func.nullif(SessionRecord.total_hashes, 0)
            result = s.query(func.avg(numerator / denominator))
            result = result.filter(SessionRecord.hash_type == hash_type_value).scalar()
            return result or 0.0
