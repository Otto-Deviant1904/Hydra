from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from hydra.knowledge.database import Base


class SessionRecord(Base):
    __tablename__ = "sessions"

    id = Column(String, primary_key=True)
    hash_type = Column(String, nullable=False)
    total_hashes = Column(Integer, default=0)
    cracked_count = Column(Integer, default=0)
    started_at = Column(DateTime, default=lambda: datetime.now(UTC))
    finished_at = Column(DateTime, nullable=True)
    config_json = Column(Text, default="{}")

    cracks = relationship("CrackRecord", back_populates="session", cascade="all, delete-orphan")


class CrackRecord(Base):
    __tablename__ = "cracks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=False)
    hash_value = Column(String, nullable=False)
    password = Column(String, nullable=False)
    hash_type = Column(String, nullable=False)
    phase = Column(String, nullable=False)
    rule = Column(String, default="")
    cost = Column(Float, default=0.0)
    cracked_at = Column(DateTime, default=lambda: datetime.now(UTC))

    session = relationship("SessionRecord", back_populates="cracks")


class RuleHitRecord(Base):
    __tablename__ = "rule_hits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule = Column(String, nullable=False)
    hash_type = Column(String, nullable=False)
    hits = Column(Integer, default=0)
    attempts = Column(Integer, default=0)
    last_seen = Column(DateTime, default=lambda: datetime.now(UTC))
