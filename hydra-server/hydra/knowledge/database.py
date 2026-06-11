from __future__ import annotations

import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class Database:
    def __init__(self, url: str = "sqlite:///hydra.db") -> None:
        self.url = url
        self.engine = create_engine(url, echo=False)
        self.Session = sessionmaker(bind=self.engine)

    def create_tables(self) -> None:
        Base.metadata.create_all(self.engine)
        logger.info("Database tables created: %s", self.url)

    def get_session(self) -> Session:
        return self.Session()
