from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, auto


class HashType(Enum):
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA512 = "SHA512"
    BCRYPT = "bcrypt"
    SCRYPT = "scrypt"
    PBKDF2 = "PBKDF2"
    NTLM = "NTLM"
    LM = "LM"
    MD4 = "MD4"
    DOUBLE_SHA1 = "double-sha1"
    SHA3_256 = "SHA3-256"
    SHA3_512 = "SHA3-512"
    GOST = "GOST"
    WHIRLPOOL = "Whirlpool"
    MD5_CRYPT = "md5crypt"
    SHA256_CRYPT = "sha256crypt"
    SHA512_CRYPT = "sha512crypt"
    DESC_CRYPT = "descrypt"
    BSDI_CRYPT = "bsdicrypt"
    RAW_MD5 = "Raw-MD5"
    RAW_SHA1 = "Raw-SHA1"
    RAW_SHA256 = "Raw-SHA256"
    RAW_SHA512 = "Raw-SHA512"
    UNKNOWN = "unknown"

    @classmethod
    def from_hashcat_mode(cls, mode: int) -> HashType:
        mode_map: dict[int, HashType] = {
            0: cls.MD5,
            100: cls.SHA1,
            1400: cls.SHA256,
            1700: cls.SHA512,
            3200: cls.BCRYPT,
            8900: cls.SCRYPT,
            1000: cls.NTLM,
            3000: cls.LM,
            900: cls.MD4,
        }
        return mode_map.get(mode, cls.UNKNOWN)

    def hashcat_mode(self) -> int:
        mode_map: dict[HashType, int] = {
            HashType.MD5: 0,
            HashType.SHA1: 100,
            HashType.SHA256: 1400,
            HashType.SHA512: 1700,
            HashType.BCRYPT: 3200,
            HashType.SCRYPT: 8900,
            HashType.NTLM: 1000,
            HashType.LM: 3000,
            HashType.MD4: 900,
        }
        return mode_map.get(self, 0)

    @property
    def speed_class(self) -> str:
        fast = {HashType.MD5, HashType.NTLM, HashType.LM, HashType.MD4, HashType.RAW_MD5}
        medium = {
            HashType.SHA1, HashType.SHA256, HashType.DOUBLE_SHA1,
            HashType.RAW_SHA1, HashType.RAW_SHA256,
        }
        if self in fast:
            return "fast"
        if self in medium:
            return "medium"
        return "slow"


class AttackMode(Enum):
    STRAIGHT = 0
    COMBINATOR = 1
    MASK = 3
    HYBRID_WORDLIST_MASK = 6
    HYBRID_MASK_WORDLIST = 7
    PRINCE = 8


class AttackPhase(Enum):
    IDENTIFY = auto()
    DICTIONARY = auto()
    MASK = auto()
    COMBINATOR = auto()
    HYBRID = auto()
    PRINCE = auto()
    RULE_BASED = auto()
    MARKOV = auto()
    EXTERNAL = auto()
    COMPLETE = auto()


@dataclass
class AttackResult:
    password: str
    hash_: str
    hash_type: HashType
    phase: AttackPhase
    rule: str = ""
    cost: float = 0.0
    cracked_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class SessionConfig:
    hash_type: HashType
    hashes: list[str]
    wordlists: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    masks: list[str] = field(default_factory=list)
    distribution: bool = False
    max_planner_depth: int = 5
    min_password_length: int = 1
    max_password_length: int = 64
    timeout_seconds: int = 3600


@dataclass
class Session:
    id: str
    config: SessionConfig
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    results: list[AttackResult] = field(default_factory=list)
    total_hashes: int = 0
    cracked_count: int = 0


@dataclass
class CrackingJob:
    id: str
    session_id: str
    phase: AttackPhase
    engine: str
    command: list[str]
    env: dict[str, str] = field(default_factory=dict)
    timeout: int = 3600
    priority: int = 0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    success: bool = False
    output: str = ""
    error: str = ""
