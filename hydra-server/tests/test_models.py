from hydra.models.base import AttackPhase, AttackResult, HashType, Session, SessionConfig


def test_hash_type_from_hashcat_mode():
    assert HashType.from_hashcat_mode(0) == HashType.MD5
    assert HashType.from_hashcat_mode(100) == HashType.SHA1
    assert HashType.from_hashcat_mode(3200) == HashType.BCRYPT
    assert HashType.from_hashcat_mode(99999) == HashType.UNKNOWN


def test_hash_type_speed_class():
    assert HashType.MD5.speed_class == "fast"
    assert HashType.SHA1.speed_class == "medium"
    assert HashType.BCRYPT.speed_class == "slow"


def test_session_config_defaults():
    cfg = SessionConfig(hash_type=HashType.MD5, hashes=["hash1"])
    assert cfg.max_planner_depth == 5
    assert cfg.min_password_length == 1
    assert cfg.timeout_seconds == 3600


def test_session_tracks_results():
    cfg = SessionConfig(hash_type=HashType.MD5, hashes=["hash1"])
    session = Session(id="test-1", config=cfg, total_hashes=1)
    session.results.append(
        AttackResult(
            password="pass123", hash_="hash1",
            hash_type=HashType.MD5, phase=AttackPhase.DICTIONARY,
        )
    )
    assert len(session.results) == 1
    assert session.results[0].password == "pass123"
