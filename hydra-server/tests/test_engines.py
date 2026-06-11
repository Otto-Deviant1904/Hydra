import pytest

from hydra.engines.hashcat import HashcatEngine
from hydra.engines.jtr import JtrEngine
from hydra.models.base import HashType


class TestHashcatEngine:
    @pytest.mark.integration
    async def test_detect(self) -> None:
        engine = HashcatEngine()
        caps = await engine.detect()
        assert caps.name == "hashcat"
        assert caps.supports_rules is True
        assert caps.supports_mask is True

    def test_parse_speed(self) -> None:
        engine = HashcatEngine()
        sample = "Speed.#1.........:  1234.5 kH/s (0.2ms)"
        assert engine._parse_speed(sample) == 1234500.0

    def test_parse_speed_ghs(self) -> None:
        engine = HashcatEngine()
        sample = "Speed.#1.........:  1.2 GH/s (0.2ms)"
        assert engine._parse_speed(sample) == 1200000000.0

    def test_parse_progress(self) -> None:
        engine = HashcatEngine()
        sample = "Recovered........: 3/5 (60.00%) Digests"
        assert engine._parse_progress(sample, 5) == 0.6

    @pytest.mark.asyncio
    async def test_identify_md5(self) -> None:
        engine = HashcatEngine()
        results = await engine.identify_hashes(["5d41402abc4b2a76b9719d911017c592"])
        assert results[0][1] == HashType.MD5


class TestJtrEngine:
    @pytest.mark.integration
    async def test_detect(self) -> None:
        engine = JtrEngine()
        caps = await engine.detect()
        assert caps.name == "john"

    def test_parse_speed(self) -> None:
        engine = JtrEngine()
        sample = "12345K p/s 5.2g 0:00:01"
        result = engine._parse_speed(sample)
        assert result > 0
