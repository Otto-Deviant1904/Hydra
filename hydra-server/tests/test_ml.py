from hydra.ml.classifier import RuleClassifier
from hydra.ml.markov import MarkovGenerator
from hydra.ml.selector import StrategySelector
from hydra.models.base import HashType


class TestMarkovGenerator:
    def test_train_and_generate(self):
        gen = MarkovGenerator(order=2, min_length=4)
        gen.train(["password", "pass123", "password123", "admin", "letmein", "welcome"])
        results = gen.generate(count=10)
        assert len(results) > 0
        for pw in results:
            assert len(pw) >= 4

    def test_generates_unique_passwords(self):
        gen = MarkovGenerator(order=3)
        gen.train(["password", "password123", "admin", "root", "test", "guest"])
        results = gen.generate(count=20)
        assert len(set(results)) == len(results)

    def test_empty_training(self):
        gen = MarkovGenerator()
        results = gen.generate()
        assert results == []

    def test_train_from_file(self, tmp_path):
        f = tmp_path / "passwords.txt"
        f.write_text("password\n123456\nadmin\n")
        gen = MarkovGenerator()
        gen.train_from_file(str(f))
        assert gen._trained


class TestRuleClassifier:
    def test_heuristic_predict(self):
        clf = RuleClassifier()
        rules = clf.predict("password", top_k=5)
        assert len(rules) > 0
        assert len(rules) <= 5

    def test_heuristic_predict_uppercase(self):
        clf = RuleClassifier()
        rules = clf.predict("PassWord", top_k=3)
        assert "l" in rules

    def test_heuristic_predict_digits(self):
        clf = RuleClassifier()
        rules = clf.predict("pass123", top_k=10)
        digit_rules = [r for r in rules if "$" in r]
        assert len(digit_rules) > 0


class TestStrategySelector:
    def setup_method(self):
        self.sel = StrategySelector()

    def test_fast_hash_gets_many_phases(self):
        phases = self.sel.select_phases(HashType.MD5)
        assert len(phases) >= 4

    def test_slow_hash_gets_few_phases(self):
        phases = self.sel.select_phases(HashType.BCRYPT)
        assert len(phases) <= 2

    def test_preferred_engine_slow(self):
        engine = self.sel.get_preferred_engine(HashType.BCRYPT)
        assert engine == "john"

    def test_preferred_engine_fast(self):
        engine = self.sel.get_preferred_engine(HashType.MD5)
        assert engine == "hashcat"

    def test_chunk_size_scales_with_speed(self):
        fast_size = self.sel.get_chunk_size(HashType.MD5, 10000)
        slow_size = self.sel.get_chunk_size(HashType.BCRYPT, 10000)
        assert fast_size >= slow_size

    def test_markov_only_for_slow_with_data(self):
        assert self.sel.should_use_markov(HashType.MD5, 2000) is False
        assert self.sel.should_use_markov(HashType.BCRYPT, 2000) is True
