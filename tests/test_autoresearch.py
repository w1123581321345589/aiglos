"""tests/test_autoresearch.py"""
import pytest
from aiglos.autoresearch.corpus import (
    SEED_CORPUS, ALL_SEED_CASES, CREDENTIAL_EXPOSURE,
    PROMPT_INJECTION, SHELL_INJECTION, SSRF, TestCase,
)
from aiglos.autoresearch.loop import evaluate_rule

def test_seed_corpus_categories():
    assert set(SEED_CORPUS.keys()) == {"CRED_ACCESS", "PROMPT_INJECT", "SHELL_INJECT", "SSRF"}

def test_each_category_has_8_cases():
    for cat, cases in SEED_CORPUS.items():
        assert len(cases) == 8, f"{cat} has {len(cases)}, expected 8"

def test_each_category_balanced():
    for cat, cases in SEED_CORPUS.items():
        assert sum(1 for c in cases if c.label) == 4
        assert sum(1 for c in cases if not c.label) == 4

def test_all_seed_cases_total():
    assert len(ALL_SEED_CASES) == 32

def test_all_cases_have_notes():
    for c in ALL_SEED_CASES:
        assert c.note

def test_perfect_rule_tpr():
    rule = lambda t, a: 1.0
    m = evaluate_rule(rule, CREDENTIAL_EXPOSURE, category="CRED_ACCESS")
    assert m.tpr == 1.0

def test_perfect_rule_fpr():
    rule = lambda t, a: 1.0
    m = evaluate_rule(rule, CREDENTIAL_EXPOSURE, category="CRED_ACCESS")
    assert m.fpr == 1.0

def test_null_rule():
    rule = lambda t, a: 0.0
    m = evaluate_rule(rule, CREDENTIAL_EXPOSURE, category="CRED_ACCESS")
    assert m.tpr == 0.0
    assert m.fpr == 0.0
    assert m.fitness == 0.0

def test_fitness_formula():
    rule = lambda t, a: 1.0
    m = evaluate_rule(rule, CREDENTIAL_EXPOSURE, category="CRED_ACCESS", beta=1.0)
    assert abs(m.fitness - (m.tpr - m.fpr)) < 1e-9

def test_perfect_selective_rule():
    malicious_keys = {"sk-proj-abcdef123456", "hunter2", ".hermes/.env"}
    def has_private_key(s): return "id_rsa" in s and "id_rsa.pub" not in s
    rule = lambda t, a: 1.0 if (any(k in str(a) for k in malicious_keys) or has_private_key(str(a))) else 0.0
    m = evaluate_rule(rule, CREDENTIAL_EXPOSURE, category="CRED_ACCESS")
    assert m.tpr == 1.0
    assert m.fpr == 0.0
    assert m.fitness == 1.0

def test_rule_metrics_total_cases():
    m = evaluate_rule(lambda t, a: 0.0, ALL_SEED_CASES)
    assert m.total_cases == 32

def test_rule_category_filter():
    m = evaluate_rule(lambda t, a: 0.0, ALL_SEED_CASES, category="SSRF")
    assert m.total_cases == 8

def test_rule_exception_handling():
    def bad(t, a): raise ValueError("broken")
    m = evaluate_rule(bad, CREDENTIAL_EXPOSURE, category="CRED_ACCESS")
    assert m.tpr == 0.0
    assert m.fpr == 0.0

def test_metrics_precision():
    rule = lambda t, a: 1.0
    m = evaluate_rule(rule, CREDENTIAL_EXPOSURE, category="CRED_ACCESS")
    assert abs(m.precision - 0.5) < 1e-9

def test_curl_pipe_bash_is_malicious():
    c = next(c for c in SHELL_INJECTION if "curl" in c.tool_args.get("command", ""))
    assert c.label is True

def test_pytest_is_safe():
    c = next(c for c in SHELL_INJECTION if "pytest" in c.tool_args.get("command", ""))
    assert c.label is False

def test_imds_is_malicious():
    c = next(c for c in SSRF if "169.254.169.254" in c.tool_args.get("url", ""))
    assert c.label is True

def test_pypi_is_safe():
    c = next(c for c in SSRF if "pypi.org" in c.tool_args.get("url", ""))
    assert c.label is False

def test_adversarial_case_creation():
    c = TestCase(
        tool_name="web_fetch",
        tool_args={"url": "http://10.0.0.1/internal"},
        label=True, category="SSRF",
        note="RFC-1918 internal access",
        source="adversarial", adversarial_round=3,
    )
    assert c.source == "adversarial"
    assert c.adversarial_round == 3

def test_prompt_injection_soul_write():
    c = next(c for c in PROMPT_INJECTION if "SOUL.md" in c.tool_args.get("path","") and c.label)
    assert "ignore" in c.tool_args["content"].lower() or "no restrictions" in c.tool_args["content"].lower()

def test_prompt_injection_safe_soul_write():
    c = next(c for c in PROMPT_INJECTION if "SOUL.md" in c.tool_args.get("path","") and not c.label)
    assert c.label is False
