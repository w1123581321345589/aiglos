"""
tests/test_validate_prompt.py
==============================
Tests for aiglos validate-prompt (Shapiro essay-based prompt quality scorer).
"""
import aiglos
from aiglos.cli.validate_prompt import (
    validate,
    ValidationResult,
    Finding,
    AMBIGUOUS_TERMS,
    PROCESS_SIGNALS,
    OUTPUT_ONLY_SIGNALS,
    CONTEXT_SIGNALS,
    HARD_BAN_SIGNALS,
    VERIFICATION_GATE_SIGNALS,
    SECURITY_SIGNALS,
)


class TestValidationResult:
    def test_empty_prompt_scores_low(self):
        result = validate("hello world", "test.md")
        assert result.score < 50
        assert result.grade in ("D", "F")

    def test_short_prompt_is_error(self):
        result = validate("do the thing", "test.md")
        assert any(f.category == "specificity" for f in result.errors)

    def test_long_prompt_scores_higher(self):
        content = " ".join(["word"] * 1600)
        result = validate(content, "test.md")
        assert any(f.category == "specificity" for f in result.strengths)

    def test_hard_bans_detected(self):
        content = "Never fabricate data. Do not make up sources. Must not skip verification. Always verify."
        result = validate(content, "test.md")
        assert any(f.category == "hard_bans" for f in result.strengths)

    def test_no_hard_bans_is_error(self):
        content = "Please write good content about the topic."
        result = validate(content, "test.md")
        assert any(f.category == "hard_bans" for f in result.errors)

    def test_process_encoding_detected(self):
        content = "Step 1, first check the data. Then verify the sources. When errors occur, do escalate. If invalid, then reject."
        result = validate(content, "test.md")
        assert any(f.category == "process_encoding" for f in result.strengths)

    def test_output_only_is_error(self):
        content = "The output should be a report. Format: markdown. Produce a summary. Generate a list."
        result = validate(content, "test.md")
        assert any(f.category == "process_encoding" for f in result.errors)

    def test_context_detected(self):
        content = "The client needs a risk tolerance assessment. Priority is budget and timeline. Background includes stakeholder requirements and constraints."
        result = validate(content, "test.md")
        assert any(f.category == "context" for f in result.strengths)

    def test_verification_gate_detected(self):
        content = "Before delivering, check if this would embarrass me in front of the client."
        result = validate(content, "test.md")
        assert any(f.category == "verification" for f in result.strengths)

    def test_ambiguous_terms_flagged(self):
        content = "Use relevant and appropriate data. Follow best practices and standard procedures."
        result = validate(content, "test.md")
        assert any(f.category == "precision" for f in result.warnings)

    def test_security_integration_detected(self):
        content = "Configure aiglos hard_bans for fabricate_data prevention. Always verify action before proceeding."
        result = validate(content, "test.md")
        assert any(f.category == "security" for f in result.strengths)

    def test_role_identity_detected(self):
        content = "You are a senior analyst. Your role is to review financial data."
        result = validate(content, "test.md")
        assert any(f.category == "identity" for f in result.strengths)

    def test_grade_a_for_high_score(self):
        content = (
            "You are a security analyst. Your role is to review code. "
            "Never fabricate data. Do not skip verification. Must not ignore warnings. "
            "Always check credentials. Under no circumstances share secrets. "
            "Step 1, review the input. Then verify the sources. When errors occur, do escalate. "
            "If invalid, then reject. After that, compile results. Finally, review. "
            "The client has a low risk tolerance. Priority is security. "
            "Constraint: no external calls. Background includes compliance. "
            "Budget is limited. Timeline is 2 weeks. "
            "Before delivering, consider: would this embarrass me? "
            "Configure aiglos hard_bans for fabricate_data. "
        ) + " ".join(["context"] * 1200)
        result = validate(content, "test.md")
        assert result.grade in ("A", "B")
        assert result.score >= 75

    def test_result_has_all_fields(self):
        result = validate("test", "test.md")
        assert hasattr(result, "filepath")
        assert hasattr(result, "word_count")
        assert hasattr(result, "char_count")
        assert hasattr(result, "score")
        assert hasattr(result, "grade")
        assert hasattr(result, "strengths")
        assert hasattr(result, "warnings")
        assert hasattr(result, "errors")
        assert hasattr(result, "recommendations")

    def test_to_dict(self):
        result = validate("test prompt content", "test.md")
        d = result.to_dict()
        assert "score" in d
        assert "grade" in d
        assert "word_count" in d

    def test_score_clamped(self):
        result = validate("x", "test.md")
        assert 0 <= result.score <= 100


class TestConstants:
    def test_ambiguous_terms_not_empty(self):
        assert len(AMBIGUOUS_TERMS) >= 20

    def test_process_signals_not_empty(self):
        assert len(PROCESS_SIGNALS) >= 10

    def test_hard_ban_signals_not_empty(self):
        assert len(HARD_BAN_SIGNALS) >= 10

    def test_verification_gate_signals(self):
        assert "embarrass" in VERIFICATION_GATE_SIGNALS

    def test_security_signals(self):
        assert "aiglos" in SECURITY_SIGNALS


class TestExportsInInit:
    def test_validate_prompt_exported(self):
        assert "validate_prompt" in aiglos.__all__
        assert hasattr(aiglos, "validate_prompt")

    def test_prompt_validation_result_exported(self):
        assert "PromptValidationResult" in aiglos.__all__
        assert hasattr(aiglos, "PromptValidationResult")

    def test_prompt_finding_exported(self):
        assert "PromptFinding" in aiglos.__all__
        assert hasattr(aiglos, "PromptFinding")

    def test_byterover_autodetect_exported(self):
        assert "byterover_autodetect" in aiglos.__all__
        assert hasattr(aiglos, "byterover_autodetect")

    def test_byterover_default_paths_exported(self):
        assert "BYTEROVER_DEFAULT_PATHS" in aiglos.__all__
        assert hasattr(aiglos, "BYTEROVER_DEFAULT_PATHS")
