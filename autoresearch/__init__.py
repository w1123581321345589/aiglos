"""
aiglos.autoresearch

Self-improving detection rule loop. The autoresearch module evolves Aiglos T1-T36
detection rules against an adversarially expanding test corpus, using the same
loop architecture as Karpathy's autoresearch (github.com/karpathy/autoresearch)
but optimizing for security detection metrics rather than neural network loss.

Usage:
    python autoresearch/autoresearch.py --list
    python autoresearch/autoresearch.py --experiment credential_exposure --cycles 20
    python autoresearch/autoresearch.py --experiment prompt_injection --adversarial
    python autoresearch/autoresearch.py --experiment credential_exposure --report
"""

from .autoresearch import run_experiment, generate_compliance_report, evaluate_rule

__all__ = ["run_experiment", "generate_compliance_report", "evaluate_rule"]
