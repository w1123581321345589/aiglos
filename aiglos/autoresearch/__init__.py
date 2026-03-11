"""
aiglos.autoresearch

LLM-driven detection rule evolution.

Inspired by Karpathy's autoresearch pattern:
  github.com/karpathy/autoresearch

The fitness function for security is binary and measurable: TPR - beta * FPR.
Every evaluation run is deterministic. The experiment log is the NDAA §1513 audit trail.

Quick start:
  python -m aiglos autoresearch --category CRED_ACCESS --rounds 20

Full API:
  from aiglos.autoresearch import AutoresearchLoop
  loop = AutoresearchLoop(category="CRED_ACCESS", rounds=20, adversarial=True)
  log = loop.run()
"""

from .loop import AutoresearchLoop, run_all_categories, evaluate_rule, ExperimentLog
from .corpus import TestCase, SEED_CORPUS, ALL_SEED_CASES

__all__ = [
    "AutoresearchLoop",
    "run_all_categories",
    "evaluate_rule",
    "ExperimentLog",
    "TestCase",
    "SEED_CORPUS",
    "ALL_SEED_CASES",
]
