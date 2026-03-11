# Aiglos Autoresearch

Self-improving threat detection through adversarial co-evolution.

Inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch) pattern.
Instead of minimizing LLM validation loss, this loop maximizes detection coverage (TPR)
while minimizing false positives (FPR) against an adversarially expanding test corpus.

---

## The two-loop architecture

**Loop A (research):** An LLM generates detection rule variants. Each variant is evaluated
against the labeled corpus. The winner is committed. Repeat.

**Loop B (adversarial):** After each research cycle, a second LLM pass generates tool call
configurations designed to evade the current winning rule. Successful evasions become new
test cases. The corpus grows harder with each cycle.

The rules and the attacks co-evolve. Rules that survive 20 cycles have been stress-tested
against adversarially generated evasion attempts, not just the original labeled cases.

---

## The NDAA Section 1513 compliance angle

Every detection rule that ships from autoresearch has a run log showing:
- True positive rate against a documented test corpus
- False positive rate against a documented test corpus
- Number of adversarial evasion cases tested
- Timestamps and git commits for all optimization cycles

The experiment log IS the compliance audit trail. No separate documentation required.

```
python autoresearch.py --experiment credential_exposure --report
```

---

## Quick start

```bash
export ANTHROPIC_API_KEY=your-key

# List available experiments
python autoresearch/autoresearch.py --list

# Run credential exposure detection optimization (20 cycles, adversarial mode)
python autoresearch/autoresearch.py --experiment credential_exposure --cycles 20

# Run prompt injection detection (faster, no adversarial loop)
python autoresearch/autoresearch.py --experiment prompt_injection --cycles 10 --no-adversarial

# Generate NDAA compliance report from run log
python autoresearch/autoresearch.py --experiment credential_exposure --report
```

---

## Experiments

| Experiment | Threat Class | Cases | MITRE ATLAS |
|-----------|-------------|-------|-------------|
| `credential_exposure` | T19_CRED_ACCESS | 10 | AML.T0007 |
| `prompt_injection` | T27_PROMPT_INJECT | 8 | AML.T0051 |
| `overpermission` | T08_PROC_INJECT | 8 | AML.T0010 |

Each experiment contains:
- `config.json` -- threat ID, MITRE mapping, fitness weights
- `prompt.md` -- research directive for the LLM (the .md equivalent in Karpathy's pattern)
- `corpus.json` -- labeled test cases (grows with adversarial additions)
- `winning_rule.py` -- best rule code from last run (generated)
- `run_log.jsonl` -- timestamped cycle results (generated, NDAA audit trail)

---

## Adding a new experiment

1. Create `experiments/<name>/config.json` with `threat_id` and `mitre_atlas`
2. Create `experiments/<name>/prompt.md` with detection objective and evasion patterns
3. Create `experiments/<name>/corpus.json` with at least 4 positive and 4 negative cases
4. Run: `python autoresearch/autoresearch.py --experiment <name>`

The adversarial loop will expand the corpus automatically.

---

## Fitness function

```
fitness = TPR - (2.0 * FPR)
```

False positives are penalized twice as heavily as missed detections. This matches
the operational reality: a rule that blocks legitimate agent traffic creates
immediate friction, while a missed detection is less visible. The penalty weighting
can be adjusted per-experiment in `config.json`.

For federal/NDAA compliance use cases, consider setting `fpr_penalty` to 3.0 or higher.
