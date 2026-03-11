# Aiglos Repository Manifest

## Package — `aiglos/`
| File | Description |
|------|-------------|
| `aiglos/__init__.py` | Public API: `attach()` / `check()` / `on_heartbeat()` / `close()` |
| `aiglos/__main__.py` | `python -m aiglos demo\|version\|check` entry point |
| `aiglos/core/__init__.py` | Core package init (embedded SDK surface) |
| `aiglos/core/attest.py` | RSA-2048 attestation artifact generator |
| `aiglos/core/gates.py` | Feature gate enforcement (free/pro/enterprise tiers) |
| `aiglos/core/licensing.py` | License management and tier validation |
| `aiglos/core/interceptor.py` | In-process MCP call interceptor (monkey-patch mode) |
| `aiglos/core/scanner.py` | Fast-path inline threat scanner (<1ms, no network) |
| `aiglos/core/metering.py` | Usage metering client (cloud telemetry, Pro+) |
| `aiglos/core/config.py` | Embedded SDK configuration |
| `aiglos/integrations/openclaw.py` | OpenClaw guard — T1-T36 detection, heartbeat, sub-agents |
| `aiglos/integrations/hermes.py` | hermes-agent guard — T1-T36 + trajectory signing |
| `aiglos/autonomous/engine.py` | Autonomous hunt engine — continuous background scan |
| `aiglos/autonomous/t30_registry.py` | T30 registry monitor — continuous supply chain watch |
| `aiglos/autonomous/t34_data_agent.py` | T34 data agent monitor — agentic data pipeline security |
| `aiglos/autonomous/t35_personal_agent.py` | T35 personal agent monitor — OpenClaw/Clawdbot surface |
| `aiglos_cli.py` | CLI manifest + architecture map (all 36 T-numbers) |

## Tests — `tests/`
| File | Coverage |
|------|----------|
| `tests/test_core.py` | 40 tests: both integrations, module API, demos |
| `tests/test_licensing.py` | License tier validation and gate enforcement |
| `tests/test_t34.py` | T34 heartbeat tamper detection |
| `tests/test_t35.py` | T35 personal agent threat surface |
| `tests/test_t36.py` | T36 memory poisoning detection |

## Website — `website/`
| File | Description |
|------|-------------|
| `index.html` | Main landing page (v7, dark aesthetic) |
| `pricing.html` | Pricing tiers |
| `defense.html` | Defense / federal market page |
| `docs.html` | Documentation |
| `threats.html` | Threat class browser |
| `changelog.html` | Public changelog |
| `success.html` | Post-checkout success page |
| `dashboard.jsx` | React dashboard component (ClawdGuard → Aiglos) |
| `demo.html` | Interactive pitch demo |
| `supernova-plan.html` | Supernova launch plan |

## Netlify — `netlify/`
| File | Description |
|------|-------------|
| `netlify.toml` | Netlify deploy config |
| `netlify/functions/create-checkout-session.js` | Stripe checkout |
| `netlify/functions/stripe-webhook.js` | Stripe webhook handler |
| `netlify/functions/signup.js` | Email signup / waitlist |

## Skills — `skills/`
| File | Description |
|------|-------------|
| `skills/openclaw/SKILL.md` | OpenClaw ClawHub publish-ready SKILL.md |
| `skills/hermes/SKILL.md` | hermes-agent agentskills.io SKILL.md |

## Docs — `docs/`
| File | Description |
|------|-------------|
| `docs/ndaa-1513.md` | NDAA §1513 compliance guide |
| `docs/threat-map-atlas.md` | Full MITRE ATLAS cross-reference (all 36 T-numbers) |
| `docs/clawhub-publish-notes.md` | ClawHub publish checklist + narrative |
| `docs/clawhub-strategy.md` | ClawHub distribution strategy |
| `docs/DEPLOY.md` | Deployment guide |
| `docs/llm-instructions.txt` | LLM integration instructions |

## CVEs — `cves/`
| File | Description |
|------|-------------|
| `cves/CVES.md` | 10 published CVEs (T07, T13, T19, T30, T34, T36) |

## Pitch — `pitch/`
| File | Description |
|------|-------------|
| `Aiglos_AD_Updated.pptx` | American Dynamism deck (latest) |
| `Aiglos_YC_Deck.pptx` | YC application deck |
| `Aiglos_Seed_Deck_v2.pptx` | Seed round deck |
| `Aiglos_KB_Memo.docx` | Katherine Boyle / a16z memo |
| `Aiglos_InvestorMemo_v15.docx` | Investor memo (latest) |
| `Aiglos_Augmentation_Brief.docx` | Defense augmentation brief |
| `Aiglos_Supernova_Plan.docx` | Supernova launch plan |
| `ClawdGuard_Origin_Pitch.pptx` | Origin pitch (ClawdGuard era) |

## Dist — `dist/`
Pre-built Python packages ready for PyPI publish.
| File | Description |
|------|-------------|
| `aiglos-0.1.0-py3-none-any.whl` | Wheel |
| `aiglos-0.1.0.tar.gz` | Source distribution |

## Legacy — `legacy/`
| File | Description |
|------|-------------|
| `ClawdGuard_PitchDemo.html` | Original ClawdGuard interactive demo |
