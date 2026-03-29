# Launch Announcement — LiteLLM Incident Amendment
# INSERT THIS AS THE FIRST SECTION OF LAUNCH_ANNOUNCEMENT.md
# DATE: March 24, 2026 — The category-defining breach

---

## THE INCIDENT (March 24, 2026 — this week)

For months the launch announcement said: "The category-defining breach hasn't
happened yet. The company that owns behavioral detection when it does owns the
category for a decade."

It happened yesterday.

LiteLLM 1.82.7 and 1.82.8 shipped a .pth file — litellm_init.pth — that
executed on every Python startup, collected every credential on the machine,
and POSTed it to models.litellm.cloud. SSH keys. AWS/GCP/Azure credentials.
Kubernetes configs. Database passwords. .env files (all API keys). Shell
history. Crypto wallets. SSL private keys. CI/CD secrets.

97 million downloads per month. Transitive dependency for dspy, smolagents,
LangChain, LangGraph, CrewAI. Every agent framework we support.

The GitHub repository is now under attacker control. The security issue
was closed as "not planned" using the stolen maintainer GitHub token.

Discovered because the attacker vibe-coded a bug. The fork bomb crashed
Callum McMahon's Mac — 11,000+ Python processes, 100% CPU. Without the bug
it could have run undetected for weeks.

---

## WHAT AIGLOS WOULD HAVE CAUGHT

Five rules firing in sequence. The REPO_TAKEOVER_CHAIN campaign pattern:

T30 SUPPLY_CHAIN    → poisoned package installed via uvx/pip
T81 PTH_FILE_INJECT → litellm_init.pth written to site-packages (score 0.98)
T04 CRED_HARVEST    → SSH keys, .env, AWS credentials collected
T41 OUTBOUND_SECRET_LEAK → credentials POSTed to models.litellm.cloud
T01 EXFIL           → exfiltration confirmed

REPO_TAKEOVER_CHAIN campaign fires at confidence 0.97 on T81 + T04 in the
same session. The signed artifact would have shown every step with timestamps.

T81 PTH_FILE_INJECT fires the moment litellm_init.pth is written to
site-packages — before the first Python restart, before the first exfil.
The .pth file never executes. The credentials never leave.

---

## IMMEDIATE ACTION

    pip install aiglos && aiglos scan-deps

scan-deps checks:
  ✓ litellm 1.82.7 and 1.82.8 (and future compromised versions)
  ✓ litellm_init.pth in site-packages and uv cache
  ✓ ~/.config/sysmon/sysmon.py persistence file
  ✓ ~/.config/systemd/user/sysmon.service
  ✓ Transitive exposure (dspy, smolagents, LangChain, LangGraph, CrewAI)

If compromised: rotate SSH keys, cloud credentials, all .env API keys,
Kubernetes configs, database passwords, GitHub/PyPI tokens, CI/CD secrets.
Block at firewall: models.litellm.cloud

---

## TWEET VERSION

The category-defining breach just happened.

LiteLLM 1.82.8. 97M downloads/month.
A .pth file that ran on every Python startup.
SSH keys. AWS creds. Kubernetes configs. Every API key in .env.
Exfiltrated to models.litellm.cloud.

The GitHub repo is under attacker control.
The security issue was closed as "not planned" using the stolen maintainer token.

Aiglos T81 PTH_FILE_INJECT catches this at the moment the .pth file is written.
Before the first restart. Before the first exfil.

    pip install aiglos && aiglos scan-deps

Are you affected?
