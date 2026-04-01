# Outreach DM — Callum McMahon (FutureSearch)
# Platform: Twitter/X DM or LinkedIn
# Send: after launch post lands today
# Context: He discovered the LiteLLM attack, wrote both blog posts, used Claude

---

Callum — you found the breach. The blog posts are the clearest technical writeup
of the attack. The fork bomb discovery story is the best possible explanation of
why this matters.

T81 PTH_FILE_INJECT in Aiglos fires the moment litellm_init.pth is written to
site-packages — before the first Python restart, before the first exfil.
The .pth file never executes. The credentials never leave the machine.

    aiglos scan-deps    # check if you're affected right now

The REPO_TAKEOVER_CHAIN campaign pattern also fires on the full sequence:
T30 (install) → T81 (.pth write) → T04 (cred harvest) → T41 (exfil) →
T30 again (attacker republishes with stolen GitHub/PyPI token).

You documented exactly the attack the taxonomy was built to catch.
Worth knowing about — no ask.

github.com/aiglos/aiglos

---

# Short version (DM)

You found the LiteLLM breach. T81 PTH_FILE_INJECT in Aiglos fires the moment
litellm_init.pth hits site-packages — before the first restart, before exfil.
aiglos scan-deps checks if you're affected. github.com/aiglos/aiglos
