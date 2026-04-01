Full picture. The README is 731 lines and stops at v0.19.0. It needs: updated stats (66 → 75 rules, 13 → 18 triggers, 10 → 19 campaigns, 1300 → 1514 tests), five new sections (Superpowers, GOVBENCH, lockdown policy, GHSA watcher, ATLAS coverage), updated threat engine table through T75, three GHSA entries in the CVE table, and v0.20–v0.24 changelog entries. Writing the full updated README now.Done. 571 lines, everything verified present.

**What changed from the old README:**

The badge row updated from 66 threat families / 1300 tests / 17 triggers to **75 / 1514 / 18 triggers / 19 campaign patterns**. The nav link row got four additions: Superpowers, GOVBENCH, Lockdown policy, GHSA intel, ATLAS coverage.

**Five new sections** inserted after the quickstart code:

The Superpowers section explains T69 PLAN_DRIFT, phase-aware detection, the TDD loop recognition, and the SUPERPOWERS_PLAN_HIJACK campaign pattern. Ends with the positioning line that doubles as the README mention Jesse gets.

The GOVBENCH section has the five dimensions with weights, the grade threshold table, and the benchmark run commands. The framing: "published before any standard body required one."

The Lockdown policy section covers the deny-first tier, explicit tool grants, the permission recommender CLI, and the policy tier reference table. Includes the baseline reset workflow that belongs with hardening.

The GHSA intelligence section has the 3/3 coverage output block, the watcher mechanics, the mitsuhiko callout, and the scan-exposed command.

The ATLAS coverage section has the full formatted coverage output showing all 22 threats with tactic grouping and rule assignments. Ends with the note about prompt injection being out of scope in OpenClaw SECURITY.md but covered by Aiglos.

**Threat engine table** updated from T01-T39 to T01-T75, with every new rule family in the right row.

**CVE/GHSA table** now has all three published advisories at the top with CVSS scores and rule assignments.

**Attestation table** has four new fields: `policy_grants` (lockdown grant log), `superpowers_session` (plan hash, phase history), `govbench_score` (grade + dimension breakdown), plus the existing `extensions.*` fields.

**Pricing** updated from $39 to $49/dev/mo, GOVBENCH and Superpowers integration added to the free tier list.

**Changelog** has clean one-line entries for v0.20-v0.24 at the top, with the older releases compressed to single-line summaries below v0.19.

**Footer** updated to include `intel` and `changelog` links pointing to the new site pages.