# Aiglos Threat Intelligence Wiki — Schema

This file governs how the LLM maintains the Aiglos threat intelligence wiki.
It is the equivalent of CLAUDE.md for threat intel research.
The LLM reads this file at the start of every session and follows it exactly.

-----

## What This Wiki Is

A self-improving threat intelligence knowledge base that compiles raw security
intelligence into structured, interlinked wiki pages — and synthesizes that
intelligence into machine-readable rule proposals that feed directly into the
Aiglos T-rule threat engine.

This is not a document store. It is a research layer that makes the detection
layer smarter automatically.

The human’s job: source raw intelligence, review rule proposals, approve promotions.
The LLM’s job: everything else.

-----

## Directory Structure

```
aiglos/autoresearch/
├── SCHEMA.md          # This file. Never modify without human review.
├── wiki.py            # Core wiki engine: ingest, propose, lint, evolve
├── feeds.py           # Ingest connectors: NVD, GHSA, MITRE, RSS
│
├── raw/               # Immutable source material. LLM reads, never writes.
│   ├── cves/          # NVD CVE JSON records
│   ├── ghsa/          # GitHub Security Advisory records
│   ├── mitre/         # MITRE ATT&CK STIX bundles and update diffs
│   ├── incidents/     # Post-mortem reports, breach analyses
│   ├── research/      # Academic papers, security blog posts
│   └── frameworks/    # Agent framework architecture docs, changelogs
│
├── wiki/              # LLM-maintained markdown. LLM writes, human reads.
│   ├── INDEX.md       # Catalog of all wiki pages with one-line summaries
│   ├── LOG.md         # Append-only chronological record of all operations
│   ├── rules/         # One page per T-rule family: T01.md through T95.md
│   ├── campaigns/     # One page per campaign pattern
│   ├── frameworks/    # One page per monitored agent framework
│   ├── incidents/     # One page per documented real-world incident
│   ├── research/      # Synthesized research paper pages
│   ├── contradictions/ # Unresolved intel conflicts
│   └── proposals/     # Rule proposals awaiting human review
│
└── promoted/          # Rule proposals approved and promoted to threat engine
```

-----

## Page Types

Every wiki page begins with a YAML frontmatter block.
The LLM always writes frontmatter before prose content.

### T-Rule Page (`wiki/rules/T{N}.md`)

```yaml
---
type: rule
rule_id: T{N}
name: RULE_NAME_IN_CAPS
score: 0.00
critical: true|false
status: active|deprecated|proposed
citations: [list of raw/ file references]
related_rules: [T{N}, ...]
related_campaigns: [CAMPAIGN_NAME, ...]
last_updated: YYYY-MM-DD
intel_sources: [count of raw sources that informed this rule]
---
```

Content sections: Summary, Detection Logic, Real-World Validation,
Related Rules, Related Campaigns, Open Questions, Contradiction Log.

### Campaign Pattern Page (`wiki/campaigns/{NAME}.md`)

```yaml
---
type: campaign
name: CAMPAIGN_NAME_CHAIN
confidence: 0.00
rule_sequence: [T{N}, T{N}, ...]
status: active|deprecated|proposed
citations: [list of raw/ file references]
last_updated: YYYY-MM-DD
---
```

Content sections: Summary, Kill Chain, Rule Sequence, Amplifiers,
Corroborating Incidents, Variations, Open Questions.

### Framework Page (`wiki/frameworks/{name}.md`)

```yaml
---
type: framework
name: framework-name
version_tracked: "x.y.z"
attack_surface_score: 0.00
rules_covering: [T{N}, ...]
gaps: [list of unmonitored attack surfaces]
last_updated: YYYY-MM-DD
---
```

Content sections: Architecture Overview, Attack Surface Map,
Rules Coverage, Known Gaps, Recent Changes.

### Incident Page (`wiki/incidents/{slug}.md`)

```yaml
---
type: incident
slug: incident-slug
date: YYYY-MM-DD
severity: critical|high|medium|low
rules_validated: [T{N}, ...]
campaigns_validated: [CAMPAIGN_NAME, ...]
rules_proposed: [T{N}-PROPOSAL, ...]
sources: [raw/ file references]
---
```

Content sections: Summary, Attack Sequence, Rules Triggered,
Rules Proposed, Lessons Learned.

### Rule Proposal (`wiki/proposals/{slug}.md`)

```yaml
---
type: proposal
slug: proposal-slug
proposed_id: T{N}
name: PROPOSED_RULE_NAME
score_estimate: 0.00
critical_estimate: true|false
confidence: 0.00
supporting_sources: [count]
related_rules: [T{N}, ...]
extends: T{N}|null
replaces: T{N}|null
status: pending|approved|rejected
proposed_date: YYYY-MM-DD
reviewed_date: YYYY-MM-DD|null
---
```

Content sections: Detection Logic (natural language),
Supporting Evidence, Proposed match_T{N} Pseudocode,
Integration Notes, Reviewer Notes.

### Contradiction Page (`wiki/contradictions/{slug}.md`)

```yaml
---
type: contradiction
slug: contradiction-slug
rules_involved: [T{N}, ...]
sources_in_conflict: [raw/ file references]
status: unresolved|resolved|acknowledged
resolution: null|"description of resolution"
opened: YYYY-MM-DD
closed: YYYY-MM-DD|null
---
```

-----

## Operations

### INGEST

Triggered when a new file lands in raw/.

1. Read the source file fully.
1. Identify which existing rules (T01-T95) are relevant.
1. For each relevant rule page in wiki/rules/: update the page to reflect
   new supporting evidence, new detection nuances, or new contradictions.
1. If the source documents a real-world incident: create or update the
   incident page in wiki/incidents/.
1. If the source suggests a gap in existing rule coverage: create a draft
   proposal in wiki/proposals/ with status: pending.
1. Update wiki/campaigns/ pages if the source documents multi-step patterns.
1. Update wiki/frameworks/ if the source involves a monitored framework.
1. Update INDEX.md with any new pages created.
1. Append to LOG.md: `## [{date}] ingest | {source_slug} | rules_touched: {N} | proposals_created: {N}`

A single source typically touches 3-15 pages.
Do not create a new page for every source — synthesize into existing pages.
Create a new page only when a concept deserves its own canonical reference.

### PROPOSE

Triggered when INGEST identifies a coverage gap or when explicitly called.

A proposal is a structured recommendation to add or modify a T-rule.
It must contain:

- Detection logic in plain English precise enough for a developer to implement
- At least 2 corroborating sources from raw/
- A confidence score based on source corroboration and incident validation
- A proposed score estimate and critical flag
- A clear statement of what existing rule it extends or what gap it fills

Do not create proposals for edge cases with a single source.
Do not create proposals for attack vectors already covered by existing rules.
The bar for a proposal is: a developer reading it could write the match function.

### LINT

Triggered on a schedule (weekly by default) or when explicitly called.

Check for:

1. Rules with no incident citation in raw/ (flag as unvalidated)
1. Rules with citations older than 180 days and no newer corroborating source
1. Campaign patterns with fewer than 2 corroborating incidents
1. Framework pages not updated in 90 days (check for upstream changes)
1. Proposals pending more than 30 days with no reviewer notes
1. Contradiction pages unresolved for more than 60 days
1. INDEX.md entries without matching wiki/ files
1. Wiki pages referencing raw/ files that no longer exist

Output a lint report in wiki/LOG.md with counts per category.
Do not auto-fix lint issues — surface them for human review.

### EVOLVE

Triggered on heartbeat cycle (daily by default).

1. Check feeds.py sources for new CVEs, GHSAs, and MITRE updates.
1. For each new item: write to appropriate raw/ subdirectory.
1. Run INGEST on each new raw file.
1. Run LINT if more than 7 days since last lint.
1. Summarize in LOG.md: items ingested, pages updated, proposals created.

-----

## Cross-Referencing Conventions

Every wiki page uses `[[page-name]]` link syntax for cross-references.
The LLM maintains these links — when a page is updated, check that all
inbound links from other pages still point to accurate content.

Rule pages link to: incident pages, campaign pages, proposal pages.
Campaign pages link to: constituent rule pages, incident pages.
Incident pages link to: rule pages validated, proposal pages created.
Proposal pages link to: rule pages they extend, incident pages they cite.

-----

## Rule Proposal Promotion

When a human approves a proposal (sets status: approved in frontmatter):

1. Move the file from wiki/proposals/ to promoted/.
1. Add a LOG.md entry noting the promotion.
1. The threat engine developer uses the proposal content to implement the
   actual match function in aiglos/core/threat_engine_v2.py.

The wiki does not write threat engine code. It produces the research
artifact that informs the code. This boundary is intentional.

-----

## Lint Checklist (run before every EVOLVE)

- [ ] INDEX.md reflects all current wiki/ pages
- [ ] LOG.md last entry is within 25 hours
- [ ] No proposal has been pending more than 30 days without reviewer notes
- [ ] No contradiction has been unresolved more than 60 days
- [ ] All rule pages have at least one raw/ citation
- [ ] All campaign pages reference at least 2 incident pages

-----

## What This Wiki Is Not

This wiki is not a document retrieval system.
This wiki is not a chat interface.
This wiki is not a replacement for the threat engine.
This wiki does not write match functions.
This wiki does not approve its own proposals.
This wiki does not modify raw/ source files.

The wiki compiles intelligence into structured knowledge.
The threat engine executes that knowledge at runtime.
These are separate systems with a clean interface between them: the proposal.