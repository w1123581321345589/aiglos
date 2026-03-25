Got the full picture. The README has the right bones but is stale on every number and missing everything built in the last several sessions. Let me enumerate the gaps before writing:

**Stale:** badge says 1,690 tests (now 1,791), stats table says 77 rules / 20 campaigns (now 81 / 22), install CTA is `pip install aiglos` (should be `pip install aiglos && aiglos launch`), "The moment" section has no mention of LiteLLM.

**Missing entirely:** `aiglos launch`, `aiglos scan-deps`, `aiglos validate-prompt`, T78-T81, ByteRover integration, smolagents integration, LiteLLM supply chain incident as proof case, dual GTM framing, the "default OpenClaw is useless" angle, REPO_TAKEOVER_CHAIN campaign pattern.

Building now:484 lines. Here's what changed and why each decision was made.

---

**The opening.** The old README opened with "Every surface. Every session. Every belief" — a positioning line that says nothing to someone who just found the repo. The new one opens with the LiteLLM incident. That's the most urgent fact in the entire AI agent security space this week. Leading with it is honest, it's proof that the threat is real, and it makes `aiglos scan-deps` the immediate CTA rather than a buried CLI command.

**The stats table.** Updated from 77/20/4 to 81/22/15. The jump from 4 to 15 known agents is notable — that's the smolagents/AutoGen/LangGraph/CrewAI additions from the HF integration work. Numbers that are wrong erode trust with exactly the developers who will check them.

**The install CTA.** Changed from `pip install aiglos` to `pip install aiglos && aiglos launch`. The launch wizard is now the product. The CTA should reflect that.

**"Two reasons to install this."** The old README had one implicit reason. The new one states two explicitly — the breach already happened (T81 proof case) and the default OpenClaw problem (aiglos launch). Different audiences, different entry points, same repo. Security engineers come through the breach. Power users come through the setup wizard.

**Persistent Memory Protection gets its own section.** Gigabrain and ByteRover both launched in the same week, both have 30k+ downloads, both are the T79 attack surface made concrete. The previous README had no mention of either. A section with the one-liner for each backend is the right way to surface this.

**`scan-deps` and `validate-prompt` get their own sections.** These are now first-class CLI commands, not footnotes in a CLI reference list. The scan-deps output block is the most immediately useful thing in the entire README for anyone reading it today.

**T67-T81 table.** The old README stopped at T75 and called them "campaign-level and infrastructure threats." The new table names every rule from T67 onward with score and a one-line description. The T79 note explaining the T31/T79 distinction is there because it's the most technically important new concept and developers will ask about it.

**Build history table.** The old README had no version history. The new one shows the progression from v0.1.0 to v0.25.6 so anyone evaluating the project can see the pace and scope of development at a glance.

**Removed.** The verbose "What changed in v0.24" section explaining each individual T71-T75 rule addition. That level of detail belongs in a changelog, not the README. The README should answer "what is this and why does it matter" — changelogs answer "what changed."