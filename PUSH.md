# Push canonical repo to GitHub

The GitHub repo at https://github.com/w1123581321345589/aiglos has an older structure
(aiglos_core/, client/, server/). This local build is the canonical state.

## Option A: Force-push (replaces old repo entirely — recommended)

```bash
cd aiglos_full_repo/

# Init git if not already done
git init
git remote remove origin 2>/dev/null || true
git remote add origin https://github.com/w1123581321345589/aiglos.git

# Stage everything
git add -A

# Commit
git commit -m "chore: canonical repo — new homepage, T30 ClawHub scanner, autoresearch module, NDAA §1513 docs"

# Force push (replaces old structure)
git push -f origin main
```

## Option B: Merge push (if you want to preserve git history)

```bash
cd aiglos_full_repo/

# Pull old repo first
git init
git remote add origin https://github.com/w1123581321345589/aiglos.git
git fetch origin
git reset --hard origin/main   # start from old state
git checkout main

# Copy in new files
cp -r /path/to/new/files .

# Commit on top
git add -A
git commit -m "feat: new homepage, scan-skill CLI, autoresearch loop, NDAA docs"
git push origin main
```

## After pushing — wire Stripe (5 minutes)

Open `index.html` and replace these two lines at the top:
```js
const STRIPE_PAYG_PAYMENT_LINK = "STRIPE_PAYG_PAYMENT_LINK";
const STRIPE_PUBLISHABLE_KEY   = "STRIPE_PUBLISHABLE_KEY";
```

With your actual values from Stripe dashboard.

Then connect the repo to Netlify:
1. app.netlify.com → Add new site → Import from GitHub
2. Select w1123581321345589/aiglos
3. Build command: (leave empty)
4. Publish directory: .
5. Deploy

`/scan` → `website/scan.html` (ClawHub scanner)
`/docs` → GitHub
Both wired in netlify.toml already.

## What changed vs the old GitHub repo

Old structure:
  aiglos_core/autonomous/
  aiglos_embed/
  client/
  server/
  script/

New canonical structure:
  aiglos/            — Python package (pip install aiglos)
  aiglos/autonomous/ — T22–T36 modules including T30 registry monitor
  aiglos/autoresearch/ — LLM-driven detection rule evolution engine
  aiglos/core/       — scanner, gates, policy engine
  aiglos/integrations/ — OpenClaw, Hermes adapters
  tests/             — 61 passing tests
  website/           — scan.html, docs.html, demo.html, defense.html
  index.html         — NEW homepage (Space Grotesk, terminal animation, live feed, Grok comparison)
  netlify.toml       — /scan and /docs redirects wired
  DEPLOY.md          — 5-minute Stripe launch checklist
  docs/              — ndaa-1513.md, threat-map-atlas.md, autoresearch-applications.md
  cves/CVES.md       — full CVE database
  skills/            — openclaw/SKILL.md, hermes/SKILL.md
  pitch/             — KB_Memo.docx, AD deck, YC deck (excluded from git via .gitignore)
