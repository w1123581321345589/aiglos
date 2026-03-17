# Aiglos Federation Server

The network effect that makes Aiglos compound. Every contributing deployment
makes the global Markov prior stronger. New deployments warm-start from the
collective intelligence of every deployment that came before.

## Deploy in 60 seconds (Railway)

```bash
# One-click Railway deploy
railway login
railway up

# Set environment variables in Railway dashboard:
#   AIGLOS_MASTER_KEY   -- admin API key (generate with: openssl rand -hex 32)
#   SUPABASE_URL        -- your Supabase project URL
#   SUPABASE_SERVICE_KEY -- Supabase service role key
```

## Deploy with Docker

```bash
docker build -t aiglos-fed -f server/Dockerfile .
docker run -p 8000:8000 \
  -e AIGLOS_MASTER_KEY=your_key \
  -e SUPABASE_URL=https://xxx.supabase.co \
  -e SUPABASE_SERVICE_KEY=your_service_key \
  aiglos-fed
```

## Local development

```bash
cd server
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Open `http://localhost:8000/docs` for the interactive API docs.

## Supabase setup

Run this SQL in your Supabase project:

```sql
create table contributions (
  id             uuid default gen_random_uuid() primary key,
  received_at    timestamptz default now(),
  approx_sessions int not null,
  vocab_size     int not null,
  epsilon        float not null,
  aiglos_version text not null default 'unknown'
);

create table global_priors (
  id              serial primary key,
  prior_version   text not null unique,
  trained_at      float not null,
  n_deployments   int not null,
  transitions_json text not null,
  vocab_json      text not null,
  created_at      timestamptz default now()
);

create table api_keys (
  key_hash    text primary key,
  tier        text not null default 'free',
  created_at  timestamptz default now(),
  revoked     boolean default false
);

-- RLS: service role bypasses all policies
alter table contributions enable row level security;
alter table global_priors enable row level security;
alter table api_keys enable row level security;
```

## API reference

| Endpoint | Auth | Tier | Description |
|----------|------|------|-------------|
| `GET /v1/health` | None | -- | Liveness check |
| `GET /v1/status` | None | -- | Public stats |
| `GET /v1/prior` | Bearer key | Free + Pro | Download global prior |
| `POST /v1/contribute` | Bearer key | Pro only | Submit transition counts |

## Privacy model

The server stores only:
- Aggregated noisy transition counts (not per-deployment)
- Integer contribution count
- Last update timestamp

The client applies Laplace noise (epsilon=0.1) before submitting.
The server applies additional Gaussian noise (sigma=0.5) before broadcasting.
Nothing traceable to a specific deployment is ever stored.

## Connecting your Aiglos deployment

```python
import aiglos

aiglos.attach(
    agent_name       = "my-agent",
    enable_federation = True,
    api_key          = "ak_live_your_pro_key",
    endpoint         = "https://intel.aiglos.dev",   # or your self-hosted URL
)
```

Free tier (pull only):
```python
aiglos.attach(
    agent_name       = "my-agent",
    enable_federation = True,
    api_key          = "ak_free_your_free_key",
)
```
