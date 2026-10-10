# 🛡️ HookArmor

> **Durable at-least-once Webhook Dead-Letter Queue (DLQ), Reliability Proxy, and Replay Gateway for Stripe, Shopify, Clerk, and modern B2B SaaS.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Tests: Passing](https://img.shields.io/badge/Tests-82%20Passing-brightgreen.svg)](https://github.com/pkdoddamani/hookarmor/actions)
[![Release: v1.3.0](https://img.shields.io/badge/Release-v1.3.0-blueviolet.svg)](https://github.com/pkdoddamani/hookarmor/releases/tag/v1.3.0)
[![npm version](https://img.shields.io/npm/v/hookarmor.svg?color=cb3837)](https://www.npmjs.com/package/hookarmor)

---

## 💥 The Problem HookArmor Solves

Every developer using Stripe, Shopify, GitHub, Clerk, Paddle, or custom webhooks faces catastrophic silent revenue loss when:
1. **Serverless cold starts & timeouts**: Next.js, Vercel, or AWS Lambda cold starts hit the 10-15s webhook limit.
2. **Zero-downtime deploy reboots**: Container restarts on Render, Railway, or Fly.io return transient `502 Bad Gateway`.
3. **Database connection pool exhaustion**: Prisma or Postgres locks during sudden traffic spikes cause unhandled `500 Internal Server Error`.
4. **Stripe's painful retry schedule**: When Stripe receives a failure, it backs off exponentially (1 hour, then several hours, then days). Meanwhile, your paying customer logs in, sees "Free Plan", assumes a scam, and disputes the charge or issues a refund.

---

## ⚡ How HookArmor Works

```
[Stripe / Shopify / Clerk]
            │ (POST webhook)
            ▼
┌───────────────────────────────────────┐
│        HookArmor Ingress Edge         │
│  - Returns immediate 200 OK           │
│  - Stores raw payload in SQLite WAL   │
└───────────────────┬───────────────────┘
                    │
                    ▼
┌───────────────────────────────────────┐
│        Relay Dispatch Engine          │
│  - Forwards request to user's server  │
│  - Preserves exact headers & HMAC sigs│
└───────┬───────────────────────┬───────┘
        │                       │
   (2xx Success)         (5xx / 4xx / Timeout)
        ▼                       ▼
┌───────────────┐       ┌─────────────────────────────────────┐
│ Event Archive │       │          Dead-Letter Queue          │
│ - Latency log │       │ - Capture error code & body         │
│ - Status 200  │       │ - Instant Discord / Slack Alert     │
│               │       │ - Smart exponential auto-retry      │
└───────────────┘       │ - 1-Click UI & CLI Replay Engine    │
                        └─────────────────────────────────────┘
```

1. **Immediate Durable Ingest**: HookArmor returns a `200 OK` once committed to durable SQLite storage so Stripe or Shopify never abandons the webhook.
2. **Cryptographic Header & Signature Preservation**: Forwards exact raw bytes, `stripe-signature`, `x-shopify-hmac-sha256`, and timestamps.
3. **Dead-Letter Queue (DLQ)**: If your server returns 500, 502, 504, 429, or times out, HookArmor safely preserves the raw event with full error diagnostics.
4. **Instant Alerts**: Sends immediate Slack / Discord webhooks when an endpoint begins failing.
5. **Webhook Disablement Sentinel**: Actively tracks consecutive delivery failure streaks per provider (Shopify 19-failure deletion cutoff, Razorpay 24h auto-disable cutoff) and dispatches tiered warnings before upstream subscriptions are cancelled or deleted, with automatic recovery notifications when restored.
6. **1-Click Bulk Replay**: As soon as you push your code fix, hit **Replay All Dead-Letter** in the Web UI or run `hookarmor replay --failed` to re-deliver customer transactions.
7. **Local Dev Relay**: `hookarmor listen http://localhost:3000/api/webhooks` to proxy webhooks straight into local dev servers with automatic re-signing.

---

## 🚀 Quickstart

### 1-Click Cloud Deployment (Free & Self-Hosted)

Deploy your own private, persistent HookArmor instance to the cloud with one click:

> **Before you deploy:** production instances refuse to start without `HOOKARMOR_API_KEY` (Render generates one automatically). Events live in SQLite under `/app/data`, so that path must be on persistent storage: Render's blueprint attaches a disk (paid `starter` plan, since free instances have no persistent disk), and on **Railway you must add a Volume mounted at `/app/data`** or every redeploy wipes the queue.

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template?template=https://github.com/pkdoddamani/hookarmor)
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/pkdoddamani/hookarmor)

---

### Local Quickstart

#### Option A: Docker Compose
```bash
git clone https://github.com/pkdoddamani/hookarmor.git
cd hookarmor
export HOOKARMOR_API_KEY=$(openssl rand -hex 32)   # required: protects the management API
docker compose up -d
```

#### Option B: Terminal CLI
```bash
npx hookarmor start
```
* **Web Dashboard**: `http://localhost:4000/dashboard`
* **Ingress Gateway**: `http://localhost:4000/in/:endpointId`

### 2. Tunnel Direct to Localhost
```bash
npx hookarmor listen http://localhost:3000/api/webhooks/stripe
```

### 3. Replay Failed Dead-Letter Events

Replaying a webhook is a state-changing operation that can trigger billing or email side-effects downstream. HookArmor safely shows you the event details and destination URL before prompting for confirmation:

```bash
# Preview event details and target URL (sensitive PII redacted), with confirmation prompt (y/N)
npx hookarmor replay evt_1758513516086_m8r0e7

# Display unredacted raw payload in terminal preview
npx hookarmor replay evt_1758513516086_m8r0e7 --show-payload

# Preview failed events (strictly bounded to batch size) before firing
npx hookarmor replay --failed --limit 50 --api-key "$HOOKARMOR_API_KEY"

# Dry-run: inspect event payload & destination without sending network requests
npx hookarmor replay evt_1758513516086_m8r0e7 --dry-run

# Non-interactive / CI mode: bypass confirmation prompt
npx hookarmor replay evt_1758513516086_m8r0e7 -y
```

---

## 📊 Verification Test Suite

HookArmor includes an 8-scenario verification suite (`test/verify.js`) plus a 67-case regression suite (`test/regression.js`) covering retry scheduling, crash recovery, multi-instance lease claims, cascading deletion, duplicate suppression, signature verification for every supported provider, outbound address validation, authentication, and dashboard escaping (**75 tests total**):
```bash
npm test
```
```
🧪 Starting HookArmor Hardened Verification Test Suite (Post-Audit)...

Test 1: Testing SSRF Protection & Endpoint Creation...
  ✅ SSRF probe against 169.254.169.254 successfully blocked.
  ✅ Valid endpoint created with secret.

Test 2: Testing Ingress Signature Verification (Security Boundary)...
  ✅ Forged signature rejected with 400 Bad Request.
  ✅ Authentic signature verified, ingested, and delivered.

Test 3: Testing 5-Minute Expiration Defeat (Fresh Outbound Re-Signing)...
  ✅ HookArmor defeated the 5-minute Stripe expiration trap:
     Stored in DB: t=1600000000 (Expired 5+ years ago)
     Re-signed on replay: t=1790970445 (Current) -> stripe.webhooks.constructEvent succeeds!
     Provenance verified: is-replay=true, orig-sig preserved.

Test 4: Simulating Downstream Failure (500) -> Dead-Letter Queue...
  ✅ Event safely quarantined in Dead-Letter Queue with HTTP 500.
     Next automated retry scheduled with exponential backoff + jitter.

Test 5: Testing Background Retry Worker (Automatic Self-Healing)...
  ✅ Background Retry Worker automatically claimed and delivered DLQ event! (Attempts: 2)

Test 6: Testing Concurrency Limiting (Pool Protection)...
  ✅ Concurrency capped at max 2 parallel in-flight connections (pool protected).

Test 7: Testing Safe Idempotency Key Deduplication...
  ✅ Duplicate event intercepted and suppressed cleanly.

Test 8: Testing API Key Authentication & Route Lockdown...
  ✅ Unauthenticated reads and replays rejected with 401.
  ✅ Bearer token and x-api-key headers validated with 200.
  ✅ Ingress gateway remains open for external webhook providers.

🎉 ALL 8 HARDENED HOOKARMOR VERIFICATION TESTS PASSED PERFECTLY!
```

---

## 🔒 Defeating the 5-Minute Stripe Signature Expiration Trap

Stripe's official SDK (`stripe.webhooks.constructEvent()`) enforces a strict 300-second (5-minute) tolerance on the `Stripe-Signature` timestamp `t=`.

If you retry a failed webhook 15 minutes later, or replay a dead-letter event tomorrow, **standard Stripe handlers will throw `Webhook signature verification failed`**.

HookArmor solves this automatically:
1. **Ingress verification**: Validates the signature at ingress using your webhook signing secret (preventing unauthorized payloads).
2. **Fresh re-signing on forward & replay**: When HookArmor delivers or replays the event, it re-signs the outbound payload using your secret with a current epoch timestamp `t=now`.
3. **Zero code changes**: Your existing backend handler code remains completely untouched and verifies 100% of the time.

---

## 🛡️ Provenance Headers & Out-of-Order Replay Protection

When replaying dead-letter events hours or days later, applying payloads out of order can accidentally clobber newer database state (e.g., an older `customer.subscription.updated` event overwriting a newer cancellation).

To protect downstream handlers against state drift, HookArmor injects explicit provenance headers on every forward and replay:

* `x-hookarmor-delivery-id`: Unique HookArmor event delivery ID.
* `x-hookarmor-attempt`: Current delivery attempt number (e.g., `1` on initial, `2+` on retries).
* `x-hookarmor-original-timestamp`: The exact ISO-8601 timestamp when the webhook originally arrived at the ingress edge.
* `x-hookarmor-is-replay`: Set to `'true'` during automated retries and manual dashboard replays (`'false'` on initial delivery).
* `x-hookarmor-original-stripe-signature`: Preserves the authentic original Stripe signature for audit logs and forensic verification.

**Recommended Downstream Handler Pattern:**
```javascript
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  // Standard verification passes 100% of the time
  const event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], endpointSecret);

  // If this is a replay, verify you are not clobbering newer database state:
  if (req.headers['x-hookarmor-is-replay'] === 'true') {
    const originalTime = new Date(req.headers['x-hookarmor-original-timestamp']).getTime();
    // Fetch latest object from Stripe API or check if local DB already has a newer updated_at timestamp
  }

  res.json({ received: true });
});
```

---

## 🏛️ Dual Trust Boundaries: Transparent vs. Isolated Mode

HookArmor supports two forwarding architectures depending on your team's security posture:

1. **Mode A: Transparent Proxy (Default · Zero Code Changes)**
   * HookArmor re-signs the outbound request using your provider secret with `t=now`.
   * Your existing application code (`stripe.webhooks.constructEvent()`) runs unmodified.
   * Original signatures are preserved in `x-hookarmor-original-stripe-signature`.

2. **Mode B: Isolated Trust Boundary (Enterprise Security)**
   * Set the `HOOKARMOR_SIGNING_SECRET` environment variable.
   * HookArmor attaches an isolated `x-hookarmor-signature: t=..., v1=...` HMAC header using your internal secret.
   * The header is only attached to events whose provider signature was **verified at ingress**, so the endpoint must have its provider secret configured. Events on endpoints without a secret are forwarded without it.
   * Downstream handlers verify HookArmor as the internal sender, maintaining strict separation between external Stripe signatures and internal relay deliveries.

---

## ⚠️ Production Durability: The Early 200 OK Tradeoff

HookArmor returns an immediate `200 OK` to Stripe and Shopify (sub-10ms when idle; measured p50 64ms, p90 153ms under concurrency 50 with `synchronous=FULL` fsync commits, sustaining ~360 events/s) to protect your ingress latency and prevent providers from marking your endpoint failed during downstream outages.

**What this means for production operators:**
* Once HookArmor returns `200 OK`, Stripe considers the webhook delivered and **halts its external retry backup**.
* HookArmor's embedded SQLite database assumes **sole custody** of that event.
* **Persistent storage is mandatory:** When deploying via Docker, you must mount the data volume (`-v $(pwd)/data:/app/data`) and ensure host-level backups are active.
* Every commit is fsynced (`synchronous=FULL`) before the `200 OK` is sent, so an acknowledged event survives a crash or power loss of the HookArmor host. It is still a single SQLite file on a single disk: back it up, and run one HookArmor process per database.
* If the process stops mid-delivery, those events are re-queued automatically on the next start.

---

## 🏗️ Architecture & Operational Scope

HookArmor is 100% free and open-source under the MIT license, architected specifically as a **single-node, low-footprint buffer and sidecar** for monolithic and containerized applications.

* **Single-Process Simplicity**: Operates entirely in a single Node.js process using embedded SQLite with Write-Ahead Logging (`WAL`) and `synchronous=FULL`. It consumes <50MB RAM and eliminates the operational overhead of running external message brokers (Kafka, RabbitMQ, SQS, or Redis).
* **Scope & Boundaries**: HookArmor is intended to run on the same VPS, container host, or private network cluster as your downstream web application. It is **not** a distributed multi-region cluster broker.
* **Persistent Disk Required**: Because events are durably acknowledged to providers with immediate fsync commits, your container volume (`/app/data`) must be backed by a persistent disk or volume mount.

---

## 📊 Prometheus & Grafana Metrics

HookArmor includes a native, zero-dependency Prometheus exposition endpoint at `GET /metrics`. When `HOOKARMOR_API_KEY` is configured, requests must supply the key via `Authorization: Bearer <key>` or `x-api-key`. Scrape this endpoint into your existing Prometheus or VictoriaMetrics instance to monitor webhook health:

```text
# Scraping: http://localhost:4000/metrics (Pass Authorization: Bearer <key> if enabled)
hookarmor_uptime_seconds 8432
hookarmor_events_total{status="delivered"} 1420
hookarmor_events_total{status="failed"} 12
hookarmor_events_total{status="pending"} 0
hookarmor_endpoints_total 4
hookarmor_endpoints_unverified_total 1
hookarmor_delivery_latency_ms_avg 34.2
```

---

## 🔒 Secret Encryption at Rest (AES-256-GCM)

By default, endpoint signing secrets are stored in SQLite. For hardened environments, set `HOOKARMOR_ENCRYPTION_KEY` to enable transparent **AES-256-GCM authenticated envelope encryption** at rest:

```bash
# Generate a 256-bit encryption key
openssl rand -hex 32

# Set in your environment:
export HOOKARMOR_ENCRYPTION_KEY=your_64_char_hex_key
```

When enabled, all provider webhook secrets are encrypted with a unique 96-bit random IV and 128-bit authentication tag before being written to disk (`enc:v1:iv:tag:ciphertext`), preventing secret extraction even if database files or backups are compromised.

## 🔐 Production Security & Admin Authentication

When running HookArmor locally on your laptop (`localhost`), management endpoints and the replay dashboard operate without authentication for fast developer onboarding.

> [!WARNING]
> **When deploying HookArmor to a public server or self-hosted cloud container (Railway, Render, VPS), you MUST set the `HOOKARMOR_API_KEY` environment variable.**

```bash
# Generate a strong 256-bit random key
openssl rand -hex 32

# Set in your production environment / Docker container:
HOOKARMOR_API_KEY=ha_sec_your_secure_random_key_here
```

When `HOOKARMOR_API_KEY` is **not** set, the management API only answers requests addressed to `localhost`, and the server refuses to start in production (`NODE_ENV=production`, Railway or Render) unless `HOOKARMOR_ALLOW_NO_AUTH=true`.

When `HOOKARMOR_API_KEY` is present:
* All management and inspection endpoints (`/api/stats`, `/api/endpoints`, `/api/events`, `/api/events/:id/replay`, `/api/events/replay-all`) strictly reject unauthenticated requests with `401 Unauthorized` and require `Authorization: Bearer <key>` or `X-Api-Key: <key>`.
* Ingress webhook receiving (`/in/:endpointId`) and public waitlist signups remain open for incoming traffic.
* Public demo access can only be enabled with `HOOKARMOR_DEMO_MODE=true` (for isolated marketing sandboxes) and is strictly read-only: replays always require the key.
* The live dashboard feed (`/ws`) only streams events after the client authenticates with the key.
* Endpoint signing secrets are write-only: the API reports `has_secret` but never returns the secret.
* Endpoints with a secret reject any request that does not carry a valid Stripe, Shopify, GitHub or Svix/Clerk signature.
* State-changing API calls must use `Content-Type: application/json`; CORS is disabled unless you list origins in `HOOKARMOR_CORS_ORIGINS`.
* Query parameter authentication (`?api_key=...`) is strictly prohibited to avoid leaking tokens into browser history and proxy access logs.
* The web dashboard displays an **Admin Login** prompt storing your key only in ephemeral session memory.

---

## ⚙️ Configuration

| Variable | Default | Purpose |
|---|---|---|
| `HOOKARMOR_API_KEY` | none (required in production) | Admin key for the management API, dashboard and CLI |
| `HOOKARMOR_ENCRYPTION_KEY` | none | 256-bit key enabling AES-256-GCM at-rest encryption for endpoint secrets |
| `HOOKARMOR_STRICT_SSRF` | `true` in production, `false` locally | Block loopback, private-network and link-local delivery targets (checked on the resolved IP at delivery time). Cloud metadata addresses are always blocked |
| `HOOKARMOR_SIGNING_SECRET` | none | Enables Mode B internal signatures |
| `HOOKARMOR_DATA_DIR` | `./data` (current directory) | Where `hookarmor.db` is stored |
| `HOOKARMOR_RETENTION_DAYS` | `0` (keep forever) | Delete delivered events older than this many days; failed events are always kept |
| `HOOKARMOR_MAX_BODY` | `10mb` | Maximum webhook body size |
| `HOOKARMOR_ENABLE_MOCK` | `false` in production | Mount the `/mock/*` simulation receiver |
| `HOOKARMOR_CORS_ORIGINS` | none | Comma-separated origins allowed to call `/api` from a browser |
| `HOOKARMOR_TRUST_PROXY` | `1` on Railway/Render | Express `trust proxy` setting, used for per-client rate limits |
| `HOOKARMOR_DEMO_MODE` | `false` | Read-only public demo |
| `HOOKARMOR_ALLOW_NO_AUTH` | `false` | Allow production start without an API key (trusted networks only) |

## 📦 Upgrade Notes (v1.1.0)

v1.1.0 includes core engine hardening, security perimeter lockdowns, and reliability enhancements. Please review the following behavior changes when upgrading:

1. **Mandatory Production API Key**: HookArmor refuses to start in `NODE_ENV=production` without `HOOKARMOR_API_KEY` unless `HOOKARMOR_ALLOW_NO_AUTH=true` is set.
2. **Strict Content-Type Enforced**: State-changing API routes (`POST`, `PUT`, `DELETE`) require `Content-Type: application/json`. Requests with missing or invalid content types receive HTTP `415 Unsupported Media Type`.
3. **Unsigned Webhooks Rejected on Secured Endpoints**: Ingress webhooks to endpoints configured with a signing secret now strictly require a recognized cryptographic signature header (`stripe-signature`, `x-shopify-hmac-sha256`, `x-hub-signature-256`, or `svix-signature`). Unsigned requests are rejected with HTTP 400.
4. **Mode B Internal Signatures**: Internal re-signing (`x-hookarmor-signature`) is now only attached to events verified at ingress.
5. **Non-blocking Replay-All**: `POST /api/events/replay-all` immediately claims up to 500 failed events and returns `{ replayedCount, eventIds, remaining }`, delivering them asynchronously in the background.
6. **Data Storage Directory**: Default database path is `./data` in current working directory (overridable with `HOOKARMOR_DATA_DIR`). Docker deployments using `/app/data` are unaffected.
7. **Root Route Behavior**: Self-hosted instances serve the interactive Dashboard at `/` by default. Set `HOOKARMOR_SERVE_LANDING=true` to serve the marketing landing page.
8. **Notification Throttling**: Alert webhooks trigger on the first delivery failure and upon final dead-letter queue exhaustion to eliminate alert flooding during outages.

---

## 📄 License
MIT License. Created by the HookArmor Team.
