# 🛡️ HookArmor

> **Zero-loss Webhook Dead-Letter Queue (DLQ), Reliability Proxy, and Replay Gateway for Stripe, Shopify, Clerk, and modern B2B SaaS.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Tests: Passing](https://img.shields.io/badge/Tests-7%20Passing-brightgreen.svg)]()
[![Status: Production Ready](https://img.shields.io/badge/Status-v1.0.0-blueviolet.svg)]()

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
│  - Returns immediate 200 OK (<10ms)   │
│  - Stores raw payload in SQLite DLQ   │
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

1. **Sub-10ms Ingest**: HookArmor returns an immediate `200 OK` to the sender so Stripe or Shopify never marks the event failed.
2. **Cryptographic Header & Signature Preservation**: Forwards exact raw bytes, `stripe-signature`, `x-shopify-hmac-sha256`, and timestamps.
3. **Dead-Letter Queue (DLQ)**: If your server returns 500, 502, 504, 429, or times out, HookArmor safely preserves the raw event with full error diagnostics.
4. **Instant Alerts**: Sends immediate Slack / Discord webhooks when an endpoint begins failing.
5. **1-Click Bulk Replay**: As soon as you push your code fix, hit **Replay All Dead-Letter** in the Web UI or run `hookarmor replay --failed` to restore all customer transactions in 2 seconds.
6. **Local Dev Tunnel**: `hookarmor listen http://localhost:3000/api/webhooks` to replay production webhooks straight into localhost debuggers.

---

## 🚀 Quickstart

### 1-Click Cloud Deployment (Free & Self-Hosted)

Deploy your own private, persistent HookArmor instance to the cloud with one click:

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template?template=https://github.com/pkdoddamani/hookarmor)
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/pkdoddamani/hookarmor)

---

### Local Quickstart

#### Option A: Docker Compose (Zero Config)
```bash
git clone https://github.com/pkdoddamani/hookarmor.git
cd hookarmor
docker compose up -d
```

#### Option B: Terminal CLI
```bash
npx hookarmor start
```
* **Web Dashboard**: `http://localhost:4000`
* **Ingress Gateway**: `http://localhost:4000/in/:endpointId`

### 2. Tunnel Direct to Localhost
```bash
npx hookarmor listen http://localhost:3000/api/webhooks/stripe
```

### 3. Replay Failed Dead-Letter Events
```bash
# Replay all failed events across all endpoints
npx hookarmor replay --failed

# Replay a specific event ID
npx hookarmor replay evt_1758513516086_m8r0e7
```

---

## 📊 Verification Test Suite

HookArmor includes a 7-scenario automated verification test suite covering edge cases, replay re-signing, and pool protection:
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
     Re-signed on replay: t=1790143178 (Current) -> stripe.webhooks.constructEvent succeeds!

Test 4: Simulating Downstream Failure (500) -> Dead-Letter Queue...
  ✅ Event safely quarantined in Dead-Letter Queue with HTTP 500.
     Next automated retry scheduled with exponential backoff + jitter.

Test 5: Testing Background Retry Worker (Automatic Self-Healing)...
  ✅ Background Retry Worker automatically claimed and delivered DLQ event! (Attempts: 2)

Test 6: Testing Concurrency Limiting (Pool Protection)...
  ✅ Concurrency capped at max 2 parallel in-flight connections (pool protected).

Test 7: Testing Safe Idempotency Key Deduplication...
  ✅ Duplicate event intercepted and suppressed cleanly.

🎉 ALL 7 HARDENED HOOKARMOR VERIFICATION TESTS PASSED PERFECTLY!
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
   * Downstream handlers verify HookArmor as the internal sender, maintaining strict separation between external Stripe signatures and internal relay deliveries.

---

## ⚠️ Production Durability: The Early 200 OK Tradeoff

HookArmor returns an immediate `200 OK` to Stripe and Shopify in `<10ms` to protect your ingress latency and prevent providers from marking your endpoint failed during downstream outages.

**What this means for production operators:**
* Once HookArmor returns `200 OK`, Stripe considers the webhook delivered and **halts its external retry backup**.
* HookArmor's embedded SQLite database assumes **sole custody** of that event.
* **Persistent storage is mandatory:** When deploying via Docker, you must mount the data volume (`-v $(pwd)/data:/app/data`) and ensure host-level backups are active.

---

## 📦 Hosted Cloud & Self-Hosting

| Feature | Self-Hosted (MIT) | Hosted Cloud Starter ($29/mo) | Hosted Cloud Pro ($79/mo) |
|---|---|---|---|
| **Ingress Proxy & Buffer** | Unlimited | 50,000 events/mo | 500,000 events/mo |
| **Instant 200 OK Ack** | Yes (<10ms) | Yes (<10ms) | Yes (<10ms) |
| **Dead-Letter Queue (DLQ)** | Yes | Yes | Yes |
| **Stripe Signature Re-Signing** | Yes | Yes | Yes |
| **Background Auto-Retries** | Yes | Yes | Yes |
| **Concurrency Pool Limiter** | Yes | Yes | Yes |
| **Event Retention** | Local Disk | 30 days | 90 days |
| **Alerting** | Discord / Slack Webhook | Discord / Slack Webhook | Priority alerts + PagerDuty |
| **Infrastructure** | Your own server | Fully managed & redundant | Fully managed & redundant |

---

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

When `HOOKARMOR_API_KEY` is present:
* Management endpoints (`/api/endpoints`, `/api/events/replay-all`, and waitlist exports) strictly reject unauthenticated requests and require an `Authorization: Bearer <key>` header.
* Query parameter authentication (`?api_key=...`) is strictly prohibited to avoid leaking tokens into browser history and proxy access logs.
* The web dashboard displays an **Admin Login** prompt storing your key only in ephemeral session memory.

---

## 📄 License
MIT License. Created by the HookArmor Team.
