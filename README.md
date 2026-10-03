# 🛡️ HookArmor

> **Zero-loss Webhook Dead-Letter Queue (DLQ), Reliability Proxy, and Replay Gateway for Stripe, Shopify, Clerk, and modern B2B SaaS.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Tests: Passing](https://img.shields.io/badge/Tests-34%20Passing-brightgreen.svg)]()
[![Status: Hardened](https://img.shields.io/badge/Status-v1.1.0-blueviolet.svg)]()

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

## 📊 Verification & Regression Test Suite

HookArmor includes a 34-scenario test suite covering core verification, replay re-signing, and 26 hardened regression scenarios:
```bash
npm test
```
```
🧪 Starting HookArmor Hardened Verification Test Suite (Post-Audit)...
  ✅ All 8 Integration & Boundary Tests Passed!

🧪 Starting HookArmor 26-Point Regression Test Suite (Hardening Verification)...
  ✅ Test 1: Retry timestamps properly due and parsed (SQLite datetime space format).
  ✅ Test 2: Dead-letter queue replayed successfully (Exhausted retries included).
  ✅ Test 3: In-flight crash recovery resets status to failed on startup.
  ✅ Test 4: Worker does not double-dispatch in-flight event during sweep.
  ✅ Test 5: 409 returned for concurrent in-flight replay.
  ✅ Test 6: Deduplication suppresses duplicates even for failed initial events.
  ✅ Test 7: Stripe secret rotation supported (Multiple v1 signatures).
  ✅ Test 8: Unsigned requests rejected on secured endpoints.
  ✅ Test 9: Svix/Clerk HMAC verified and re-signed.
  ✅ Test 10: Mode B internal signature requires verified flag.
  ✅ Test 11: Full SSRF address matrix blocked (IPv4, IPv6, CGNAT, int IPs).
  ✅ Test 12: Alert URL metadata SSRF blocked.
  ✅ Test 13: DNS lookup to loopback blocked.
  ✅ Test 14: Endpoints API is write-only for secrets.
  ✅ Test 15: Updating endpoint preserves existing secret.
  ✅ Test 16: WebSocket auth challenge verified.
  ✅ Test 17: Demo mode is strictly read-only for public.
  ✅ Test 18: Default wide-open CORS disabled.
  ✅ Test 19: 415 enforced on state-changing API routes.
  ✅ Test 20: Host header validation blocks DNS rebinding.
  ✅ Test 21: Production mode mandates API key on startup.
  ✅ Test 22: Mock targets disabled in production.
  ✅ Test 23: Waitlist IP rate limiting verified.
  ✅ Test 24: Dashboard XSS escaping and CSV sanitizer verified.
  ✅ Test 25: SQLite synchronous = FULL.
  ✅ Test 26: Retention pruning removes old delivered events and preserves failures.

🎉 ALL 34 HOOKARMOR TESTS PASSED CLEANLY!
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
* All management and inspection endpoints (`/api/stats`, `/api/endpoints`, `/api/events`, `/api/events/:id/replay`, `/api/events/replay-all`) strictly reject unauthenticated requests with `401 Unauthorized` and require `Authorization: Bearer <key>` or `X-Api-Key: <key>`.
* Ingress webhook receiving (`/in/:endpointId`) and public waitlist signups remain open for incoming traffic.
* Public read-only demo access can only be enabled if explicitly running with `HOOKARMOR_DEMO_MODE=true` (for isolated marketing sandboxes).
* Query parameter authentication (`?api_key=...`) is strictly prohibited to avoid leaking tokens into browser history and proxy access logs.
* The web dashboard displays an **Admin Login** prompt storing your key only in ephemeral session memory.

---

## 📄 License
MIT License. Created by the HookArmor Team.
