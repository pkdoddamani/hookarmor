# 🛡️ HookArmor

> **Zero-loss Webhook Dead-Letter Queue (DLQ), Reliability Proxy, and Replay Gateway for Stripe, Shopify, Clerk, and modern B2B SaaS.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Tests: Passing](https://img.shields.io/badge/Tests-5%20Passing-brightgreen.svg)]()
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

HookArmor includes a 5-scenario automated verification test suite:
```bash
npm test
```
```
🧪 Starting HookArmor End-to-End Verification Test Suite...

Test 1: Creating endpoint "stripe-live"...
  ✅ Endpoint created successfully.

Test 2: Ingesting Stripe webhook with healthy destination (200 OK)...
  ✅ Ingress returned 200 OK in <10ms.
  ✅ Dispatcher successfully relayed payload and verified 200 response.

Test 3: Simulating downstream crash (500 Internal Server Error)...
  ✅ Event safely quarantined in Dead-Letter Queue with HTTP 500 status.
  ✅ Next retry scheduled with exponential backoff.

Test 4: Simulating server recovery (200 OK) and triggering Dead-Letter Replay...
  ✅ Dead-letter event successfully replayed! Status is now: delivered (Attempts: 2)

Test 5: Verifying aggregate metrics endpoint...
  ✅ Metrics verified: Total=2, Delivered=2, Dead-Letter=0, AvgLatency=8ms

🎉 ALL 5 HOOKARMOR VERIFICATION TESTS PASSED PERFECTLY!
```

---

## 💰 Monetization & The \$1M Valuation Target

* **Self-Hosted Open Source**: Free forever.
* **Starter Cloud (\$29/mo)**: 50k events/mo, 30-day retention, 5 endpoints, Slack & Discord alerts.
* **Scale Cloud (\$79/mo)**: 250k events/mo, 90-day retention, unlimited endpoints, automated circuit breakers.
* **Business Cloud (\$199/mo)**: 1M events/mo, custom domain (`webhooks.yourdomain.com`), 1-year audit logs.

**To reach \$1,000,000 valuation** (at 8x ARR software multiple):
* Target ARR: **\$125,000** (\$10,400 MRR).
* Customer requirement: **~200 paying accounts** across a global addressable market of >2,000,000 companies receiving Stripe/Shopify webhooks.

---

## 📄 License
MIT License. Created by the HookArmor Team.
