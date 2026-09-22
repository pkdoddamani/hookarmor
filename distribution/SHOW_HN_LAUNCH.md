# Show HN Launch Draft

## Submission Details
* **Title**: `Show HN: HookArmor – Zero-loss Dead-Letter Queue & 1-Click Replay for Stripe Webhooks`
* **URL**: `https://github.com/pkdoddamani/hookarmor` (or `https://hookarmor.tech` once live)

---

## Post Body

Hey HN,

I built **HookArmor** ([GitHub](https://github.com/pkdoddamani/hookarmor)) to solve an infuriating problem every SaaS developer encounters when integrating payment gateways like Stripe, Shopify, or Clerk: **silent webhook failures during deploys and cold starts**.

### The Problem
When your serverless functions (Next.js App Router, Vercel, AWS Lambda) experience cold starts, or when your containers restart during rolling zero-downtime deploys on Render/Fly.io, incoming webhook requests frequently return `502 Bad Gateway`, `504 Gateway Timeout`, or `500 ConnectionPoolTimeoutError`.

Stripe expects a fast 2xx response. When it gets a 5xx or timeout, it triggers an exponential backoff retry schedule:
* Attempt 1: immediate failure
* Attempt 2: ~1 hour later
* Attempt 3+: hours or days later

In that multi-hour gap:
1. A paying customer logs into your app.
2. Their account is still on the "Free Plan" because the provisioning webhook hasn't processed.
3. They assume they got scammed, file a support ticket, or immediately dispute the charge with their bank.
4. You have to open the Stripe Dashboard, copy raw JSON, reverse-engineer HMAC headers, and write a manual script to replay the event against production.

### How HookArmor Solves This
HookArmor is an open-source, lightweight Ingress Proxy, Dead-Letter Queue (DLQ), and Replay Gateway:

1. **Sub-10ms Ingress Buffer**: HookArmor intercepts the incoming webhook at the edge, persists the raw bytes durably into SQLite, and returns an immediate `200 OK` to Stripe/Shopify so the sender never enters retry backoff purgatory.
2. **Cryptographic HMAC Passthrough**: It proxies the raw byte payload to your actual backend while preserving all cryptographic verification headers (`Stripe-Signature`, `X-Shopify-Hmac-Sha256`, timestamps).
3. **Dead-Letter Quarantine**: If your backend server returns 500, 502, 504, 429, or times out, the exact raw body and error stack are preserved in durable storage with automatic exponential retry schedules.
4. **1-Click Bulk Replay**: As soon as you push your bug fix or database migration, hit **"Replay All Dead-Letter"** in the Web UI or run `npx hookarmor replay --failed` from your terminal to restore all dropped customer transactions in 2 seconds.
5. **Local Dev Forwarding**: Run `npx hookarmor listen http://localhost:3000/api/webhook` to stream production webhooks straight into your local IDE debugger with hot reloading.

### Technical Architecture
* **Stack**: Node.js, Fastify/Express, SQLite (`better-sqlite3`), WebSockets for real-time dashboard updates.
* **Open Source**: MIT licensed. Runs with 1 command (`npx hookarmor start` or `docker compose up -d`).
* **CI**: Automated test matrix across Node 18, 20, and 22.

We are launching the open-source engine today, with a hosted managed cloud tier coming soon.

Check out the code, run it locally, and let me know your thoughts:
GitHub: https://github.com/pkdoddamani/hookarmor

Would love to hear how you currently handle payment webhook failures in your stacks!
