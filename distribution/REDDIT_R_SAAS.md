# Post for r/SaaS

* **Subreddit**: [reddit.com/r/SaaS/submit](https://www.reddit.com/r/SaaS/submit)
* **Title**: `The silent bug that cost us paying customers on Stripe (and how we fixed it)`
* **Flair**: `Discussion` or `Case Study` or `Feedback`

---

### Post Body:

If you run a SaaS company using Stripe or LemonSqueezy, there is a silent edge-case that might be losing you paying customers without you ever seeing an error in your analytics.

### How it happens:
1. A customer clicks "Upgrade to Pro" ($49/mo or $299/yr) and completes checkout.
2. Stripe sends a `customer.subscription.created` webhook to your backend.
3. Your serverless function (Vercel/Next.js/AWS Lambda) hits a cold start while initializing the database connection pool, OR your container reboots during a zero-downtime deploy.
4. The request takes longer than Stripe's timeout threshold, or returns a transient 502.
5. Stripe flags the webhook as failed.

### The dangerous part: Stripe's retry schedule
Stripe does not retry immediately. It retries on an exponential schedule:
* Attempt 1: Failed
* Attempt 2: ~1 hour later
* Attempt 3: 4–12 hours later

In that multi-hour window, the customer logs into your app. Their account is still on the "Free Plan" because the provisioning webhook hasn't processed.

They assume your app is broken or a scam, cancel their subscription, and dispute the charge with their bank. You lose the customer, pay a $15 chargeback fee, and spend hours manually debugging Stripe logs.

### The Solution
We built an open-source tool to solve this once and for all: **HookArmor**
👉 GitHub: https://github.com/pkdoddamani/hookarmor

### How it works:
1. **Sub-10ms Ingress**: HookArmor sits in front of your webhook URL. It intercepts incoming Stripe/Shopify events, saves the raw payload durably in SQLite, and returns an immediate `200 OK` to Stripe so it never backs off.
2. **Signature Preserving Relay**: It forwards the event to your app while preserving raw bytes and cryptographic `Stripe-Signature` headers intact.
3. **Dead-Letter Queue & 1-Click Replay**: If your server returns 500 or times out, HookArmor quarantines the event, sends an instant Discord/Slack alert, and lets you 1-click replay all failed customer events into production the second your app recovers.
4. **Local Dev Tunnel**: `npx hookarmor listen http://localhost:3000/api/webhook` to replay real production events straight to localhost.

It’s 100% open-source (MIT licensed) and takes 30 seconds to run via Docker or `npx hookarmor start`.

Check out the code on GitHub: https://github.com/pkdoddamani/hookarmor

How are other SaaS founders currently monitoring failed payment webhooks? Would love to hear your setup.
