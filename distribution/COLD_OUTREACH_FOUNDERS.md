# 1-to-1 Cold Outreach Templates

## Target Audience
* Indie founders & CTOs launching new SaaS products on Product Hunt, Twitter/X, and Indie Hackers.
* Engineering leads at B2B companies processing payments via Stripe, LemonSqueezy, or Shopify.

---

### Template 1: The "Cold Start / Deploy Webhook" Angle (Email / DM)

**Subject**: Quick question about your Stripe webhook failover setup

Hey [Name],

Saw your launch for [Product] on [Platform]—congrats on shipping!

Quick question: how are you handling Stripe webhook failures during rolling deploys or cold starts?

We kept seeing founders lose customer activations when Next.js/Vercel functions timed out during subscription events (and Stripe backed off for 3+ hours).

We built an open-source tool called **HookArmor** ([github.com/pkdoddamani/hookarmor](https://github.com/pkdoddamani/hookarmor)) that buffers webhooks at the edge in <10ms, catches 5xx errors in a Dead-Letter Queue, and lets you 1-click replay failed events into production once your server recovers.

It's MIT open-source and runs with `npx hookarmor start`. Would love to know if you've hit this issue, or if having a hosted cloud failover endpoint would be useful for [Product].

Best,  
[Your Name]  
HookArmor Team

---

### Template 2: Twitter / LinkedIn Direct Message (Short)

Hey [Name], noticed you're building [Product] on Stripe!

Quick heads-up: if you ever run into Stripe webhooks timing out or failing during deploys (leaving paying users stuck on free tier while Stripe backs off), check out our open-source Dead-Letter Queue tool: https://github.com/pkdoddamani/hookarmor

It buffers incoming webhooks in <10ms and gives you 1-click replay for any dropped payment events. Free & open-source—hope it helps save some support tickets!
