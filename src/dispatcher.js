const http = require('http');
const https = require('https');
const crypto = require('crypto');
const EventEmitter = require('events');
const Alerter = require('./alerter');
const { checkUrl, guardedLookup } = require('./netguard');

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

// Svix (used by Clerk) secrets are "whsec_" + base64 key bytes
function svixKey(secret) {
  return Buffer.from(String(secret).replace(/^whsec_/, ''), 'base64');
}

function svixSignature(secret, msgId, timestamp, rawBody) {
  const hmac = crypto.createHmac('sha256', svixKey(secret));
  hmac.update(Buffer.from(`${msgId}.${timestamp}.`, 'utf8'));
  hmac.update(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody || ''), 'utf8'));
  return hmac.digest('base64');
}

const STRIPPED_INBOUND_HEADERS = new Set([
  'forwarded',
  'x-real-ip',
  'x-original-url',
  'x-rewrite-url',
  'x-http-method-override',
  'cf-connecting-ip',
  'true-client-ip',
  'proxy-authorization',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-forwarded-port',
  'x-forwarded-server',
  'x-forwarded-prefix',
  'x-forwarded-ssl'
]);

class Dispatcher extends EventEmitter {
  constructor(storage, options = {}) {
    super();
    this.storage = storage;
    this.defaultConcurrency = options.defaultConcurrency || 5;
    this.inFlightCount = new Map();
    this.waitQueues = new Map();
    this.defaultTimeoutMs = options.defaultTimeoutMs || 25000;
    this.strictSSRF = Boolean(options.strictSSRF);
    this.signingSecret = options.signingSecret || null;
    this.instanceId = options.instanceId || null;
    this.activeDeliveries = 0;
  }

  // Verify signature at ingress (preventing HookArmor from acting as an open signature oracle).
  // When a secret is configured, events without a supported signature scheme are rejected.
  static verifyIngressSignature(provider, rawBody, headers, secret, toleranceSec = 300) {
    if (!secret) return { valid: true };

    try {
      if (provider === 'stripe') {
        const sigHeader = headers['stripe-signature'];
        if (!sigHeader) return { valid: false, reason: 'Missing Stripe-Signature header' };

        // Stripe may send several v1 signatures (e.g. while a secret is being rolled)
        let timestampStr = null;
        const signatures = [];
        for (const item of sigHeader.split(',')) {
          const idx = item.indexOf('=');
          if (idx === -1) continue;
          const k = item.slice(0, idx).trim();
          const v = item.slice(idx + 1).trim();
          if (k === 't') timestampStr = v;
          if (k === 'v1' && v) signatures.push(v);
        }

        if (!timestampStr || signatures.length === 0) return { valid: false, reason: 'Malformed Stripe-Signature header' };

        const timestamp = parseInt(timestampStr, 10);
        const now = Math.floor(Date.now() / 1000);
        if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > toleranceSec) {
          return { valid: false, reason: `Timestamp outside tolerance (${toleranceSec}s)` };
        }

        const hmac = crypto.createHmac('sha256', secret);
        hmac.update(Buffer.from(`${timestampStr}.`, 'utf8'));
        hmac.update(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody || ''), 'utf8'));
        const expectedSig = hmac.digest('hex');

        if (!signatures.some((sig) => safeEqual(expectedSig, sig))) {
          return { valid: false, reason: 'Signature mismatch' };
        }
        return { valid: true };
      }

      if (provider === 'shopify') {
        const hmac = headers['x-shopify-hmac-sha256'];
        if (!hmac) return { valid: false, reason: 'Missing X-Shopify-Hmac-Sha256 header' };

        const expectedSig = crypto
          .createHmac('sha256', secret)
          .update(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody || ''), 'utf8'))
          .digest('base64');

        if (!safeEqual(expectedSig, hmac)) {
          return { valid: false, reason: 'Shopify HMAC mismatch' };
        }
        return { valid: true };
      }

      if (provider === 'github') {
        const sig = headers['x-hub-signature-256'];
        if (!sig) return { valid: false, reason: 'Missing X-Hub-Signature-256 header' };

        const expectedSig = 'sha256=' + crypto
          .createHmac('sha256', secret)
          .update(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody || ''), 'utf8'))
          .digest('hex');
        if (!safeEqual(expectedSig, sig)) {
          return { valid: false, reason: 'GitHub signature mismatch' };
        }
        return { valid: true };
      }

      if (provider === 'clerk/svix') {
        const msgId = headers['svix-id'];
        const timestampStr = headers['svix-timestamp'];
        const sigHeader = headers['svix-signature'];
        if (!msgId || !timestampStr || !sigHeader) {
          return { valid: false, reason: 'Missing svix-id, svix-timestamp or svix-signature header' };
        }

        const timestamp = parseInt(timestampStr, 10);
        const now = Math.floor(Date.now() / 1000);
        if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > toleranceSec) {
          return { valid: false, reason: `Timestamp outside tolerance (${toleranceSec}s)` };
        }

        const expectedSig = svixSignature(secret, msgId, timestampStr, rawBody);
        // Header is a space-separated list of "v1,<base64>" entries
        const matches = sigHeader.split(' ').some((entry) => {
          const [version, sig] = entry.split(',');
          return version === 'v1' && sig && safeEqual(expectedSig, sig);
        });
        if (!matches) return { valid: false, reason: 'Svix signature mismatch' };
        return { valid: true };
      }

      return { valid: false, reason: 'Endpoint has a secret but the request carries no supported signature (Stripe, Shopify, GitHub, Svix/Clerk)' };
    } catch (err) {
      return { valid: false, reason: err.message };
    }
  }

  // Fresh re-signing on forward/replay to defeat the 5-minute Stripe expiration trap
  signHeaders(provider, rawBody, headers, secret) {
    if (!secret) return headers;

    const modified = { ...headers };
    try {
      if (provider === 'stripe') {
        const freshTimestamp = Math.floor(Date.now() / 1000);
        const hmac = crypto.createHmac('sha256', secret);
        hmac.update(Buffer.from(`${freshTimestamp}.`, 'utf8'));
        hmac.update(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody || ''), 'utf8'));
        const freshSignature = hmac.digest('hex');
        modified['stripe-signature'] = `t=${freshTimestamp},v1=${freshSignature}`;
      } else if (provider === 'shopify') {
        const freshHmac = crypto
          .createHmac('sha256', secret)
          .update(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody || ''), 'utf8'))
          .digest('base64');
        modified['x-shopify-hmac-sha256'] = freshHmac;
      } else if (provider === 'github') {
        const freshSig = 'sha256=' + crypto
          .createHmac('sha256', secret)
          .update(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody || ''), 'utf8'))
          .digest('hex');
        modified['x-hub-signature-256'] = freshSig;
      } else if (provider === 'clerk/svix' && modified['svix-id']) {
        const freshTimestamp = String(Math.floor(Date.now() / 1000));
        modified['svix-timestamp'] = freshTimestamp;
        modified['svix-signature'] = `v1,${svixSignature(secret, modified['svix-id'], freshTimestamp, rawBody)}`;
      }
    } catch (e) {}

    return modified;
  }

  async acquireSlot(endpointId, limit) {
    const current = this.inFlightCount.get(endpointId) || 0;
    if (current < limit) {
      this.inFlightCount.set(endpointId, current + 1);
      return;
    }

    return new Promise(resolve => {
      if (!this.waitQueues.has(endpointId)) this.waitQueues.set(endpointId, []);
      this.waitQueues.get(endpointId).push(resolve);
    });
  }

  releaseSlot(endpointId, limit) {
    const queue = this.waitQueues.get(endpointId);
    if (queue && queue.length > 0) {
      const next = queue.shift();
      next();
    } else {
      const current = this.inFlightCount.get(endpointId) || 1;
      this.inFlightCount.set(endpointId, Math.max(0, current - 1));
    }
  }

  // Calculate exponential backoff with jitter: 30s, 2m, 10m, 30m, 2h
  calculateNextRetry(attempt) {
    const intervals = [30, 120, 600, 1800, 7200]; // seconds
    const base = intervals[Math.min(attempt, intervals.length - 1)];
    const jitter = Math.floor(Math.random() * (base * 0.2));
    const delaySec = base + jitter;
    // SQLite datetime format, so the worker's comparison against datetime('now') is correct
    return new Date(Date.now() + delaySec * 1000).toISOString().slice(0, 19).replace('T', ' ');
  }

  pendingDeliveries() {
    let queued = 0;
    for (const q of this.waitQueues.values()) {
      queued += q.length;
    }
    return this.activeDeliveries + queued;
  }

  async drain(timeoutMs = 15000) {
    const start = Date.now();
    while (this.pendingDeliveries() > 0) {
      if (Date.now() - start > timeoutMs) break;
      await new Promise(r => setTimeout(r, 100));
    }
    return this.pendingDeliveries() === 0;
  }

  // Callers must have claimed the event (status 'replaying') before dispatching
  async dispatch(event, endpoint, { replay = false } = {}) {
    const limit = endpoint.concurrency_limit || this.defaultConcurrency;
    await this.acquireSlot(endpoint.id, limit);
    this.activeDeliveries++;

    try {
      return await this._executeDispatch(event, endpoint, replay);
    } finally {
      this.activeDeliveries = Math.max(0, this.activeDeliveries - 1);
      this.releaseSlot(endpoint.id, limit);
    }
  }

  async _executeDispatch(event, endpoint, replay = false) {
    const startTime = Date.now();
    const targetUrl = endpoint.target_url;

    let headers = { ...event.headers };

    // Never forward sender-supplied HookArmor headers, spoofable routing headers,
    // or literal redaction placeholders from legacy rows saved before 1.2.3
    for (const [name, val] of Object.entries(headers)) {
      const lower = name.toLowerCase();
      if (
        lower.startsWith('x-hookarmor-') ||
        lower.startsWith('x-forwarded-') ||
        STRIPPED_INBOUND_HEADERS.has(lower) ||
        val === '[REDACTED]' ||
        val === '[ENCRYPTED]'
      ) {
        delete headers[name];
      }
    }

    // Preserve original raw signatures before re-signing for audit and forensic trace
    if (event.headers && event.headers['stripe-signature']) {
      headers['x-hookarmor-original-stripe-signature'] = event.headers['stripe-signature'];
    }
    if (event.headers && event.headers['x-shopify-hmac-sha256']) {
      headers['x-hookarmor-original-shopify-hmac'] = event.headers['x-shopify-hmac-sha256'];
    }
    if (event.headers && event.headers['svix-signature']) {
      headers['x-hookarmor-original-svix-signature'] = event.headers['svix-signature'];
    }

    const rawBuffer = Buffer.isBuffer(event.raw_body)
      ? event.raw_body
      : Buffer.from(String(event.raw_body || ''), 'utf8');

    // Re-sign outbound headers if endpoint secret is configured (Transparent Zero-Code-Change Mode)
    // Only re-sign if the inbound event was verified (prevents signature laundering F-01)
    if (endpoint.secret && event.verified) {
      headers = this.signHeaders(event.provider, rawBuffer, headers, endpoint.secret);
    }

    // Isolated Trust Domain mode: vouch only for events whose signature was verified at ingress
    if (this.signingSecret && event.verified) {
      const freshTs = Math.floor(Date.now() / 1000);
      const hmac = crypto.createHmac('sha256', this.signingSecret);
      hmac.update(Buffer.from(`${freshTs}.`, 'utf8'));
      hmac.update(rawBuffer);
      const internalSig = hmac.digest('hex');
      headers['x-hookarmor-signature'] = `t=${freshTs},v1=${internalSig}`;
    }

    // Strip provider signature headers if inbound event was unverified (N9 fix).
    // Prevents forwarding unverified cryptographic material downstream that could be accepted
    // under key rotation or shared secret environments.
    if (!event.verified) {
      for (const h of [
        'stripe-signature',
        'x-shopify-hmac-sha256',
        'x-shopify-topic',
        'x-hub-signature-256',
        'x-hub-signature',
        'svix-id',
        'svix-signature',
        'svix-timestamp',
        'clerk-signature'
      ]) {
        delete headers[h];
      }
      headers['x-hookarmor-unverified'] = 'true';
    }

    // Remove hop-by-hop and encoding headers
    delete headers['host'];
    delete headers['connection'];
    delete headers['content-length'];
    delete headers['content-encoding'];
    delete headers['transfer-encoding'];
    delete headers['expect'];

    headers['content-length'] = String(rawBuffer.length);
    headers['x-hookarmor-delivery-id'] = event.id;
    headers['x-hookarmor-attempt'] = String(event.attempts + 1);
    // Strict ISO-8601 UTC timestamp with Z to prevent client-side local timezone parsing skew
    const createdAtStr = String(event.created_at || '');
    const originalTimestamp = createdAtStr.includes('T')
      ? (createdAtStr.endsWith('Z') ? createdAtStr : `${createdAtStr}Z`)
      : (createdAtStr ? `${createdAtStr.replace(' ', 'T')}Z` : new Date().toISOString());
    headers['x-hookarmor-original-timestamp'] = originalTimestamp;
    const isReplay = replay || event.attempts > 0;
    headers['x-hookarmor-is-replay'] = isReplay ? 'true' : 'false';
    if (!event.verified) {
      headers['x-hookarmor-unverified'] = 'true';
    }

    // Merge custom destination headers configured on the endpoint (e.g. X-Api-Key)
    if (endpoint.custom_headers && typeof endpoint.custom_headers === 'object') {
      for (const [k, v] of Object.entries(endpoint.custom_headers)) {
        if (v !== undefined && v !== null && !STRIPPED_INBOUND_HEADERS.has(k.toLowerCase())) {
          headers[k.toLowerCase()] = String(v);
        }
      }
    }

    return new Promise((resolve) => {
      let settled = false;

      // Single exit point: every outcome records exactly one attempt and resolves exactly once
      const finish = async ({ statusCode = 0, responseBody = '', errorMessage = '' }) => {
        if (settled) return;
        settled = true;

        const latencyMs = Date.now() - startTime;
        const isSuccess = statusCode >= 200 && statusCode < 300;

        let nextRetryAt = null;
        if (!isSuccess && endpoint.auto_retry && (event.attempts + 1) < endpoint.max_retries) {
          nextRetryAt = this.calculateNextRetry(event.attempts);
        }

        const message = isSuccess ? '' : (errorMessage || `Destination returned HTTP ${statusCode}`);
        try {
          this.storage.recordAttempt({
            eventId: event.id,
            statusCode,
            responseBody,
            errorMessage: message,
            latencyMs,
            nextRetryAt
          });
        } catch (err) {
          console.error(`[Dispatcher] Failed to record attempt for ${event.id}:`, err.message);
          try { this.storage.releaseClaim(event.id); } catch (_) {}
        }

        const result = {
          eventId: event.id,
          endpointId: endpoint.id,
          success: isSuccess,
          statusCode,
          latencyMs,
          responseBody,
          errorMessage: message || undefined,
          nextRetryAt
        };

        this.emit('delivery', result);

        if (!isSuccess) {
          // Alert on initial failure and on final exhaustion to prevent notification flood (§6.6)
          const isFirstFailure = (event.attempts === 0);
          const isExhausted = !nextRetryAt;
          if (isFirstFailure || isExhausted) {
            await Alerter.sendAlert(endpoint.alert_webhook_url, {
              event,
              endpoint,
              attempt: { statusCode, errorMessage: message, latencyMs, isExhausted }
            }, { strictSSRF: this.strictSSRF });
          }
        }

        resolve(result);
      };

      try {
        const check = checkUrl(targetUrl, this.strictSSRF);
        if (!check.ok) {
          finish({ errorMessage: `Delivery blocked: ${check.reason}` });
          return;
        }

        const url = new URL(targetUrl);
        const isHttps = url.protocol === 'https:';
        const client = isHttps ? https : http;

        let gotResponse = false;
        const req = client.request(url, {
          method: 'POST',
          headers,
          timeout: this.defaultTimeoutMs,
          lookup: guardedLookup(this.strictSSRF)
        }, (res) => {
          gotResponse = true;
          let responseBody = '';
          res.setEncoding('utf8');
          res.on('data', chunk => {
            if (responseBody.length < 4000) {
              responseBody += chunk;
            }
          });
          res.on('end', () => finish({ statusCode: res.statusCode || 0, responseBody }));
          res.on('error', (err) => finish({ errorMessage: err.message }));
          res.on('aborted', () => finish({ errorMessage: 'Response aborted by destination' }));
          res.on('close', () => {
            if (!res.complete) finish({ errorMessage: 'Response closed before it completed' });
          });
        });

        req.on('timeout', () => {
          req.destroy(new Error(`Connection timed out after ${this.defaultTimeoutMs}ms`));
        });

        req.on('error', (err) => finish({ errorMessage: err.message }));
        req.on('close', () => {
          if (!gotResponse) finish({ errorMessage: 'Connection closed before a response was received' });
        });

        req.write(rawBuffer);
        req.end();
      } catch (err) {
        finish({ errorMessage: err.message });
      }
    });
  }

  async replayEvent(eventId) {
    const event = this.storage.getEvent(eventId);
    if (!event) {
      const err = new Error(`Event not found: ${eventId}`);
      err.code = 'NOT_FOUND';
      throw err;
    }
    const endpoint = this.storage.getEndpoint(event.endpoint_id);
    if (!endpoint) {
      const err = new Error(`Endpoint not found: ${event.endpoint_id}`);
      err.code = 'NOT_FOUND';
      throw err;
    }
    if (!this.storage.claimEventForManualReplay(eventId, this.instanceId)) {
      const err = new Error(`Event ${eventId} is already being delivered`);
      err.code = 'IN_FLIGHT';
      throw err;
    }

    return this.dispatch(event, endpoint, { replay: true });
  }

  // Claims every failed event (or specific ids if provided) and delivers
  // them in the background through the per-endpoint concurrency limiter.
  replayAllFailed(endpointIdOrOpts = null, batchSizeArg = 500, idsArg = null) {
    let endpointId = null;
    let batchSize = 500;
    let ids = null;

    if (endpointIdOrOpts && typeof endpointIdOrOpts === 'object' && !Array.isArray(endpointIdOrOpts)) {
      endpointId = endpointIdOrOpts.endpointId || null;
      batchSize = typeof endpointIdOrOpts.batchSize === 'number' ? endpointIdOrOpts.batchSize : (typeof endpointIdOrOpts.limit === 'number' ? endpointIdOrOpts.limit : 500);
      ids = Array.isArray(endpointIdOrOpts.ids) ? endpointIdOrOpts.ids : null;
    } else {
      endpointId = endpointIdOrOpts || null;
      batchSize = typeof batchSizeArg === 'number' ? batchSizeArg : 500;
      ids = Array.isArray(idsArg) ? idsArg : null;
    }

    const failedEvents = this.storage.getFailedEventsForReplay({ endpointId, limit: batchSize, ids });
    const claimed = [];
    for (const event of failedEvents) {
      const endpoint = this.storage.getEndpoint(event.endpoint_id);
      if (!endpoint || !this.storage.claimEventForRetry(event.id, this.instanceId)) continue;
      claimed.push(event.id);
      this.dispatch(event, endpoint, { replay: true }).catch((err) => {
        console.error(`[Dispatcher] Replay error for ${event.id}:`, err.message);
      });
    }
    return { replayedCount: claimed.length, eventIds: claimed, remaining: this.storage.countFailed(endpointId) };
  }
}

module.exports = Dispatcher;
