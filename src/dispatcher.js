const http = require('http');
const https = require('https');
const crypto = require('crypto');
const EventEmitter = require('events');
const Alerter = require('./alerter');
const { isPrivateOrMetadataUrl, guardedLookup } = require('./ssrf');

class Dispatcher extends EventEmitter {
  constructor(storage, options = {}) {
    super();
    this.storage = storage;
    this.defaultConcurrency = options.defaultConcurrency || 5;
    this.inFlightCount = new Map();
    this.waitQueues = new Map();
    this.defaultTimeoutMs = options.defaultTimeoutMs || 25000;
    this.strictSSRF = options.strictSSRF !== undefined
      ? options.strictSSRF
      : (process.env.HOOKARMOR_STRICT_SSRF === 'true');
  }

  // Verify signature at ingress (preventing HookArmor from acting as an open signature oracle)
  static verifyIngressSignature(provider, rawBody, headers, secret, toleranceSec = 300) {
    if (!secret) return { valid: true };

    try {
      if (provider === 'stripe' || headers['stripe-signature']) {
        const sigHeader = headers['stripe-signature'];
        if (!sigHeader) return { valid: false, reason: 'Missing Stripe-Signature header' };

        const v1Signatures = [];
        let timestamp = null;
        for (const item of sigHeader.split(',')) {
          const [k, v] = item.split('=');
          if (k && v) {
            const key = k.trim();
            const val = v.trim();
            if (key === 't') timestamp = parseInt(val, 10);
            if (key === 'v1') v1Signatures.push(val);
          }
        }

        if (!timestamp || v1Signatures.length === 0) {
          return { valid: false, reason: 'Malformed Stripe-Signature header' };
        }

        const now = Math.floor(Date.now() / 1000);
        if (Math.abs(now - timestamp) > toleranceSec) {
          return { valid: false, reason: `Timestamp outside tolerance (${Math.abs(now - timestamp)}s > ${toleranceSec}s)` };
        }

        const expectedSig = crypto
          .createHmac('sha256', secret)
          .update(`${timestamp}.${rawBody}`)
          .digest('hex');

        const expectedBuf = Buffer.from(expectedSig);
        const matched = v1Signatures.some(sig => {
          const actualBuf = Buffer.from(sig);
          return expectedBuf.length === actualBuf.length && crypto.timingSafeEqual(expectedBuf, actualBuf);
        });

        if (!matched) {
          return { valid: false, reason: 'Signature mismatch' };
        }
        return { valid: true };
      }

      if (provider === 'shopify' || headers['x-shopify-hmac-sha256']) {
        const hmac = headers['x-shopify-hmac-sha256'];
        if (!hmac) return { valid: false, reason: 'Missing X-Shopify-Hmac-Sha256 header' };

        const expectedSig = crypto
          .createHmac('sha256', secret)
          .update(rawBody)
          .digest('base64');

        const expectedBuf = Buffer.from(expectedSig);
        const actualBuf = Buffer.from(hmac);
        if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
          return { valid: false, reason: 'Shopify HMAC mismatch' };
        }
        return { valid: true };
      }

      if (provider === 'github' || headers['x-hub-signature-256']) {
        const sig = headers['x-hub-signature-256'];
        if (!sig) return { valid: false, reason: 'Missing X-Hub-Signature-256 header' };

        const expectedSig = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
        const expectedBuf = Buffer.from(expectedSig);
        const actualBuf = Buffer.from(sig);
        if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
          return { valid: false, reason: 'GitHub signature mismatch' };
        }
        return { valid: true };
      }

      if (provider === 'clerk/svix' || headers['svix-id'] || headers['svix-signature'] || headers['clerk-signature']) {
        const svixId = headers['svix-id'];
        const svixTimestamp = headers['svix-timestamp'];
        const svixSigHeader = headers['svix-signature'] || headers['clerk-signature'];
        if (!svixId || !svixTimestamp || !svixSigHeader) {
          return { valid: false, reason: 'Missing required Svix/Clerk signature headers (svix-id, svix-timestamp, svix-signature)' };
        }

        const timestamp = parseInt(svixTimestamp, 10);
        const now = Math.floor(Date.now() / 1000);
        if (Math.abs(now - timestamp) > toleranceSec) {
          return { valid: false, reason: `Timestamp outside tolerance (${Math.abs(now - timestamp)}s > ${toleranceSec}s)` };
        }

        const secretBytes = secret.startsWith('whsec_')
          ? Buffer.from(secret.slice(6), 'base64')
          : Buffer.from(secret, 'utf8');

        const expectedSig = crypto
          .createHmac('sha256', secretBytes)
          .update(`${svixId}.${svixTimestamp}.${rawBody}`)
          .digest('base64');
        const expectedBuf = Buffer.from(expectedSig);

        const signatures = svixSigHeader.split(' ').map(s => s.startsWith('v1,') ? s.slice(3) : s);
        const matched = signatures.some(sig => {
          const actualBuf = Buffer.from(sig);
          return expectedBuf.length === actualBuf.length && crypto.timingSafeEqual(expectedBuf, actualBuf);
        });

        if (!matched) {
          return { valid: false, reason: 'Svix signature mismatch' };
        }
        return { valid: true };
      }

      // If an endpoint has a secret configured, reject any unsupported or unsigned requests
      return { valid: false, reason: 'Endpoint requires signature verification, but no supported signature header was provided' };
    } catch (err) {
      return { valid: false, reason: err.message };
    }
  }

  // Fresh re-signing on forward/replay to defeat the 5-minute Stripe expiration trap
  signHeaders(provider, rawBody, headers, secret) {
    if (!secret) return headers;

    const modified = { ...headers };
    try {
      if (provider === 'stripe' || modified['stripe-signature']) {
        const freshTimestamp = Math.floor(Date.now() / 1000);
        const freshSignature = crypto
          .createHmac('sha256', secret)
          .update(`${freshTimestamp}.${rawBody}`)
          .digest('hex');
        modified['stripe-signature'] = `t=${freshTimestamp},v1=${freshSignature}`;
      } else if (provider === 'shopify' || modified['x-shopify-hmac-sha256']) {
        const freshHmac = crypto
          .createHmac('sha256', secret)
          .update(rawBody)
          .digest('base64');
        modified['x-shopify-hmac-sha256'] = freshHmac;
      } else if (provider === 'github' || modified['x-hub-signature-256']) {
        const freshSig = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
        modified['x-hub-signature-256'] = freshSig;
      } else if (provider === 'clerk/svix' || modified['svix-id'] || modified['svix-signature'] || modified['clerk-signature']) {
        const freshTimestamp = Math.floor(Date.now() / 1000);
        const svixId = modified['svix-id'] || `msg_${Date.now()}`;
        const secretBytes = secret.startsWith('whsec_')
          ? Buffer.from(secret.slice(6), 'base64')
          : Buffer.from(secret, 'utf8');
        const freshSig = crypto
          .createHmac('sha256', secretBytes)
          .update(`${svixId}.${freshTimestamp}.${rawBody}`)
          .digest('base64');
        modified['svix-id'] = svixId;
        modified['svix-timestamp'] = String(freshTimestamp);
        modified['svix-signature'] = `v1,${freshSig}`;
        if (modified['clerk-signature']) {
          modified['clerk-signature'] = `v1,${freshSig}`;
        }
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
    return new Date(Date.now() + delaySec * 1000).toISOString().slice(0, 19).replace('T', ' ');
  }

  async dispatch(event, endpoint) {
    const limit = endpoint.concurrency_limit || this.defaultConcurrency;
    await this.acquireSlot(endpoint.id, limit);

    try {
      return await this._executeDispatch(event, endpoint);
    } finally {
      this.releaseSlot(endpoint.id, limit);
    }
  }

  async _executeDispatch(event, endpoint) {
    const startTime = Date.now();
    const targetUrl = endpoint.target_url;

    // Check SSRF before initiating connection
    if (isPrivateOrMetadataUrl(targetUrl, this.strictSSRF)) {
      const blockMsg = `Outbound delivery blocked: targetUrl targets restricted/private network (${targetUrl})`;
      const latencyMs = Date.now() - startTime;
      this.storage.recordAttempt({
        eventId: event.id,
        statusCode: 0,
        responseBody: '',
        errorMessage: blockMsg,
        latencyMs
      });
      const result = {
        eventId: event.id,
        endpointId: endpoint.id,
        success: false,
        statusCode: 0,
        latencyMs,
        errorMessage: blockMsg
      };
      this.emit('delivery', result);
      return result;
    }

    let headers = { ...event.headers };

    // Strip incoming spoofed x-hookarmor-* headers
    for (const key of Object.keys(headers)) {
      if (key.toLowerCase().startsWith('x-hookarmor-')) {
        delete headers[key];
      }
    }

    // Preserve original raw signatures before re-signing for audit and forensic trace
    if (event.headers && event.headers['stripe-signature']) {
      headers['x-hookarmor-original-stripe-signature'] = event.headers['stripe-signature'];
    }
    if (event.headers && event.headers['x-shopify-hmac-sha256']) {
      headers['x-hookarmor-original-shopify-hmac'] = event.headers['x-shopify-hmac-sha256'];
    }
    if (event.headers && (event.headers['svix-signature'] || event.headers['clerk-signature'])) {
      headers['x-hookarmor-original-svix-signature'] = event.headers['svix-signature'] || event.headers['clerk-signature'];
    }

    // Re-sign outbound headers if endpoint secret is configured (Transparent Zero-Code-Change Mode)
    if (endpoint.secret) {
      headers = this.signHeaders(event.provider, event.raw_body, headers, endpoint.secret);
    }

    // Isolated Trust Domain mode: only attach internal signature if event was verified at ingress
    const internalSecret = process.env.HOOKARMOR_SIGNING_SECRET;
    if (internalSecret && event.verified) {
      const freshTs = Math.floor(Date.now() / 1000);
      const internalSig = crypto.createHmac('sha256', internalSecret).update(`${freshTs}.${event.raw_body}`).digest('hex');
      headers['x-hookarmor-signature'] = `t=${freshTs},v1=${internalSig}`;
    }

    // Remove hop-by-hop and encoding headers
    delete headers['host'];
    delete headers['connection'];
    delete headers['content-length'];
    delete headers['content-encoding'];
    delete headers['transfer-encoding'];

    const rawBuffer = Buffer.from(event.raw_body, 'utf8');
    headers['content-length'] = rawBuffer.length;
    headers['x-hookarmor-delivery-id'] = event.id;
    headers['x-hookarmor-attempt'] = String(event.attempts + 1);
    headers['x-hookarmor-original-timestamp'] = event.created_at;
    const isReplay = (event.attempts > 0 || event.status === 'replaying');
    headers['x-hookarmor-is-replay'] = isReplay ? 'true' : 'false';

    return new Promise((resolve) => {
      let settled = false;
      const settle = (result) => {
        if (settled) return;
        settled = true;
        this.emit('delivery', result);
        resolve(result);
      };

      try {
        const url = new URL(targetUrl);
        const isHttps = url.protocol === 'https:';
        const client = isHttps ? https : http;

        const reqOptions = {
          method: 'POST',
          headers,
          timeout: this.defaultTimeoutMs
        };
        if (this.strictSSRF) {
          reqOptions.lookup = guardedLookup;
        }

        let resReceived = false;
        const req = client.request(url, reqOptions, (res) => {
          resReceived = true;
          let responseBody = '';
          res.setEncoding('utf8');
          res.on('data', chunk => {
            if (responseBody.length < 4000) {
              responseBody += chunk;
            }
          });

          res.on('end', () => {
            const latencyMs = Date.now() - startTime;
            const statusCode = res.statusCode || 0;
            const isSuccess = statusCode >= 200 && statusCode < 300;

            let nextRetryAt = null;
            if (!isSuccess && endpoint.auto_retry && (event.attempts + 1) < endpoint.max_retries) {
              nextRetryAt = this.calculateNextRetry(event.attempts);
            }

            this.storage.recordAttempt({
              eventId: event.id,
              statusCode,
              responseBody,
              errorMessage: isSuccess ? '' : `Destination returned HTTP ${statusCode}`,
              latencyMs,
              nextRetryAt
            });

            const result = {
              eventId: event.id,
              endpointId: endpoint.id,
              success: isSuccess,
              statusCode,
              latencyMs,
              responseBody,
              nextRetryAt
            };

            settle(result);

            if (!isSuccess && endpoint.alert_webhook_url) {
              Alerter.sendAlert(endpoint.alert_webhook_url, {
                event,
                endpoint,
                attempt: { statusCode, errorMessage: `HTTP ${statusCode}`, latencyMs }
              }).catch(() => {});
            }
          });

          res.on('error', (err) => {
            const latencyMs = Date.now() - startTime;
            let nextRetryAt = null;
            if (endpoint.auto_retry && (event.attempts + 1) < endpoint.max_retries) {
              nextRetryAt = this.calculateNextRetry(event.attempts);
            }
            this.storage.recordAttempt({
              eventId: event.id,
              statusCode: 0,
              responseBody: '',
              errorMessage: err.message,
              latencyMs,
              nextRetryAt
            });
            settle({
              eventId: event.id,
              endpointId: endpoint.id,
              success: false,
              statusCode: 0,
              latencyMs,
              errorMessage: err.message,
              nextRetryAt
            });
          });

          res.on('close', () => {
            if (!res.complete && !settled) {
              const latencyMs = Date.now() - startTime;
              this.storage.recordAttempt({
                eventId: event.id,
                statusCode: 0,
                responseBody: '',
                errorMessage: 'Connection closed prematurely before response completed',
                latencyMs
              });
              settle({
                eventId: event.id,
                endpointId: endpoint.id,
                success: false,
                statusCode: 0,
                latencyMs,
                errorMessage: 'Connection closed prematurely before response completed'
              });
            }
          });
        });

        req.on('timeout', () => {
          req.destroy(new Error(`Connection timed out after ${this.defaultTimeoutMs}ms`));
        });

        req.on('error', (err) => {
          const latencyMs = Date.now() - startTime;
          let nextRetryAt = null;
          if (endpoint.auto_retry && (event.attempts + 1) < endpoint.max_retries) {
            nextRetryAt = this.calculateNextRetry(event.attempts);
          }

          this.storage.recordAttempt({
            eventId: event.id,
            statusCode: 0,
            responseBody: '',
            errorMessage: err.message,
            latencyMs,
            nextRetryAt
          });

          const result = {
            eventId: event.id,
            endpointId: endpoint.id,
            success: false,
            statusCode: 0,
            latencyMs,
            errorMessage: err.message,
            nextRetryAt
          };

          settle(result);

          if (endpoint.alert_webhook_url) {
            Alerter.sendAlert(endpoint.alert_webhook_url, {
              event,
              endpoint,
              attempt: { statusCode: 0, errorMessage: err.message, latencyMs }
            }).catch(() => {});
          }
        });

        req.on('close', () => {
          if (!resReceived && !settled) {
            const latencyMs = Date.now() - startTime;
            this.storage.recordAttempt({
              eventId: event.id,
              statusCode: 0,
              responseBody: '',
              errorMessage: 'Request socket closed prematurely before response received',
              latencyMs
            });
            settle({
              eventId: event.id,
              endpointId: endpoint.id,
              success: false,
              statusCode: 0,
              latencyMs,
              errorMessage: 'Request socket closed prematurely before response received'
            });
          }
        });

        req.write(rawBuffer);
        req.end();
      } catch (err) {
        const latencyMs = Date.now() - startTime;
        this.storage.recordAttempt({
          eventId: event.id,
          statusCode: 0,
          responseBody: '',
          errorMessage: err.message,
          latencyMs
        });

        settle({
          eventId: event.id,
          endpointId: endpoint.id,
          success: false,
          statusCode: 0,
          latencyMs,
          errorMessage: err.message
        });
      }
    });
  }

  async replayEvent(eventId) {
    const event = this.storage.getEvent(eventId);
    if (!event) {
      const err = new Error(`Event not found: ${eventId}`);
      err.statusCode = 404;
      throw err;
    }
    const endpoint = this.storage.getEndpoint(event.endpoint_id);
    if (!endpoint) {
      const err = new Error(`Endpoint not found: ${event.endpoint_id}`);
      err.statusCode = 404;
      throw err;
    }

    const claimed = this.storage.claimEventForManualReplay(eventId);
    if (!claimed) {
      const err = new Error(`Event ${eventId} is already in flight`);
      err.statusCode = 409;
      throw err;
    }

    const claimedEvent = this.storage.getEvent(eventId);
    return this.dispatch(claimedEvent, endpoint);
  }

  async replayAllFailed(endpointId = null) {
    const failedEvents = this.storage.getFailedEventsToRetry(endpointId);
    const claimedEvents = [];
    for (const event of failedEvents) {
      const claimed = this.storage.claimEventForRetry(event.id);
      if (claimed) {
        claimedEvents.push(event);
      }
    }

    const results = [];
    for (const event of claimedEvents) {
      const endpoint = this.storage.getEndpoint(event.endpoint_id);
      if (endpoint) {
        const freshEvent = this.storage.getEvent(event.id);
        const res = await this.dispatch(freshEvent, endpoint);
        results.push(res);
      }
    }
    return results;
  }
}

module.exports = Dispatcher;
