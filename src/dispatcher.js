const http = require('http');
const https = require('https');
const crypto = require('crypto');
const EventEmitter = require('events');
const Alerter = require('./alerter');

class Dispatcher extends EventEmitter {
  constructor(storage, options = {}) {
    super();
    this.storage = storage;
    this.defaultConcurrency = options.defaultConcurrency || 5;
    this.inFlightCount = new Map();
    this.waitQueues = new Map();
    this.defaultTimeoutMs = options.defaultTimeoutMs || 25000;
  }

  // Verify signature at ingress (preventing HookArmor from acting as an open signature oracle)
  static verifyIngressSignature(provider, rawBody, headers, secret, toleranceSec = 300) {
    if (!secret) return { valid: true };

    try {
      if (provider === 'stripe') {
        const sigHeader = headers['stripe-signature'];
        if (!sigHeader) return { valid: false, reason: 'Missing Stripe-Signature header' };

        const parts = sigHeader.split(',').reduce((acc, item) => {
          const [k, v] = item.split('=');
          if (k && v) acc[k.trim()] = v.trim();
          return acc;
        }, {});

        if (!parts.t || !parts.v1) return { valid: false, reason: 'Malformed Stripe-Signature header' };

        const timestamp = parseInt(parts.t, 10);
        const now = Math.floor(Date.now() / 1000);
        if (Math.abs(now - timestamp) > toleranceSec) {
          return { valid: false, reason: `Timestamp outside tolerance (${Math.abs(now - timestamp)}s > ${toleranceSec}s)` };
        }

        const expectedSig = crypto
          .createHmac('sha256', secret)
          .update(`${parts.t}.${rawBody}`)
          .digest('hex');

        const expectedBuf = Buffer.from(expectedSig);
        const actualBuf = Buffer.from(parts.v1);
        if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
          return { valid: false, reason: 'Signature mismatch' };
        }
        return { valid: true };
      }

      if (provider === 'shopify') {
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

      if (provider === 'github') {
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

      return { valid: true };
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
        const freshSignature = crypto
          .createHmac('sha256', secret)
          .update(`${freshTimestamp}.${rawBody}`)
          .digest('hex');
        modified['stripe-signature'] = `t=${freshTimestamp},v1=${freshSignature}`;
      } else if (provider === 'shopify') {
        const freshHmac = crypto
          .createHmac('sha256', secret)
          .update(rawBody)
          .digest('base64');
        modified['x-shopify-hmac-sha256'] = freshHmac;
      } else if (provider === 'github') {
        const freshSig = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
        modified['x-hub-signature-256'] = freshSig;
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
    return new Date(Date.now() + delaySec * 1000).toISOString();
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

    let headers = { ...event.headers };

    // Re-sign outbound headers if endpoint secret is configured
    if (endpoint.secret) {
      headers = this.signHeaders(event.provider, event.raw_body, headers, endpoint.secret);
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

    return new Promise((resolve) => {
      try {
        const url = new URL(targetUrl);
        const isHttps = url.protocol === 'https:';
        const client = isHttps ? https : http;

        const req = client.request(url, {
          method: 'POST',
          headers,
          timeout: this.defaultTimeoutMs
        }, (res) => {
          let responseBody = '';
          res.setEncoding('utf8');
          res.on('data', chunk => {
            if (responseBody.length < 4000) {
              responseBody += chunk;
            }
          });

          res.on('end', async () => {
            const latencyMs = Date.now() - startTime;
            const statusCode = res.statusCode || 0;
            const isSuccess = statusCode >= 200 && statusCode < 300;

            let nextRetryAt = null;
            if (!isSuccess && endpoint.auto_retry && (event.attempts + 1) < endpoint.max_retries) {
              nextRetryAt = this.calculateNextRetry(event.attempts);
            }

            const updatedEvent = this.storage.recordAttempt({
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

            this.emit('delivery', result);

            if (!isSuccess) {
              await Alerter.sendAlert(endpoint.alert_webhook_url, {
                event,
                endpoint,
                attempt: { statusCode, errorMessage: `HTTP ${statusCode}`, latencyMs }
              });
            }

            resolve(result);
          });
        });

        req.on('timeout', async () => {
          req.destroy(new Error(`Connection timed out after ${this.defaultTimeoutMs}ms`));
        });

        req.on('error', async (err) => {
          const latencyMs = Date.now() - startTime;
          let nextRetryAt = null;
          if (endpoint.auto_retry && (event.attempts + 1) < endpoint.max_retries) {
            nextRetryAt = this.calculateNextRetry(event.attempts);
          }

          const updatedEvent = this.storage.recordAttempt({
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

          this.emit('delivery', result);

          await Alerter.sendAlert(endpoint.alert_webhook_url, {
            event,
            endpoint,
            attempt: { statusCode: 0, errorMessage: err.message, latencyMs }
          });

          resolve(result);
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

        const result = {
          eventId: event.id,
          endpointId: endpoint.id,
          success: false,
          statusCode: 0,
          latencyMs,
          errorMessage: err.message
        };

        this.emit('delivery', result);
        resolve(result);
      }
    });
  }

  async replayEvent(eventId) {
    const event = this.storage.getEvent(eventId);
    if (!event) throw new Error(`Event not found: ${eventId}`);
    const endpoint = this.storage.getEndpoint(event.endpoint_id);
    if (!endpoint) throw new Error(`Endpoint not found: ${event.endpoint_id}`);

    return this.dispatch(event, endpoint);
  }

  async replayAllFailed(endpointId = null) {
    const failedEvents = this.storage.getFailedEventsToRetry(endpointId);
    const results = [];
    for (const event of failedEvents) {
      const endpoint = this.storage.getEndpoint(event.endpoint_id);
      if (endpoint) {
        const res = await this.dispatch(event, endpoint);
        results.push(res);
      }
    }
    return results;
  }
}

module.exports = Dispatcher;
