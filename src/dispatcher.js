const http = require('http');
const https = require('https');
const EventEmitter = require('events');
const Alerter = require('./alerter');

class Dispatcher extends EventEmitter {
  constructor(storage) {
    super();
    this.storage = storage;
    this.activeRetries = new Set();
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
    const startTime = Date.now();
    const targetUrl = endpoint.target_url;

    const headers = { ...event.headers };
    // Remove hop-by-hop headers and update host
    delete headers['host'];
    delete headers['connection'];
    delete headers['content-length'];

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
          timeout: 10000 // 10 second timeout
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
          req.destroy(new Error('Connection timed out after 10000ms'));
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
