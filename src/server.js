const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { WebSocketServer, WebSocket } = require('ws');

const Storage = require('./storage');
const Dispatcher = require('./dispatcher');
const RetryWorker = require('./worker');
const { checkUrl } = require('./netguard');

const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
const ENDPOINT_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

const SENSITIVE_INBOUND_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'api-key'
]);

function redactInboundHeaders(headers) {
  if (!headers || typeof headers !== 'object') return {};
  const clean = { ...headers };
  for (const name of Object.keys(clean)) {
    if (SENSITIVE_INBOUND_HEADERS.has(name.toLowerCase())) {
      clean[name] = '[REDACTED]';
    }
  }
  return clean;
}

function envFlag(name) {
  const v = process.env[name];
  if (v === undefined || v === '') return undefined;
  return v === 'true' || v === '1';
}

function hostnameOf(hostHeader = '') {
  const h = String(hostHeader).toLowerCase();
  if (h.startsWith('[')) return h.slice(0, h.indexOf(']') + 1);
  return h.split(':')[0];
}

function clampInt(value, fallback, min, max) {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(n, min), max);
}

// Fixed-window in-memory rate limiter keyed by client IP
function createRateLimiter({ limit, windowMs }) {
  const hits = new Map();
  return (key) => {
    const now = Date.now();
    if (hits.size > 10000) {
      for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k);
    }
    const entry = hits.get(key);
    if (!entry || entry.resetAt <= now) {
      hits.set(key, { count: 1, resetAt: now + windowMs });
      return true;
    }
    entry.count++;
    return entry.count <= limit;
  };
}

function publicEndpoint(ep) {
  if (!ep) return ep;
  const { secret, custom_headers, ...rest } = ep;
  let maskedHeaders = {};
  if (custom_headers && typeof custom_headers === 'object') {
    for (const [k, v] of Object.entries(custom_headers)) {
      if (SENSITIVE_INBOUND_HEADERS.has(k.toLowerCase())) {
        maskedHeaders[k] = '••••••••';
      } else {
        maskedHeaders[k] = v;
      }
    }
  }
  return { ...rest, custom_headers: maskedHeaders, has_secret: Boolean(secret) };
}

function createServer(options = {}) {
  const isProduction = options.production !== undefined
    ? options.production
    : Boolean(process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT || process.env.RENDER);
  const apiKey = options.apiKey || process.env.HOOKARMOR_API_KEY || null;
  const isDemoMode = options.demoMode !== undefined
    ? options.demoMode
    : (process.env.HOOKARMOR_DEMO_MODE === 'true');
  const allowNoAuth = options.allowNoAuth !== undefined ? options.allowNoAuth : envFlag('HOOKARMOR_ALLOW_NO_AUTH') === true;
  // Strict outbound address checks default on in production (block loopback/private networks)
  const strictSSRF = options.strictSSRF !== undefined
    ? options.strictSSRF
    : (envFlag('HOOKARMOR_STRICT_SSRF') !== undefined ? envFlag('HOOKARMOR_STRICT_SSRF') : isProduction);
  const mockEnabled = options.enableMock !== undefined
    ? options.enableMock
    : (envFlag('HOOKARMOR_ENABLE_MOCK') !== undefined ? envFlag('HOOKARMOR_ENABLE_MOCK') : !isProduction);
  const corsOrigins = options.corsOrigins || (process.env.HOOKARMOR_CORS_ORIGINS
    ? process.env.HOOKARMOR_CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean)
    : []);
  const maxBody = options.maxBodySize || process.env.HOOKARMOR_MAX_BODY || '10mb';
  const retentionDays = options.retentionDays !== undefined
    ? options.retentionDays
    : clampInt(process.env.HOOKARMOR_RETENTION_DAYS, 30, 0, 3650);
  const maxPendingEvents = options.maxPendingEvents !== undefined
    ? options.maxPendingEvents
    : clampInt(process.env.HOOKARMOR_MAX_PENDING_EVENTS, 50000, 100, 1000000);

  if (isProduction && !apiKey && !allowNoAuth) {
    throw new Error(
      'HOOKARMOR_API_KEY is required in production: without it the management API (events, endpoints, replays) is open to anyone. ' +
      'Generate one with `openssl rand -hex 32`. Set HOOKARMOR_ALLOW_NO_AUTH=true only if the instance is not reachable from untrusted networks.'
    );
  }

  const app = express();
  const server = http.createServer(app);

  app.disable('x-powered-by');

  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none';"
    );
    const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
    if (isHttps) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
  });

  const trustProxy = process.env.HOOKARMOR_TRUST_PROXY || ((process.env.RAILWAY_ENVIRONMENT || process.env.RENDER) ? '1' : null);
  if (trustProxy) app.set('trust proxy', /^\d+$/.test(trustProxy) ? parseInt(trustProxy, 10) : trustProxy);

  const storage = new Storage(options.dbPath, {
    encryptionKey: options.encryptionKey || process.env.HOOKARMOR_ENCRYPTION_KEY
  });

  const instanceId = options.instanceId || `inst_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  storage.registerInstance({
    id: instanceId,
    hostname: require('os').hostname(),
    pid: process.pid
  });

  const recovered = storage.recoverInterruptedDeliveries(instanceId);
  if (recovered > 0) {
    console.warn(`[HookArmor] Re-queued ${recovered} event(s) that were mid-delivery when the process last stopped.`);
  }

  // Fail-fast verification: ensure all endpoint secrets can be read with the active encryption key
  storage.assertSecretsReadable(Boolean(process.env.HOOKARMOR_ALLOW_UNREADABLE_SECRETS === 'true'));

  // Security audit check: warn about endpoints without secrets on startup
  try {
    const initialEndpoints = storage.listEndpoints();
    for (const ep of initialEndpoints) {
      if (!ep.secret) {
        console.warn(`[Security Warning] Endpoint '${ep.id}' has no signing secret. Incoming webhooks cannot be cryptographically verified against spoofing!`);
      }
    }
  } catch (_) {}

  const dispatcher = new Dispatcher(storage, {
    defaultConcurrency: options.defaultConcurrency || 5,
    defaultTimeoutMs: options.defaultTimeoutMs || 25000,
    strictSSRF,
    signingSecret: options.signingSecret || process.env.HOOKARMOR_SIGNING_SECRET || null,
    instanceId
  });

  const worker = new RetryWorker(storage, dispatcher, {
    intervalMs: options.retryIntervalMs || 5000,
    retentionDays,
    instanceId
  });
  if (options.autoStartWorker !== false) {
    worker.start();
  }

  server.on('close', () => {
    worker.stop();
  });

  function tokenMatches(token) {
    if (!apiKey || !token) return false;
    // Hash both sides so the comparison is constant-time regardless of length
    const a = crypto.createHash('sha256').update(String(token)).digest();
    const b = crypto.createHash('sha256').update(String(apiKey)).digest();
    return crypto.timingSafeEqual(a, b);
  }

  const authFailureLimiter = createRateLimiter({ limit: options.authFailureLimit || 30, windowMs: 10 * 60 * 1000 });
  const waitlistLimiter = createRateLimiter({ limit: options.waitlistRateLimit || 5, windowMs: 10 * 60 * 1000 });

  // ---------------------------------------------------------------- live WebSocket feed
  const wss = new WebSocketServer({
    server,
    path: '/ws',
    maxPayload: 4096,
    // Without an API key the feed is only served to localhost (blocks DNS-rebinding pages)
    // and verifies Origin to prevent cross-site WebSocket hijacking (F-06)
    verifyClient: (info) => {
      if (apiKey) return true;
      const remote = info.req.socket && info.req.socket.remoteAddress;
      const isLoopbackRemote = !remote || remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
      if (!isLoopbackRemote || !LOCAL_HOSTNAMES.has(hostnameOf(info.req.headers.host))) return false;
      const origin = info.origin || info.req.headers.origin;
      if (!origin) return false;
      try {
        const u = new URL(origin);
        if (!LOCAL_HOSTNAMES.has(u.hostname)) return false;
      } catch (_) {
        return false;
      }
      return true;
    }
  });

  wss.on('connection', (socket) => {
    socket.isAuthed = !apiKey || isDemoMode;
    let authTimer = null;
    if (!socket.isAuthed) {
      authTimer = setTimeout(() => { if (!socket.isAuthed) socket.close(4001, 'Authentication required'); }, 5000);
      if (authTimer.unref) authTimer.unref();
    }
    // Browsers cannot set headers on WebSocket upgrades, so the key arrives as the first message
    socket.on('message', (raw) => {
      try {
        const msg = JSON.parse(String(raw));
        if (msg.type === 'auth') {
          if (tokenMatches(msg.token)) {
            socket.isAuthed = true;
            if (authTimer) clearTimeout(authTimer);
            socket.send(JSON.stringify({ type: 'auth:ok' }));
          } else {
            socket.close(4001, 'Invalid API key');
          }
        }
      } catch (e) {}
    });
  });

  function broadcast(type, data) {
    const payload = JSON.stringify({ type, data });
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN && client.isAuthed) {
        client.send(payload);
      }
    });
  }

  // Hook dispatcher events to WebSocket broadcasts
  dispatcher.on('delivery', (res) => {
    broadcast('delivery', res);
  });

  // CORS is opt-in: the dashboard and landing page are same-origin and need none
  if (corsOrigins.length > 0) {
    app.use('/api', cors({ origin: corsOrigins }));
  }

  // Serve static UI assets
  app.use('/static', express.static(path.join(__dirname, 'public')));

  const ingressLimiter = createRateLimiter({
    limit: clampInt(process.env.HOOKARMOR_INGRESS_RATE_LIMIT, 600, 1, 50000),
    windowMs: 60000
  });
  const parseBytes = (val, defaultBytes = 10 * 1024 * 1024) => {
    if (typeof val === 'number') return val;
    if (typeof val !== 'string') return defaultBytes;
    const match = val.match(/^(\d+(?:\.\d+)?)\s*(kb|mb|gb|b)?$/i);
    if (!match) return defaultBytes;
    const num = parseFloat(match[1]);
    const unit = (match[2] || 'b').toLowerCase();
    if (unit === 'gb') return Math.round(num * 1024 * 1024 * 1024);
    if (unit === 'mb') return Math.round(num * 1024 * 1024);
    if (unit === 'kb') return Math.round(num * 1024);
    return Math.round(num);
  };
  const maxBodyBytes = parseBytes(maxBody, 10 * 1024 * 1024);

  const ingressPreflight = (req, res, next) => {
    const cl = req.headers['content-length'];
    if (cl) {
      const len = parseInt(cl, 10);
      if (Number.isFinite(len) && len > maxBodyBytes) {
        res.setHeader('Connection', 'close');
        return res.status(413).json({ error: 'Request body exceeds maximum allowed size' });
      }
    }
    if (!ingressLimiter(req.ip)) {
      res.setHeader('Connection', 'close');
      return res.status(429).json({ error: 'Too many ingress requests from this IP; rate limit exceeded' });
    }
    const endpointId = req.params.endpointId;
    if (!ENDPOINT_ID_PATTERN.test(endpointId)) {
      res.setHeader('Connection', 'close');
      return res.status(404).json({ error: 'HookArmor endpoint not found' });
    }
    const endpoint = storage.getEndpoint(endpointId);
    if (!endpoint) {
      res.setHeader('Connection', 'close');
      return res.status(404).json({ error: 'HookArmor endpoint not found' });
    }
    req.endpoint = endpoint;
    next();
  };

  // Ingress endpoint for webhooks - uses raw body parser to preserve raw bytes
  app.post('/in/:endpointId', ingressPreflight, express.raw({ type: () => true, limit: maxBody }), (req, res) => {
    const endpoint = req.endpoint;
    const endpointId = endpoint.id;

    // Storage capacity backpressure protection per endpoint
    if (storage.countPending && storage.countPending(endpointId) >= maxPendingEvents) {
      return res.status(503).json({ error: 'Ingress queue capacity reached. System is under high load; retry shortly.' });
    }

    const rawBodyBuffer = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || '');
    let rawBody = '';
    try {
      rawBody = rawBodyBuffer.toString('utf8');
    } catch (_) {}
    const headers = { ...req.headers };

    // Detect provider & idempotency key
    let provider = 'generic';
    let eventType = null;
    let idempotencyKey = headers['idempotency-key'] || headers['x-idempotency-key'] || null;

    if (headers['stripe-signature']) {
      provider = 'stripe';
      try {
        const parsed = JSON.parse(rawBody);
        eventType = parsed.type;
        if (parsed.id) idempotencyKey = parsed.id;
      } catch (e) {}
    } else if (headers['x-shopify-hmac-sha256'] || headers['x-shopify-topic']) {
      provider = 'shopify';
      eventType = headers['x-shopify-topic'];
      if (headers['x-shopify-webhook-id']) idempotencyKey = headers['x-shopify-webhook-id'];
    } else if (headers['x-github-event']) {
      provider = 'github';
      eventType = headers['x-github-event'];
      if (headers['x-github-delivery']) idempotencyKey = headers['x-github-delivery'];
    } else if (headers['clerk-signature'] || headers['svix-id']) {
      provider = 'clerk/svix';
      if (headers['svix-id']) idempotencyKey = headers['svix-id'];
      try {
        const parsed = JSON.parse(rawBody);
        eventType = parsed.type;
      } catch (e) {}
    } else {
      try {
        const parsed = JSON.parse(rawBody);
        eventType = parsed.event || parsed.type || parsed.action || null;
        if (parsed.id) idempotencyKey = String(parsed.id);
      } catch (e) {}
    }
    if (typeof eventType !== 'string') eventType = eventType == null ? null : String(eventType);
    if (eventType) eventType = eventType.slice(0, 200);
    if (idempotencyKey) idempotencyKey = String(idempotencyKey).slice(0, 255);

    // Provider scheme pinning check (F-03)
    if (endpoint.provider && provider !== endpoint.provider) {
      return res.status(400).json({
        error: `Signature scheme mismatch: endpoint is configured for ${endpoint.provider}, but received ${provider}`,
        provider,
        configuredProvider: endpoint.provider
      });
    }

    // 0. Verify signature on ingress if endpoint secret is configured
    let verified = false;
    if (endpoint.secret) {
      const verification = Dispatcher.verifyIngressSignature(provider, rawBodyBuffer, headers, endpoint.secret);
      if (!verification.valid) {
        return res.status(400).json({
          error: 'Webhook signature verification failed',
          provider,
          reason: verification.reason
        });
      }
      verified = true;
      // Auto-pin provider scheme on first verified event (closes F-03 scheme mix-up on unconfigured endpoints)
      if (!endpoint.provider && provider && provider !== 'generic') {
        try {
          storage.db.prepare('UPDATE endpoints SET provider = ? WHERE id = ?').run(provider, endpoint.id);
          endpoint.provider = provider;
        } catch (_) {}
      }
    } else {
      console.warn(`[Ingress Warning] Ingested webhook for endpoint '${endpoint.id}' without signature verification (no secret configured).`);
      headers['x-hookarmor-unverified'] = 'true';
    }

    let savedEvent;
    try {
      // Deduplication: if HookArmor already holds this event, ack without creating a second delivery
      if (idempotencyKey) {
        const existing = storage.findEventByIdempotencyKey(endpoint.id, idempotencyKey);
        if (existing) {
          // If the event was cryptographically verified, deduplicate by ID as standard.
          // If the endpoint is unverified (no secret), only deduplicate if the payload bodies match,
          // preventing an attacker from suppressing real events with arbitrary payloads.
          const isSamePayload = !existing.raw_body || Buffer.compare(existing.raw_body, rawBodyBuffer) === 0;
          if (verified || isSamePayload) {
            return res.status(200).json({
              received: true,
              hookarmor_id: existing.id,
              status: 'deduplicated',
              message: `Idempotency key already received (current status: ${existing.status}). Suppressed duplicate delivery.`
            });
          } else {
            // Unverified payload collision: do not suppress. Qualify idempotency key so both events persist.
            idempotencyKey = `${idempotencyKey}_collision_${Date.now()}`;
          }
        }
      }

      const eventId = `evt_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;

      // 1. Durably save event in SQLite, already claimed for its first delivery
      // (Sensitive headers are encrypted at rest by storage._writeHeaders)
      savedEvent = storage.saveEvent({
        id: eventId,
        endpointId: endpoint.id,
        idempotencyKey,
        provider,
        eventType,
        headers,
        rawBody: rawBodyBuffer,
        status: 'replaying',
        claimedBy: instanceId,
        verified
      });
    } catch (err) {
      // Not persisted: return an error so the provider keeps its own retry schedule
      console.error('[Ingress] Failed to persist event:', err.message);
      return res.status(503).json({ error: 'HookArmor could not persist the event; please retry' });
    }

    broadcast('event:received', {
      id: savedEvent.id,
      endpointId: endpoint.id,
      provider,
      eventType,
      createdAt: savedEvent.created_at
    });

    // 2. Respond immediately with 200 OK to the sender so Stripe never times out or backs off
    res.status(200).json({
      received: true,
      hookarmor_id: savedEvent.id,
      status: 'buffered'
    });

    // 3. Dispatch to target destination asynchronously
    setImmediate(() => {
      dispatcher.dispatch(savedEvent, endpoint).catch((err) => {
        console.error(`[Ingress] Dispatch error for ${savedEvent.id}:`, err);
      });
    });
  });

  // REST API: JSON Body Parser for Dashboard / Management
  app.use(express.json({ limit: '100kb' }));

  app.use('/api', (req, res, next) => {
    // Public waitlist signup for the landing page (rate limited)
    if (req.path === '/waitlist' && req.method === 'POST') {
      if (!waitlistLimiter(req.ip)) return res.status(429).json({ error: 'Too many signups from this address; try again later' });
      return next();
    }

    if (!apiKey) {
      if (!isDemoMode) {
        // Open local-dev mode: only answer to loopback connections and localhost host names,
        // so LAN attackers or web pages through DNS rebinding cannot reach this API
        const remote = req.socket && req.socket.remoteAddress;
        const isLoopbackRemote = !remote || remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
        if (!isLoopbackRemote || !LOCAL_HOSTNAMES.has(hostnameOf(req.headers.host))) {
          return res.status(403).json({ error: 'Without HOOKARMOR_API_KEY the management API is only accessible locally from loopback interfaces (localhost/127.0.0.1)' });
        }
        return next();
      }
    }

    // Demo mode (public marketing sandbox): read-only access without a key
    if (isDemoMode) {
      const isPublicDemoRead = req.method === 'GET' &&
        (req.path === '/stats' || req.path === '/endpoints' || req.path === '/events' || /^\/events\/[^\/]+$/.test(req.path));
      if (isPublicDemoRead) return next();
    }

    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim() || req.headers['x-api-key'] || '';
    if (!tokenMatches(token)) {
      // Only wrong keys count towards the lockout, not anonymous page loads
      if (token && !authFailureLimiter(req.ip)) {
        return res.status(429).json({ error: 'Too many failed authentication attempts; try again later' });
      }
      return res.status(401).json({ error: 'Unauthorized: valid HookArmor API key required in header' });
    }
    next();
  });

  // State-changing calls must be JSON. Cross-site forms cannot send that content type without a
  // CORS preflight, which this server does not grant.
  app.use('/api', (req, res, next) => {
    const contentType = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    const isJson = contentType === 'application/json' || contentType.endsWith('+json');
    const isBodyMethod = req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH';
    const hasBody = Boolean(req.headers['content-length'] && req.headers['content-length'] !== '0');
    if ((isBodyMethod || hasBody) && !isJson) {
      return res.status(415).json({ error: 'Content-Type must be application/json' });
    }
    next();
  });

  // Get Stats
  app.get('/api/stats', (req, res) => {
    res.json(storage.getStats());
  });

  // List Endpoints (secrets are never returned)
  app.get('/api/endpoints', (req, res) => {
    res.json(storage.listEndpoints().map(publicEndpoint));
  });

  // Create or Update Endpoint
  app.post('/api/endpoints', (req, res) => {
    const { id, name, targetUrl, secret, provider, alertWebhookUrl, autoRetry, maxRetries, concurrencyLimit, concurrency_limit, customHeaders, custom_headers } = req.body || {};
    if (!id || !name || !targetUrl) {
      return res.status(400).json({ error: 'id, name, and targetUrl are required' });
    }
    if (typeof id !== 'string' || !ENDPOINT_ID_PATTERN.test(id)) {
      return res.status(400).json({ error: 'id must be 1-64 characters: letters, digits, "-" or "_"' });
    }
    if (typeof name !== 'string' || name.length > 200) {
      return res.status(400).json({ error: 'name must be a string of at most 200 characters' });
    }
    if (secret !== undefined && (typeof secret !== 'string' || secret.length > 500)) {
      return res.status(400).json({ error: 'secret must be a string of at most 500 characters' });
    }
    if (provider !== undefined && provider !== null && (typeof provider !== 'string' || provider.length > 50)) {
      return res.status(400).json({ error: 'provider must be a string of at most 50 characters' });
    }
    const targetCheck = checkUrl(String(targetUrl), strictSSRF);
    if (!targetCheck.ok) {
      return res.status(400).json({ error: `targetUrl rejected: ${targetCheck.reason} (cloud metadata${strictSSRF ? ', loopback and private network' : ''} addresses are blocked)` });
    }
    if (alertWebhookUrl) {
      const alertCheck = checkUrl(String(alertWebhookUrl), strictSSRF);
      if (!alertCheck.ok) {
        return res.status(400).json({ error: `alertWebhookUrl rejected: ${alertCheck.reason}` });
      }
    }
    const endpoint = storage.createEndpoint({
      id,
      name,
      targetUrl: String(targetUrl),
      secret,
      provider: provider === undefined ? undefined : (provider ? String(provider) : null),
      alertWebhookUrl: alertWebhookUrl === undefined ? undefined : String(alertWebhookUrl || ''),
      autoRetry: autoRetry !== undefined ? autoRetry : 1,
      maxRetries: clampInt(maxRetries, 5, 1, 50),
      concurrencyLimit: clampInt(concurrencyLimit || concurrency_limit, 5, 1, 100),
      customHeaders: customHeaders !== undefined ? customHeaders : custom_headers
    });
    res.json(publicEndpoint(endpoint));
  });

  // Delete an endpoint (F-09: protected against accidental DLQ data loss unless force=true)
  app.delete('/api/endpoints/:id', (req, res) => {
    const endpoint = storage.getEndpoint(req.params.id);
    if (!endpoint) return res.status(404).json({ error: 'Endpoint not found' });

    const force = req.query.force === 'true' || req.query.force === '1';
    if (!force) {
      const failedCount = storage.countFailed(req.params.id);
      const pendingCount = storage.countPending(req.params.id);
      if (failedCount > 0 || pendingCount > 0) {
        return res.status(409).json({
          error: 'Endpoint has active pending or failed events in DLQ. Deletion would cause data loss.',
          failedCount,
          pendingCount,
          hint: 'Pass ?force=true to permanently delete the endpoint and discard all associated events.'
        });
      }
    }

    const deleted = storage.deleteEndpoint(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Endpoint not found' });
    res.json({ success: true, message: 'Endpoint deleted' });
  });

  // List Events
  app.get('/api/events', (req, res) => {
    const { endpointId, status, limit, offset } = req.query;
    const events = storage.listEvents({
      endpointId: typeof endpointId === 'string' ? endpointId : null,
      status: typeof status === 'string' ? status : null,
      limit: clampInt(limit, 50, 1, 500),
      offset: clampInt(offset, 0, 0, Number.MAX_SAFE_INTEGER)
    });
    res.json(events.map(e => ({
      ...e,
      headers: redactInboundHeaders(e.headers),
      raw_body: Buffer.isBuffer(e.raw_body) ? e.raw_body.toString('utf8') : String(e.raw_body || '')
    })));
  });

  // Get single event with attempts
  app.get('/api/events/:id', (req, res) => {
    const event = storage.getEvent(req.params.id);
    if (!event) return res.status(404).json({ error: 'Event not found' });
    const attempts = storage.getAttempts(req.params.id);
    res.json({
      ...event,
      headers: redactInboundHeaders(event.headers),
      raw_body: Buffer.isBuffer(event.raw_body) ? event.raw_body.toString('utf8') : String(event.raw_body || ''),
      attempts
    });
  });

  // Delete a specific event and its attempts
  app.delete('/api/events/:id', (req, res) => {
    const deleted = storage.deleteEvent(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Event not found' });
    res.json({ success: true, message: 'Event deleted' });
  });

  // Replay a specific event
  app.post('/api/events/:id/replay', async (req, res) => {
    try {
      const result = await dispatcher.replayEvent(req.params.id);
      res.json(result);
    } catch (err) {
      const status = err.code === 'NOT_FOUND' ? 404 : (err.code === 'IN_FLIGHT' ? 409 : 500);
      res.status(status).json({ error: err.message });
    }
  });

  // Replay all failed events, including ones that exhausted automatic retries.
  // Returns immediately; deliveries run in the background through the concurrency limiter.
  app.post('/api/events/replay-all', (req, res) => {
    try {
      const { endpointId } = req.body || {};
      const result = dispatcher.replayAllFailed(typeof endpointId === 'string' ? endpointId : null);
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Waitlist Registration
  app.post('/api/waitlist', (req, res) => {
    const { email, source } = req.body || {};
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    if (!cleanEmail || cleanEmail.length > 254 || !/^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']+$/.test(cleanEmail)) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    const cleanSource = typeof source === 'string' ? source.replace(/[^A-Za-z0-9_-]/g, '').slice(0, 50) || 'landing_page' : 'landing_page';
    const result = storage.addWaitlist(cleanEmail, cleanSource);
    res.json({ success: true, message: 'Added to HookArmor Cloud beta waitlist!', email: result.email });
  });

  app.get('/api/waitlist', (req, res) => {
    res.json(storage.listWaitlist());
  });

  // Mock Target Receiver (local simulation only; not mounted in production unless HOOKARMOR_ENABLE_MOCK=true)
  if (mockEnabled) {
    let mockTargetBehavior = {
      statusCode: 200,
      delayMs: 15,
      responseBody: { status: 'mock_processed' }
    };

    const mockAuthMiddleware = (req, res, next) => {
      if (apiKey) {
        const header = req.headers['authorization'] || '';
        const token = header.startsWith('Bearer ') ? header.slice(7) : (req.headers['x-api-key'] || '');
        if (!tokenMatches(token)) {
          return res.status(401).json({ error: 'Unauthorized: valid API key required for /mock/config' });
        }
      } else {
        const host = hostnameOf(req.headers['host']);
        if (!LOCAL_HOSTNAMES.has(host) && !allowNoAuth) {
          return res.status(403).json({ error: 'Forbidden: loopback access only' });
        }
      }
      next();
    };

    app.post('/mock/target', (req, res) => {
      setTimeout(() => {
        res.status(mockTargetBehavior.statusCode).json(mockTargetBehavior.responseBody);
      }, mockTargetBehavior.delayMs);
    });

    app.post('/mock/config', mockAuthMiddleware, (req, res) => {
      const body = req.body || {};
      mockTargetBehavior = {
        statusCode: clampInt(body.statusCode, mockTargetBehavior.statusCode, 100, 599),
        delayMs: clampInt(body.delayMs, mockTargetBehavior.delayMs, 0, 30000),
        responseBody: body.responseBody !== undefined ? body.responseBody : mockTargetBehavior.responseBody
      };
      res.json({ message: 'Mock target configuration updated', config: mockTargetBehavior });
    });

    app.get('/mock/config', mockAuthMiddleware, (req, res) => {
      res.json(mockTargetBehavior);
    });
  }

  // Prometheus Metrics Exposition Endpoint (Requires API key if configured; otherwise loopback only)
  app.get('/metrics', (req, res) => {
    if (apiKey) {
      const authHeader = req.headers['authorization'] || '';
      const token = authHeader.replace(/^Bearer\s+/i, '').trim() || req.headers['x-api-key'] || '';
      if (!tokenMatches(token)) {
        res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
        return res.status(401).end('# Unauthorized: valid API key required for /metrics\n');
      }
    } else if (!isDemoMode) {
      const remote = req.socket && req.socket.remoteAddress;
      const isLoopbackRemote = !remote || remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
      if (!isLoopbackRemote || !LOCAL_HOSTNAMES.has(hostnameOf(req.headers.host))) {
        res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
        return res.status(403).end('# Forbidden: loopback only without API key\n');
      }
    }

    try {
      const stats = storage.getStats();
      const endpoints = storage.listEndpoints();
      const unverifiedCount = endpoints.filter((e) => !e.secret).length;
      const uptime = Math.floor(process.uptime());

      const lines = [
        '# HELP hookarmor_uptime_seconds Total process uptime in seconds',
        '# TYPE hookarmor_uptime_seconds counter',
        `hookarmor_uptime_seconds ${uptime}`,
        '',
        '# HELP hookarmor_events_total Total number of events by status',
        '# TYPE hookarmor_events_total gauge',
        `hookarmor_events_total{status="delivered"} ${stats.delivered || 0}`,
        `hookarmor_events_total{status="failed"} ${stats.failed || 0}`,
        `hookarmor_events_total{status="pending"} ${stats.pending || 0}`,
        `hookarmor_events_total{status="total"} ${stats.total || 0}`,
        '',
        '# HELP hookarmor_endpoints_total Total number of configured endpoints',
        '# TYPE hookarmor_endpoints_total gauge',
        `hookarmor_endpoints_total ${endpoints.length}`,
        '',
        '# HELP hookarmor_endpoints_unverified_total Number of endpoints without a cryptographic signing secret',
        '# TYPE hookarmor_endpoints_unverified_total gauge',
        `hookarmor_endpoints_unverified_total ${unverifiedCount}`,
        '',
        '# HELP hookarmor_delivery_latency_ms_avg Average delivery latency in milliseconds',
        '# TYPE hookarmor_delivery_latency_ms_avg gauge',
        `hookarmor_delivery_latency_ms_avg ${stats.avgLatencyMs || 0}`
      ];

      res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
      res.end(lines.join('\n') + '\n');
    } catch (err) {
      res.status(500).setHeader('Content-Type', 'text/plain').end(`# Error collecting metrics: ${err.message}\n`);
    }
  });

  // Health and Version Check Endpoint
  app.get('/healthz', (req, res) => {
    res.json({
      status: 'ok',
      version: require('../package.json').version,
      uptime: Math.floor(process.uptime())
    });
  });

  // SEO & Web Crawler Discovery
  app.get('/robots.txt', (req, res) => {
    res.type('text/plain');
    res.sendFile('robots.txt', { root: path.join(__dirname, 'public') });
  });

  app.get('/sitemap.xml', (req, res) => {
    res.type('application/xml');
    res.sendFile('sitemap.xml', { root: path.join(__dirname, 'public') });
  });

  app.get('/og-preview.png', (req, res) => {
    res.type('image/png');
    res.sendFile('og-preview.png', { root: path.join(__dirname, 'public') });
  });

  // Root Route: Marketing landing page on cloud production (Railway/Render) or when explicitly configured;
  // Dashboard on /dashboard and /app, or on / for local self-hosted instances.
  app.get('/', (req, res) => {
    const isCloud = Boolean(process.env.RAILWAY_ENVIRONMENT || process.env.RENDER || process.env.HOOKARMOR_SERVE_LANDING === 'true');
    if (isCloud && process.env.HOOKARMOR_SERVE_LANDING !== 'false') {
      return res.sendFile('landing.html', { root: path.join(__dirname, 'public') });
    }
    res.sendFile('index.html', { root: path.join(__dirname, 'public') });
  });

  // Interactive Dashboard Routes
  app.get(['/dashboard', '/app'], (req, res) => {
    res.sendFile('index.html', { root: path.join(__dirname, 'public') });
  });

  // Engineering Blog Routes
  app.get('/blog', (req, res) => {
    res.sendFile('index.html', { root: path.join(__dirname, 'public', 'blog') });
  });

  app.get('/blog/:slug', (req, res) => {
    const slug = req.params.slug.replace(/[^a-zA-Z0-9-_]/g, '');
    const fileName = `${slug}.html`;
    const filePath = path.join(__dirname, 'public', 'blog', fileName);
    if (fs.existsSync(filePath)) {
      return res.sendFile(fileName, { root: path.join(__dirname, 'public', 'blog') });
    }
    res.redirect('/blog');
  });

  // Error handling middleware: prevent stack traces leaking and return clean JSON (F-11)
  app.use((err, req, res, next) => {
    console.error('[SERVER ERROR]:', err);
    const status = err.status || err.statusCode || 500;
    const message = err.expose || status < 500 ? err.message : 'Internal server error';
    if (res.headersSent) return next(err);
    res.status(status).json({ error: message });
  });

  return { app, server, storage, dispatcher, worker, mockEnabled, strictSSRF, instanceId };
}

module.exports = { createServer };
