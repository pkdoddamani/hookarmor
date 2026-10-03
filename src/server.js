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
const { isPrivateOrMetadataUrl } = require('./ssrf');

function safeKeyCompare(provided, expected) {
  if (typeof provided !== 'string' || typeof expected !== 'string') return false;
  const h1 = crypto.createHash('sha256').update(provided).digest();
  const h2 = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(h1, h2);
}

function createServer(options = {}) {
  const isProduction = options.production !== undefined
    ? options.production
    : (process.env.NODE_ENV === 'production');

  const apiKey = options.apiKey || process.env.HOOKARMOR_API_KEY || null;

  if (isProduction && !apiKey) {
    throw new Error('HOOKARMOR_API_KEY environment variable is required in production mode');
  }

  const app = express();
  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws' });

  // Rate limiting map for waitlist
  const waitlistRateLimit = new Map();

  const isDemoMode = options.demoMode !== undefined 
    ? options.demoMode 
    : (process.env.HOOKARMOR_DEMO_MODE === 'true');
  const strictSSRF = options.strictSSRF !== undefined
    ? options.strictSSRF
    : (isProduction ? true : (process.env.HOOKARMOR_STRICT_SSRF === 'true'));

  const storage = new Storage(options.dbPath);
  const dispatcher = new Dispatcher(storage, {
    defaultConcurrency: options.defaultConcurrency || 5,
    defaultTimeoutMs: options.defaultTimeoutMs || 25000,
    strictSSRF
  });

  const worker = new RetryWorker(storage, dispatcher, {
    intervalMs: options.retryIntervalMs || 5000
  });
  if (options.autoStartWorker !== false) {
    worker.start();
  }

  server.on('close', () => {
    worker.stop();
  });

  // WebSocket authentication & connection handling
  wss.on('connection', (socket, req) => {
    if (!apiKey) {
      const hostHeader = req.headers['host'] || '';
      const hostname = hostHeader.split(':')[0].toLowerCase();
      if (hostname !== 'localhost' && hostname !== '127.0.0.1' && hostname !== '::1' && hostname !== '[::1]') {
        socket.close(4003, 'Forbidden host');
        return;
      }
      socket.authenticated = true;
    } else {
      socket.authenticated = false;
      const timeout = setTimeout(() => {
        if (!socket.authenticated) {
          socket.close(4001, 'Unauthorized');
        }
      }, 5000);

      socket.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw);
          if (msg.type === 'auth' && safeKeyCompare(msg.token, apiKey)) {
            socket.authenticated = true;
            clearTimeout(timeout);
            socket.send(JSON.stringify({ type: 'authenticated' }));
          }
        } catch (e) {}
      });

      socket.on('close', () => clearTimeout(timeout));
    }
  });

  // Broadcast helper for real-time WebSocket dashboard
  function broadcast(type, data) {
    const payload = JSON.stringify({ type, data });
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN && client.authenticated) {
        client.send(payload);
      }
    });
  }

  // Hook dispatcher events to WebSocket broadcasts
  dispatcher.on('delivery', (res) => {
    broadcast('delivery', res);
  });

  // CORS configuration (only enable when explicitly configured)
  if (options.cors || process.env.HOOKARMOR_CORS_ORIGIN) {
    const corsOptions = typeof options.cors === 'object'
      ? options.cors
      : (process.env.HOOKARMOR_CORS_ORIGIN ? { origin: process.env.HOOKARMOR_CORS_ORIGIN } : {});
    app.use(cors(corsOptions));
  }

  // Serve static UI assets
  app.use('/static', express.static(path.join(__dirname, 'public')));

  // Ingress endpoint for webhooks - uses raw body parser to preserve raw bytes
  app.post('/in/:endpointId', express.raw({ type: '*/*', limit: '10mb' }), async (req, res) => {
    const endpointId = req.params.endpointId;
    const endpoint = storage.getEndpoint(endpointId);

    if (!endpoint) {
      return res.status(404).json({ error: `HookArmor endpoint not found: ${endpointId}` });
    }

    const rawBodyBuffer = req.body || Buffer.from('');
    const rawBody = rawBodyBuffer.toString('utf8');
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
    } else if (headers['x-github-event'] || headers['x-hub-signature-256']) {
      provider = 'github';
      eventType = headers['x-github-event'];
      if (headers['x-github-delivery']) idempotencyKey = headers['x-github-delivery'];
    } else if (headers['clerk-signature'] || headers['svix-id'] || headers['svix-signature']) {
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

    // 0. Verify signature on ingress if endpoint secret is configured
    let isVerified = 0;
    if (endpoint.secret) {
      const verification = Dispatcher.verifyIngressSignature(provider, rawBody, headers, endpoint.secret);
      if (!verification.valid) {
        return res.status(400).json({
          error: 'Webhook signature verification failed',
          provider,
          reason: verification.reason
        });
      }
      isVerified = 1;
    }

    // Deduplication check: suppress duplicate execution if idempotency key was already received in any status
    if (idempotencyKey) {
      const existing = storage.findEventByIdempotencyKey(endpoint.id, idempotencyKey);
      if (existing) {
        return res.status(200).json({
          received: true,
          hookarmor_id: existing.id,
          status: 'deduplicated',
          message: `Idempotency key ${idempotencyKey} already received (status: ${existing.status}). Suppressed duplicate execution.`
        });
      }
    }

    const eventId = `evt_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

    // 1. Durably save event in SQLite with try/catch to prevent unhandled rejection crashes
    let savedEvent;
    try {
      savedEvent = storage.saveEvent({
        id: eventId,
        endpointId: endpoint.id,
        idempotencyKey,
        provider,
        eventType,
        headers,
        rawBody,
        status: 'pending',
        verified: isVerified
      });
    } catch (err) {
      console.error(`[Ingress] Database storage error for event ${eventId}:`, err);
      return res.status(503).json({
        error: 'Service temporarily unavailable: unable to persist webhook payload'
      });
    }

    broadcast('event:received', {
      id: eventId,
      endpointId: endpoint.id,
      provider,
      eventType,
      createdAt: savedEvent.created_at
    });

    // 2. Respond immediately with 200 OK to the sender so Stripe never times out or backs off
    res.status(200).json({
      received: true,
      hookarmor_id: eventId,
      status: 'buffered'
    });

    // 3. Dispatch to target destination asynchronously
    setImmediate(async () => {
      try {
        await dispatcher.dispatch(savedEvent, endpoint);
      } catch (err) {
        console.error(`[Ingress] Dispatch error for ${eventId}:`, err);
      }
    });
  });

  // Host validation & DNS-rebinding protection for API
  app.use('/api', (req, res, next) => {
    if (!apiKey) {
      const hostHeader = req.headers['host'] || '';
      const hostname = hostHeader.split(':')[0].toLowerCase();
      if (hostname !== 'localhost' && hostname !== '127.0.0.1' && hostname !== '::1' && hostname !== '[::1]') {
        return res.status(403).json({ error: 'Forbidden: host not permitted without API key configuration' });
      }
    }
    next();
  });

  // Require Content-Type: application/json on state-changing API routes
  app.use('/api', (req, res, next) => {
    if (['POST', 'PUT', 'DELETE'].includes(req.method) && req.path !== '/waitlist') {
      const contentType = req.headers['content-type'] || '';
      if (!contentType.includes('application/json')) {
        return res.status(415).json({
          error: 'Unsupported Media Type: Content-Type must be application/json'
        });
      }
    }
    next();
  });

  // REST API: JSON Body Parser for Dashboard / Management
  app.use(express.json());

  // Management API Authentication Middleware
  app.use('/api', (req, res, next) => {
    // Keep public waitlist signup open for landing page
    if (req.path === '/waitlist' && req.method === 'POST') return next();

    // If apiKey is NOT configured and demo mode is NOT forced, allow open local dev access
    if (!apiKey && !isDemoMode) return next();

    // If explicit demo mode is active (e.g. public marketing demo sandbox), allow read-only GET routes
    if (isDemoMode) {
      const isPublicDemo =
        req.method === 'GET' && (
          req.path === '/stats' ||
          req.path === '/endpoints' ||
          req.path === '/events' ||
          /^\/events\/[^\/]+$/.test(req.path)
        );

      if (isPublicDemo) return next();
    }

    // Require valid authentication
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim() || req.headers['x-api-key'] || '';
    if (!token || !safeKeyCompare(token, apiKey)) {
      return res.status(401).json({ error: 'Unauthorized: valid HookArmor API key required in header' });
    }
    next();
  });

  // Get Stats
  app.get('/api/stats', (req, res) => {
    res.json(storage.getStats());
  });

  // List Endpoints (Secrets are write-only, never returned in API)
  app.get('/api/endpoints', (req, res) => {
    const endpoints = storage.listEndpoints().map(ep => {
      const { secret, ...safe } = ep;
      return {
        ...safe,
        has_secret: Boolean(secret)
      };
    });
    res.json(endpoints);
  });

  // Create or Update Endpoint
  app.post('/api/endpoints', (req, res) => {
    const { id, name, targetUrl, secret, alertWebhookUrl, autoRetry, maxRetries, concurrencyLimit, concurrency_limit } = req.body || {};
    if (!id || !name || !targetUrl) {
      return res.status(400).json({ error: 'id, name, and targetUrl are required' });
    }

    if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) {
      return res.status(400).json({ error: 'Endpoint ID must be 1-64 alphanumeric characters, underscores, or hyphens' });
    }

    if (isPrivateOrMetadataUrl(targetUrl, strictSSRF)) {
      return res.status(400).json({ error: 'targetUrl cannot target cloud metadata or private network addresses (SSRF blocked)' });
    }

    if (alertWebhookUrl && isPrivateOrMetadataUrl(alertWebhookUrl, strictSSRF)) {
      return res.status(400).json({ error: 'alertWebhookUrl cannot target cloud metadata or private network addresses (SSRF blocked)' });
    }

    const endpoint = storage.createEndpoint({
      id,
      name,
      targetUrl,
      secret,
      alertWebhookUrl,
      autoRetry: autoRetry !== undefined ? autoRetry : 1,
      maxRetries: maxRetries || 5,
      concurrencyLimit: concurrencyLimit || concurrency_limit || 5
    });

    const { secret: _s, ...safe } = endpoint;
    res.json({ ...safe, has_secret: Boolean(_s) });
  });

  // List Events
  app.get('/api/events', (req, res) => {
    const { endpointId, status } = req.query;
    const limit = Math.max(1, Math.min(500, parseInt(req.query.limit, 10) || 50));
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);

    const events = storage.listEvents({
      endpointId,
      status,
      limit,
      offset
    });
    res.json(events);
  });

  // Get single event with attempts
  app.get('/api/events/:id', (req, res) => {
    const event = storage.getEvent(req.params.id);
    if (!event) return res.status(404).json({ error: 'Event not found' });
    const attempts = storage.getAttempts(req.params.id);
    res.json({ ...event, attempts });
  });

  // Replay a specific event
  app.post('/api/events/:id/replay', async (req, res) => {
    try {
      const result = await dispatcher.replayEvent(req.params.id);
      res.json(result);
    } catch (err) {
      const status = err.statusCode || (err.message.includes('already in flight') ? 409 : 500);
      res.status(status).json({ error: err.message });
    }
  });

  // Replay all failed events (optionally filtered by endpoint)
  app.post('/api/events/replay-all', async (req, res) => {
    try {
      const { endpointId } = req.body || {};
      const results = await dispatcher.replayAllFailed(endpointId);
      res.json({ replayedCount: results.length, results });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Waitlist Registration
  app.post('/api/waitlist', (req, res) => {
    const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const now = Date.now();
    const windowMs = 10 * 60 * 1000; // 10 minutes
    const maxRequests = 5;

    let timestamps = waitlistRateLimit.get(clientIp) || [];
    timestamps = timestamps.filter(t => now - t < windowMs);

    if (timestamps.length >= maxRequests) {
      return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }

    const { email, source } = req.body || {};
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || typeof email !== 'string' || email.length > 255 || !emailRegex.test(email.trim())) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    timestamps.push(now);
    waitlistRateLimit.set(clientIp, timestamps);

    const safeSource = typeof source === 'string' ? source.slice(0, 50) : 'landing_page';
    const result = storage.addWaitlist(email.trim().toLowerCase(), safeSource);
    res.json({ success: true, message: 'Added to HookArmor Cloud beta waitlist!', email: result.email });
  });

  app.get('/api/waitlist', (req, res) => {
    res.json(storage.listWaitlist());
  });

  // Mock Target Receiver (for self-testing and local simulation, disabled in production unless forced)
  if (!isProduction || options.enableMockTarget) {
    let mockTargetBehavior = {
      statusCode: 200,
      delayMs: 15,
      responseBody: { status: 'mock_processed' }
    };

    app.post('/mock/target', (req, res) => {
      setTimeout(() => {
        res.status(mockTargetBehavior.statusCode).json(mockTargetBehavior.responseBody);
      }, mockTargetBehavior.delayMs);
    });

    app.post('/mock/config', (req, res) => {
      mockTargetBehavior = { ...mockTargetBehavior, ...req.body };
      res.json({ message: 'Mock target configuration updated', config: mockTargetBehavior });
    });

    app.get('/mock/config', (req, res) => {
      res.json(mockTargetBehavior);
    });
  }

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

  // Root Route: Dashboard if run locally via CLI; Landing page on cloud deployment
  app.get('/', (req, res) => {
    const isCloudProduction = Boolean(process.env.RAILWAY_ENVIRONMENT || process.env.RENDER || isProduction);
    if (!isCloudProduction) {
      return res.sendFile('index.html', { root: path.join(__dirname, 'public') });
    }
    res.sendFile('landing.html', { root: path.join(__dirname, 'public') });
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

  return { app, server, storage, dispatcher, worker };
}

module.exports = { createServer };
