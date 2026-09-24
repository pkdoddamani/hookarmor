const express = require('express');
const cors = require('cors');
const { randomUUID } = require('crypto');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { WebSocketServer, WebSocket } = require('ws');

const Storage = require('./storage');
const Dispatcher = require('./dispatcher');
const RetryWorker = require('./worker');

function isPrivateOrMetadataUrl(urlString) {
  try {
    const parsed = new URL(urlString);
    const hostname = parsed.hostname.toLowerCase();
    if (
      hostname === '169.254.169.254' ||
      hostname === 'metadata.google.internal' ||
      hostname === '100.100.100.200' ||
      hostname.startsWith('169.254.')
    ) {
      return true;
    }
    return false;
  } catch (e) {
    return true;
  }
}

function createServer(options = {}) {
  const app = express();
  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws' });

  const storage = new Storage(options.dbPath);
  const dispatcher = new Dispatcher(storage, {
    defaultConcurrency: options.defaultConcurrency || 5,
    defaultTimeoutMs: options.defaultTimeoutMs || 25000
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

  // Broadcast helper for real-time WebSocket dashboard
  function broadcast(type, data) {
    const payload = JSON.stringify({ type, data });
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(payload);
      }
    });
  }

  // Hook dispatcher events to WebSocket broadcasts
  dispatcher.on('delivery', (res) => {
    broadcast('delivery', res);
  });

  // Enable CORS
  app.use(cors());

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

    // 0. Verify signature on ingress if endpoint secret is configured
    if (endpoint.secret) {
      const verification = Dispatcher.verifyIngressSignature(provider, rawBody, headers, endpoint.secret);
      if (!verification.valid) {
        return res.status(400).json({
          error: 'Webhook signature verification failed',
          provider,
          reason: verification.reason
        });
      }
    }

    // Deduplication check: if this event ID was already delivered, ack immediately without duplicating downstream side effects
    if (idempotencyKey) {
      const existing = storage.findEventByIdempotencyKey(endpoint.id, idempotencyKey);
      if (existing && existing.status === 'delivered') {
        return res.status(200).json({
          received: true,
          hookarmor_id: existing.id,
          status: 'deduplicated',
          message: `Idempotency key ${idempotencyKey} already delivered. Suppressed duplicate execution.`
        });
      }
    }

    const eventId = `evt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    // 1. Durably save event in SQLite
    const savedEvent = storage.saveEvent({
      id: eventId,
      endpointId: endpoint.id,
      idempotencyKey,
      provider,
      eventType,
      headers,
      rawBody,
      status: 'pending'
    });

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

  // REST API: JSON Body Parser for Dashboard / Management
  app.use(express.json());

  // Management API Authentication Middleware (optional, active when HOOKARMOR_API_KEY is configured)
  const apiKey = options.apiKey || process.env.HOOKARMOR_API_KEY || null;
  app.use('/api', (req, res, next) => {
    // Keep public waitlist signup open for landing page
    if (req.path === '/waitlist' && req.method === 'POST') return next();

    // Allow public read-only demo access & replay simulation so prospective users can explore live
    const isPublicDemo =
      (req.method === 'GET' && (req.path === '/stats' || req.path === '/endpoints' || req.path === '/events' || /^\/events\/[^\/]+$/.test(req.path))) ||
      (req.method === 'POST' && (req.path === '/events/replay-all' || /^\/events\/[^\/]+\/replay$/.test(req.path)));

    if (isPublicDemo) return next();

    if (!apiKey) return next();

    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim() || req.headers['x-api-key'] || req.query.api_key;
    if (token !== apiKey) {
      return res.status(401).json({ error: 'Unauthorized: valid HookArmor API key required' });
    }
    next();
  });

  // Get Stats
  app.get('/api/stats', (req, res) => {
    res.json(storage.getStats());
  });

  // List Endpoints
  app.get('/api/endpoints', (req, res) => {
    res.json(storage.listEndpoints());
  });

  // Create or Update Endpoint
  app.post('/api/endpoints', (req, res) => {
    const { id, name, targetUrl, secret, alertWebhookUrl, autoRetry, maxRetries, concurrencyLimit, concurrency_limit } = req.body;
    if (!id || !name || !targetUrl) {
      return res.status(400).json({ error: 'id, name, and targetUrl are required' });
    }
    if (isPrivateOrMetadataUrl(targetUrl)) {
      return res.status(400).json({ error: 'targetUrl cannot target cloud metadata or link-local addresses (SSRF blocked)' });
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
    res.json(endpoint);
  });

  // List Events
  app.get('/api/events', (req, res) => {
    const { endpointId, status, limit, offset } = req.query;
    const events = storage.listEvents({
      endpointId,
      status,
      limit: parseInt(limit, 10) || 50,
      offset: parseInt(offset, 10) || 0
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
      res.status(500).json({ error: err.message });
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
    const { email, source } = req.body || {};
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    const result = storage.addWaitlist(email.trim().toLowerCase(), source || 'landing_page');
    res.json({ success: true, message: 'Added to HookArmor Cloud beta waitlist!', email: result.email });
  });

  app.get('/api/waitlist', (req, res) => {
    res.json(storage.listWaitlist());
  });

  // Mock Target Receiver (for self-testing and local simulation)
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

  // SEO & Web Crawler Discovery
  app.get('/robots.txt', (req, res) => {
    res.type('text/plain');
    res.sendFile(path.join(__dirname, 'public', 'robots.txt'));
  });

  app.get('/sitemap.xml', (req, res) => {
    res.type('application/xml');
    res.sendFile(path.join(__dirname, 'public', 'sitemap.xml'));
  });

  // Landing Page Route
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
  });

  // Interactive Dashboard Routes
  app.get(['/dashboard', '/app'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  // Engineering Blog Routes
  app.get('/blog', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'blog', 'index.html'));
  });

  app.get('/blog/:slug', (req, res) => {
    const slug = req.params.slug.replace(/[^a-zA-Z0-9-_]/g, '');
    const filePath = path.join(__dirname, 'public', 'blog', `${slug}.html`);
    if (fs.existsSync(filePath)) {
      return res.sendFile(filePath);
    }
    res.redirect('/blog');
  });

  return { app, server, storage, dispatcher, worker };
}

module.exports = { createServer };
