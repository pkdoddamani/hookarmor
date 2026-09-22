const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('crypto');
const path = require('path');
const http = require('http');
const { WebSocketServer, WebSocket } = require('ws');

const Storage = require('./storage');
const Dispatcher = require('./dispatcher');

function createServer(options = {}) {
  const app = express();
  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws' });

  const storage = new Storage(options.dbPath);
  const dispatcher = new Dispatcher(storage);

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

    // Detect provider
    let provider = 'generic';
    let eventType = null;

    if (headers['stripe-signature']) {
      provider = 'stripe';
      try {
        const parsed = JSON.parse(rawBody);
        eventType = parsed.type;
      } catch (e) {}
    } else if (headers['x-shopify-hmac-sha256'] || headers['x-shopify-topic']) {
      provider = 'shopify';
      eventType = headers['x-shopify-topic'];
    } else if (headers['x-github-event']) {
      provider = 'github';
      eventType = headers['x-github-event'];
    } else if (headers['clerk-signature'] || headers['svix-id']) {
      provider = 'clerk/svix';
      try {
        const parsed = JSON.parse(rawBody);
        eventType = parsed.type;
      } catch (e) {}
    } else {
      try {
        const parsed = JSON.parse(rawBody);
        eventType = parsed.event || parsed.type || parsed.action || null;
      } catch (e) {}
    }

    const eventId = `evt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    // 1. Durably save event in SQLite
    const savedEvent = storage.saveEvent({
      id: eventId,
      endpointId: endpoint.id,
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
    const { id, name, targetUrl, secret, alertWebhookUrl, autoRetry, maxRetries } = req.body;
    if (!id || !name || !targetUrl) {
      return res.status(400).json({ error: 'id, name, and targetUrl are required' });
    }
    const endpoint = storage.createEndpoint({
      id,
      name,
      targetUrl,
      secret,
      alertWebhookUrl,
      autoRetry: autoRetry !== undefined ? autoRetry : 1,
      maxRetries: maxRetries || 5
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

  // Dashboard Web UI Route
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  return { app, server, storage, dispatcher };
}

module.exports = { createServer };
