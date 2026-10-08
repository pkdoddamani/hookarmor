// Regression suite for the hardening pass. Each case covers one defect found in review.
// Runs every case and reports all failures instead of stopping at the first.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const { createServer } = require('../src/server');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function stripeSig(secret, body, t = Math.floor(Date.now() / 1000)) {
  const v1 = crypto.createHmac('sha256', secret).update(`${t}.${body}`).digest('hex');
  return { t, v1, header: `t=${t},v1=${v1}` };
}

function svixSig(secret, id, ts, body) {
  const key = Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
  return 'v1,' + crypto.createHmac('sha256', key).update(`${id}.${ts}.${body}`).digest('base64');
}

// Local HTTP target that records requests. Optionally holds responses until released.
async function startTarget({ status = 200, hold = false } = {}) {
  const requests = [];
  const pending = [];
  const target = { status, requests };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => { chunks.push(c); });
    req.on('end', () => {
      const bodyBuffer = Buffer.concat(chunks);
      requests.push({ headers: req.headers, body: bodyBuffer.toString('utf8'), bodyBuffer });
      const respond = () => { res.writeHead(target.status); res.end('ok'); };
      if (hold) pending.push(respond); else respond();
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  target.url = `http://127.0.0.1:${server.address().port}/hook`;
  target.release = () => { while (pending.length) pending.shift()(); };
  target.close = () => { target.release(); server.close(); };
  return target;
}

async function startHA(options = {}) {
  const ha = createServer({ dbPath: ':memory:', autoStartWorker: false, ...options });
  await new Promise((r) => ha.server.listen(0, '127.0.0.1', r));
  ha.base = `http://127.0.0.1:${ha.server.address().port}`;
  ha.close = () => new Promise((r) => { ha.worker.stop(); ha.server.close(() => r()); ha.server.closeAllConnections?.(); });
  return ha;
}

async function waitFor(fn, timeoutMs = 5000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const v = fn();
    if (v) return v;
    await sleep(20);
  }
  return fn();
}

// Shift a stored timestamp while keeping whatever format the code wrote.
function shiftStored(str, seconds) {
  const isIso = str.includes('T');
  const d = new Date(isIso ? str : str.replace(' ', 'T') + 'Z');
  const shifted = new Date(d.getTime() + seconds * 1000);
  return isIso ? shifted.toISOString() : shifted.toISOString().slice(0, 19).replace('T', ' ');
}

const JSON_HEADERS = { 'Content-Type': 'application/json' };
const cases = [];
const test = (name, fn) => cases.push({ name, fn });

// ---------------------------------------------------------------- retries & replay

test('failed event becomes due for retry once its backoff has elapsed', async () => {
  const target = await startTarget({ status: 500 });
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: target.url, maxRetries: 5 });
    const res = await fetch(`${ha.base}/in/ep`, { method: 'POST', headers: JSON_HEADERS, body: '{"id":"a1"}' });
    const { hookarmor_id } = await res.json();
    const ev = await waitFor(() => { const e = ha.storage.getEvent(hookarmor_id); return e.status === 'failed' && e; });
    assert.ok(ev && ev.next_retry_at, 'next_retry_at must be set after a failure');
    // Move the stored backoff 60s into the past, preserving the format the dispatcher wrote
    ha.storage.db.prepare('UPDATE events SET next_retry_at = ? WHERE id = ?').run(shiftStored(ev.next_retry_at, -3600), hookarmor_id);
    const due = ha.storage.getEventsDueForRetry(25).map((e) => e.id);
    assert.ok(due.includes(hookarmor_id), `event with elapsed backoff must be due (stored next_retry_at=${ev.next_retry_at})`);
  } finally { await ha.close(); target.close(); }
});

test('replay-all re-delivers events that exhausted their automatic retries', async () => {
  const target = await startTarget({ status: 500 });
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: target.url, maxRetries: 1 });
    const res = await fetch(`${ha.base}/in/ep`, { method: 'POST', headers: JSON_HEADERS, body: '{"id":"b1"}' });
    const { hookarmor_id } = await res.json();
    await waitFor(() => ha.storage.getEvent(hookarmor_id).status === 'failed');
    target.status = 200; // downstream fixed
    await fetch(`${ha.base}/api/events/replay-all`, { method: 'POST', headers: JSON_HEADERS, body: '{}' });
    const ev = await waitFor(() => { const e = ha.storage.getEvent(hookarmor_id); return e.status === 'delivered' && e; });
    assert.ok(ev, 'exhausted dead-letter event must be delivered by replay-all');
  } finally { await ha.close(); target.close(); }
});

test('events left mid-delivery by a crash are recovered on restart', async () => {
  const dbPath = path.join(os.tmpdir(), `ha_reg_${process.pid}_${Date.now()}.db`);
  const first = createServer({ dbPath, autoStartWorker: false });
  first.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: 'http://127.0.0.1:9/never' });
  first.storage.saveEvent({ id: 'evt_crash', endpointId: 'ep', provider: 'generic', headers: {}, rawBody: '{}' });
  first.storage.db.prepare("UPDATE events SET status = 'replaying' WHERE id = 'evt_crash'").run();
  first.storage.db.close();
  const second = createServer({ dbPath, autoStartWorker: false });
  try {
    const ev = second.storage.getEvent('evt_crash');
    assert.notStrictEqual(ev.status, 'replaying', 'stranded in-flight event must be returned to the retry queue on startup');
  } finally {
    second.storage.db.close();
    for (const f of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) fs.rmSync(f, { force: true });
  }
});

test('slow first delivery is not dispatched a second time by the retry sweep', async () => {
  const target = await startTarget({ hold: true });
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: target.url });
    const res = await fetch(`${ha.base}/in/ep`, { method: 'POST', headers: JSON_HEADERS, body: '{"id":"c1"}' });
    const { hookarmor_id } = await res.json();
    await waitFor(() => target.requests.length === 1);
    // Age the event past the 20s pending sweep while the first delivery is still in flight
    ha.storage.db.prepare("UPDATE events SET created_at = datetime('now', '-60 seconds') WHERE id = ?").run(hookarmor_id);
    await ha.worker.tick();
    await sleep(200);
    target.release();
    await sleep(200);
    target.release();
    assert.strictEqual(target.requests.length, 1, `target must receive exactly one delivery, got ${target.requests.length}`);
  } finally { await ha.close(); target.close(); }
});

test('manual replay of an event already in flight is refused', async () => {
  const target = await startTarget({ hold: true });
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: target.url });
    const res = await fetch(`${ha.base}/in/ep`, { method: 'POST', headers: JSON_HEADERS, body: '{"id":"d1"}' });
    const { hookarmor_id } = await res.json();
    await waitFor(() => target.requests.length === 1);
    const replay = await fetch(`${ha.base}/api/events/${hookarmor_id}/replay`, { method: 'POST', headers: JSON_HEADERS, body: '{}' });
    assert.strictEqual(replay.status, 409, 'replaying an in-flight event must return 409');
  } finally { await ha.close(); target.close(); }
});

test('provider re-send of an event still in the dead-letter queue is deduplicated', async () => {
  const target = await startTarget({ status: 500 });
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: target.url });
    const body = JSON.stringify({ id: 'evt_resend_1', type: 'invoice.paid' });
    const first = await (await fetch(`${ha.base}/in/ep`, { method: 'POST', headers: JSON_HEADERS, body })).json();
    await waitFor(() => ha.storage.getEvent(first.hookarmor_id).status === 'failed');
    const second = await (await fetch(`${ha.base}/in/ep`, { method: 'POST', headers: JSON_HEADERS, body })).json();
    assert.strictEqual(second.status, 'deduplicated', 'second copy must not create a new delivery');
    const count = ha.storage.db.prepare("SELECT count(*) AS n FROM events WHERE idempotency_key = 'evt_resend_1'").get().n;
    assert.strictEqual(count, 1);
  } finally { await ha.close(); target.close(); }
});

// ---------------------------------------------------------------- signature verification

test('Stripe signature header with two v1 values (secret rotation) is accepted', async () => {
  const target = await startTarget();
  const ha = await startHA();
  try {
    const secret = 'whsec_rotation_new';
    ha.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: target.url, secret });
    const body = JSON.stringify({ id: 'evt_rot', type: 'charge.succeeded' });
    const good = stripeSig(secret, body);
    const old = stripeSig('whsec_rotation_old', body, good.t);
    const res = await fetch(`${ha.base}/in/ep`, {
      method: 'POST',
      headers: { ...JSON_HEADERS, 'Stripe-Signature': `t=${good.t},v1=${good.v1},v1=${old.v1}` },
      body
    });
    assert.strictEqual(res.status, 200, 'a matching v1 in any position must verify');
  } finally { await ha.close(); target.close(); }
});

test('endpoint with a secret rejects events that carry no recognised signature', async () => {
  const target = await startTarget();
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: target.url, secret: 'whsec_x' });
    const res = await fetch(`${ha.base}/in/ep`, { method: 'POST', headers: JSON_HEADERS, body: '{"id":"evt_nosig"}' });
    assert.strictEqual(res.status, 400, 'unsigned event on a secret-protected endpoint must be rejected');
    await sleep(100);
    assert.strictEqual(target.requests.length, 0);
  } finally { await ha.close(); target.close(); }
});

test('Clerk/Svix signatures are verified on ingress and re-signed on delivery', async () => {
  const target = await startTarget();
  const ha = await startHA();
  try {
    const secret = 'whsec_' + Buffer.from('clerk-test-key-0123456789').toString('base64');
    ha.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: target.url, secret });
    const body = JSON.stringify({ type: 'user.created', data: { id: 'user_1' } });
    const ts = String(Math.floor(Date.now() / 1000));
    const bad = await fetch(`${ha.base}/in/ep`, {
      method: 'POST',
      headers: { ...JSON_HEADERS, 'svix-id': 'msg_bad', 'svix-timestamp': ts, 'svix-signature': 'v1,AAAA' },
      body
    });
    assert.strictEqual(bad.status, 400, 'invalid svix signature must be rejected');
    const good = await fetch(`${ha.base}/in/ep`, {
      method: 'POST',
      headers: { ...JSON_HEADERS, 'svix-id': 'msg_good', 'svix-timestamp': ts, 'svix-signature': svixSig(secret, 'msg_good', ts, body) },
      body
    });
    assert.strictEqual(good.status, 200, 'valid svix signature must be accepted');
    await waitFor(() => target.requests.length === 1);
    const fwd = target.requests[0].headers;
    const expected = svixSig(secret, fwd['svix-id'], fwd['svix-timestamp'], body);
    assert.ok(fwd['svix-signature'].split(' ').includes(expected), 'forwarded svix signature must be valid for the forwarded timestamp');
  } finally { await ha.close(); target.close(); }
});

test('internal HookArmor signature is only attached to events verified at ingress', async () => {
  const target = await startTarget();
  const ha = await startHA({ signingSecret: 'internal_relay_secret' });
  try {
    ha.storage.createEndpoint({ id: 'open', name: 'open', targetUrl: target.url });
    await fetch(`${ha.base}/in/open`, { method: 'POST', headers: JSON_HEADERS, body: '{"id":"evt_open"}' });
    await waitFor(() => target.requests.length === 1);
    assert.strictEqual(target.requests[0].headers['x-hookarmor-signature'], undefined, 'unverified event must not be vouched for');

    const secret = 'whsec_verified';
    ha.storage.createEndpoint({ id: 'signed', name: 'signed', targetUrl: target.url, secret });
    const body = JSON.stringify({ id: 'evt_signed', type: 'charge.succeeded' });
    await fetch(`${ha.base}/in/signed`, { method: 'POST', headers: { ...JSON_HEADERS, 'Stripe-Signature': stripeSig(secret, body).header }, body });
    await waitFor(() => target.requests.length === 2);
    assert.ok(target.requests[1].headers['x-hookarmor-signature'], 'verified event must carry the internal signature');
  } finally { await ha.close(); target.close(); }
});

// ---------------------------------------------------------------- outbound URL validation

test('strict mode blocks loopback, private and IPv6 internal target URLs', async () => {
  const ha = await startHA({ strictSSRF: true });
  try {
    const urls = [
      'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://2130706433/', 'http://10.0.0.5/',
      'http://[fd00::1]/', 'http://[fe80::1]/', 'http://100.64.0.1/', 'http://0.0.0.0/'
    ];
    for (const targetUrl of urls) {
      const res = await fetch(`${ha.base}/api/endpoints`, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ id: 'x', name: 'x', targetUrl }) });
      assert.strictEqual(res.status, 400, `${targetUrl} must be rejected in strict mode`);
    }
  } finally { await ha.close(); }
});

test('alert webhook URL is validated like the target URL', async () => {
  const ha = await startHA();
  try {
    const res = await fetch(`${ha.base}/api/endpoints`, {
      method: 'POST', headers: JSON_HEADERS,
      body: JSON.stringify({ id: 'x', name: 'x', targetUrl: 'https://example.com/hook', alertWebhookUrl: 'http://169.254.169.254/latest' })
    });
    assert.strictEqual(res.status, 400, 'metadata address in alertWebhookUrl must be rejected');
  } finally { await ha.close(); }
});

test('strict mode re-checks the resolved address at delivery time', async () => {
  const target = await startTarget();
  const ha = await startHA({ strictSSRF: true });
  try {
    // Stored directly, bypassing the API check: simulates a hostname that later resolves internally
    const port = new URL(target.url).port;
    ha.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: `http://localhost:${port}/hook`, autoRetry: 0 });
    const { hookarmor_id } = await (await fetch(`${ha.base}/in/ep`, { method: 'POST', headers: JSON_HEADERS, body: '{}' })).json();
    await waitFor(() => ha.storage.getEvent(hookarmor_id).status === 'failed');
    assert.strictEqual(target.requests.length, 0, 'delivery to an address that resolves internally must be blocked');
    // DNS path: a hostname resolving to loopback is refused by the request-time lookup
    const { guardedLookup } = require('../src/netguard');
    const lookupErr = await new Promise((r) => guardedLookup(true)('localhost', {}, (err) => r(err)));
    assert.ok(lookupErr && lookupErr.code === 'EBLOCKEDADDRESS', 'resolved loopback address must be refused');
  } finally { await ha.close(); target.close(); }
});

// ---------------------------------------------------------------- management API & dashboard

test('endpoint listing does not expose signing secrets', async () => {
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: 'https://example.com/h', secret: 'whsec_do_not_leak' });
    const text = await (await fetch(`${ha.base}/api/endpoints`)).text();
    assert.ok(!text.includes('whsec_do_not_leak'), 'secret must not appear in API output');
  } finally { await ha.close(); }
});

test('updating an endpoint without a secret keeps the existing secret', async () => {
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: 'https://example.com/h', secret: 'whsec_keep' });
    await fetch(`${ha.base}/api/endpoints`, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ id: 'ep', name: 'renamed', targetUrl: 'https://example.com/h2' }) });
    assert.strictEqual(ha.storage.getEndpoint('ep').secret, 'whsec_keep');
  } finally { await ha.close(); }
});

test('live WebSocket feed requires the API key when one is configured', async () => {
  const target = await startTarget();
  const ha = await startHA({ apiKey: 'k_live_feed' });
  try {
    ha.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: target.url });
    const wsUrl = ha.base.replace('http', 'ws') + '/ws';
    const anon = new WebSocket(wsUrl);
    const authed = new WebSocket(wsUrl);
    const anonMsgs = [], authedMsgs = [];
    anon.on('message', (m) => anonMsgs.push(String(m)));
    authed.on('message', (m) => authedMsgs.push(String(m)));
    await Promise.all([anon, authed].map((s) => new Promise((r) => s.on('open', r))));
    authed.send(JSON.stringify({ type: 'auth', token: 'k_live_feed' }));
    await sleep(100);
    await fetch(`${ha.base}/in/ep`, { method: 'POST', headers: JSON_HEADERS, body: '{"id":"ws1"}' });
    await sleep(300);
    anon.close(); authed.close();
    assert.ok(authedMsgs.some((m) => m.includes('ws1') || m.includes('event:received')), 'authenticated client must receive events');
    assert.strictEqual(anonMsgs.filter((m) => !m.includes('auth')).length, 0, 'unauthenticated client must not receive events');
  } finally { await ha.close(); target.close(); }
});

test('demo mode is read-only (no replays)', async () => {
  const ha = await startHA({ apiKey: 'k_demo', demoMode: true });
  try {
    const res = await fetch(`${ha.base}/api/events/replay-all`, { method: 'POST', headers: JSON_HEADERS, body: '{}' });
    assert.strictEqual(res.status, 401, 'unauthenticated replay must be refused in demo mode');
  } finally { await ha.close(); }
});

test('management API does not send permissive CORS headers', async () => {
  const ha = await startHA();
  try {
    const res = await fetch(`${ha.base}/api/stats`, { headers: { Origin: 'https://other.example' } });
    assert.strictEqual(res.headers.get('access-control-allow-origin'), null);
  } finally { await ha.close(); }
});

test('state-changing API calls require a JSON content type', async () => {
  const ha = await startHA();
  try {
    const res = await fetch(`${ha.base}/api/events/replay-all`, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'x' });
    assert.strictEqual(res.status, 415, 'form/plain-text POSTs (cross-site requests) must be refused');
  } finally { await ha.close(); }
});

test('without an API key the management API only answers to localhost host names', async () => {
  const ha = await startHA();
  try {
    const port = ha.server.address().port;
    const status = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port, path: '/api/stats', headers: { Host: `rebind.example:${port}` } }, (res) => { res.resume(); resolve(res.statusCode); }).on('error', reject);
    });
    assert.strictEqual(status, 403);
  } finally { await ha.close(); }
});

test('production mode refuses to start without an API key', async () => {
  assert.throws(() => createServer({ dbPath: ':memory:', autoStartWorker: false, production: true }), /HOOKARMOR_API_KEY/);
});

test('mock receiver routes are not mounted in production', async () => {
  const ha = await startHA({ production: true, apiKey: 'k_prod' });
  try {
    const res = await fetch(`${ha.base}/mock/config`, { method: 'POST', headers: JSON_HEADERS, body: '{"statusCode":500}' });
    assert.strictEqual(res.status, 404);
  } finally { await ha.close(); }
});

test('waitlist signups are rate limited per client', async () => {
  const ha = await startHA({ waitlistRateLimit: 3 });
  try {
    const codes = [];
    for (let i = 0; i < 5; i++) {
      const res = await fetch(`${ha.base}/api/waitlist`, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ email: `u${i}@example.com` }) });
      codes.push(res.status);
    }
    assert.ok(codes.includes(429), `expected a 429 after the limit, got ${codes.join(',')}`);
  } finally { await ha.close(); }
});

test('dashboard escapes untrusted values before inserting HTML', async () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'public', 'index.html'), 'utf8');
  assert.ok(/function esc\(/.test(html), 'dashboard must define an esc() helper');
  const untrusted = ['raw_body', 'response_body', 'error_message', 'l.email', 'l.source', 'ep.name', 'ep.target_url', 'event_type', 'evt.provider', 'evt.endpoint_id', 'evt.headers'];
  const exprs = html.match(/\$\{[^}]*\}/g) || [];
  for (const field of untrusted) {
    for (const e of exprs.filter((x) => x.includes(field))) {
      assert.ok(e.startsWith('${esc('), `${e} must be escaped`);
    }
  }
  assert.ok(/csvCell|=\+\-@/.test(html), 'CSV export must neutralise formula prefixes');
});

// ---------------------------------------------------------------- storage

test('SQLite fsyncs every commit (synchronous=FULL)', async () => {
  const ha = await startHA();
  try {
    assert.strictEqual(ha.storage.db.pragma('synchronous', { simple: true }), 2);
  } finally { await ha.close(); }
});

test('retention pruning removes old delivered events but keeps failed ones', async () => {
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep', name: 'ep', targetUrl: 'https://example.com/h' });
    for (const [id, status] of [['old_ok', 'delivered'], ['old_bad', 'failed'], ['new_ok', 'delivered']]) {
      ha.storage.saveEvent({ id, endpointId: 'ep', provider: 'generic', headers: {}, rawBody: '{}', status });
    }
    ha.storage.db.prepare("UPDATE events SET created_at = datetime('now', '-40 days') WHERE id IN ('old_ok','old_bad')").run();
    ha.storage.pruneEvents(30);
    assert.strictEqual(ha.storage.getEvent('old_ok'), null);
    assert.ok(ha.storage.getEvent('old_bad'));
    assert.ok(ha.storage.getEvent('new_ok'));
  } finally { await ha.close(); }
});

test('DELETE /api/endpoints/:id and /api/events/:id remove rows and delivery attempts', async () => {
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_del', name: 'ep_del', targetUrl: 'https://example.com/del' });
    ha.storage.saveEvent({ id: 'evt_del', endpointId: 'ep_del', provider: 'generic', headers: {}, rawBody: '{}', status: 'failed' });
    ha.storage.recordAttempt({ eventId: 'evt_del', statusCode: 500, responseBody: 'fail', errorMessage: 'err', latencyMs: 10 });
    
    // Delete event
    const resEvt = await fetch(`${ha.base}/api/events/evt_del`, { method: 'DELETE' });
    assert.strictEqual(resEvt.status, 200);
    assert.strictEqual(ha.storage.getEvent('evt_del'), null);
    assert.strictEqual(ha.storage.getAttempts('evt_del').length, 0);

    // Delete endpoint
    const resEp = await fetch(`${ha.base}/api/endpoints/ep_del`, { method: 'DELETE' });
    assert.strictEqual(resEp.status, 200);
    assert.strictEqual(ha.storage.getEndpoint('ep_del'), null);
  } finally { await ha.close(); }
});

test('outbound x-hookarmor-original-timestamp is formatted with UTC Z suffix', async () => {
  const target = await startTarget();
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_ts', name: 'ep_ts', targetUrl: target.url });
    await fetch(`${ha.base}/in/ep_ts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ping: true })
    });
    await sleep(60);
    assert.strictEqual(target.requests.length, 1);
    const ts = target.requests[0].headers['x-hookarmor-original-timestamp'];
    assert.ok(ts && ts.endsWith('Z'), `Must end with Z: ${ts}`);
    assert.ok(!isNaN(Date.parse(ts)));
  } finally {
    await ha.close();
    target.close();
  }
});

test('arbitrary non-UTF-8 bytes (61 ff 62) are preserved byte-for-byte on dispatch without mutation', async () => {
  const target = await startTarget();
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_bin', name: 'ep_bin', targetUrl: target.url });
    const rawPayload = Buffer.from([0x61, 0xff, 0x62]);
    await fetch(`${ha.base}/in/ep_bin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: rawPayload
    });
    await sleep(60);
    assert.strictEqual(target.requests.length, 1);
    assert.deepStrictEqual(target.requests[0].bodyBuffer, rawPayload, 'Must preserve exact bytes 61 ff 62 without Unicode replacement corruption');
  } finally {
    await ha.close();
    target.close();
  }
});

test('ingress rate limiting throttles requests per client IP when limit is reached', async () => {
  const orig = process.env.HOOKARMOR_INGRESS_RATE_LIMIT;
  process.env.HOOKARMOR_INGRESS_RATE_LIMIT = '3';
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_rl', name: 'ep_rl', targetUrl: 'https://example.com/h' });
    const statuses = [];
    for (let i = 0; i < 4; i++) {
      const res = await fetch(`${ha.base}/in/ep_rl`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ i })
      });
      statuses.push(res.status);
    }
    assert.deepStrictEqual(statuses, [200, 200, 200, 429]);
  } finally {
    process.env.HOOKARMOR_INGRESS_RATE_LIMIT = orig || '';
    await ha.close();
  }
});

test('endpoint secrets are encrypted with AES-256-GCM at rest when HOOKARMOR_ENCRYPTION_KEY is set', async () => {
  const encKey = 'test_master_encryption_key_abcdef123456';
  const ha = await startHA({ encryptionKey: encKey });
  try {
    ha.storage.createEndpoint({
      id: 'ep_enc',
      name: 'Encrypted Endpoint',
      targetUrl: 'https://example.com/enc',
      secret: 'whsec_very_secret_signing_token_999'
    });

    // 1. Raw database row must store authenticated ciphertext, not plaintext
    const rawRow = ha.storage.db.prepare("SELECT secret FROM endpoints WHERE id = 'ep_enc'").get();
    assert.ok(rawRow.secret.startsWith('enc:v1:'), 'Stored secret must be prefixed with enc:v1:');
    assert.strictEqual(rawRow.secret.includes('whsec_very_secret'), false, 'Plaintext secret must not appear in SQLite database');

    // 2. getEndpoint transparently decrypts using the key
    const ep = ha.storage.getEndpoint('ep_enc');
    assert.strictEqual(ep.secret, 'whsec_very_secret_signing_token_999');

    // 3. Tampering with ciphertext fails authentication
    const tampered = rawRow.secret.slice(0, -4) + '0000';
    ha.storage.db.prepare("UPDATE endpoints SET secret = ? WHERE id = 'ep_enc'").run(tampered);
    assert.throws(() => ha.storage.getEndpoint('ep_enc'), /Unsupported state or unable to authenticate data|authentication failed/i);
  } finally {
    await ha.close();
  }
});

test('Prometheus /metrics endpoint returns standard exposition format', async () => {
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_m1', name: 'ep_m1', targetUrl: 'https://example.com/1', secret: 'whsec_1' });
    ha.storage.createEndpoint({ id: 'ep_m2', name: 'ep_m2', targetUrl: 'https://example.com/2' }); // unverified
    const res = await fetch(`${ha.base}/metrics`);
    assert.strictEqual(res.status, 200);
    assert.ok(res.headers.get('content-type').includes('text/plain'));
    const body = await res.text();
    assert.ok(body.includes('hookarmor_uptime_seconds'));
    assert.ok(body.includes('hookarmor_events_total{status="delivered"}'));
    assert.ok(body.includes('hookarmor_endpoints_total 2'));
    assert.ok(body.includes('hookarmor_endpoints_unverified_total 1'));
  } finally {
    await ha.close();
  }
});

test('ingress on endpoints without secrets records x-hookarmor-unverified diagnostic header', async () => {
  const target = await startTarget();
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_no_sec', name: 'No Secret', targetUrl: target.url });
    const res = await fetch(`${ha.base}/in/ep_no_sec`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hello: 'world' })
    });
    assert.strictEqual(res.status, 200);
    const { hookarmor_id } = await res.json();
    const ev = await waitFor(() => ha.storage.getEvent(hookarmor_id));
    assert.strictEqual(ev.verified, 0);
    await waitFor(() => target.requests.length === 1);
    assert.strictEqual(target.requests[0].headers['x-hookarmor-unverified'], 'true');
  } finally {
    await ha.close();
    target.close();
  }
});

test('B1: multi-instance lease claims prevent active peer delivery theft while recovering dead instances', async () => {
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_multi', name: 'Multi', targetUrl: 'https://example.com' });
    ha.storage.saveEvent({ id: 'evt_peer_active', endpointId: 'ep_multi', headers: {}, rawBody: 'ping' });
    ha.storage.saveEvent({ id: 'evt_dead_worker', endpointId: 'ep_multi', headers: {}, rawBody: 'ping2' });

    // Register active peer instance and dead peer instance
    ha.storage.registerInstance({ id: 'inst_active', hostname: 'host1', pid: 1001 });
    ha.storage.registerInstance({ id: 'inst_dead', hostname: 'host2', pid: 1002 });
    // Backdate dead instance heartbeat to 60 seconds ago
    ha.storage.db.prepare("UPDATE instances SET last_heartbeat = datetime('now', '-60 seconds') WHERE id = 'inst_dead'").run();

    // Claim one event by active peer, and one by dead peer
    ha.storage.claimEventForRetry('evt_peer_active', 'inst_active');
    ha.storage.claimEventForRetry('evt_dead_worker', 'inst_dead');

    // Instance 3 starts up and runs recovery
    const recovered = ha.storage.recoverInterruptedDeliveries('inst_3');
    assert.strictEqual(recovered, 1, 'Must recover exactly 1 dead worker event, leaving active peer claim untouched');

    const evActive = ha.storage.getEvent('evt_peer_active');
    assert.strictEqual(evActive.status, 'replaying', 'Active peer delivery must remain in-flight');

    const evDead = ha.storage.getEvent('evt_dead_worker');
    assert.strictEqual(evDead.status, 'failed', 'Dead worker delivery must be re-queued to failed');
  } finally {
    await ha.close();
  }
});

test('B2: cascading endpoint deletion succeeds even when endpoint has events and attempts history', async () => {
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_cascade', name: 'Cascade Test', targetUrl: 'https://example.com' });
    ha.storage.saveEvent({ id: 'evt_hist_1', endpointId: 'ep_cascade', headers: {}, rawBody: 'test1' });
    ha.storage.recordAttempt({ eventId: 'evt_hist_1', statusCode: 500, errorMessage: 'Failed' });

    // Deleting endpoint directly must cascade and not throw SQLite FK error
    const deleted = ha.storage.deleteEndpoint('ep_cascade');
    assert.strictEqual(deleted, true);

    assert.strictEqual(ha.storage.getEndpoint('ep_cascade'), null);
    assert.strictEqual(ha.storage.getEvent('evt_hist_1'), null);
    assert.strictEqual(ha.storage.getAttempts('evt_hist_1').length, 0);
  } finally {
    await ha.close();
  }
});

test('B3: outbound dispatch strips spoofable routing and trust headers', async () => {
  const target = await startTarget();
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_strip', name: 'Header Strip', targetUrl: target.url });
    await fetch(`${ha.base}/in/ep_strip`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '10.0.0.99',
        'X-Real-IP': '10.0.0.99',
        'X-Original-URL': '/admin/delete',
        'CF-Connecting-IP': '10.0.0.99',
        'X-Custom-Header': 'keep-me'
      },
      body: JSON.stringify({ ok: true })
    });

    await waitFor(() => target.requests.length === 1);
    const receivedHeaders = target.requests[0].headers;
    assert.strictEqual(receivedHeaders['x-custom-header'], 'keep-me');
    assert.strictEqual(receivedHeaders['x-forwarded-for'], undefined);
    assert.strictEqual(receivedHeaders['x-real-ip'], undefined);
    assert.strictEqual(receivedHeaders['x-original-url'], undefined);
    assert.strictEqual(receivedHeaders['cf-connecting-ip'], undefined);
  } finally {
    await ha.close();
    target.close();
  }
});

test('B4: /mock/config route requires authentication when API key is configured', async () => {
  const apiKey = 'test_mock_secret_key_777';
  const ha = await startHA({ apiKey, enableMock: true });
  try {
    // Unauthenticated write must fail with 401
    const resNoAuth = await fetch(`${ha.base}/mock/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ statusCode: 503 })
    });
    assert.strictEqual(resNoAuth.status, 401);

    // Authenticated write must succeed with 200
    const resAuth = await fetch(`${ha.base}/mock/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify({ statusCode: 503 })
    });
    assert.strictEqual(resAuth.status, 200);
    const data = await resAuth.json();
    assert.strictEqual(data.config.statusCode, 503);
  } finally {
    await ha.close();
  }
});

test('B5: unique index on events(endpoint_id, idempotency_key) enforces cross-instance dedup', async () => {
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_idem_idx', name: 'Idem Index', targetUrl: 'https://example.com' });
    const ev1 = ha.storage.saveEvent({
      id: 'evt_idem_1',
      endpointId: 'ep_idem_idx',
      idempotencyKey: 'dup_key_999',
      headers: {},
      rawBody: 'one'
    });
    assert.strictEqual(ev1.id, 'evt_idem_1');

    // Second insert with exact same idempotency key must not throw or insert a duplicate
    const ev2 = ha.storage.saveEvent({
      id: 'evt_idem_2',
      endpointId: 'ep_idem_idx',
      idempotencyKey: 'dup_key_999',
      headers: {},
      rawBody: 'two'
    });
    assert.strictEqual(ev2.id, 'evt_idem_1', 'Must return existing event on collision');
  } finally {
    await ha.close();
  }
});

test('B7: HTTP response includes security headers and disables X-Powered-By', async () => {
  const ha = await startHA();
  try {
    const res = await fetch(`${ha.base}/dashboard`);
    assert.strictEqual(res.headers.get('x-frame-options'), 'DENY');
    assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
    assert.ok(res.headers.get('content-security-policy'));
    assert.strictEqual(res.headers.get('x-powered-by'), null);
  } finally {
    await ha.close();
  }
});

test('N1: active heartbeating instance claims are not reclaimed after 180s', async () => {
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_n1', name: 'ep_n1', targetUrl: 'http://127.0.0.1:4999/hook' });
    ha.storage.registerInstance({ id: 'inst_live', hostname: 'host1', pid: 1111 });
    
    ha.storage.saveEvent({
      id: 'evt_n1',
      endpointId: 'ep_n1',
      headers: {},
      rawBody: 'n1',
      status: 'replaying',
      claimedBy: 'inst_live'
    });
    // Artificially age claimed_at to 200s ago
    ha.storage.db.prepare("UPDATE events SET claimed_at = datetime('now', '-200 seconds') WHERE id = 'evt_n1'").run();

    // inst_live heartbeats now
    ha.storage.heartbeatInstance('inst_live');

    // recoverInterruptedDeliveries must NOT reclaim this event because inst_live is heartbeating
    const recovered = ha.storage.recoverInterruptedDeliveries();
    assert.strictEqual(recovered, 0, 'Must not steal claim from an active heartbeating instance');
    
    const ev = ha.storage.getEvent('evt_n1');
    assert.strictEqual(ev.status, 'replaying');
    assert.strictEqual(ev.claimed_by, 'inst_live');
  } finally {
    await ha.close();
  }
});

test('N3: /metrics requires API key when configured and rejects unauthorized requests with 401', async () => {
  const ha = await startHA({ apiKey: 'secret-key-123' });
  try {
    const unauthed = await fetch(`${ha.base}/metrics`);
    assert.strictEqual(unauthed.status, 401, 'Unauthenticated /metrics should return 401');

    const authed = await fetch(`${ha.base}/metrics`, {
      headers: { Authorization: 'Bearer secret-key-123' }
    });
    assert.strictEqual(authed.status, 200, 'Authenticated /metrics should return 200');
    const body = await authed.text();
    assert.ok(body.includes('hookarmor_uptime_seconds'));
  } finally {
    await ha.close();
  }
});

test('N4: assertSecretsReadable fails fast when encryption key cannot decrypt stored secrets', async () => {
  const Storage = require('../src/storage');
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ha-n4-'));
  const dbFile = path.join(tempDir, 'n4.db');
  let s1 = null;
  let s2 = null;
  try {
    s1 = new Storage(dbFile, { encryptionKey: 'key-alpha-32-chars-long-test-pass' });
    s1.createEndpoint({ id: 'ep_enc', name: 'ep_enc', targetUrl: 'https://example.com', secret: 'whsec_secret_val' });
    s1.close();
    s1 = null;

    s2 = new Storage(dbFile, { encryptionKey: 'key-bravo-32-chars-long-test-fail' });
    assert.throws(() => {
      s2.assertSecretsReadable(false);
    }, /Failed to decrypt signing secrets/);

    assert.strictEqual(s2.assertSecretsReadable(true), false);
  } finally {
    if (s1) { try { s1.close(); } catch (_) {} }
    if (s2) { try { s2.close(); } catch (_) {} }
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch (_) {}
  }
});

test('N5: releaseClaimsOwnedBy and deregisterInstance clean up instance state on shutdown', async () => {
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_n5', name: 'ep_n5', targetUrl: 'http://127.0.0.1:4999/hook' });
    ha.storage.registerInstance({ id: 'inst_n5', hostname: 'host_n5', pid: 5555 });
    ha.storage.saveEvent({
      id: 'evt_n5',
      endpointId: 'ep_n5',
      headers: {},
      rawBody: 'n5',
      status: 'replaying',
      claimedBy: 'inst_n5'
    });

    const released = ha.storage.releaseClaimsOwnedBy('inst_n5');
    assert.strictEqual(released, 1);
    const ev = ha.storage.getEvent('evt_n5');
    assert.strictEqual(ev.status, 'pending');
    assert.strictEqual(ev.claimed_by, null);

    const dereg = ha.storage.deregisterInstance('inst_n5');
    assert.strictEqual(dereg, 1);
    const remaining = ha.storage.db.prepare('SELECT count(*) as c FROM instances WHERE id = ?').get('inst_n5').c;
    assert.strictEqual(remaining, 0);
  } finally {
    await ha.close();
  }
});

test('healthz: /healthz returns status 200, version, and uptime', async () => {
  const ha = await startHA();
  try {
    const res = await fetch(`${ha.base}/healthz`);
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.status, 'ok');
    assert.ok(data.version);
    assert.strictEqual(typeof data.uptime, 'number');
  } finally {
    await ha.close();
  }
});

test('custom_headers: outbound dispatch includes configured destination headers', async () => {
  const target = await startTarget({ status: 200 });
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({
      id: 'ep_cust_h',
      name: 'Custom Headers Endpoint',
      targetUrl: target.url,
      customHeaders: {
        'x-internal-secret': 'sec_abc123',
        'authorization': 'Bearer backend-jwt-token'
      }
    });

    const res = await fetch(`${ha.base}/in/ep_cust_h`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hello: 'world' })
    });
    assert.strictEqual(res.status, 200);

    const received = await waitFor(() => target.requests.find((r) => r.body.includes('hello')));
    assert.ok(received, 'Target must receive dispatched request');
    assert.strictEqual(received.headers['x-internal-secret'], 'sec_abc123');
    assert.strictEqual(received.headers['authorization'], 'Bearer backend-jwt-token');
  } finally {
    await ha.close();
    target.close();
  }
});

test('inbound sensitive headers (authorization, cookie, x-api-key) are redacted before storage', async () => {
  const target = await startTarget();
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_redact', name: 'ep_redact', targetUrl: target.url });
    const res = await fetch(`${ha.base}/in/ep_redact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer leaked-secret-token',
        'Cookie': 'session=super-secret-cookie',
        'X-Api-Key': 'key-12345'
      },
      body: JSON.stringify({ event: 'ping' })
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    const stored = ha.storage.getEvent(body.hookarmor_id);
    assert.strictEqual(stored.headers['authorization'], '[REDACTED]');
    assert.strictEqual(stored.headers['cookie'], '[REDACTED]');
    assert.strictEqual(stored.headers['x-api-key'], '[REDACTED]');
  } finally {
    await ha.close();
    target.close();
  }
});

test('unsigned endpoint dedupe does not suppress conflicting payloads with the same ID', async () => {
  const target = await startTarget();
  const ha = await startHA();
  try {
    ha.storage.createEndpoint({ id: 'ep_poison', name: 'ep_poison', targetUrl: target.url });
    // First: attacker sends an unverified event with ID 'evt_clash'
    const res1 = await fetch(`${ha.base}/in/ep_poison`, {
      method: 'POST',
      headers: JSON_HEADERS,
      body: JSON.stringify({ id: 'evt_clash', amount: 10 })
    });
    const b1 = await res1.json();
    assert.strictEqual(b1.received, true);

    // Second: legitimate provider delivers real payload with same ID 'evt_clash' but different amount
    const res2 = await fetch(`${ha.base}/in/ep_poison`, {
      method: 'POST',
      headers: JSON_HEADERS,
      body: JSON.stringify({ id: 'evt_clash', amount: 50000 })
    });
    const b2 = await res2.json();
    assert.notStrictEqual(b2.status, 'deduplicated', 'Conflicting payload must not be suppressed by unverified pre-occupation');
    assert.strictEqual(b2.received, true);
  } finally {
    await ha.close();
    target.close();
  }
});

(async () => {
  let failed = 0;
  for (const c of cases) {
    try {
      await c.fn();
      console.log(`  PASS  ${c.name}`);
    } catch (err) {
      failed++;
      console.log(`  FAIL  ${c.name}\n        ${String(err.message).split('\n')[0]}`);
    }
  }
  console.log(`\n${cases.length - failed}/${cases.length} regression checks passed`);
  process.exit(failed ? 1 : 0);
})();
