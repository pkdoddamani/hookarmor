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
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      requests.push({ headers: req.headers, body });
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
    assert.strictEqual(ha.storage.getEndpoint('ep_del'), undefined);
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
