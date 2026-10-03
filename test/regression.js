const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { WebSocket } = require('ws');

const { createServer } = require('../src/server');
const Storage = require('../src/storage');
const Dispatcher = require('../src/dispatcher');
const { isPrivateOrMetadataUrl, isPrivateIp, guardedLookup } = require('../src/ssrf');

async function runRegressionSuite() {
  console.log('🧪 Starting HookArmor 26-Point Regression Test Suite (Hardening Verification)...\n');

  // Test 1: A failed event becomes due once its stored backoff time has passed (§3.1)
  {
    console.log('Test 1: Backoff timestamp format in DB is due after delay passes (§3.1)...');
    const storage = new Storage(':memory:');
    const dispatcher = new Dispatcher(storage);
    storage.createEndpoint({ id: 'ep-test-1', name: 'Test 1', targetUrl: 'http://127.0.0.1:9999/wh', autoRetry: 1, maxRetries: 3 });

    const nextRetry = dispatcher.calculateNextRetry(0);
    // Confirm SQLite space format YYYY-MM-DD HH:MM:SS
    assert.ok(!nextRetry.includes('T'), `Stored format must use space separator, not T: ${nextRetry}`);

    const ev = storage.saveEvent({
      id: 'evt_reg_1',
      endpointId: 'ep-test-1',
      provider: 'stripe',
      eventType: 'payment_intent.succeeded',
      headers: {},
      rawBody: '{}',
      status: 'pending'
    });

    storage.recordAttempt({
      eventId: ev.id,
      statusCode: 500,
      errorMessage: 'HTTP 500',
      nextRetryAt: nextRetry
    });

    // Shift next_retry_at 1 minute into the past using the exact format written
    const pastTime = new Date(Date.now() - 60000).toISOString().slice(0, 19).replace('T', ' ');
    storage.db.prepare('UPDATE events SET next_retry_at = ? WHERE id = ?').run(pastTime, ev.id);

    const dueEvents = storage.getEventsDueForRetry(10);
    assert.strictEqual(dueEvents.length, 1, 'Failed event with past next_retry_at must be returned as due');
    assert.strictEqual(dueEvents[0].id, 'evt_reg_1');
    console.log('  ✅ Test 1 Passed: Retry timestamps properly due and parsed.\n');
  }

  // Test 2: Replay-all delivers an event that used up its automatic retries (§3.2)
  {
    console.log('Test 2: Replay-all includes exhausted dead-letter events (§3.2)...');
    let targetRequests = 0;
    let targetStatus = 500;
    const testServer = http.createServer((req, res) => {
      targetRequests++;
      res.writeHead(targetStatus, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: targetStatus }));
    });
    const sPort = 4801;
    await new Promise(r => testServer.listen(sPort, '127.0.0.1', r));

    try {
      const storage = new Storage(':memory:');
      const dispatcher = new Dispatcher(storage);
      storage.createEndpoint({
        id: 'ep-reg-2',
        name: 'Test 2',
        targetUrl: `http://127.0.0.1:${sPort}/hook`,
        autoRetry: 1,
        maxRetries: 1 // Only 1 attempt before DLQ exhaustion
      });

      const ep = storage.getEndpoint('ep-reg-2');
      const ev = storage.saveEvent({
        id: 'evt_reg_2',
        endpointId: ep.id,
        provider: 'stripe',
        eventType: 'charge.failed',
        headers: {},
        rawBody: '{}',
        status: 'pending'
      });

      // First delivery fails -> attempts = 1 = max_retries (exhausted dead-letter)
      await dispatcher.dispatch(ev, ep);
      const failedEv = storage.getEvent(ev.id);
      assert.strictEqual(failedEv.status, 'failed');
      assert.strictEqual(failedEv.attempts, 1);

      // Now heal target and run replayAllFailed
      targetStatus = 200;
      const replayResults = await dispatcher.replayAllFailed(ep.id);
      assert.strictEqual(replayResults.length, 1, 'Replay all must include exhausted dead letter');
      const healedEv = storage.getEvent(ev.id);
      assert.strictEqual(healedEv.status, 'delivered', 'Event must now be delivered after replay-all');
      console.log('  ✅ Test 2 Passed: Dead-letter queue replayed successfully.\n');
    } finally {
      testServer.close();
    }
  }

  // Test 3: An event left replaying in a file database is back in the retry queue after restart (§4.4)
  {
    console.log('Test 3: Stranded in-flight events recovered to failed on startup (§4.4)...');
    const tmpDb = path.join(os.tmpdir(), `hookarmor_crash_${Date.now()}.db`);
    try {
      const storage1 = new Storage(tmpDb);
      storage1.createEndpoint({ id: 'ep-crash', name: 'Crash Test', targetUrl: 'http://127.0.0.1:8888/wh' });
      const ev = storage1.saveEvent({
        id: 'evt_stranded_1',
        endpointId: 'ep-crash',
        provider: 'generic',
        eventType: 'crash.test',
        headers: {},
        rawBody: '{}',
        status: 'pending'
      });
      // Simulate crash during execution
      storage1.db.prepare("UPDATE events SET status = 'replaying' WHERE id = ?").run(ev.id);
      storage1.db.close();

      // Restart storage instance on same file
      const storage2 = new Storage(tmpDb);
      const recovered = storage2.getEvent('evt_stranded_1');
      assert.strictEqual(recovered.status, 'failed', 'Stranded replaying event must be recovered to failed');
      assert.ok(recovered.next_retry_at, 'Recovered event must have next_retry_at set');
      storage2.db.close();
      console.log('  ✅ Test 3 Passed: In-flight crash recovery resets status to failed.\n');
    } finally {
      if (fs.existsSync(tmpDb)) fs.unlinkSync(tmpDb);
    }
  }

  // Test 4: Slow first delivery is not re-sent by worker sweep (§4.4)
  {
    console.log('Test 4: Slow in-flight delivery is not picked up by worker sweep (§4.4)...');
    let requestsReceived = 0;
    const slowServer = http.createServer((req, res) => {
      requestsReceived++;
      setTimeout(() => {
        res.writeHead(200);
        res.end('ok');
      }, 300);
    });
    const slowPort = 4802;
    await new Promise(r => slowServer.listen(slowPort, '127.0.0.1', r));

    try {
      const storage = new Storage(':memory:');
      const dispatcher = new Dispatcher(storage);
      storage.createEndpoint({
        id: 'ep-slow',
        name: 'Slow Target',
        targetUrl: `http://127.0.0.1:${slowPort}/target`,
        autoRetry: 1,
        maxRetries: 3
      });
      const ep = storage.getEndpoint('ep-slow');
      const ev = storage.saveEvent({
        id: 'evt_slow_1',
        endpointId: ep.id,
        provider: 'generic',
        eventType: 'slow.test',
        headers: {},
        rawBody: '{}',
        status: 'replaying' // In flight
      });

      // Age event created_at 25 seconds ago
      storage.db.prepare("UPDATE events SET created_at = datetime('now', '-25 seconds') WHERE id = ?").run(ev.id);

      const due = storage.getEventsDueForRetry(10);
      assert.strictEqual(due.length, 0, 'In-flight event must not be returned in due sweep');
      console.log('  ✅ Test 4 Passed: Worker does not double-dispatch in-flight event.\n');
    } finally {
      slowServer.close();
    }
  }

  // Test 5: Manual replay of an in-flight event returns 409 (§4.4)
  {
    console.log('Test 5: Manual replay of in-flight event returns 409 Conflict (§4.4)...');
    const { server, storage } = createServer({ dbPath: ':memory:', apiKey: 'testkey' });
    const port = 4803;
    await new Promise(r => server.listen(port, '127.0.0.1', r));

    try {
      storage.createEndpoint({ id: 'ep-flight', name: 'Flight', targetUrl: 'http://127.0.0.1:4803/mock/target' });
      const ev = storage.saveEvent({
        id: 'evt_inflight',
        endpointId: 'ep-flight',
        provider: 'generic',
        eventType: 'flight.test',
        headers: {},
        rawBody: '{}',
        status: 'replaying'
      });

      const res = await fetch(`http://127.0.0.1:${port}/api/events/${ev.id}/replay`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer testkey'
        }
      });
      assert.strictEqual(res.status, 409, 'Replay of in-flight event must return 409');
      console.log('  ✅ Test 5 Passed: 409 returned for concurrent in-flight replay.\n');
    } finally {
      server.close();
    }
  }

  // Test 6: Provider re-send while first copy is failed returns deduplicated (§5.1)
  {
    console.log('Test 6: Deduplication catches re-sends when first is failed (§5.1)...');
    const storage = new Storage(':memory:');
    storage.createEndpoint({ id: 'ep-dedup', name: 'Dedup', targetUrl: 'http://127.0.0.1:9999/wh' });
    storage.saveEvent({
      id: 'evt_first_failed',
      endpointId: 'ep-dedup',
      idempotencyKey: 'idemp_key_100',
      provider: 'stripe',
      eventType: 'payment.failed',
      headers: {},
      rawBody: '{}',
      status: 'failed'
    });

    const found = storage.findEventByIdempotencyKey('ep-dedup', 'idemp_key_100');
    assert.ok(found, 'Must find event regardless of failed status');
    assert.strictEqual(found.id, 'evt_first_failed');
    console.log('  ✅ Test 6 Passed: Deduplication suppresses duplicates even for failed initial events.\n');
  }

  // Test 7: Stripe header with two v1 values is accepted (§5.2)
  {
    console.log('Test 7: Stripe multiple v1 rotation headers accepted (§5.2)...');
    const secret = 'whsec_rotatetest_123';
    const now = Math.floor(Date.now() / 1000);
    const body = '{"hello":"world"}';
    const validSig = crypto.createHmac('sha256', secret).update(`${now}.${body}`).digest('hex');
    const multiHeader = `t=${now},v1=bad_old_sig,v1=${validSig}`;

    const res = Dispatcher.verifyIngressSignature('stripe', body, { 'stripe-signature': multiHeader }, secret);
    assert.strictEqual(res.valid, true, 'Must accept matching signature when multiple v1 entries are present');
    console.log('  ✅ Test 7 Passed: Stripe secret rotation supported.\n');
  }

  // Test 8: Endpoint with secret rejects request with no recognized signature (§4.1)
  {
    console.log('Test 8: Reject unsigned request when endpoint has secret (§4.1)...');
    const res = Dispatcher.verifyIngressSignature('generic', '{"test":1}', {}, 'whsec_secret_must_exist');
    assert.strictEqual(res.valid, false, 'Must reject unsigned request on secured endpoint');
    console.log('  ✅ Test 8 Passed: Unsigned requests rejected on secured endpoints.\n');
  }

  // Test 9: Svix/Clerk verification and fresh re-signing (§4.1)
  {
    console.log('Test 9: Svix/Clerk verification and fresh re-signing (§4.1)...');
    const secret = 'whsec_52hPqyO9JzXW1mF4R6T8uV0bN2cE4gI6';
    const secretBytes = Buffer.from(secret.slice(6), 'base64');
    const now = Math.floor(Date.now() / 1000);
    const msgId = 'msg_svix_test_1';
    const body = '{"event":"user.created"}';
    const validSig = crypto.createHmac('sha256', secretBytes).update(`${msgId}.${now}.${body}`).digest('base64');

    const headers = {
      'svix-id': msgId,
      'svix-timestamp': String(now),
      'svix-signature': `v1,${validSig}`
    };

    const validCheck = Dispatcher.verifyIngressSignature('clerk/svix', body, headers, secret);
    assert.strictEqual(validCheck.valid, true, 'Valid Svix signature must pass');

    const badHeaders = { ...headers, 'svix-signature': 'v1,invalid_sig' };
    const badCheck = Dispatcher.verifyIngressSignature('clerk/svix', body, badHeaders, secret);
    assert.strictEqual(badCheck.valid, false, 'Invalid Svix signature must fail');

    // Test fresh re-signing
    const dispatcher = new Dispatcher(new Storage(':memory:'));
    const reSigned = dispatcher.signHeaders('clerk/svix', body, headers, secret);
    assert.ok(reSigned['svix-signature'].startsWith('v1,'), 'Re-signed header must have v1 prefix');
    console.log('  ✅ Test 9 Passed: Svix/Clerk HMAC verified and re-signed.\n');
  }

  // Test 10: Mode B isolated trust boundary attaches signature only when verified (§4.2)
  {
    console.log('Test 10: Mode B signature only attached when verified (§4.2)...');
    process.env.HOOKARMOR_SIGNING_SECRET = 'internal_shared_secret';
    let captured = null;
    const s = http.createServer((req, res) => {
      captured = req.headers;
      res.writeHead(200);
      res.end('ok');
    });
    const mPort = 4804;
    await new Promise(r => s.listen(mPort, '127.0.0.1', r));

    try {
      const storage = new Storage(':memory:');
      const dispatcher = new Dispatcher(storage);
      const ep = storage.createEndpoint({ id: 'ep-mode-b', name: 'Mode B', targetUrl: `http://127.0.0.1:${mPort}/test` });

      // Unverified event
      const unverifiedEv = storage.saveEvent({
        id: 'evt_unverified',
        endpointId: ep.id,
        provider: 'generic',
        eventType: 'test',
        headers: {},
        rawBody: '{}',
        status: 'pending',
        verified: 0
      });
      await dispatcher.dispatch(unverifiedEv, ep);
      assert.strictEqual(captured['x-hookarmor-signature'], undefined, 'Unverified event must NOT have x-hookarmor-signature');

      // Verified event
      const verifiedEv = storage.saveEvent({
        id: 'evt_verified',
        endpointId: ep.id,
        provider: 'stripe',
        eventType: 'test',
        headers: {},
        rawBody: '{}',
        status: 'pending',
        verified: 1
      });
      await dispatcher.dispatch(verifiedEv, ep);
      assert.ok(captured['x-hookarmor-signature'], 'Verified event must have x-hookarmor-signature');
      console.log('  ✅ Test 10 Passed: Mode B internal signature requires verified flag.\n');
    } finally {
      delete process.env.HOOKARMOR_SIGNING_SECRET;
      s.close();
    }
  }

  // Test 11: Strict mode rejects all internal/metadata addresses (§4.3)
  {
    console.log('Test 11: Strict mode rejects all IPv4, IPv6, CGNAT, and int IP targets (§4.3)...');
    const probeUrls = [
      'http://[::1]/test',
      'http://[::ffff:127.0.0.1]/test',
      'http://2130706433/test',
      'http://10.0.0.5/test',
      'http://[fd00::1]/test',
      'http://[fe80::1]/test',
      'http://100.64.0.1/test',
      'http://0.0.0.0/test',
      'http://169.254.169.254/latest'
    ];

    for (const url of probeUrls) {
      assert.strictEqual(isPrivateOrMetadataUrl(url, true), true, `Must block ${url} in strict mode`);
    }
    console.log('  ✅ Test 11 Passed: Full SSRF address matrix blocked.\n');
  }

  // Test 12: Metadata address in alertWebhookUrl is rejected (§4.3)
  {
    console.log('Test 12: Alert webhook URL rejects metadata address (§4.3)...');
    const { server } = createServer({ dbPath: ':memory:', strictSSRF: true });
    const aPort = 4805;
    await new Promise(r => server.listen(aPort, '127.0.0.1', r));

    try {
      const res = await fetch(`http://127.0.0.1:${aPort}/api/endpoints`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'ep-alert-ssrf',
          name: 'Alert SSRF',
          targetUrl: 'https://example.com/target',
          alertWebhookUrl: 'http://169.254.169.254/leak'
        })
      });
      assert.strictEqual(res.status, 400, 'Must reject endpoint with metadata alert URL');
      console.log('  ✅ Test 12 Passed: Alert URL metadata SSRF blocked.\n');
    } finally {
      server.close();
    }
  }

  // Test 13: DNS resolution checks block private IP resolution (§4.3)
  {
    console.log('Test 13: Guarded DNS lookup blocks localhost/private resolution (§4.3)...');
    await new Promise((resolve) => {
      guardedLookup('localhost', (err, addr) => {
        assert.ok(err, 'guardedLookup must error on localhost');
        assert.ok(err.message.includes('SSRF blocked') || err.code === 'ENOTFOUND');
        resolve();
      });
    });
    console.log('  ✅ Test 13 Passed: DNS lookup to loopback blocked.\n');
  }

  // Test 14: GET /api/endpoints never returns secret (§5.5)
  {
    console.log('Test 14: GET /api/endpoints output never contains secret (§5.5)...');
    const { server, storage } = createServer({ dbPath: ':memory:' });
    const port = 4806;
    await new Promise(r => server.listen(port, '127.0.0.1', r));

    try {
      storage.createEndpoint({
        id: 'ep-secret-test',
        name: 'Secret Shield',
        targetUrl: 'https://example.com/webhook',
        secret: 'whsec_super_secret_never_leak'
      });

      const res = await fetch(`http://127.0.0.1:${port}/api/endpoints`);
      const list = await res.json();
      assert.strictEqual(list[0].secret, undefined, 'Secret must not be exposed');
      assert.strictEqual(list[0].has_secret, true, 'has_secret must be true');
      console.log('  ✅ Test 14 Passed: Endpoints API is write-only for secrets.\n');
    } finally {
      server.close();
    }
  }

  // Test 15: Updating endpoint without secret preserves stored secret (§5.6)
  {
    console.log('Test 15: Updating endpoint preserves secret if omitted (§5.6)...');
    const storage = new Storage(':memory:');
    storage.createEndpoint({
      id: 'ep-up',
      name: 'Initial Name',
      targetUrl: 'https://initial.com/hook',
      secret: 'whsec_important_keep_me'
    });

    storage.createEndpoint({
      id: 'ep-up',
      name: 'Updated Name',
      targetUrl: 'https://updated.com/hook'
      // secret omitted!
    });

    const ep = storage.getEndpoint('ep-up');
    assert.strictEqual(ep.name, 'Updated Name');
    assert.strictEqual(ep.target_url, 'https://updated.com/hook');
    assert.strictEqual(ep.secret, 'whsec_important_keep_me', 'Secret must be preserved');
    console.log('  ✅ Test 15 Passed: Updating endpoint preserves existing secret.\n');
  }

  // Test 16: WebSocket auth challenge (§4.6)
  {
    console.log('Test 16: WebSocket authentication handshake enforcement (§4.6)...');
    const { server, dispatcher } = createServer({ dbPath: ':memory:', apiKey: 'ws_secret_token' });
    const wsPort = 4807;
    await new Promise(r => server.listen(wsPort, '127.0.0.1', r));

    try {
      let receivedCount = 0;
      const client = new WebSocket(`ws://127.0.0.1:${wsPort}/ws`);
      client.on('message', (data) => {
        const msg = JSON.parse(data);
        if (msg.type === 'delivery') receivedCount++;
      });

      await new Promise(r => client.on('open', r));
      // Broadcast while unauthenticated
      dispatcher.emit('delivery', { test: 1 });
      await new Promise(r => setTimeout(r, 50));
      assert.strictEqual(receivedCount, 0, 'Unauthenticated socket must not receive broadcast');

      // Send auth handshake
      client.send(JSON.stringify({ type: 'auth', token: 'ws_secret_token' }));
      await new Promise(r => setTimeout(r, 50));

      // Broadcast while authenticated
      dispatcher.emit('delivery', { test: 2 });
      await new Promise(r => setTimeout(r, 50));
      assert.strictEqual(receivedCount, 1, 'Authenticated socket must receive broadcast');
      client.close();
      console.log('  ✅ Test 16 Passed: WebSocket auth challenge verified.\n');
    } finally {
      server.close();
    }
  }

  // Test 17: Demo mode: anonymous POST /api/events/replay-all returns 401 (§5.4)
  {
    console.log('Test 17: Demo mode rejects unauthenticated replays with 401 (§5.4)...');
    const { server } = createServer({ dbPath: ':memory:', demoMode: true, apiKey: 'vault_key' });
    const port = 4808;
    await new Promise(r => server.listen(port, '127.0.0.1', r));

    try {
      const res = await fetch(`http://127.0.0.1:${port}/api/events/replay-all`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      assert.strictEqual(res.status, 401, 'Anonymous replay-all must return 401 in demo mode');
      console.log('  ✅ Test 17 Passed: Demo mode is strictly read-only for public.\n');
    } finally {
      server.close();
    }
  }

  // Test 18: Cross-origin request gets no Access-Control-Allow-Origin header by default (§5.3)
  {
    console.log('Test 18: CORS header not present for unauthorized origin by default (§5.3)...');
    const { server } = createServer({ dbPath: ':memory:' });
    const port = 4809;
    await new Promise(r => server.listen(port, '127.0.0.1', r));

    try {
      const res = await fetch(`http://127.0.0.1:${port}/api/stats`, {
        headers: { 'Origin': 'http://malicious-website.com' }
      });
      assert.strictEqual(res.headers.get('access-control-allow-origin'), null, 'CORS header must not be set');
      console.log('  ✅ Test 18 Passed: Default wide-open CORS disabled.\n');
    } finally {
      server.close();
    }
  }

  // Test 19: text/plain POST to state-changing route returns 415 (§5.3)
  {
    console.log('Test 19: Non-JSON POST to state-changing route returns 415 (§5.3)...');
    const { server } = createServer({ dbPath: ':memory:' });
    const port = 4810;
    await new Promise(r => server.listen(port, '127.0.0.1', r));

    try {
      const res = await fetch(`http://127.0.0.1:${port}/api/endpoints`, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: 'hello'
      });
      assert.strictEqual(res.status, 415, 'text/plain POST must return 415');
      console.log('  ✅ Test 19 Passed: 415 enforced on state-changing API routes.\n');
    } finally {
      server.close();
    }
  }

  // Test 20: Without API key, DNS-rebinding Host header gets 403 (§5.3)
  {
    console.log('Test 20: DNS-rebinding Host header rejected with 403 (§5.3)...');
    const { server } = createServer({ dbPath: ':memory:' });
    const port = 4811;
    await new Promise(r => server.listen(port, '127.0.0.1', r));

    try {
      const statusCode = await new Promise((resolve) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port,
          path: '/api/stats',
          method: 'GET',
          headers: { Host: 'rebind.evil.com' }
        }, (res) => {
          resolve(res.statusCode);
        });
        req.end();
      });
      assert.strictEqual(statusCode, 403, 'Rebind host header must return 403');
      console.log('  ✅ Test 20 Passed: Host header validation blocks DNS rebinding.\n');
    } finally {
      server.close();
    }
  }

  // Test 21: Production mode without API key throws error mentioning HOOKARMOR_API_KEY (§3.3)
  {
    console.log('Test 21: Production startup without API key throws (§3.3)...');
    assert.throws(
      () => createServer({ production: true, apiKey: null }),
      /HOOKARMOR_API_KEY/,
      'Must throw error mentioning HOOKARMOR_API_KEY'
    );
    console.log('  ✅ Test 21 Passed: Production mode mandates API key on startup.\n');
  }

  // Test 22: /mock/config returns 404 in production (§6.1)
  {
    console.log('Test 22: /mock/config returns 404 in production (§6.1)...');
    const { server } = createServer({ dbPath: ':memory:', production: true, apiKey: 'prod_key' });
    const port = 4812;
    await new Promise(r => server.listen(port, '127.0.0.1', r));

    try {
      const res = await fetch(`http://127.0.0.1:${port}/mock/config`);
      assert.strictEqual(res.status, 404, '/mock/config must return 404 in production');
      console.log('  ✅ Test 22 Passed: Mock targets disabled in production.\n');
    } finally {
      server.close();
    }
  }

  // Test 23: Waitlist returns 429 after per-IP limit (§5.7)
  {
    console.log('Test 23: Waitlist rate limits per IP (§5.7)...');
    const { server } = createServer({ dbPath: ':memory:' });
    const port = 4813;
    await new Promise(r => server.listen(port, '127.0.0.1', r));

    try {
      for (let i = 0; i < 5; i++) {
        const res = await fetch(`http://127.0.0.1:${port}/api/waitlist`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: `user${i}@example.com` })
        });
        assert.strictEqual(res.status, 200);
      }
      // 6th request must exceed limit
      const blocked = await fetch(`http://127.0.0.1:${port}/api/waitlist`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'user_excess@example.com' })
      });
      assert.strictEqual(blocked.status, 429, 'Waitlist 6th request must return 429');
      console.log('  ✅ Test 23 Passed: Waitlist IP rate limiting verified.\n');
    } finally {
      server.close();
    }
  }

  // Test 24: Static check of index.html (§3.4, §6.2)
  {
    console.log('Test 24: Static analysis of index.html for XSS escaping & CSV injection (§3.4, §6.2)...');
    const htmlContent = fs.readFileSync(path.join(__dirname, '../src/public/index.html'), 'utf8');
    assert.ok(htmlContent.includes('function esc('), 'index.html must define esc() helper');
    assert.ok(htmlContent.includes('sanitizeCsvCell') || htmlContent.includes(/^[=+\-@]/), 'index.html must sanitize CSV formula characters');
    assert.ok(htmlContent.includes('${esc(l.email)}'), 'Waitlist email must be escaped');
    assert.ok(htmlContent.includes('${esc(ep.name)}'), 'Endpoint name must be escaped');
    assert.ok(htmlContent.includes('${esc(evt.raw_body)}'), 'Event raw body must be escaped');
    console.log('  ✅ Test 24 Passed: Dashboard XSS escaping and CSV sanitizer verified.\n');
  }

  // Test 25: PRAGMA synchronous returns 2 (FULL) (§4.5)
  {
    console.log('Test 25: PRAGMA synchronous returns 2 (FULL) (§4.5)...');
    const storage = new Storage(':memory:');
    const syncVal = storage.db.pragma('synchronous', { simple: true });
    assert.strictEqual(syncVal, 2, 'PRAGMA synchronous must be 2 (FULL)');
    console.log('  ✅ Test 25 Passed: SQLite synchronous = FULL.\n');
  }

  // Test 26: Retention pruning deletes delivered events older than N days and keeps failed (§5.7)
  {
    console.log('Test 26: Retention pruning deletes delivered events older than N days (§5.7)...');
    const storage = new Storage(':memory:');
    storage.createEndpoint({ id: 'ep-prune', name: 'Prune Test', targetUrl: 'http://127.0.0.1:9999/wh' });

    // Old delivered event (40 days ago)
    storage.saveEvent({
      id: 'evt_old_delivered',
      endpointId: 'ep-prune',
      provider: 'stripe',
      eventType: 'old.delivered',
      headers: {},
      rawBody: '{}',
      status: 'delivered'
    });
    storage.db.prepare("UPDATE events SET created_at = datetime('now', '-40 days') WHERE id = 'evt_old_delivered'").run();

    // Old failed event (40 days ago) - MUST BE KEPT!
    storage.saveEvent({
      id: 'evt_old_failed',
      endpointId: 'ep-prune',
      provider: 'stripe',
      eventType: 'old.failed',
      headers: {},
      rawBody: '{}',
      status: 'failed'
    });
    storage.db.prepare("UPDATE events SET created_at = datetime('now', '-40 days') WHERE id = 'evt_old_failed'").run();

    const deletedCount = storage.pruneEvents({ olderThanDays: 30 });
    assert.strictEqual(deletedCount, 1, 'Should prune exactly 1 delivered event');
    assert.strictEqual(storage.getEvent('evt_old_delivered'), null, 'Old delivered event must be deleted');
    assert.ok(storage.getEvent('evt_old_failed'), 'Old failed event must be preserved in dead-letter queue');
    console.log('  ✅ Test 26 Passed: Retention pruning removes old delivered events and preserves failures.\n');
  }

  console.log('🎉 ALL 26 HARDENED REGRESSION TESTS PASSED CLEANLY!\n');
}

runRegressionSuite().catch((err) => {
  console.error('❌ Regression test failed:', err);
  process.exit(1);
});
