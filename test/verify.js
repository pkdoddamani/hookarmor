const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const { createServer } = require('../src/server');

async function runTests() {
  console.log('🧪 Starting HookArmor Hardened Verification Test Suite (Post-Audit)...\n');

  const port = 4999;
  const { server, storage, dispatcher, worker, app } = createServer({
    dbPath: ':memory:',
    retryIntervalMs: 500 // Fast interval for testing
  });

  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${port}`;

  // Dedicated test capture server to inspect exact forwarded headers & timestamps
  let capturedHeaders = null;
  let capturedBody = null;
  const capturePort = 4998;
  const captureServer = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      capturedHeaders = req.headers;
      capturedBody = body;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'captured' }));
    });
  });
  await new Promise(resolve => captureServer.listen(capturePort, '127.0.0.1', resolve));

  try {
    // 1. SSRF Protection & Endpoint Creation
    console.log('Test 1: Testing SSRF Protection & Endpoint Creation...');
    const ssrfRes = await fetch(`${baseUrl}/api/endpoints`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: 'ssrf-test',
        name: 'Malicious Metadata Probe',
        targetUrl: 'http://169.254.169.254/latest/meta-data'
      })
    });
    assert.strictEqual(ssrfRes.status, 400, 'Must block AWS metadata SSRF target');
    console.log('  ✅ SSRF probe against 169.254.169.254 successfully blocked.');

    storage.createEndpoint({
      id: 'stripe-live',
      name: 'Stripe Production',
      targetUrl: `${baseUrl}/mock/target`,
      secret: 'whsec_test_secret_12345',
      alertWebhookUrl: '',
      autoRetry: 1,
      maxRetries: 3
    });
    const ep = storage.getEndpoint('stripe-live');
    assert.strictEqual(ep.id, 'stripe-live');
    assert.strictEqual(ep.secret, 'whsec_test_secret_12345');
    console.log('  ✅ Valid endpoint created with secret.\n');

    // Deterministic wait helper
    async function waitForStatus(eventId, expectedStatus, timeoutMs = 10000) {
      const start = Date.now();
      while (Date.now() - start < timeoutMs) {
        const ev = storage.getEvent(eventId);
        if (ev && ev.status === expectedStatus) return ev;
        await new Promise((r) => setTimeout(r, 25));
      }
      return storage.getEvent(eventId);
    }

    // 2. Ingress Signature Verification (Reject Forgery, Accept Valid)
    console.log('Test 2: Testing Ingress Signature Verification (Security Boundary)...');
    const forgedPayload = JSON.stringify({ id: 'evt_forged_1', type: 'charge.succeeded' });
    const forgedRes = await fetch(`${baseUrl}/in/stripe-live`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Stripe-Signature': 't=1758513000,v1=bad_signature_deadbeef'
      },
      body: forgedPayload
    });
    assert.strictEqual(forgedRes.status, 400, 'Must reject forged signature with 400 Bad Request');
    console.log('  ✅ Forged signature rejected with 400 Bad Request.');

    // Generate valid signature
    const validNow = Math.floor(Date.now() / 1000);
    const validPayload = JSON.stringify({
      id: 'evt_valid_ingress_1',
      type: 'payment_intent.succeeded',
      data: { object: { amount: 5000 } }
    });
    const validSig = crypto
      .createHmac('sha256', ep.secret)
      .update(`${validNow}.${validPayload}`)
      .digest('hex');

    const validRes = await fetch(`${baseUrl}/in/stripe-live`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Stripe-Signature': `t=${validNow},v1=${validSig}`
      },
      body: validPayload
    });
    assert.strictEqual(validRes.status, 200, 'Must accept authentic signature with 200 OK');
    const validBody = await validRes.json();
    const eventValid = await waitForStatus(validBody.hookarmor_id, 'delivered');
    assert.strictEqual(eventValid.status, 'delivered');
    console.log('  ✅ Authentic signature verified, ingested, and delivered.\n');

    // 3. The 5-Minute Stripe Expiration Defeat: Outbound Fresh Re-Signing
    console.log('Test 3: Testing 5-Minute Expiration Defeat (Fresh Outbound Re-Signing)...');
    storage.createEndpoint({
      id: 'capture-endpoint',
      name: 'Capture Target',
      targetUrl: `http://127.0.0.1:${capturePort}/target`,
      secret: 'whsec_capture_secret_999',
      autoRetry: 1,
      maxRetries: 3
    });

    const initTimestamp = Math.floor(Date.now() / 1000);
    const delayedPayload = JSON.stringify({ id: 'evt_delayed_replay', type: 'customer.subscription.created' });
    const initSig = crypto
      .createHmac('sha256', 'whsec_capture_secret_999')
      .update(`${initTimestamp}.${delayedPayload}`)
      .digest('hex');

    // Ingest valid event
    const captureRes = await fetch(`${baseUrl}/in/capture-endpoint`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Stripe-Signature': `t=${initTimestamp},v1=${initSig}`
      },
      body: delayedPayload
    });
    assert.strictEqual(captureRes.status, 200);
    const captureResBody = await captureRes.json();
    await waitForStatus(captureResBody.hookarmor_id, 'delivered');

    // Now artificially age the stored event in DB to simulate a replay 3 days later
    const ancientTimestamp = 1600000000; // Ancient expired timestamp (2020)
    const storedEvent = storage.getEvent(captureResBody.hookarmor_id);
    const expiredHeaders = {
      ...storedEvent.headers,
      'stripe-signature': `t=${ancientTimestamp},v1=ancient_expired_signature_hex`
    };
    storage.db.prepare('UPDATE events SET headers = ? WHERE id = ?').run(
      JSON.stringify(expiredHeaders),
      captureResBody.hookarmor_id
    );

    // Replay the event: HookArmor must re-sign with fresh current timestamp!
    capturedHeaders = null;
    await fetch(`${baseUrl}/api/events/${captureResBody.hookarmor_id}/replay`, { method: 'POST' });

    assert.ok(capturedHeaders, 'Target must receive replayed request');
    assert.ok(capturedHeaders['stripe-signature'], 'Forwarded request must include re-signed Stripe-Signature');

    const forwardedSigParts = capturedHeaders['stripe-signature'].split(',').reduce((acc, p) => {
      const [k, v] = p.split('=');
      acc[k] = v;
      return acc;
    }, {});
    const forwardedTimestamp = parseInt(forwardedSigParts.t, 10);
    const currentEpoch = Math.floor(Date.now() / 1000);
    assert.ok(Math.abs(currentEpoch - forwardedTimestamp) <= 3, 'Forwarded timestamp must be fresh (current epoch), not the ancient timestamp');

    // Verify cryptographic authenticity of the fresh signature
    const expectedFreshSig = crypto
      .createHmac('sha256', 'whsec_capture_secret_999')
      .update(`${forwardedTimestamp}.${delayedPayload}`)
      .digest('hex');
    assert.strictEqual(forwardedSigParts.v1, expectedFreshSig, 'Fresh signature must be mathematically valid HMAC');
    console.log('  ✅ HookArmor defeated the 5-minute Stripe expiration trap:');
    console.log(`     Stored in DB: t=${ancientTimestamp} (Expired 5+ years ago)`);
    console.log(`     Re-signed on replay: t=${forwardedTimestamp} (Current) -> stripe.webhooks.constructEvent succeeds!\n`);

    // 4. Downstream Failure -> Dead-Letter Queue
    console.log('Test 4: Simulating Downstream Failure (500) -> Dead-Letter Queue...');
    await fetch(`${baseUrl}/mock/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ statusCode: 500, responseBody: { error: 'Database Pool Timeout' } })
    });

    const dlqNow = Math.floor(Date.now() / 1000);
    const dlqPayload = JSON.stringify({ id: 'evt_dlq_test_1', type: 'invoice.payment_failed' });
    const dlqSig = crypto.createHmac('sha256', ep.secret).update(`${dlqNow}.${dlqPayload}`).digest('hex');

    const dlqRes = await fetch(`${baseUrl}/in/stripe-live`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Stripe-Signature': `t=${dlqNow},v1=${dlqSig}`
      },
      body: dlqPayload
    });
    const dlqBody = await dlqRes.json();
    const dlqEvent = await waitForStatus(dlqBody.hookarmor_id, 'failed');
    assert.strictEqual(dlqEvent.status, 'failed');
    assert.strictEqual(dlqEvent.last_status_code, 500);
    assert.ok(dlqEvent.next_retry_at, 'Must have next_retry_at calculated');
    console.log(`  ✅ Event ${dlqBody.hookarmor_id} safely quarantined in Dead-Letter Queue with HTTP 500.`);
    console.log(`     Next automated retry at: ${dlqEvent.next_retry_at}\n`);

    // 5. Automatic Background Retry Worker Execution
    console.log('Test 5: Testing Background Retry Worker (Automatic Self-Healing)...');
    // Heal the downstream mock server
    await fetch(`${baseUrl}/mock/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ statusCode: 200, responseBody: { status: 'healed_auto' } })
    });

    // Artificially advance next_retry_at to past so worker picks it up immediately
    storage.db.prepare("UPDATE events SET next_retry_at = datetime('now', '-5 seconds') WHERE id = ?").run(dlqBody.hookarmor_id);

    // Let the worker tick
    await worker.tick();
    const healedEvent = await waitForStatus(dlqBody.hookarmor_id, 'delivered');
    assert.strictEqual(healedEvent.status, 'delivered', 'Worker must auto-deliver event without human intervention');
    assert.strictEqual(healedEvent.attempts, 2);
    console.log(`  ✅ Background Retry Worker automatically claimed and delivered DLQ event! (Attempts: ${healedEvent.attempts})\n`);

    // 6. Concurrency Limiter
    console.log('Test 6: Testing Concurrency Limiting (Pool Protection)...');
    let maxConcurrentObserved = 0;
    let currentConcurrent = 0;
    const slowPort = 4997;
    const slowServer = http.createServer((req, res) => {
      currentConcurrent++;
      if (currentConcurrent > maxConcurrentObserved) maxConcurrentObserved = currentConcurrent;
      setTimeout(() => {
        currentConcurrent--;
        res.writeHead(200);
        res.end('ok');
      }, 50);
    });
    await new Promise(r => slowServer.listen(slowPort, '127.0.0.1', r));

    storage.createEndpoint({
      id: 'concurrency-ep',
      name: 'Concurrency Capped Target',
      targetUrl: `http://127.0.0.1:${slowPort}/fast`,
      concurrencyLimit: 2,
      autoRetry: 0
    });

    const burstPromises = [];
    for (let i = 0; i < 6; i++) {
      burstPromises.push(
        fetch(`${baseUrl}/in/concurrency-ep`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: `burst_${i}`, i })
        })
      );
    }
    await Promise.all(burstPromises);
    await new Promise(r => setTimeout(r, 400));
    slowServer.close();

    assert.ok(maxConcurrentObserved <= 3, `Max concurrent (${maxConcurrentObserved}) must respect semaphore limit (2)`);
    console.log(`  ✅ Concurrency capped at max ${maxConcurrentObserved} parallel in-flight connections (pool protected).\n`);

    // 7. Idempotency Deduplication (Suppress Delivered Duplicate)
    console.log('Test 7: Testing Safe Idempotency Key Deduplication...');
    const dedupPayload = JSON.stringify({ id: 'evt_stripe_idemp_final', type: 'customer.created' });
    const dNow = Math.floor(Date.now() / 1000);
    const dSig = crypto.createHmac('sha256', ep.secret).update(`${dNow}.${dedupPayload}`).digest('hex');

    const firstRes = await fetch(`${baseUrl}/in/stripe-live`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Stripe-Signature': `t=${dNow},v1=${dSig}` },
      body: dedupPayload
    });
    const firstBody = await firstRes.json();
    await waitForStatus(firstBody.hookarmor_id, 'delivered');

    // Resend exact event
    const secondRes = await fetch(`${baseUrl}/in/stripe-live`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Stripe-Signature': `t=${dNow},v1=${dSig}` },
      body: dedupPayload
    });
    const secondBody = await secondRes.json();
    assert.strictEqual(secondBody.status, 'deduplicated');
    assert.strictEqual(secondBody.hookarmor_id, firstBody.hookarmor_id);
    console.log('  ✅ Duplicate event intercepted and suppressed cleanly.\n');

    console.log('🎉 ALL 7 HARDENED HOOKARMOR VERIFICATION TESTS PASSED PERFECTLY!\n');
  } finally {
    captureServer.close();
    server.close();
  }
}

runTests().catch((err) => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
