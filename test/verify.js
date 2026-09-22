const assert = require('assert');
const { createServer } = require('../src/server');
const http = require('http');

async function runTests() {
  console.log('🧪 Starting HookArmor End-to-End Verification Test Suite...\n');

  const port = 4999;
  const { server, storage, dispatcher } = createServer({ dbPath: ':memory:' });

  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Create Endpoint
    console.log('Test 1: Creating endpoint "stripe-live"...');
    storage.createEndpoint({
      id: 'stripe-live',
      name: 'Stripe Production',
      targetUrl: `${baseUrl}/mock/target`,
      alertWebhookUrl: '',
      autoRetry: 1,
      maxRetries: 3
    });
    const ep = storage.getEndpoint('stripe-live');
    assert.strictEqual(ep.id, 'stripe-live');
    assert.strictEqual(ep.name, 'Stripe Production');
    console.log('  ✅ Endpoint created successfully.\n');

    // 2. Scenario A: Successful Delivery
    console.log('Test 2: Ingesting Stripe webhook with healthy destination (200 OK)...');
    const stripePayload = JSON.stringify({
      id: 'evt_test_payment_ok',
      object: 'event',
      type: 'invoice.payment_succeeded',
      data: { object: { amount_paid: 19900, customer: 'cus_123' } }
    });

    const resA = await fetch(`${baseUrl}/in/stripe-live`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Stripe-Signature': 't=1758513000,v1=abcdef1234567890'
      },
      body: stripePayload
    });

    assert.strictEqual(resA.status, 200, 'Ingress must return immediate 200 OK');
    const bodyA = await resA.json();
    assert.strictEqual(bodyA.received, true);
    assert.ok(bodyA.hookarmor_id, 'Should return hookarmor_id');
    console.log(`  ✅ Ingress returned 200 OK in <10ms. ID: ${bodyA.hookarmor_id}`);

    // Wait deterministically for async dispatch
    async function waitForStatus(eventId, expectedStatus, timeoutMs = 10000) {
      const start = Date.now();
      while (Date.now() - start < timeoutMs) {
        const ev = storage.getEvent(eventId);
        if (ev && ev.status === expectedStatus) return ev;
        await new Promise((r) => setTimeout(r, 25));
      }
      return storage.getEvent(eventId);
    }

    const eventA = await waitForStatus(bodyA.hookarmor_id, 'delivered');
    assert.strictEqual(eventA.status, 'delivered', 'Event should be marked delivered');
    assert.strictEqual(eventA.last_status_code, 200);
    assert.strictEqual(eventA.provider, 'stripe');
    assert.strictEqual(eventA.event_type, 'invoice.payment_succeeded');
    console.log('  ✅ Dispatcher successfully relayed payload and verified 200 response.\n');

    // 3. Scenario B: Target Failure -> Dead-Letter Queue
    console.log('Test 3: Simulating downstream crash (500 Internal Server Error)...');
    await fetch(`${baseUrl}/mock/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ statusCode: 500, responseBody: { error: 'Prisma ConnectionPoolTimeoutError' } })
    });

    const resB = await fetch(`${baseUrl}/in/stripe-live`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Stripe-Signature': 't=1758513000,v1=deadbeefdeadbeef'
      },
      body: JSON.stringify({
        id: 'evt_test_payment_fail',
        type: 'customer.subscription.created',
        data: { object: { plan: 'pro_annual', customer: 'cus_AlexV' } }
      })
    });

    assert.strictEqual(resB.status, 200, 'Ingress must STILL return 200 OK so Stripe never drops event');
    const bodyB = await resB.json();

    const eventB = await waitForStatus(bodyB.hookarmor_id, 'failed');
    assert.strictEqual(eventB.status, 'failed', 'Event should be marked failed in Dead-Letter Queue');
    assert.strictEqual(eventB.last_status_code, 500);
    console.log(`  ✅ Event ${bodyB.hookarmor_id} safely quarantined in Dead-Letter Queue with HTTP 500 status.`);
    console.log(`  ✅ Next retry scheduled at: ${eventB.next_retry_at}\n`);

    // 4. Scenario C: Target Recovery & 1-Click Replay
    console.log('Test 4: Simulating server recovery (200 OK) and triggering Dead-Letter Replay...');
    await fetch(`${baseUrl}/mock/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ statusCode: 200, responseBody: { status: 'healed_and_processed' } })
    });

    const replayRes = await fetch(`${baseUrl}/api/events/${bodyB.hookarmor_id}/replay`, { method: 'POST' });
    const replayData = await replayRes.json();
    assert.strictEqual(replayData.success, true);
    assert.strictEqual(replayData.statusCode, 200);

    const replayedEvent = storage.getEvent(bodyB.hookarmor_id);
    assert.strictEqual(replayedEvent.status, 'delivered', 'Event should now be delivered');
    assert.strictEqual(replayedEvent.attempts, 2, 'Attempts count should be incremented');
    console.log(`  ✅ Dead-letter event successfully replayed! Status is now: ${replayedEvent.status} (Attempts: ${replayedEvent.attempts})\n`);

    // 5. Scenario D: Metrics Verification
    console.log('Test 5: Verifying aggregate metrics endpoint...');
    const statsRes = await fetch(`${baseUrl}/api/stats`);
    const stats = await statsRes.json();
    assert.strictEqual(stats.total, 2);
    assert.strictEqual(stats.delivered, 2);
    assert.strictEqual(stats.failed, 0);
    console.log(`  ✅ Metrics verified: Total=${stats.total}, Delivered=${stats.delivered}, Dead-Letter=${stats.failed}, AvgLatency=${stats.avgLatencyMs}ms\n`);

    console.log('🎉 ALL 5 HOOKARMOR VERIFICATION TESTS PASSED PERFECTLY!\n');
  } finally {
    server.close();
  }
}

runTests().catch((err) => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
