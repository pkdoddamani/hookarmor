const assert = require('assert');
const http = require('http');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { createServer } = require('../src/server');
const Storage = require('../src/storage');
const Dispatcher = require('../src/dispatcher');
const Alerter = require('../src/alerter');
const { assessDisablementRisk } = require('../src/sentinel');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function startTarget({ status = 200, delayMs = 0 } = {}) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      if (delayMs > 0) await sleep(delayMs);
      requests.push({ headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(status);
      res.end('ok');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    server,
    requests,
    url: `http://127.0.0.1:${server.address().port}/hook`,
    close: () => new Promise(r => server.close(r))
  };
}

async function waitForAlerts(target, minCount, timeoutMs = 3000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (target.requests.length >= minCount) return;
    await sleep(25);
  }
}

async function runProbes() {
  console.log('====================================================');
  console.log('HOOKARMOR v1.3.0 SECURITY & RUNTIME AUDIT PROBES (V2)');
  console.log('====================================================\n');

  let passed = 0;
  let failed = 0;

  async function probe(name, fn) {
    try {
      console.log(`[PROBE] ${name}...`);
      await fn();
      console.log(`  ==> PASSED\n`);
      passed++;
    } catch (err) {
      console.log(`  ==> FAILED: ${err.message}\n  Stack: ${err.stack}\n`);
      failed++;
    }
  }

  // ---------------------------------------------------------------
  // PROBE 1: Concurrency & Race Conditions during 10 simultaneous failures
  // ---------------------------------------------------------------
  await probe('VECTOR 1A: 10 concurrent failures - consecutive_failures counter & alert race', async () => {
    const alertTarget = await startTarget({ status: 200 });
    const hookTarget = await startTarget({ status: 500 });
    const ha = createServer({ dbPath: ':memory:', autoStartWorker: false });
    await new Promise((r) => ha.server.listen(0, '127.0.0.1', r));

    try {
      ha.storage.createEndpoint({
        id: 'ep_concurrent',
        name: 'Concurrent Failing EP',
        targetUrl: hookTarget.url,
        provider: 'shopify',
        alertWebhookUrl: alertTarget.url,
        concurrencyLimit: 10,
        autoRetry: 0
      });

      // Save 10 events
      const events = [];
      for (let i = 1; i <= 10; i++) {
        events.push(ha.storage.saveEvent({
          id: `evt_conc_${i}`,
          endpointId: 'ep_concurrent',
          provider: 'shopify',
          headers: {},
          rawBody: `{"seq":${i}}`
        }));
      }

      // Dispatch all 10 concurrently
      const ep = ha.storage.getEndpoint('ep_concurrent');
      await Promise.all(events.map(ev => ha.dispatcher.dispatch(ev, ep)));

      // Wait for alerts to arrive at alertTarget
      await waitForAlerts(alertTarget, 10, 2000);
      await sleep(200);

      // Check SQLite consecutive_failures
      const epAfter = ha.storage.getEndpoint('ep_concurrent');
      console.log(`      Final consecutive_failures in DB: ${epAfter.consecutive_failures}`);
      console.log(`      Final last_alerted_level in DB: ${epAfter.last_alerted_level}`);
      console.log(`      Total alert requests received: ${alertTarget.requests.length}`);

      const sentinelAlerts = alertTarget.requests.filter(r => r.body.includes('HookArmor Sentinel'));
      console.log(`      Sentinel alert requests received: ${sentinelAlerts.length}`);
      for (const a of sentinelAlerts) {
        const payload = JSON.parse(a.body);
        console.log(`        - Sentinel Alert: ${payload.attachments?.[0]?.title}`);
      }

      assert.strictEqual(epAfter.consecutive_failures, 10, 'consecutive_failures must be exactly 10');

      // Analyze if sentinel alert deduplication failed
      // For Shopify: failures 1-4: healthy (no alert); failure 5-9: Warning (level 1); failure 10: Danger (level 2).
      // Ideally, exactly 1 Warning and 1 Danger should be sent (2 total).
      // In a concurrent burst, events 5, 6, 7, 8, 9 can ALL see prevAlertLevel = 0 and send duplicate alerts!
      if (sentinelAlerts.length > 2) {
        console.warn(`      [CONCURRENCY FLAW CONFIRMED] Sentinel sent ${sentinelAlerts.length} alerts for a 10-failure burst (expected at most 2)!`);
      }
    } finally {
      await new Promise(r => ha.server.close(r));
      await alertTarget.close();
      await hookTarget.close();
    }
  });

  // ---------------------------------------------------------------
  // PROBE 1B: Race between concurrent success and failure
  // ---------------------------------------------------------------
  await probe('VECTOR 1B: Concurrent success and failure race', async () => {
    const alertTarget = await startTarget({ status: 200 });
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end', () => {
        const body = Buffer.concat(chunks).toString();
        if (body.includes('success')) {
          res.writeHead(200);
          res.end('ok');
        } else {
          res.writeHead(500);
          res.end('error');
        }
      });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const hookUrl = `http://127.0.0.1:${server.address().port}/hook`;

    const ha = createServer({ dbPath: ':memory:', autoStartWorker: false });
    await new Promise((r) => ha.server.listen(0, '127.0.0.1', r));

    try {
      ha.storage.createEndpoint({
        id: 'ep_race_sf',
        name: 'Race SF EP',
        targetUrl: hookUrl,
        provider: 'shopify',
        alertWebhookUrl: alertTarget.url,
        concurrencyLimit: 5,
        autoRetry: 0
      });

      // Pre-set failure streak to 10 and last_alerted_level to 2
      ha.storage.db.prepare('UPDATE endpoints SET consecutive_failures = 10, last_alerted_level = 2 WHERE id = ?').run('ep_race_sf');

      const evSuccess = ha.storage.saveEvent({ id: 'evt_race_succ', endpointId: 'ep_race_sf', provider: 'shopify', headers: {}, rawBody: '{"type":"success"}' });
      const evFailure = ha.storage.saveEvent({ id: 'evt_race_fail', endpointId: 'ep_race_sf', provider: 'shopify', headers: {}, rawBody: '{"type":"failure"}' });

      const ep = ha.storage.getEndpoint('ep_race_sf');
      await Promise.all([
        ha.dispatcher.dispatch(evSuccess, ep),
        ha.dispatcher.dispatch(evFailure, ep)
      ]);

      await sleep(200);

      const epAfter = ha.storage.getEndpoint('ep_race_sf');
      console.log(`      Post-race consecutive_failures: ${epAfter.consecutive_failures}`);
      console.log(`      Post-race last_alerted_level: ${epAfter.last_alerted_level}`);
      console.log(`      Alert requests received: ${alertTarget.requests.length}`);
      for (const a of alertTarget.requests) {
        const payload = JSON.parse(a.body);
        console.log(`        - Alert: ${payload.text}`);
      }
    } finally {
      await new Promise(r => ha.server.close(r));
      await new Promise(r => server.close(r));
      await alertTarget.close();
    }
  });

  // ---------------------------------------------------------------
  // PROBE 2: Alert Throttling at Level 3 & Recovery at Attempt 51
  // ---------------------------------------------------------------
  await probe('VECTOR 2: Level 3 throttling across 50 failures and recovery on attempt 51', async () => {
    const alertTarget = await startTarget({ status: 200 });
    const hookTarget = await startTarget({ status: 500 });
    const ha = createServer({ dbPath: ':memory:', autoStartWorker: false });
    await new Promise((r) => ha.server.listen(0, '127.0.0.1', r));

    try {
      ha.storage.createEndpoint({
        id: 'ep_throttle_test',
        name: 'Throttle Test EP',
        targetUrl: hookTarget.url,
        provider: 'shopify',
        alertWebhookUrl: alertTarget.url,
        concurrencyLimit: 1,
        autoRetry: 0
      });

      // Reach Level 3 (Shopify: 15 consecutive failures)
      for (let i = 1; i <= 15; i++) {
        const ev = ha.storage.saveEvent({ id: `evt_th_${i}`, endpointId: 'ep_throttle_test', provider: 'shopify', headers: {}, rawBody: '{}' });
        await ha.dispatcher.dispatch(ev, ha.storage.getEndpoint('ep_throttle_test'));
      }

      await waitForAlerts(alertTarget, 3, 2000);
      await sleep(100);

      const epAt15 = ha.storage.getEndpoint('ep_throttle_test');
      assert.strictEqual(epAt15.consecutive_failures, 15);
      assert.strictEqual(epAt15.last_alerted_level, 3);

      const sentinelAlertsCountAt15 = alertTarget.requests.filter(r => r.body.includes('HookArmor Sentinel')).length;
      console.log(`      Sentinel alerts up to Level 3 (failures 1-15): ${sentinelAlertsCountAt15}`);
      assert.strictEqual(sentinelAlertsCountAt15, 3, 'Must have received 3 sentinel alerts (Warning, Danger, Critical)');

      // Now fail 50 more times (attempts 16 to 65)
      for (let i = 16; i <= 65; i++) {
        const ev = ha.storage.saveEvent({ id: `evt_th_${i}`, endpointId: 'ep_throttle_test', provider: 'shopify', headers: {}, rawBody: '{}' });
        await ha.dispatcher.dispatch(ev, ha.storage.getEndpoint('ep_throttle_test'));
      }

      await sleep(200);

      const epAt65 = ha.storage.getEndpoint('ep_throttle_test');
      assert.strictEqual(epAt65.consecutive_failures, 65);
      assert.strictEqual(epAt65.last_alerted_level, 3);

      const sentinelAlertsCountAt65 = alertTarget.requests.filter(r => r.body.includes('HookArmor Sentinel')).length;
      console.log(`      Sentinel alerts after 50 more failures (failures 16-65): ${sentinelAlertsCountAt65}`);
      assert.strictEqual(sentinelAlertsCountAt65, 3, 'Must NOT send ANY additional sentinel alerts while staying at Level 3!');

      // Attempt 66: Recovery (200 OK)
      await hookTarget.close();
      const recoverServer = http.createServer((req, res) => { res.writeHead(200); res.end('ok'); });
      await new Promise(r => recoverServer.listen(0, '127.0.0.1', r));
      const newUrl = `http://127.0.0.1:${recoverServer.address().port}/hook`;

      ha.storage.createEndpoint({
        id: 'ep_throttle_test',
        name: 'Throttle Test EP',
        targetUrl: newUrl,
        provider: 'shopify',
        alertWebhookUrl: alertTarget.url,
        concurrencyLimit: 1,
        autoRetry: 0
      });

      const evRec = ha.storage.saveEvent({ id: 'evt_th_66', endpointId: 'ep_throttle_test', provider: 'shopify', headers: {}, rawBody: '{}' });
      await ha.dispatcher.dispatch(evRec, ha.storage.getEndpoint('ep_throttle_test'));

      await sleep(200);

      const epRecovered = ha.storage.getEndpoint('ep_throttle_test');
      assert.strictEqual(epRecovered.consecutive_failures, 0);
      assert.strictEqual(epRecovered.last_alerted_level, 0);

      const recoveryAlerts = alertTarget.requests.filter(r => r.body.includes('Endpoint Recovered') || r.body.includes('back online'));
      console.log(`      Recovery alerts received on attempt 66: ${recoveryAlerts.length}`);
      assert.strictEqual(recoveryAlerts.length, 1, 'Must send exactly 1 recovery alert upon recovery');

      // Subsequent 200 OK: attempt 67
      const evRec2 = ha.storage.saveEvent({ id: 'evt_th_67', endpointId: 'ep_throttle_test', provider: 'shopify', headers: {}, rawBody: '{}' });
      await ha.dispatcher.dispatch(evRec2, ha.storage.getEndpoint('ep_throttle_test'));
      await sleep(100);

      const recoveryAlertsAfter67 = alertTarget.requests.filter(r => r.body.includes('Endpoint Recovered') || r.body.includes('back online'));
      assert.strictEqual(recoveryAlertsAfter67.length, 1, 'Must NOT send duplicate recovery alert on subsequent successes');

      await new Promise(r => recoverServer.close(r));
    } finally {
      await new Promise(r => ha.server.close(r));
      await alertTarget.close();
    }
  });

  // ---------------------------------------------------------------
  // PROBE 3: Time & Date Edge Cases in assessDisablementRisk
  // ---------------------------------------------------------------
  await probe('VECTOR 3: SQLite timestamp parsing, timezones, NaN and edge cases', async () => {
    // 1. Standard SQLite UTC datetime('now'): '2026-10-11 02:30:00'
    const ep1 = { provider: 'razorpay', consecutive_failures: 5, streak_started_at: '2026-10-10 12:00:00' };
    const r1 = assessDisablementRisk(ep1);
    console.log(`      Standard SQLite format streakHours: ${r1.streakHours} (is NaN: ${isNaN(r1.streakHours)})`);
    assert.ok(!isNaN(r1.streakHours), 'Standard SQLite format must not be NaN');
    assert.ok(r1.streakHours > 0, 'Streak hours must be positive');

    // 2. ISO timestamp with Z: '2026-10-10T12:00:00Z'
    const ep2 = { provider: 'razorpay', consecutive_failures: 5, streak_started_at: '2026-10-10T12:00:00Z' };
    const r2 = assessDisablementRisk(ep2);
    assert.ok(!isNaN(r2.streakHours));
    assert.strictEqual(r1.streakHours, r2.streakHours, 'SQLite format and ISO Z format should compute identical streakHours');

    // 3. ISO timestamp with offset: '2026-10-10T12:00:00+05:30'
    const ep3 = { provider: 'razorpay', consecutive_failures: 5, streak_started_at: '2026-10-10T12:00:00+05:30' };
    const r3 = assessDisablementRisk(ep3);
    console.log(`      Offset ISO timestamp streakHours: ${r3.streakHours} (level: ${r3.level})`);
    const badDateStr = `${ep3.streak_started_at}Z`;
    const isBadNaN = isNaN(new Date(badDateStr).getTime());
    console.log(`      new Date('${badDateStr}').getTime(): ${new Date(badDateStr).getTime()} (NaN: ${isBadNaN})`);
    if (isBadNaN) {
      console.warn('      [EDGE CASE BUG] Appending Z to timezone-offset strings causes Date to parse as NaN, resetting streakHours to 0!');
    }

    // 4. Future timestamp (clock skew): '2099-01-01 00:00:00'
    const ep4 = { provider: 'razorpay', consecutive_failures: 5, streak_started_at: '2099-01-01 00:00:00' };
    const r4 = assessDisablementRisk(ep4);
    assert.strictEqual(r4.streakHours, 0, 'Future streak started at must be clamped to 0');

    // 5. Non-string streak_started_at: number or Date object
    let numericThrew = false;
    try {
      const ep6 = { provider: 'razorpay', consecutive_failures: 5, streak_started_at: 1728600000000 };
      assessDisablementRisk(ep6);
    } catch (e) {
      numericThrew = true;
      console.warn(`      [TYPE SAFETY BUG] assessDisablementRisk throws on numeric streak_started_at: ${e.message}`);
    }
  });

  // ---------------------------------------------------------------
  // PROBE 4: Error Handling & Crashes with bad alertWebhookUrl
  // ---------------------------------------------------------------
  await probe('VECTOR 4: Malformed, blocking or failing alert_webhook_url', async () => {
    const hookTarget = await startTarget({ status: 500 });
    const ha = createServer({ dbPath: ':memory:', autoStartWorker: false });
    await new Promise((r) => ha.server.listen(0, '127.0.0.1', r));

    try {
      const badAlertUrls = [
        'ftp://invalid-scheme.com',
        'http://256.256.256.256',
        'http://127.0.0.1:1/nonexistent',
        'not_a_valid_url',
        'https://'
      ];

      for (const badUrl of badAlertUrls) {
        ha.storage.createEndpoint({
          id: `ep_bad_alert_${Math.random().toString(36).slice(2, 7)}`,
          name: 'Bad Alert EP',
          targetUrl: hookTarget.url,
          provider: 'shopify',
          alertWebhookUrl: badUrl,
          autoRetry: 0
        });
      }

      // Check if dispatching to these endpoints ever crashes or hangs
      const eps = ha.storage.listEndpoints();
      for (const ep of eps) {
        const ev = ha.storage.saveEvent({ id: `evt_bad_${ep.id}`, endpointId: ep.id, provider: 'shopify', headers: {}, rawBody: '{}' });
        const res = await ha.dispatcher.dispatch(ev, ep);
        assert.ok(res, 'Dispatch must resolve even with malformed alert URL');
        assert.strictEqual(res.success, false);
      }
      console.log('      All dispatches resolved cleanly without unhandled exceptions.');
    } finally {
      await new Promise(r => ha.server.close(r));
      await hookTarget.close();
    }
  });

  // ---------------------------------------------------------------
  // PROBE 5: Schema & Upgrade from v1.2.0 Database
  // ---------------------------------------------------------------
  await probe('VECTOR 5: Upgrade integrity from v1.2.0 database schema', async () => {
    const tmpDb = path.join(os.tmpdir(), `ha_upgrade_test_${Date.now()}.db`);

    const Database = require('better-sqlite3');
    const legacyDb = new Database(tmpDb);
    legacyDb.exec(`
      CREATE TABLE endpoints (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        target_url TEXT NOT NULL,
        secret TEXT,
        alert_webhook_url TEXT,
        auto_retry INTEGER DEFAULT 1,
        max_retries INTEGER DEFAULT 5,
        concurrency_limit INTEGER DEFAULT 5,
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE TABLE events (
        id TEXT PRIMARY KEY,
        endpoint_id TEXT NOT NULL,
        idempotency_key TEXT,
        provider TEXT DEFAULT 'generic',
        event_type TEXT,
        headers TEXT NOT NULL,
        raw_body TEXT NOT NULL,
        status TEXT NOT NULL,
        attempts INTEGER DEFAULT 0,
        last_status_code INTEGER,
        last_error TEXT,
        last_latency_ms INTEGER,
        next_retry_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
      );

      INSERT INTO endpoints (id, name, target_url, secret)
      VALUES ('legacy_ep_1', 'Legacy Endpoint 1', 'https://example.com/webhook', 'whsec_old');

      INSERT INTO events (id, endpoint_id, headers, raw_body, status)
      VALUES ('evt_leg_1', 'legacy_ep_1', '{}', '{"legacy":true}', 'failed');
    `);
    legacyDb.close();

    const storage = new Storage(tmpDb);
    try {
      const ep = storage.getEndpoint('legacy_ep_1');
      assert.ok(ep, 'Legacy endpoint must exist');
      assert.strictEqual(ep.consecutive_failures, 0, 'consecutive_failures must default to 0');
      assert.strictEqual(ep.last_alerted_level, 0, 'last_alerted_level must default to 0');
      assert.strictEqual(ep.streak_started_at, null);
      assert.strictEqual(ep.provider, null);

      storage.recordAttempt({ eventId: 'evt_leg_1', statusCode: 500, errorMessage: 'Legacy Fail' });
      const epAfter = storage.getEndpoint('legacy_ep_1');
      assert.strictEqual(epAfter.consecutive_failures, 1);
      assert.ok(epAfter.streak_started_at);

      console.log('      v1.2.0 database migrated and recorded attempt cleanly.');
    } finally {
      storage.db.close();
      for (const f of [tmpDb, `${tmpDb}-wal`, `${tmpDb}-shm`]) {
        try { fs.rmSync(f, { force: true }); } catch (_) {}
      }
    }
  });

  // ---------------------------------------------------------------
  // PROBE 6: CLI Resilience with null/edge values
  // ---------------------------------------------------------------
  await probe('VECTOR 6: CLI commands against null providers and streak times', async () => {
    const ha = createServer({ dbPath: ':memory:', autoStartWorker: false });
    await new Promise((r) => ha.server.listen(0, '127.0.0.1', r));
    const baseUrl = `http://127.0.0.1:${ha.server.address().port}`;

    try {
      ha.storage.createEndpoint({
        id: 'ep_cli_test',
        name: 'Special "Quotes" & <Tags>',
        targetUrl: 'http://127.0.0.1:9999/hook',
        provider: null
      });

      const { execFile } = require('child_process');
      const runCli = (args) => new Promise((resolve, reject) => {
        execFile(process.execPath, ['bin/hookarmor.js', ...args, '-u', baseUrl], (err, stdout, stderr) => {
          if (err) return reject(new Error(stderr || err.message));
          resolve(stdout);
        });
      });

      const statusOut = await runCli(['status']);
      assert.ok(statusOut.includes('HookArmor Metrics'), 'status command must succeed');

      const listOut = await runCli(['endpoints', 'list']);
      assert.ok(listOut.includes('ep_cli_test'), 'endpoints list command must list endpoint');
      assert.ok(listOut.includes('Healthy'), 'must display healthy sentinel status');

      console.log('      CLI commands ran and formatted output successfully.');
    } finally {
      await new Promise(r => ha.server.close(r));
    }
  });

  console.log('====================================================');
  console.log(`PROBE RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('====================================================\n');
}

runProbes().catch(e => {
  console.error('Fatal probe error:', e);
  process.exit(1);
});
