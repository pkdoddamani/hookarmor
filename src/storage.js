const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// SQLite datetime() format (UTC, "YYYY-MM-DD HH:MM:SS") so stored times compare correctly with datetime('now')
function toSqliteTime(date) {
  return date.toISOString().slice(0, 19).replace('T', ' ');
}

function deriveKey(keyInput) {
  if (!keyInput) return null;
  if (Buffer.isBuffer(keyInput) && keyInput.length === 32) return keyInput;
  return crypto.createHash('sha256').update(String(keyInput)).digest();
}

function encryptSecret(plaintext, key) {
  if (!plaintext || typeof plaintext !== 'string') return plaintext || '';
  if (!key) return plaintext;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:v1:${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

function decryptSecret(stored, key) {
  if (!stored || typeof stored !== 'string') return stored || '';
  if (!stored.startsWith('enc:v1:')) {
    return stored; // Plaintext legacy or fallback
  }
  if (!key) {
    throw new Error('Endpoint secret is encrypted with AES-256-GCM, but HOOKARMOR_ENCRYPTION_KEY is not configured');
  }
  const parts = stored.split(':');
  if (parts.length !== 5) {
    throw new Error('Malformed encrypted secret format in database');
  }
  const iv = Buffer.from(parts[2], 'hex');
  const tag = Buffer.from(parts[3], 'hex');
  const ciphertext = Buffer.from(parts[4], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

class Storage {
  constructor(dbPath, options = {}) {
    if (!dbPath) {
      const dataDir = process.env.HOOKARMOR_DATA_DIR || path.join(process.cwd(), 'data');
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }
      dbPath = path.join(dataDir, 'hookarmor.db');
    }
    const envKey = process.env.HOOKARMOR_ENCRYPTION_KEY;
    this.encryptionKey = options.encryptionKey !== undefined
      ? deriveKey(options.encryptionKey)
      : deriveKey(envKey);

    if (!this.encryptionKey && !Storage._warnedNoKey && process.env.NODE_ENV !== 'test') {
      console.warn('[Security Warning] HOOKARMOR_ENCRYPTION_KEY is not set. Endpoint secrets are stored in plaintext. Set a 32+ character key to enable AES-256-GCM at-rest encryption.');
      Storage._warnedNoKey = true;
    }

    this.db = new Database(dbPath);
    this.init();
  }

  init() {
    try {
      this.db.pragma('journal_mode = WAL');
      // FULL fsyncs every commit: an event acknowledged with 200 OK survives power loss
      this.db.pragma('synchronous = FULL');
    } catch (e) {}

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS endpoints (
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

      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        endpoint_id TEXT NOT NULL,
        idempotency_key TEXT,
        provider TEXT DEFAULT 'generic',
        event_type TEXT,
        headers TEXT NOT NULL,
        raw_body TEXT NOT NULL,
        status TEXT NOT NULL, -- 'pending', 'replaying' (claimed / in flight), 'delivered', 'failed'
        attempts INTEGER DEFAULT 0,
        last_status_code INTEGER,
        last_error TEXT,
        last_latency_ms INTEGER,
        next_retry_at TEXT,
        claimed_by TEXT,
        claimed_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
      );

      CREATE TABLE IF NOT EXISTS delivery_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL,
        status_code INTEGER,
        response_body TEXT,
        error_message TEXT,
        latency_ms INTEGER,
        attempted_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (event_id) REFERENCES events(id)
      );

      CREATE TABLE IF NOT EXISTS instances (
        id TEXT PRIMARY KEY,
        hostname TEXT,
        pid INTEGER,
        started_at TEXT DEFAULT (datetime('now')),
        last_heartbeat TEXT DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS waitlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        source TEXT DEFAULT 'website',
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
      CREATE INDEX IF NOT EXISTS idx_events_endpoint ON events(endpoint_id);
      CREATE INDEX IF NOT EXISTS idx_events_idempotency ON events(endpoint_id, idempotency_key);
      CREATE INDEX IF NOT EXISTS idx_events_retry ON events(status, next_retry_at);
      CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
      CREATE INDEX IF NOT EXISTS idx_attempts_event ON delivery_attempts(event_id);
    `);

    // Migrations for existing databases
    const eventColumns = this.db.prepare('PRAGMA table_info(events)').all().map((c) => c.name);
    if (!eventColumns.includes('verified')) {
      this.db.exec('ALTER TABLE events ADD COLUMN verified INTEGER DEFAULT 0');
    }
    if (!eventColumns.includes('claimed_by')) {
      this.db.exec('ALTER TABLE events ADD COLUMN claimed_by TEXT');
    }
    if (!eventColumns.includes('claimed_at')) {
      this.db.exec('ALTER TABLE events ADD COLUMN claimed_at TEXT');
    }

    try {
      this.db.exec(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_events_idem_unique
          ON events(endpoint_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
      `);
    } catch (_) {}
  }

  // Upsert. Omitting secret or alertWebhookUrl (undefined) keeps the stored value; '' clears it.
  createEndpoint({ id, name, targetUrl, secret, alertWebhookUrl, autoRetry = 1, maxRetries = 5, concurrencyLimit = 5 }) {
    const existing = this.getEndpoint(id);
    const finalSecret = secret !== undefined ? secret : (existing ? existing.secret : '');
    const finalAlert = alertWebhookUrl !== undefined ? alertWebhookUrl : (existing ? existing.alert_webhook_url : '');
    const encryptedSecret = encryptSecret(finalSecret, this.encryptionKey);
    this.db.prepare(`
      INSERT INTO endpoints (id, name, target_url, secret, alert_webhook_url, auto_retry, max_retries, concurrency_limit)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        target_url = excluded.target_url,
        secret = excluded.secret,
        alert_webhook_url = excluded.alert_webhook_url,
        auto_retry = excluded.auto_retry,
        max_retries = excluded.max_retries,
        concurrency_limit = excluded.concurrency_limit
    `).run(id, name, targetUrl, encryptedSecret || '', finalAlert || '', autoRetry ? 1 : 0, maxRetries, concurrencyLimit || 5);
    return this.getEndpoint(id);
  }

  getEndpoint(id) {
    const row = this.db.prepare('SELECT * FROM endpoints WHERE id = ?').get(id);
    if (!row) return null;
    return { ...row, secret: decryptSecret(row.secret, this.encryptionKey) };
  }

  listEndpoints() {
    const rows = this.db.prepare('SELECT * FROM endpoints ORDER BY created_at DESC').all();
    return rows.map((r) => ({ ...r, secret: decryptSecret(r.secret, this.encryptionKey) }));
  }

  deleteEndpoint(id) {
    const deleteTx = this.db.transaction((epId) => {
      this.db.prepare(`
        DELETE FROM delivery_attempts WHERE event_id IN (
          SELECT id FROM events WHERE endpoint_id = ?
        )
      `).run(epId);
      this.db.prepare('DELETE FROM events WHERE endpoint_id = ?').run(epId);
      return this.db.prepare('DELETE FROM endpoints WHERE id = ?').run(epId).changes > 0;
    });
    return deleteTx(id);
  }

  // Any stored copy counts: once HookArmor has custody, a provider re-send is redundant
  findEventByIdempotencyKey(endpointId, idempotencyKey) {
    if (!idempotencyKey) return null;
    const row = this.db.prepare('SELECT * FROM events WHERE endpoint_id = ? AND idempotency_key = ? ORDER BY created_at ASC LIMIT 1').get(endpointId, idempotencyKey);
    if (!row) return null;
    return { ...row, headers: JSON.parse(row.headers) };
  }

  saveEvent({ id, endpointId, idempotencyKey = null, provider, eventType, headers, rawBody, status = 'pending', claimedBy = null, verified = false }) {
    const rawBuffer = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody || ''), 'utf8');
    const stmt = this.db.prepare(`
      INSERT INTO events (id, endpoint_id, idempotency_key, provider, event_type, headers, raw_body, status, attempts, claimed_by, claimed_at, verified, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ${claimedBy ? "datetime('now')" : 'NULL'}, ?, datetime('now'), datetime('now'))
    `);
    try {
      stmt.run(
        id,
        endpointId,
        idempotencyKey,
        provider,
        eventType,
        JSON.stringify(headers),
        rawBuffer,
        status,
        claimedBy,
        verified ? 1 : 0
      );
      return this.getEvent(id);
    } catch (err) {
      if (idempotencyKey && (err.code === 'SQLITE_CONSTRAINT_UNIQUE' || (err.message && err.message.includes('UNIQUE constraint failed')))) {
        const existing = this.findEventByIdempotencyKey(endpointId, idempotencyKey);
        if (existing) return existing;
      }
      throw err;
    }
  }

  getPendingCount() {
    return this.db.prepare("SELECT count(*) as count FROM events WHERE status IN ('pending', 'replaying')").get().count;
  }

  recordAttempt({ eventId, statusCode, responseBody = '', errorMessage = '', latencyMs = 0, nextRetryAt = null }) {
    const insertAttempt = this.db.prepare(`
      INSERT INTO delivery_attempts (event_id, status_code, response_body, error_message, latency_ms, attempted_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `);
    const isSuccess = statusCode >= 200 && statusCode < 300;
    const newStatus = isSuccess ? 'delivered' : 'failed';

    const updateEvent = this.db.prepare(`
      UPDATE events
      SET status = ?,
          attempts = attempts + 1,
          last_status_code = ?,
          last_error = ?,
          last_latency_ms = ?,
          next_retry_at = ?,
          updated_at = datetime('now')
      WHERE id = ?
    `);

    this.db.transaction(() => {
      insertAttempt.run(eventId, statusCode, responseBody.slice(0, 4000), errorMessage.slice(0, 1000), latencyMs);
      updateEvent.run(newStatus, statusCode, errorMessage || (isSuccess ? null : `HTTP ${statusCode}`), latencyMs, nextRetryAt, eventId);
    })();

    return this.getEvent(eventId);
  }

  getEvent(id) {
    const row = this.db.prepare('SELECT * FROM events WHERE id = ?').get(id);
    if (!row) return null;
    return {
      ...row,
      headers: JSON.parse(row.headers)
    };
  }

  getAttempts(eventId) {
    return this.db.prepare('SELECT * FROM delivery_attempts WHERE event_id = ? ORDER BY id DESC').all(eventId);
  }

  deleteEvent(id) {
    const deleteTx = this.db.transaction((eventId) => {
      this.db.prepare('DELETE FROM delivery_attempts WHERE event_id = ?').run(eventId);
      return this.db.prepare('DELETE FROM events WHERE id = ?').run(eventId).changes > 0;
    });
    return deleteTx(id);
  }

  listEvents({ endpointId = null, status = null, limit = 50, offset = 0 } = {}) {
    let sql = 'SELECT * FROM events WHERE 1=1';
    const params = [];

    if (endpointId) {
      sql += ' AND endpoint_id = ?';
      params.push(endpointId);
    }
    if (status === 'pending') {
      sql += " AND status IN ('pending', 'replaying')";
    } else if (status) {
      sql += ' AND status = ?';
      params.push(status);
    }
    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(Math.min(Math.max(limit, 1), 500), Math.max(offset, 0));

    const rows = this.db.prepare(sql).all(...params);
    return rows.map(r => ({
      ...r,
      headers: JSON.parse(r.headers)
    }));
  }

  getStats() {
    const total = this.db.prepare('SELECT count(*) as count FROM events').get().count;
    const delivered = this.db.prepare("SELECT count(*) as count FROM events WHERE status = 'delivered'").get().count;
    const failed = this.db.prepare("SELECT count(*) as count FROM events WHERE status = 'failed'").get().count;
    const pending = this.db.prepare("SELECT count(*) as count FROM events WHERE status IN ('pending', 'replaying')").get().count;
    const avgLatency = this.db.prepare('SELECT avg(last_latency_ms) as avg_lat FROM events WHERE last_latency_ms IS NOT NULL').get().avg_lat || 0;

    return {
      total,
      delivered,
      failed,
      pending,
      avgLatencyMs: Math.round(avgLatency)
    };
  }

  // Manual "replay all": every failed event, including ones that exhausted automatic retries
  getFailedEventsForReplay(endpointId = null, limit = 500) {
    let sql = "SELECT * FROM events WHERE status = 'failed'";
    const params = [];
    if (endpointId) {
      sql += ' AND endpoint_id = ?';
      params.push(endpointId);
    }
    sql += ' ORDER BY created_at ASC LIMIT ?';
    params.push(limit);
    return this.db.prepare(sql).all(...params).map(r => ({
      ...r,
      headers: JSON.parse(r.headers)
    }));
  }

  countFailed(endpointId = null) {
    if (endpointId) {
      return this.db.prepare("SELECT count(*) AS n FROM events WHERE status = 'failed' AND endpoint_id = ?").get(endpointId).n;
    }
    return this.db.prepare("SELECT count(*) AS n FROM events WHERE status = 'failed'").get().n;
  }

  getEventsDueForRetry(limit = 25) {
    // datetime() normalises both legacy ISO-8601 values and SQLite-format values before comparing
    const sql = `
      SELECT e.*, ep.max_retries, ep.target_url, ep.secret, ep.alert_webhook_url
      FROM events e
      JOIN endpoints ep ON e.endpoint_id = ep.id
      WHERE (
        (e.status = 'failed' AND ep.auto_retry = 1 AND e.attempts < ep.max_retries AND e.next_retry_at IS NOT NULL AND datetime(e.next_retry_at) <= datetime('now'))
        OR
        (e.status = 'pending' AND ep.auto_retry = 1 AND e.created_at <= datetime('now', '-20 seconds'))
      )
      ORDER BY e.created_at ASC
      LIMIT ?
    `;
    const rows = this.db.prepare(sql).all(limit);
    return rows.map(r => ({
      ...r,
      headers: JSON.parse(r.headers)
    }));
  }

  registerInstance({ id, hostname, pid }) {
    if (!id) return;
    this.db.prepare(`
      INSERT INTO instances (id, hostname, pid, started_at, last_heartbeat)
      VALUES (?, ?, ?, datetime('now'), datetime('now'))
      ON CONFLICT(id) DO UPDATE SET last_heartbeat = datetime('now'), pid = excluded.pid, hostname = excluded.hostname
    `).run(id, hostname || null, pid || null);
  }

  heartbeatInstance(id) {
    if (!id) return;
    this.db.prepare(`
      UPDATE instances SET last_heartbeat = datetime('now') WHERE id = ?
    `).run(id);
  }

  reapStaleInstances(timeoutSeconds = 300) {
    return this.db.prepare(`
      DELETE FROM instances WHERE datetime(last_heartbeat) < datetime('now', '-' || ? || ' seconds')
    `).run(timeoutSeconds).changes;
  }

  claimEventForRetry(eventId, instanceId = null) {
    const info = this.db.prepare(`
      UPDATE events
      SET status = 'replaying',
          claimed_by = ?,
          claimed_at = datetime('now'),
          updated_at = datetime('now')
      WHERE id = ? AND status IN ('failed', 'pending')
    `).run(instanceId, eventId);
    return info.changes > 0;
  }

  // Manual replay may re-send delivered events, but never one that is already in flight
  claimEventForManualReplay(eventId, instanceId = null) {
    const info = this.db.prepare(`
      UPDATE events
      SET status = 'replaying',
          claimed_by = ?,
          claimed_at = datetime('now'),
          updated_at = datetime('now')
      WHERE id = ? AND status IN ('failed', 'pending', 'delivered')
    `).run(instanceId, eventId);
    return info.changes > 0;
  }

  // Run at startup or worker tick:
  // Reclaim events if:
  // 1. claimed_by is NULL, OR
  // 2. claimed_by is not active in instances table (last_heartbeat < 45 seconds ago), OR
  // 3. claimed_at is older than 180 seconds (worker hung)
  recoverInterruptedDeliveries() {
    const sql = `
      UPDATE events
      SET status = 'failed',
          next_retry_at = datetime('now'),
          last_error = COALESCE(last_error, 'Delivery interrupted by restart'),
          claimed_by = NULL,
          claimed_at = NULL,
          updated_at = datetime('now')
      WHERE status = 'replaying'
        AND (
          claimed_by IS NULL
          OR claimed_by NOT IN (
            SELECT id FROM instances WHERE datetime(last_heartbeat) >= datetime('now', '-45 seconds')
          )
          OR (claimed_at IS NOT NULL AND datetime(claimed_at) < datetime('now', '-180 seconds'))
        )
    `;
    return this.db.prepare(sql).run().changes;
  }

  // Delete delivered events (and their attempt logs) older than `days`. Failed events are kept.
  pruneEvents(days) {
    if (!days || days <= 0) return 0;
    const cutoff = `-${Math.floor(days)} days`;
    return this.db.transaction(() => {
      this.db.prepare(`
        DELETE FROM delivery_attempts WHERE event_id IN (
          SELECT id FROM events WHERE status = 'delivered' AND created_at < datetime('now', ?)
        )
      `).run(cutoff);
      return this.db.prepare("DELETE FROM events WHERE status = 'delivered' AND created_at < datetime('now', ?)").run(cutoff).changes;
    })();
  }

  addWaitlist(email, source = 'website') {
    const stmt = this.db.prepare(`
      INSERT INTO waitlist (email, source, created_at)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(email) DO UPDATE SET created_at = datetime('now')
    `);
    stmt.run(email, source);
    return { email, source, status: 'registered' };
  }

  listWaitlist() {
    return this.db.prepare('SELECT * FROM waitlist ORDER BY created_at DESC').all();
  }
}

Storage.toSqliteTime = toSqliteTime;
Storage.deriveKey = deriveKey;
Storage.encryptSecret = encryptSecret;
Storage.decryptSecret = decryptSecret;

module.exports = Storage;
