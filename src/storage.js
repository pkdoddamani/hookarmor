const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

class Storage {
  constructor(dbPath) {
    if (!dbPath) {
      const dataDir = path.join(__dirname, '..', 'data');
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }
      dbPath = path.join(dataDir, 'hookarmor.db');
    }
    this.db = new Database(dbPath);
    this.init();
  }

  init() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS endpoints (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        target_url TEXT NOT NULL,
        secret TEXT,
        alert_webhook_url TEXT,
        auto_retry INTEGER DEFAULT 1,
        max_retries INTEGER DEFAULT 5,
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        endpoint_id TEXT NOT NULL,
        provider TEXT DEFAULT 'generic',
        event_type TEXT,
        headers TEXT NOT NULL,
        raw_body TEXT NOT NULL,
        status TEXT NOT NULL, -- 'pending', 'delivered', 'failed', 'replaying'
        attempts INTEGER DEFAULT 0,
        last_status_code INTEGER,
        last_error TEXT,
        last_latency_ms INTEGER,
        next_retry_at TEXT,
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

      CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
      CREATE INDEX IF NOT EXISTS idx_events_endpoint ON events(endpoint_id);
    `);
  }

  createEndpoint({ id, name, targetUrl, secret = '', alertWebhookUrl = '', autoRetry = 1, maxRetries = 5 }) {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO endpoints (id, name, target_url, secret, alert_webhook_url, auto_retry, max_retries)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(id, name, targetUrl, secret, alertWebhookUrl, autoRetry ? 1 : 0, maxRetries);
    return this.getEndpoint(id);
  }

  getEndpoint(id) {
    return this.db.prepare('SELECT * FROM endpoints WHERE id = ?').get(id);
  }

  listEndpoints() {
    return this.db.prepare('SELECT * FROM endpoints ORDER BY created_at DESC').all();
  }

  saveEvent({ id, endpointId, provider, eventType, headers, rawBody, status = 'pending' }) {
    const stmt = this.db.prepare(`
      INSERT INTO events (id, endpoint_id, provider, event_type, headers, raw_body, status, attempts, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 0, datetime('now'), datetime('now'))
    `);
    stmt.run(
      id,
      endpointId,
      provider,
      eventType,
      JSON.stringify(headers),
      rawBody,
      status
    );
    return this.getEvent(id);
  }

  recordAttempt({ eventId, statusCode, responseBody = '', errorMessage = '', latencyMs = 0, nextRetryAt = null }) {
    const insertAttempt = this.db.prepare(`
      INSERT INTO delivery_attempts (event_id, status_code, response_body, error_message, latency_ms, attempted_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `);
    insertAttempt.run(eventId, statusCode, responseBody.slice(0, 4000), errorMessage.slice(0, 1000), latencyMs);

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
    updateEvent.run(newStatus, statusCode, errorMessage || (isSuccess ? null : `HTTP ${statusCode}`), latencyMs, nextRetryAt, eventId);

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
    return this.db.prepare('SELECT * FROM delivery_attempts WHERE event_id = ? ORDER BY attempted_at DESC').all(eventId);
  }

  listEvents({ endpointId = null, status = null, limit = 50, offset = 0 } = {}) {
    let sql = 'SELECT * FROM events WHERE 1=1';
    const params = [];

    if (endpointId) {
      sql += ' AND endpoint_id = ?';
      params.push(endpointId);
    }
    if (status) {
      sql += ' AND status = ?';
      params.push(status);
    }
    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

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
    const pending = this.db.prepare("SELECT count(*) as count FROM events WHERE status = 'pending'").get().count;
    const avgLatency = this.db.prepare('SELECT avg(last_latency_ms) as avg_lat FROM events WHERE last_latency_ms IS NOT NULL').get().avg_lat || 0;

    return {
      total,
      delivered,
      failed,
      pending,
      avgLatencyMs: Math.round(avgLatency)
    };
  }

  getFailedEventsToRetry(endpointId = null) {
    let sql = `
      SELECT e.*, ep.max_retries, ep.target_url, ep.alert_webhook_url
      FROM events e
      JOIN endpoints ep ON e.endpoint_id = ep.id
      WHERE e.status = 'failed' AND ep.auto_retry = 1 AND e.attempts < ep.max_retries
    `;
    const params = [];
    if (endpointId) {
      sql += ' AND e.endpoint_id = ?';
      params.push(endpointId);
    }
    const rows = this.db.prepare(sql).all(...params);
    return rows.map(r => ({
      ...r,
      headers: JSON.parse(r.headers)
    }));
  }
}

module.exports = Storage;
