const EventEmitter = require('events');

class RetryWorker extends EventEmitter {
  constructor(storage, dispatcher, options = {}) {
    super();
    this.storage = storage;
    this.dispatcher = dispatcher;
    this.intervalMs = options.intervalMs || 5000;
    this.retentionDays = options.retentionDays || 0;
    this.pruneIntervalMs = options.pruneIntervalMs || 60 * 60 * 1000;
    this.lastPruneAt = 0;
    this.instanceId = options.instanceId || null;
    this.leaseTimeoutSeconds = options.leaseTimeoutSeconds || 60;
    // Endpoints whose in-memory queue is at least this long are left for later ticks
    this.maxQueuedPerEndpoint = options.maxQueuedPerEndpoint || 1000;
    // Up to batchSize * maxBatchesPerTick events are claimed per tick (default 1000 per 5s)
    this.batchSize = options.batchSize || 200;
    this.maxBatchesPerTick = options.maxBatchesPerTick || 5;
    this.timer = null;
    this.isProcessing = false;
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.tick().catch(err => {
        this.emit('error', err);
      });
    }, this.intervalMs);
    // Unref timer so it doesn't hold Node process open during graceful shutdown or tests if desired
    if (this.timer.unref) this.timer.unref();
    this.emit('started');
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      this.emit('stopped');
    }
  }

  prune() {
    if (!this.retentionDays || Date.now() - this.lastPruneAt < this.pruneIntervalMs) return;
    this.lastPruneAt = Date.now();
    const removed = this.storage.pruneEvents(this.retentionDays);
    if (removed > 0) this.emit('pruned', { removed });
  }

  async tick() {
    if (this.isProcessing) return;
    this.isProcessing = true;

    try {
      if (this.instanceId) {
        this.storage.heartbeatInstance(this.instanceId);
        this.storage.renewClaims(this.dispatcher.heldEventIds(), this.instanceId);
      }
      this.storage.recoverInterruptedDeliveries(this.leaseTimeoutSeconds);
      this.storage.reapStaleInstances(300);

      this.prune();

      // Pull batches until nothing is due, every due endpoint's queue is full, or the per-tick cap is hit
      const saturated = new Set();
      for (let batch = 0; batch < this.maxBatchesPerTick; batch++) {
        const eventsDue = this.storage.getEventsDueForRetry(this.batchSize, [...saturated]);
        if (!eventsDue || eventsDue.length === 0) break;

        const endpoints = new Map();
        for (const event of eventsDue) {
          if (saturated.has(event.endpoint_id)) continue;
          if (this.dispatcher.queuedFor(event.endpoint_id) >= this.maxQueuedPerEndpoint) {
            saturated.add(event.endpoint_id);
            continue;
          }
          const claimed = this.storage.claimEventForRetry(event.id, this.instanceId);
          if (!claimed) continue; // Another process or manual replay already claimed it

          if (!endpoints.has(event.endpoint_id)) endpoints.set(event.endpoint_id, this.storage.getEndpoint(event.endpoint_id));
          const endpoint = endpoints.get(event.endpoint_id);
          if (!endpoint) {
            this.storage.releaseClaim(event.id);
            continue;
          }

          this.emit('retry:claimed', { eventId: event.id, endpointId: endpoint.id });

          // Dispatch asynchronously without blocking next iterations
          this.dispatcher.dispatch(event, endpoint, { replay: true }).catch((err) => {
            this.emit('retry:error', { eventId: event.id, error: err.message });
          });
        }
        if (eventsDue.length < this.batchSize) break;
      }
    } catch (err) {
      if (this.listenerCount('error') > 0) this.emit('error', err);
      else console.error('[RetryWorker] Tick failed:', err.message);
    } finally {
      this.isProcessing = false;
    }
  }
}

module.exports = RetryWorker;
