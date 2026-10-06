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
    this.timer = null;
    this.isProcessing = false;
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => this.tick(), this.intervalMs);
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
      }
      this.storage.recoverInterruptedDeliveries(this.instanceId);
      this.storage.reapStaleInstances(300);

      this.prune();

      const eventsDue = this.storage.getEventsDueForRetry(25);
      if (!eventsDue || eventsDue.length === 0) return;

      for (const event of eventsDue) {
        const claimed = this.storage.claimEventForRetry(event.id, this.instanceId);
        if (!claimed) continue; // Another process or manual replay already claimed it

        const endpoint = this.storage.getEndpoint(event.endpoint_id);
        if (!endpoint) continue;

        this.emit('retry:claimed', { eventId: event.id, endpointId: endpoint.id });

        // Dispatch asynchronously without blocking next iterations
        this.dispatcher.dispatch(event, endpoint, { replay: true }).catch((err) => {
          this.emit('retry:error', { eventId: event.id, error: err.message });
        });
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
