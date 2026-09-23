const EventEmitter = require('events');

class RetryWorker extends EventEmitter {
  constructor(storage, dispatcher, options = {}) {
    super();
    this.storage = storage;
    this.dispatcher = dispatcher;
    this.intervalMs = options.intervalMs || 5000;
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

  async tick() {
    if (this.isProcessing) return;
    this.isProcessing = true;

    try {
      const eventsDue = this.storage.getEventsDueForRetry(25);
      if (!eventsDue || eventsDue.length === 0) {
        this.isProcessing = false;
        return;
      }

      for (const event of eventsDue) {
        const claimed = this.storage.claimEventForRetry(event.id);
        if (!claimed) continue; // Another process or manual replay already claimed it

        const endpoint = this.storage.getEndpoint(event.endpoint_id);
        if (!endpoint) continue;

        this.emit('retry:claimed', { eventId: event.id, endpointId: endpoint.id });

        // Dispatch asynchronously without blocking next iterations
        this.dispatcher.dispatch(event, endpoint).catch((err) => {
          this.emit('retry:error', { eventId: event.id, error: err.message });
        });
      }
    } catch (err) {
      this.emit('error', err);
    } finally {
      this.isProcessing = false;
    }
  }
}

module.exports = RetryWorker;
