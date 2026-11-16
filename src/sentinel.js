/**
 * HookArmor Delivery Sentinel
 *
 * Tracks the streak of consecutive failed deliveries from HookArmor to the destination app and turns
 * it into a warning / danger / critical level for the dashboard, CLI and alerts.
 *
 * What this streak does NOT measure is the provider's own view. Shopify, Razorpay and Stripe only see
 * HookArmor's response, and HookArmor acknowledges every accepted webhook with 200, so a failing
 * destination does not move a provider towards disabling or deleting the subscription. The real
 * exposure during a streak is that events use up their automatic retries and then wait in the DLQ
 * for a manual replay.
 *
 * What does put a subscription at risk is HookArmor itself refusing webhooks (a signing secret that
 * was rotated at the provider but not here, the rate limit, a full queue). That is tracked at ingress:
 * `ingressRejections` on the endpoint API, `hookarmor_ingress_rejected_total` in /metrics, and the
 * ingress rejection alert.
 */

const HELD = 'HookArmor keeps answering the provider with 200, so the subscription itself is not at risk; events are held for retry and replay.';

function streakHoursSince(streakStartedAt) {
  if (!streakStartedAt) return 0;
  let startedMs = NaN;
  if (typeof streakStartedAt === 'number') {
    startedMs = streakStartedAt;
  } else if (streakStartedAt instanceof Date) {
    startedMs = streakStartedAt.getTime();
  } else if (typeof streakStartedAt === 'string') {
    const s = streakStartedAt.trim();
    // SQLite datetime('now') strings are UTC without a zone marker
    startedMs = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(s)
      ? new Date(`${s.replace(' ', 'T')}Z`).getTime()
      : new Date(s).getTime();
  }
  if (isNaN(startedMs)) return 0;
  return Math.max(0, Math.floor((Date.now() - startedMs) / (1000 * 60 * 60)));
}

// Thresholds are unchanged from earlier releases, so alert cadence stays the same
function levelFor(provider, consecutiveFailures, streakHours) {
  if (provider === 'shopify') {
    if (consecutiveFailures >= 15) return 3;
    if (consecutiveFailures >= 10) return 2;
    if (consecutiveFailures >= 5) return 1;
    return 0;
  }
  if (provider === 'razorpay') {
    if (streakHours >= 18 || consecutiveFailures >= 20) return 3;
    if (streakHours >= 6 || consecutiveFailures >= 10) return 2;
    if (streakHours >= 1 || consecutiveFailures >= 5) return 1;
    return 0;
  }
  if (consecutiveFailures >= 20) return 3;
  if (consecutiveFailures >= 10) return 2;
  if (consecutiveFailures >= 5) return 1;
  return 0;
}

function assessDisablementRisk(endpoint) {
  if (!endpoint) return { level: 'healthy', numericLevel: 0, message: 'Healthy' };

  const provider = (endpoint.provider || 'generic').toLowerCase();
  const consecutiveFailures = endpoint.consecutive_failures || 0;

  if (consecutiveFailures === 0) {
    return {
      provider,
      level: 'healthy',
      numericLevel: 0,
      consecutiveFailures: 0,
      streakHours: 0,
      message: 'All webhooks delivering successfully.'
    };
  }

  const streakHours = streakHoursSince(endpoint.streak_started_at || null);
  const numericLevel = levelFor(provider, consecutiveFailures, streakHours);
  const base = { provider, numericLevel, consecutiveFailures, streakHours };

  if (numericLevel === 0) {
    return { ...base, level: 'healthy', message: `${consecutiveFailures} transient failure(s).` };
  }

  const duration = streakHours >= 1 ? ` over ${streakHours}h` : '';
  const failing = `Destination app has failed ${consecutiveFailures} consecutive deliveries${duration}.`;
  const shared = { ...base, providerSubscriptionAtRisk: false };

  if (numericLevel === 3) {
    return {
      ...shared,
      level: 'critical',
      alertTitle: 'CRITICAL: Destination App Down',
      message: `${failing} Events are running out of automatic retries and will wait in the DLQ for replay. ${HELD}`
    };
  }
  if (numericLevel === 2) {
    return {
      ...shared,
      level: 'danger',
      alertTitle: 'DANGER: Destination App Failing',
      message: `${failing} ${HELD}`
    };
  }
  return {
    ...shared,
    level: 'warning',
    alertTitle: 'WARNING: Webhook Delivery Errors',
    message: `${failing} ${HELD}`
  };
}

module.exports = {
  assessDisablementRisk
};
