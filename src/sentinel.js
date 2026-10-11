/**
 * HookArmor Webhook Disablement Sentinel
 *
 * Tracks consecutive failure streaks and alerts teams BEFORE upstream providers
 * (Shopify, Razorpay, etc.) automatically disable or delete webhook subscriptions.
 *
 * Provider Cutoff Policies:
 * - Shopify: Automatically deletes webhook subscriptions after 19 consecutive failures.
 * - Razorpay: Automatically disables webhook subscriptions after 24 hours of failure.
 * - Stripe / Generic: Exponential backoff cutoff after repeated failed deliveries.
 */

function assessDisablementRisk(endpoint) {
  if (!endpoint) return { level: 'healthy', numericLevel: 0, message: 'Healthy' };

  const provider = (endpoint.provider || 'generic').toLowerCase();
  const consecutiveFailures = endpoint.consecutive_failures || 0;
  const streakStartedAt = endpoint.streak_started_at || null;

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

  const now = Date.now();
  let streakHours = 0;
  if (streakStartedAt) {
    let startedMs = NaN;
    if (typeof streakStartedAt === 'number') {
      startedMs = streakStartedAt;
    } else if (streakStartedAt instanceof Date) {
      startedMs = streakStartedAt.getTime();
    } else if (typeof streakStartedAt === 'string') {
      const s = streakStartedAt.trim();
      if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(s)) {
        startedMs = new Date(`${s.replace(' ', 'T')}Z`).getTime();
      } else {
        startedMs = new Date(s).getTime();
      }
    }
    if (!isNaN(startedMs)) {
      streakHours = Math.max(0, Math.floor((now - startedMs) / (1000 * 60 * 60)));
    }
  }

  // 1. Shopify Webhook Disablement Policy
  if (provider === 'shopify') {
    const cutoff = 19;
    const remaining = Math.max(0, cutoff - consecutiveFailures);

    if (consecutiveFailures >= 15) {
      return {
        provider: 'shopify',
        level: 'critical',
        numericLevel: 3,
        consecutiveFailures,
        cutoff,
        remaining,
        streakHours,
        alertTitle: 'CRITICAL: Destination App Down (Shopify Cutoff Risk)',
        message: `Destination app delivery streak failing (${consecutiveFailures} failures). HookArmor is holding events in DLQ to prevent permanent deletion (Shopify cutoff at 19 failures, ${remaining} remaining).`
      };
    }
    if (consecutiveFailures >= 10) {
      return {
        provider: 'shopify',
        level: 'danger',
        numericLevel: 2,
        consecutiveFailures,
        cutoff,
        remaining,
        streakHours,
        alertTitle: 'DANGER: Destination App Failing (Shopify DLQ Streak 10+)',
        message: `Destination app has failed 10+ consecutive deliveries (${remaining} failures remaining before Shopify cutoff). Events buffered in DLQ.`
      };
    }
    if (consecutiveFailures >= 5) {
      return {
        provider: 'shopify',
        level: 'warning',
        numericLevel: 1,
        consecutiveFailures,
        cutoff,
        remaining,
        streakHours,
        alertTitle: 'WARNING: Shopify Webhook Delivery Streak Failing',
        message: `Destination app has failed 5 consecutive deliveries (${remaining} failures remaining before Shopify cutoff). Events buffered in DLQ.`
      };
    }

    return {
      provider: 'shopify',
      level: 'healthy',
      numericLevel: 0,
      consecutiveFailures,
      cutoff,
      remaining,
      streakHours,
      message: `${consecutiveFailures} transient failure(s).`
    };
  }

  // 2. Razorpay Webhook Disablement Policy
  if (provider === 'razorpay') {
    const cutoffHours = 24;
    const hoursRemaining = Math.max(0, cutoffHours - streakHours);

    if (streakHours >= 18 || consecutiveFailures >= 20) {
      return {
        provider: 'razorpay',
        level: 'critical',
        numericLevel: 3,
        consecutiveFailures,
        cutoffHours,
        hoursRemaining,
        streakHours,
        alertTitle: 'CRITICAL: Destination App Down (Razorpay 24h Cutoff Risk)',
        message: `Destination app has failed deliveries for ${streakHours}h (${consecutiveFailures} failures). HookArmor is holding events in DLQ to prevent Razorpay 24h auto-disablement (~${hoursRemaining}h remaining).`
      };
    }
    if (streakHours >= 6 || consecutiveFailures >= 10) {
      return {
        provider: 'razorpay',
        level: 'danger',
        numericLevel: 2,
        consecutiveFailures,
        cutoffHours,
        hoursRemaining,
        streakHours,
        alertTitle: 'DANGER: Destination App Failing (Razorpay Streak ' + streakHours + 'h)',
        message: `Destination app delivery failing for ${streakHours}h (${consecutiveFailures} failures). HookArmor is buffering events in DLQ.`
      };
    }
    if (streakHours >= 1 || consecutiveFailures >= 5) {
      return {
        provider: 'razorpay',
        level: 'warning',
        numericLevel: 1,
        consecutiveFailures,
        cutoffHours,
        hoursRemaining,
        streakHours,
        alertTitle: 'WARNING: Razorpay Webhook Failures Detected',
        message: `Destination app has experienced ${consecutiveFailures} consecutive delivery failures. HookArmor is buffering events in DLQ.`
      };
    }

    return {
      provider: 'razorpay',
      level: 'healthy',
      numericLevel: 0,
      consecutiveFailures,
      streakHours,
      message: `${consecutiveFailures} transient failure(s).`
    };
  }

  // 3. Generic / Stripe / Other Providers
  if (consecutiveFailures >= 20) {
    return {
      provider,
      level: 'critical',
      numericLevel: 3,
      consecutiveFailures,
      streakHours,
      alertTitle: 'CRITICAL: Webhook Endpoint Offline',
      message: `Endpoint has reached 20 consecutive delivery failures. Upstream provider retries may be exhausted.`
    };
  }
  if (consecutiveFailures >= 10) {
    return {
      provider,
      level: 'danger',
      numericLevel: 2,
      consecutiveFailures,
      streakHours,
      alertTitle: 'DANGER: Webhook Delivery Failing',
      message: `Endpoint has reached 10 consecutive delivery failures.`
    };
  }
  if (consecutiveFailures >= 5) {
    return {
      provider,
      level: 'warning',
      numericLevel: 1,
      consecutiveFailures,
      streakHours,
      alertTitle: 'WARNING: Webhook Delivery Errors',
      message: `Endpoint has reached 5 consecutive delivery failures.`
    };
  }

  return {
    provider,
    level: 'healthy',
    numericLevel: 0,
    consecutiveFailures,
    streakHours,
    message: `${consecutiveFailures} transient failure(s).`
  };
}

module.exports = {
  assessDisablementRisk
};
