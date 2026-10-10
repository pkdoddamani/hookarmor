const http = require('http');
const https = require('https');
const { checkUrl, guardedLookup } = require('./netguard');

class Alerter {
  static async _dispatchPost(alertWebhookUrl, payload, strictSSRF = false) {
    try {
      const url = new URL(alertWebhookUrl);
      const isHttps = url.protocol === 'https:';
      const client = isHttps ? https : http;

      const postData = JSON.stringify(payload);
      const req = client.request(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        },
        timeout: 5000,
        lookup: guardedLookup(strictSSRF)
      }, (res) => res.resume());

      req.on('timeout', () => req.destroy(new Error('Alert webhook timed out')));
      req.on('error', (err) => {
        console.error('[Alerter] Failed to send alert webhook:', err.message);
      });

      req.write(postData);
      req.end();
    } catch (err) {
      console.error('[Alerter] Error parsing alert webhook URL:', err.message);
    }
  }

  static async sendAlert(alertWebhookUrl, { event, endpoint, attempt }, { strictSSRF = false } = {}) {
    if (!alertWebhookUrl) return;

    const check = checkUrl(alertWebhookUrl, strictSSRF);
    if (!check.ok) {
      console.error(`[Alerter] Alert webhook URL blocked: ${check.reason}`);
      return;
    }

    const payload = {
      text: `🚨 [HookArmor Alert] Webhook delivery failed for endpoint: ${endpoint.name}`,
      attachments: [
        {
          color: '#e02424',
          title: `Event: ${event.event_type || 'Unknown'} (${event.id})`,
          fields: [
            { title: 'Endpoint', value: endpoint.name, short: true },
            { title: 'Target URL', value: endpoint.target_url, short: true },
            { title: 'Status Code', value: String(attempt.statusCode || 'Timeout/Error'), short: true },
            { title: 'Attempt', value: `${event.attempts + 1} / ${endpoint.max_retries}`, short: true },
            { title: 'Error', value: attempt.errorMessage || 'Unknown error', short: false }
          ],
          footer: 'HookArmor Webhook Sentinel',
          ts: Math.floor(Date.now() / 1000)
        }
      ],
      embeds: [
        {
          title: `🚨 Webhook Delivery Failed: ${endpoint.name}`,
          description: `**Event:** \`${event.event_type || event.id}\`\n**Target:** \`${endpoint.target_url}\`\n**HTTP Status:** \`${attempt.statusCode || 'Error'}\`\n**Error:** ${attempt.errorMessage || 'No response'}`,
          color: 14689316,
          timestamp: new Date().toISOString()
        }
      ]
    };

    return Alerter._dispatchPost(alertWebhookUrl, payload, strictSSRF);
  }

  static async sendDisablementAlert(alertWebhookUrl, { endpoint, risk }, { strictSSRF = false } = {}) {
    if (!alertWebhookUrl) return;

    const check = checkUrl(alertWebhookUrl, strictSSRF);
    if (!check.ok) {
      console.error(`[Alerter] Alert webhook URL blocked: ${check.reason}`);
      return;
    }

    const isCritical = risk.level === 'critical';
    const color = isCritical ? '#dc2626' : (risk.level === 'danger' ? '#ea580c' : '#eab308');
    const discordColor = isCritical ? 14427686 : (risk.level === 'danger' ? 15358988 : 15381256);

    const payload = {
      text: `🚨 [HookArmor Sentinel] ${risk.alertTitle}: ${endpoint.name}`,
      attachments: [
        {
          color,
          title: risk.alertTitle,
          text: risk.message,
          fields: [
            { title: 'Endpoint', value: `${endpoint.name} (${endpoint.id})`, short: true },
            { title: 'Provider', value: (risk.provider || 'generic').toUpperCase(), short: true },
            { title: 'Consecutive Failures', value: `${risk.consecutiveFailures}`, short: true },
            { title: 'Cutoff Policy', value: risk.cutoff ? `${risk.cutoff} failures (Remaining: ${risk.remaining})` : (risk.cutoffHours ? `24h (Remaining: ~${risk.hoursRemaining}h)` : 'Retries failing'), short: true },
            { title: 'Target Destination', value: endpoint.target_url, short: false }
          ],
          footer: 'HookArmor Disablement Sentinel',
          ts: Math.floor(Date.now() / 1000)
        }
      ],
      embeds: [
        {
          title: `🚨 ${risk.alertTitle}`,
          description: `**${risk.message}**\n\n• **Endpoint:** \`${endpoint.name}\` (\`${endpoint.id}\`)\n• **Provider:** \`${(risk.provider || 'generic').toUpperCase()}\`\n• **Consecutive Failures:** \`${risk.consecutiveFailures}\`\n• **Target:** \`${endpoint.target_url}\``,
          color: discordColor,
          timestamp: new Date().toISOString()
        }
      ]
    };

    return Alerter._dispatchPost(alertWebhookUrl, payload, strictSSRF);
  }

  static async sendRecoveryAlert(alertWebhookUrl, { endpoint }, { strictSSRF = false } = {}) {
    if (!alertWebhookUrl) return;

    const check = checkUrl(alertWebhookUrl, strictSSRF);
    if (!check.ok) return;

    const payload = {
      text: `✅ [HookArmor Sentinel] Endpoint recovered: ${endpoint.name} is back online!`,
      attachments: [
        {
          color: '#16a34a',
          title: `Endpoint Recovered: ${endpoint.name}`,
          text: `Webhook deliveries to ${endpoint.target_url} are succeeding (HTTP 200 OK). Failure streak cleared.`,
          footer: 'HookArmor Disablement Sentinel',
          ts: Math.floor(Date.now() / 1000)
        }
      ],
      embeds: [
        {
          title: `✅ Endpoint Recovered: ${endpoint.name}`,
          description: `Deliveries to \`${endpoint.target_url}\` are succeeding again (HTTP 200 OK). Consecutive failure counter has been reset to 0.`,
          color: 1483690,
          timestamp: new Date().toISOString()
        }
      ]
    };

    return Alerter._dispatchPost(alertWebhookUrl, payload, strictSSRF);
  }
}

module.exports = Alerter;
