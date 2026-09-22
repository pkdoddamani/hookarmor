const http = require('http');
const https = require('https');

class Alerter {
  static async sendAlert(alertWebhookUrl, { event, endpoint, attempt }) {
    if (!alertWebhookUrl) return;

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
      // Discord-compatible embed
      embeds: [
        {
          title: `🚨 Webhook Delivery Failed: ${endpoint.name}`,
          description: `**Event:** \`${event.event_type || event.id}\`\n**Target:** \`${endpoint.target_url}\`\n**HTTP Status:** \`${attempt.statusCode || 'Error'}\`\n**Error:** ${attempt.errorMessage || 'No response'}`,
          color: 14689316,
          timestamp: new Date().toISOString()
        }
      ]
    };

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
        timeout: 5000
      });

      req.on('error', (err) => {
        console.error('[Alerter] Failed to send alert webhook:', err.message);
      });

      req.write(postData);
      req.end();
    } catch (err) {
      console.error('[Alerter] Error parsing alert webhook URL:', err.message);
    }
  }
}

module.exports = Alerter;
