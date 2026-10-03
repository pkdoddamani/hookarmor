#!/usr/bin/env node

const { Command } = require('commander');
const _chalk = require('chalk');
const chalk = _chalk.default || _chalk;
const { createServer } = require('../src/server');

const program = new Command();

program
  .name('hookarmor')
  .description('🛡️ HookArmor: Webhook Dead-Letter Queue & Replay Sentinel')
  .version(require('../package.json').version);

// Build the server, exiting with a readable message on configuration errors
function startServerOrExit() {
  try {
    return createServer();
  } catch (err) {
    console.error(chalk.red.bold(`\n✖ HookArmor could not start: ${err.message}\n`));
    process.exit(1);
  }
}

function apiHeaders(apiKey) {
  const headers = { 'Content-Type': 'application/json' };
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
  return headers;
}

async function readJson(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const hint = res.status === 401 ? ' (pass --api-key or set HOOKARMOR_API_KEY)' : '';
    throw new Error(`${data.error || `HTTP ${res.status}`}${hint}`);
  }
  return data;
}

program
  .command('start')
  .description('Start HookArmor server with web dashboard and ingress proxy')
  .option('-p, --port <number>', 'Port to listen on', process.env.PORT || '4000')
  .action((options) => {
    const port = parseInt(options.port, 10);
    const { server, storage, mockEnabled } = startServerOrExit();

    // Ensure a default mock endpoint exists for first-time onboarding (local simulation only)
    if (mockEnabled && !storage.getEndpoint('demo-stripe')) {
      storage.createEndpoint({
        id: 'demo-stripe',
        name: 'Stripe Payments Demo',
        targetUrl: `http://localhost:${port}/mock/target`,
        alertWebhookUrl: '',
        autoRetry: 1,
        maxRetries: 5
      });
    }

    server.listen(port, () => {
      console.log(chalk.blue.bold('\n🛡️  HookArmor Webhook Sentinel is LIVE!'));
      console.log(chalk.gray('─────────────────────────────────────────'));
      console.log(`📡 Ingress Gateway : ${chalk.cyan(`http://localhost:${port}/in/:endpointId`)}`);
      console.log(`📊 Web Dashboard   : ${chalk.green.bold(`http://localhost:${port}/dashboard`)}`);
      if (mockEnabled) {
        console.log(`⚙️  Mock Receiver  : ${chalk.yellow(`http://localhost:${port}/mock/target`)}`);
      }
      console.log(chalk.gray('─────────────────────────────────────────'));
      console.log(chalk.white('Press Ctrl+C to stop.\n'));
    });
  });

program
  .command('listen')
  .description('Tunnel incoming webhooks directly to a local or remote target')
  .argument('<targetUrl>', 'Destination target URL (e.g. http://localhost:3000/api/webhook)')
  .option('-p, --port <number>', 'Proxy port', '4000')
  .option('-e, --endpoint <id>', 'Endpoint ID slug', 'local-dev')
  .option('-s, --secret <secret>', 'Provider signing secret: verify on ingress and re-sign on delivery')
  .action(async (targetUrl, options) => {
    const port = parseInt(options.port, 10);
    const { server, storage, dispatcher } = startServerOrExit();

    storage.createEndpoint({
      id: options.endpoint,
      name: `Local Tunnel -> ${targetUrl}`,
      targetUrl,
      secret: options.secret,
      autoRetry: 1,
      maxRetries: 5
    });

    dispatcher.on('delivery', (res) => {
      const statusStr = res.success
        ? chalk.green.bold(`[${res.statusCode}] DELIVERED`)
        : chalk.red.bold(`[${res.statusCode || 'ERR'}] DEAD-LETTER`);
      console.log(`[${new Date().toLocaleTimeString()}] ${statusStr} ${res.eventId} -> ${targetUrl} (${res.latencyMs}ms)`);
      if (!res.success && res.errorMessage) {
        console.log(chalk.red(`   └─ Error: ${res.errorMessage}`));
      }
    });

    server.listen(port, () => {
      console.log(chalk.cyan.bold(`\n⚡ HookArmor Listen Active`));
      console.log(`Forwarding: ${chalk.yellow(`http://localhost:${port}/in/${options.endpoint}`)} ➔ ${chalk.green(targetUrl)}`);
      console.log(`Dashboard:  ${chalk.cyan(`http://localhost:${port}/dashboard`)}\n`);
    });
  });

program
  .command('replay')
  .description('Replay dead-letter events from terminal')
  .argument('[eventId]', 'Specific event ID to replay')
  .option('--failed', 'Replay all failed events (including ones that used up their automatic retries)')
  .option('-u, --url <url>', 'HookArmor server URL', 'http://localhost:4000')
  .option('-k, --api-key <key>', 'Admin API key (default: HOOKARMOR_API_KEY)', process.env.HOOKARMOR_API_KEY)
  .action(async (eventId, options) => {
    const baseUrl = options.url.replace(/\/$/, '');
    try {
      if (options.failed || !eventId) {
        console.log(chalk.yellow('🔄 Replaying all dead-letter events...'));
        const res = await fetch(`${baseUrl}/api/events/replay-all`, { method: 'POST', headers: apiHeaders(options.apiKey), body: '{}' });
        const data = await readJson(res);
        console.log(chalk.green(`✅ Dispatched replay for ${data.replayedCount} events.`));
        if (data.remaining > 0) {
          console.log(chalk.yellow(`   ${data.remaining} failed events still queued; run the command again to continue.`));
        }
      } else {
        console.log(chalk.yellow(`🔄 Replaying event ${eventId}...`));
        const res = await fetch(`${baseUrl}/api/events/${encodeURIComponent(eventId)}/replay`, { method: 'POST', headers: apiHeaders(options.apiKey), body: '{}' });
        const data = await readJson(res);
        if (data.success) {
          console.log(chalk.green(`✅ Replay successful: HTTP ${data.statusCode} (${data.latencyMs}ms)`));
        } else {
          console.log(chalk.red(`❌ Replay failed: HTTP ${data.statusCode} (${data.errorMessage || 'Target rejected'})`));
          process.exitCode = 1;
        }
      }
    } catch (err) {
      console.error(chalk.red(`Replay request to ${baseUrl} failed: ${err.message}`));
      process.exitCode = 1;
    }
  });

program
  .command('status')
  .description('Check HookArmor metrics and dead-letter queue count')
  .option('-u, --url <url>', 'HookArmor server URL', 'http://localhost:4000')
  .option('-k, --api-key <key>', 'Admin API key (default: HOOKARMOR_API_KEY)', process.env.HOOKARMOR_API_KEY)
  .action(async (options) => {
    const baseUrl = options.url.replace(/\/$/, '');
    try {
      const res = await fetch(`${baseUrl}/api/stats`, { headers: apiHeaders(options.apiKey) });
      const data = await readJson(res);
      console.log(chalk.blue.bold('\n🛡️  HookArmor Metrics'));
      console.log(chalk.gray('───────────────────────'));
      console.log(`Total Ingested : ${chalk.cyan(data.total)}`);
      console.log(`Delivered      : ${chalk.green(data.delivered)}`);
      console.log(`Dead-Letter    : ${chalk.red(data.failed)}`);
      console.log(`Pending        : ${chalk.yellow(data.pending)}`);
      console.log(`Avg Latency    : ${chalk.white(`${data.avgLatencyMs} ms`)}\n`);
    } catch (err) {
      console.error(chalk.red(`Status request to ${baseUrl} failed: ${err.message}`));
      process.exitCode = 1;
    }
  });

program.parse();
