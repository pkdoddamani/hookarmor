#!/usr/bin/env node

const { Command } = require('commander');
const chalk = require('chalk');
const { createServer } = require('../src/server');
const http = require('http');

const program = new Command();

program
  .name('hookarmor')
  .description('🛡️ HookArmor: Webhook Dead-Letter Queue & Replay Sentinel')
  .version('1.0.0');

program
  .command('start')
  .description('Start HookArmor server with web dashboard and ingress proxy')
  .option('-p, --port <number>', 'Port to listen on', '4000')
  .action((options) => {
    const port = parseInt(options.port, 10);
    const { server, storage } = createServer();

    // Ensure a default mock endpoint exists for first-time onboarding
    const defaultEp = storage.getEndpoint('demo-stripe');
    if (!defaultEp) {
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
      console.log(chalk.bold.blue('\n🛡️  HookArmor Webhook Sentinel is LIVE!'));
      console.log(chalk.gray('─────────────────────────────────────────'));
      console.log(`📡 Ingress Gateway : ${chalk.cyan(`http://localhost:${port}/in/:endpointId`)}`);
      console.log(`📊 Web Dashboard   : ${chalk.green.bold(`http://localhost:${port}`)}`);
      console.log(`⚙️  Mock Receiver  : ${chalk.yellow(`http://localhost:${port}/mock/target`)}`);
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
  .action(async (targetUrl, options) => {
    const port = parseInt(options.port, 10);
    const { server, storage, dispatcher } = createServer();

    storage.createEndpoint({
      id: options.endpoint,
      name: `Local Tunnel -> ${targetUrl}`,
      targetUrl,
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
      console.log(chalk.bold.cyan(`\n⚡ HookArmor Listen Active`));
      console.log(`Forwarding: ${chalk.yellow(`http://localhost:${port}/in/${options.endpoint}`)} ➔ ${chalk.green(targetUrl)}`);
      console.log(`Dashboard:  ${chalk.cyan(`http://localhost:${port}`)}\n`);
    });
  });

program
  .command('replay')
  .description('Replay dead-letter events from terminal')
  .argument('[eventId]', 'Specific event ID to replay')
  .option('--failed', 'Replay all failed events')
  .option('-u, --url <url>', 'HookArmor server URL', 'http://localhost:4000')
  .action(async (eventId, options) => {
    const baseUrl = options.url.replace(/\/$/, '');
    try {
      if (options.failed || !eventId) {
        console.log(chalk.yellow('🔄 Replaying all dead-letter events...'));
        const res = await fetch(`${baseUrl}/api/events/replay-all`, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
        const data = await res.json();
        console.log(chalk.green(`✅ Dispatched replay for ${data.replayedCount} events.`));
      } else {
        console.log(chalk.yellow(`🔄 Replaying event ${eventId}...`));
        const res = await fetch(`${baseUrl}/api/events/${eventId}/replay`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
          console.log(chalk.green(`✅ Replay successful: HTTP ${data.statusCode} (${data.latencyMs}ms)`));
        } else {
          console.log(chalk.red(`❌ Replay failed: HTTP ${data.statusCode} (${data.errorMessage || 'Target rejected'})`));
        }
      }
    } catch (err) {
      console.error(chalk.red(`Failed to connect to HookArmor at ${baseUrl}: ${err.message}`));
    }
  });

program
  .command('status')
  .description('Check HookArmor metrics and dead-letter queue count')
  .option('-u, --url <url>', 'HookArmor server URL', 'http://localhost:4000')
  .action(async (options) => {
    const baseUrl = options.url.replace(/\/$/, '');
    try {
      const res = await fetch(`${baseUrl}/api/stats`);
      const data = await res.json();
      console.log(chalk.bold.blue('\n🛡️  HookArmor Metrics'));
      console.log(chalk.gray('───────────────────────'));
      console.log(`Total Ingested : ${chalk.cyan(data.total)}`);
      console.log(`Delivered      : ${chalk.green(data.delivered)}`);
      console.log(`Dead-Letter    : ${chalk.red(data.failed)}`);
      console.log(`Pending        : ${chalk.yellow(data.pending)}`);
      console.log(`Avg Latency    : ${chalk.white(`${data.avgLatencyMs} ms`)}\n`);
    } catch (err) {
      console.error(chalk.red(`Failed to connect to HookArmor at ${baseUrl}: ${err.message}`));
    }
  });

program.parse();
