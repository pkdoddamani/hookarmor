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

function setupGracefulShutdown(server, dispatcher, storage, instanceId) {
  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(chalk.yellow(`\n⏻  ${signal} received: stopping incoming traffic and draining in-flight webhooks...`));
    server.close();
    if (dispatcher && dispatcher.drain) {
      const clean = await dispatcher.drain(15000);
      if (!clean) {
        console.warn(chalk.yellow(`⚠️  Drain timed out with ${dispatcher.pendingDeliveries()} deliveries still pending.`));
      }
    }
    if (storage) {
      try {
        if (instanceId) {
          storage.releaseClaimsOwnedBy(instanceId);
          storage.deregisterInstance(instanceId);
        }
        if (storage.db) {
          storage.db.pragma('wal_checkpoint(TRUNCATE)');
        }
      } catch (_) {}
    }
    console.log(chalk.green('✔  Shutdown complete.'));
    process.exit(0);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
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
  .option('-H, --host <host>', 'Host address to bind to', process.env.HOOKARMOR_HOST || process.env.HOST || (process.env.HOOKARMOR_API_KEY || process.env.NODE_ENV === 'production' ? '0.0.0.0' : '127.0.0.1'))
  .action((options) => {
    const port = parseInt(options.port, 10);
    const host = options.host;
    const { server, storage, dispatcher, mockEnabled, instanceId } = startServerOrExit();
    setupGracefulShutdown(server, dispatcher, storage, instanceId);

    // Ensure a default mock endpoint exists for first-time onboarding (local simulation only)
    if (mockEnabled && !storage.getEndpoint('demo-stripe')) {
      storage.createEndpoint({
        id: 'demo-stripe',
        name: 'Stripe Payments Demo',
        targetUrl: `http://localhost:${port}/mock/target`,
        provider: 'stripe',
        alertWebhookUrl: '',
        autoRetry: 1,
        maxRetries: 5
      });
    }

    server.listen(port, host, () => {
      console.log(chalk.blue.bold('\n🛡️  HookArmor Webhook Sentinel is LIVE!'));
      console.log(chalk.gray('─────────────────────────────────────────'));
      const displayHost = (host === '0.0.0.0' || host === '127.0.0.1') ? 'localhost' : host;
      console.log(`📡 Ingress Gateway : ${chalk.cyan(`http://${displayHost}:${port}/in/:endpointId`)}`);
      console.log(`📊 Web Dashboard   : ${chalk.green.bold(`http://${displayHost}:${port}/dashboard`)}`);
      if (mockEnabled) {
        console.log(`⚙️  Mock Receiver  : ${chalk.yellow(`http://${displayHost}:${port}/mock/target`)}`);
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
  .option('-H, --host <host>', 'Host address to bind to', '127.0.0.1')
  .option('-e, --endpoint <id>', 'Endpoint ID slug', 'local-dev')
  .option('-s, --secret <secret>', 'Provider signing secret: verify on ingress and re-sign on delivery')
  .action(async (targetUrl, options) => {
    const port = parseInt(options.port, 10);
    const host = options.host || '127.0.0.1';
    if (host === '0.0.0.0') {
      console.warn(chalk.yellow('\n[Security Warning] hookarmor listen is bound to 0.0.0.0 — reachable by anyone on your local network. Use 127.0.0.1 for local isolation.'));
    }
    const { server, storage, dispatcher, instanceId } = startServerOrExit();
    setupGracefulShutdown(server, dispatcher, storage, instanceId);

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

    server.listen(port, host, () => {
      console.log(chalk.cyan.bold(`\n⚡ HookArmor Listen Active`));
      console.log(`Forwarding: ${chalk.yellow(`http://${host}:${port}/in/${options.endpoint}`)} ➔ ${chalk.green(targetUrl)}`);
      console.log(`Dashboard:  ${chalk.cyan(`http://${host}:${port}/dashboard`)}\n`);
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
      if (options.failed) {
        console.log(chalk.yellow('🔄 Replaying all dead-letter events...'));
        const res = await fetch(`${baseUrl}/api/events/replay-all`, { method: 'POST', headers: apiHeaders(options.apiKey), body: '{}' });
        const data = await readJson(res);
        console.log(chalk.green(`✅ Dispatched replay for ${data.replayedCount} events.`));
        if (data.remaining > 0) {
          console.log(chalk.yellow(`   ${data.remaining} failed events still queued; run the command again to continue.`));
        }
      } else if (eventId) {
        console.log(chalk.yellow(`🔄 Replaying event ${eventId}...`));
        const res = await fetch(`${baseUrl}/api/events/${encodeURIComponent(eventId)}/replay`, { method: 'POST', headers: apiHeaders(options.apiKey), body: '{}' });
        const data = await readJson(res);
        if (data.success) {
          console.log(chalk.green(`✅ Replay successful: HTTP ${data.statusCode} (${data.latencyMs}ms)`));
        } else {
          console.log(chalk.red(`❌ Replay failed: HTTP ${data.statusCode} (${data.errorMessage || 'Target rejected'})`));
          process.exitCode = 1;
        }
      } else {
        console.error(chalk.red('✖ Missing argument: specify an [eventId] or pass --failed to replay all dead-letter events.'));
        console.log(chalk.gray('  Usage: hookarmor replay <eventId>  OR  hookarmor replay --failed\n'));
        process.exitCode = 1;
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

const endpointsCmd = program
  .command('endpoints')
  .description('Manage webhook endpoints via CLI');

endpointsCmd
  .command('add')
  .description('Create or update an endpoint')
  .requiredOption('-i, --id <id>', 'Unique endpoint ID slug')
  .requiredOption('-t, --target <url>', 'Destination URL')
  .option('-n, --name <name>', 'Descriptive endpoint name')
  .option('-s, --secret <secret>', 'Provider signing secret')
  .option('-a, --alert <url>', 'Alert webhook URL')
  .option('--headers <json>', 'Custom destination headers JSON string')
  .option('--max-retries <num>', 'Maximum retry attempts', '5')
  .option('--concurrency <num>', 'Concurrency limit', '5')
  .option('-u, --url <url>', 'HookArmor server URL', 'http://localhost:4000')
  .option('-k, --api-key <key>', 'Admin API key', process.env.HOOKARMOR_API_KEY)
  .action(async (options) => {
    const baseUrl = options.url.replace(/\/$/, '');
    let customHeaders = {};
    if (options.headers) {
      try {
        customHeaders = JSON.parse(options.headers);
      } catch (e) {
        console.error(chalk.red(`--headers must be valid JSON: ${e.message}`));
        process.exitCode = 1;
        return;
      }
    }
    const payload = {
      id: options.id,
      name: options.name || options.id,
      targetUrl: options.target,
      secret: options.secret,
      alertWebhookUrl: options.alert,
      maxRetries: parseInt(options.maxRetries, 10),
      concurrencyLimit: parseInt(options.concurrency, 10),
      customHeaders
    };
    try {
      const res = await fetch(`${baseUrl}/api/endpoints`, {
        method: 'POST',
        headers: apiHeaders(options.apiKey),
        body: JSON.stringify(payload)
      });
      const data = await readJson(res);
      console.log(chalk.green(`✅ Endpoint '${data.id}' successfully saved -> ${data.target_url}`));
    } catch (err) {
      console.error(chalk.red(`Failed to save endpoint: ${err.message}`));
      process.exitCode = 1;
    }
  });

endpointsCmd
  .command('list')
  .description('List configured endpoints')
  .option('-u, --url <url>', 'HookArmor server URL', 'http://localhost:4000')
  .option('-k, --api-key <key>', 'Admin API key', process.env.HOOKARMOR_API_KEY)
  .action(async (options) => {
    const baseUrl = options.url.replace(/\/$/, '');
    try {
      const res = await fetch(`${baseUrl}/api/endpoints`, { headers: apiHeaders(options.apiKey) });
      const endpoints = await readJson(res);
      console.log(chalk.blue.bold(`\n🛡️  HookArmor Endpoints (${endpoints.length})`));
      console.log(chalk.gray('───────────────────────────────────────────────────────'));
      for (const ep of endpoints) {
        console.log(`• ${chalk.cyan.bold(ep.id)} (${ep.name})`);
        console.log(`  Target:  ${chalk.green(ep.target_url)}`);
        console.log(`  Secret:  ${ep.has_secret ? chalk.yellow('Configured (AES-256-GCM)') : chalk.gray('None')}`);
        if (ep.custom_headers && Object.keys(ep.custom_headers).length > 0) {
          console.log(`  Headers: ${chalk.gray(JSON.stringify(ep.custom_headers))}`);
        }
        console.log('');
      }
    } catch (err) {
      console.error(chalk.red(`Failed to list endpoints: ${err.message}`));
      process.exitCode = 1;
    }
  });

endpointsCmd
  .command('rm <id>')
  .description('Delete an endpoint and its events')
  .option('-u, --url <url>', 'HookArmor server URL', 'http://localhost:4000')
  .option('-k, --api-key <key>', 'Admin API key', process.env.HOOKARMOR_API_KEY)
  .action(async (id, options) => {
    const baseUrl = options.url.replace(/\/$/, '');
    try {
      const res = await fetch(`${baseUrl}/api/endpoints/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: apiHeaders(options.apiKey)
      });
      await readJson(res);
      console.log(chalk.green(`✅ Endpoint '${id}' and its history deleted.`));
    } catch (err) {
      console.error(chalk.red(`Failed to delete endpoint: ${err.message}`));
      process.exitCode = 1;
    }
  });

program.parse();
