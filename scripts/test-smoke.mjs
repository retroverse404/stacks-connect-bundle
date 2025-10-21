#!/usr/bin/env node
import { spawn } from 'child_process';
import { once } from 'events';

const port = process.env.PORT ?? '5173';
const baseUrl = `http://localhost:${port}`;
const pingUrl = `${baseUrl}/api/ping`;
const waitIntervalMs = Number.parseInt(process.env.SMOKE_WAIT_INTERVAL_MS ?? '500', 10);
const maxAttempts = Number.parseInt(process.env.SMOKE_MAX_ATTEMPTS ?? '30', 10);

let server;
let serverExit;
let serverLogs = '';

const startServer = () => {
  server = spawn('node', ['server/server.js'], {
    env: process.env,
    detached: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  server.stdout?.setEncoding('utf8');
  server.stdout?.on('data', (chunk) => {
    serverLogs += chunk;
    console.log('SERVER:', chunk.toString().trimEnd());
  });

  server.stderr?.setEncoding('utf8');
  server.stderr?.on('data', (chunk) => {
    serverLogs += chunk;
    console.error('SERVER ERR:', chunk.toString().trimEnd());
  });

  server.on('exit', (code, signal) => {
    serverExit = { code, signal };
  });

  server.on('error', (error) => {
    serverExit = { error };
  });
};

const stopServer = async () => {
  if (!server) return;
  try {
    server.kill('SIGTERM');
  } catch (error) {
    console.error('Failed to terminate server process', error);
  }

  if (!serverExit) {
    try {
      await once(server, 'exit');
    } catch (error) {
      console.error('Error while waiting for server exit', error);
    }
  }
};

const waitForServer = async () => {
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    if (serverExit) {
      throw new Error('Server exited before readiness check completed');
    }

    try {
      const res = await fetch(pingUrl, { cache: 'no-store' });
      if (res.ok) return true;
    } catch (error) {
      // ignore and retry
    }

    await new Promise((resolve) => setTimeout(resolve, waitIntervalMs));
  }

  throw new Error('Server never became ready');
};

const main = async () => {
  try {
    try {
      const res = await fetch(pingUrl, { cache: 'no-store' });
      if (res.ok) {
        console.log('Smoke: server already responding at /api/ping');
        return;
      }
    } catch (error) {
      // Server not running; proceed to start it
    }

    console.log('Smoke: starting server...');
    startServer();
    await waitForServer();
    console.log('Smoke: success');
  } catch (error) {
    console.error(error.message || error);
    if (serverLogs.trim()) {
      console.error('---- server logs ----');
      console.error(serverLogs.trimEnd());
      console.error('---------------------');
    }
    process.exitCode = 1;
  } finally {
    await stopServer();
  }
};

main().catch((error) => {
  console.error(error.message || error);
  process.exitCode = 1;
});
