#!/usr/bin/env node
import { createReadStream, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Client, initialize, pair } from './client.ts';
import { createMcpServer } from './mcp.ts';
import { startRelay } from './relay.ts';
import { MAX_BODY, invitationLink, inviteSchema, readLimited, tokenSchema } from './wire.ts';

const help = `a2a — one-to-one Signal-encrypted agent messages (AGPL-3.0-only)

  init   --relay <https-origin> --token-file <file> [--data <directory>]
  join   --invite <peer-invite.json> [--data <directory>]
  pair   --invite <peer-invite.json> [--data <directory>]
  status [--data <directory>]
  mcp    [--data <directory>]
  relay  --token-file <file> [--data <directory>] [--port 8787]

Exchange invitation files privately through an authenticated channel.
init/join write <data>/invite.json. Share that file only, never the database.
Use one fresh data directory per person per conversation.
Relay binds to loopback; put it behind an HTTPS reverse proxy or private tunnel.
Generate a token file with permissions 0600 containing 64 random hex characters.
See README.md for pairing, hosting, security boundaries, and source obligations.
`;

async function main() {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: {
    data: { type: 'string' }, relay: { type: 'string' }, 'token-file': { type: 'string' },
    invite: { type: 'string' }, port: { type: 'string' }, help: { type: 'boolean', short: 'h' },
  } });
  const command = positionals[0];
  if (values.help || !command) { console.log(help); return; }
  if (positionals.length !== 1 || !['init', 'join', 'pair', 'status', 'mcp', 'relay'].includes(command)) throw new Error('Unknown command; use --help');
  const directory = resolve(values.data ?? join(homedir(), '.a2a', command === 'relay' ? 'relay' : 'client'));
  const required = (name: 'relay' | 'token-file' | 'invite') => {
    const value = values[name];
    if (!value) throw new Error(`--${name} is required`);
    return value;
  };
  const readToken = async () => tokenSchema.parse((await readLimited(createReadStream(required('token-file')), 128)).trim());

  if (command === 'relay') {
    const port = Number(values.port ?? 8787);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
    const relay = await startRelay(directory, await readToken(), port);
    console.error(`Relay listening on loopback port ${port}; state: ${directory}`);
    const stop = () => { relay.close().then(() => process.exit(0), () => process.exit(1)); };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
    return;
  }

  const client = new Client(directory);
  if (command === 'mcp') {
    const server = createMcpServer(client);
    const stop = () => { server.close().then(() => client.close()).then(() => process.exit(0), () => process.exit(1)); };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
    process.stdin.once('end', stop);
    await server.connect(new StdioServerTransport());
    return;
  }

  try {
    if (command === 'init') await initialize(client.store, required('relay'), await readToken());
    if (command === 'join' || command === 'pair') {
      const peer = inviteSchema.parse(JSON.parse(await readLimited(createReadStream(required('invite')), MAX_BODY)));
      if (command === 'join') await client.acceptInvite(invitationLink(peer));
      else pair(client.store, peer);
    }
    if (command === 'init' || command === 'join') {
      const path = join(directory, 'invite.json');
      writeFileSync(path, JSON.stringify(client.store.local, null, 2) + '\n', { mode: 0o600, flag: 'w' });
      console.log(`Share privately: ${path}`);
    }
    console.log(JSON.stringify(await client.status(), null, 2));
  } finally {
    await client.close();
  }
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : 'Command failed');
  process.exitCode = 1;
});
