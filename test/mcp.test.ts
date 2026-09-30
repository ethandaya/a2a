import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import type { AddressInfo } from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';
import { startRelay } from '../src/relay.ts';
import { inviteSchema } from '../src/wire.ts';

test('built CLI pairing and two real stdio MCP processes exchange messages and survive reconnect', async t => {
  const root = mkdtempSync(join(tmpdir(), 'a2a-mcp-'));
  const token = randomBytes(32).toString('hex');
  const tokenFile = join(root, 'token');
  writeFileSync(tokenFile, token, { mode: 0o600 });
  const relay = await startRelay(join(root, 'relay'), token, 0);
  const port = (relay.server.address() as AddressInfo).port;
  const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const clients: Client[] = [];
  t.after(async () => {
    for (const client of clients) await client.close();
    await relay.close();
    rmSync(root, { recursive: true, force: true });
  });
  const run = (...args: string[]) => execFileSync(process.execPath, [cli, ...args], { encoding: 'utf8', stdio: 'pipe', timeout: 10000 });
  const alice = join(root, 'alice');
  const bob = join(root, 'bob');
  assert.match(run('--help'), /Signal-encrypted/);
  assert.match(run('init', '--data', alice, '--relay', `http://127.0.0.1:${port}`, '--token-file', tokenFile), /Share privately:/);
  const invitation = inviteSchema.parse(JSON.parse(readFileSync(join(alice, 'invite.json'), 'utf8')));
  const invalidFile = join(root, 'invalid.json');
  for (const field of ['signature', 'kyberSignature']) {
    writeFileSync(invalidFile, JSON.stringify({
      ...invitation, relay: 'https://rejected.example', token: randomBytes(32).toString('hex'),
      [field]: Buffer.alloc(64).toString('base64'),
    }), { mode: 0o600 });
    assert.throws(() => run('join', '--data', bob, '--invite', invalidFile), /Invalid invitation signatures/);
    assert.deepEqual(JSON.parse(run('status', '--data', bob)), { initialized: false, paired: false, queued: 0, received: 0 });
  }
  assert.match(run('join', '--data', bob, '--invite', join(alice, 'invite.json')), /"paired": true/);
  assert.match(run('pair', '--data', alice, '--invite', join(bob, 'invite.json')), /"paired": true/);
  assert.equal(readFileSync(join(alice, 'invite.json'), 'utf8').includes('private'), false);

  async function connect(directory: string) {
    const client = new Client({ name: 'test-agent', version: '1.0.0' });
    clients.push(client);
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [cli, 'mcp', '--data', directory], stderr: 'pipe' }));
    return client;
  }
  const a = await connect(alice);
  const b = await connect(bob);
  assert.deepEqual((await a.listTools()).tools.map(tool => tool.name).sort(), ['invite', 'pair', 'receive', 'send', 'status']);

  async function call(client: Client, name: string, args = {}) {
    const result = CallToolResultSchema.parse(await client.callTool({ name, arguments: args }));
    assert.notEqual(result.isError, true);
    const block = result.content[0];
    assert.ok(block && block.type === 'text');
    return JSON.parse(block.text);
  }
  const text = 'Why does case 27 fail only on arm64?\0café 🧪';
  const sent = await call(a, 'send', { request_id: 'investigate-1', text });
  assert.equal(sent.delivery, 'relayed');
  const inbox = await call(b, 'receive');
  assert.deepEqual(inbox.messages, [{ cursor: 1, id: sent.id, text }]);
  const truncatedRetry = await a.callTool({ name: 'send', arguments: { request_id: 'investigate-1', text: text.split('\0')[0] } });
  assert.equal(truncatedRetry.isError, true);
  await call(b, 'send', { request_id: 'answer-1', text: 'The signed shift is the difference.' });
  assert.equal((await call(a, 'receive')).messages[0].text, 'The signed shift is the difference.');
  assert.equal((await call(a, 'status')).fingerprint, (await call(b, 'status')).fingerprint);
  const invalid = await a.callTool({ name: 'send', arguments: { request_id: 'bad', text: '' } });
  assert.equal(invalid.isError, true);
  const unknown = await a.callTool({ name: 'replace_peer', arguments: {} });
  assert.equal(unknown.isError, true);
  await b.close();
  const restarted = await connect(bob);
  assert.deepEqual((await call(restarted, 'receive')).messages, inbox.messages);
  assert.equal((await call(restarted, 'receive', { after: inbox.cursor })).messages.length, 0);
  assert.equal((await call(a, 'send', { request_id: 'investigate-1', text })).id, sent.id);
});

test('TypeScript CLI pairs fresh MCP clients without fetching links and survives reconnect', async t => {
  const root = mkdtempSync(join(tmpdir(), 'a2a-pairing-'));
  const token = randomBytes(32).toString('hex');
  const tokenFile = join(root, 'token');
  writeFileSync(tokenFile, token, { mode: 0o600 });
  const relay = await startRelay(join(root, 'relay'), token, 0);
  const origin = `http://127.0.0.1:${(relay.server.address() as AddressInfo).port}`;
  const requests: string[] = [];
  relay.server.on('request', request => requests.push(request.url!));
  const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
  const clients: Client[] = [];
  t.after(async () => {
    for (const client of clients) await client.close();
    await relay.close();
    rmSync(root, { recursive: true, force: true });
  });
  const alice = join(root, 'alice');
  const bob = join(root, 'bob');
  execFileSync(process.execPath, [cli, 'init', '--data', alice, '--relay', origin, '--token-file', tokenFile], { timeout: 10000 });
  async function connect(directory: string) {
    const client = new Client({ name: 'pairing-test', version: '1.0.0' });
    clients.push(client);
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [cli, 'mcp', '--data', directory], stderr: 'pipe' }));
    return client;
  }
  async function call(client: Client, name: string, args = {}) {
    const result = CallToolResultSchema.parse(await client.callTool({ name, arguments: args }));
    assert.notEqual(result.isError, true);
    const block = result.content[0];
    assert.ok(block && block.type === 'text');
    return JSON.parse(block.text);
  }
  const a = await connect(alice);
  const b = await connect(bob);
  assert.match(a.getInstructions() ?? '', /intended peer through a trusted private channel/);
  assert.match(a.getInstructions() ?? '', /manual fingerprint comparison is optional/);
  const pairTool = (await a.listTools()).tools.find(tool => tool.name === 'pair');
  assert.match(pairTool?.description ?? '', /trusted private channel/);
  assert.match(pairTool?.description ?? '', /if our invitation has not already been shared/);
  assert.doesNotMatch(pairTool?.description ?? '', /fingerprint/i);
  assert.deepEqual(await call(b, 'status'), { initialized: false, paired: false, queued: 0, received: 0 });
  assert.equal((await b.callTool({ name: 'invite', arguments: {} })).isError, true);
  assert.equal((await a.callTool({ name: 'send', arguments: { request_id: 'early', text: 'not paired' } })).isError, true);

  const invitation = await call(a, 'invite');
  assert.equal(invitation.relay, origin);
  assert.equal(new URL(invitation.link).origin, origin);
  assert.ok(invitation.prompt.includes(invitation.link));
  assert.match(invitation.prompt, /intended person through a trusted private channel/);
  assert.match(invitation.prompt, /If we have not already shared our invitation.*same trusted private channel/);
  assert.doesNotMatch(invitation.prompt, /fingerprint/i);
  assert.deepEqual(await call(a, 'invite'), invitation);
  assert.equal((await a.callTool({ name: 'pair', arguments: { link: invitation.link } })).isError, true);
  assert.equal((await call(a, 'status')).paired, false);
  assert.equal((await b.callTool({ name: 'pair', arguments: { link: `${origin}/#a2a=invalid` } })).isError, true);
  assert.equal((await call(b, 'status')).initialized, false);

  const reply = await call(b, 'pair', { link: invitation.link });
  assert.equal(reply.initialized, true);
  assert.equal(reply.paired, true);
  assert.equal(reply.relay, origin);
  assert.ok(reply.prompt.includes(reply.link));
  assert.match(reply.prompt, /intended person through a trusted private channel/);
  assert.doesNotMatch(reply.prompt, /fingerprint/i);
  assert.equal((await call(a, 'status')).paired, false);
  const paired = await call(a, 'pair', { link: reply.link });
  assert.equal(paired.fingerprint, reply.fingerprint);
  assert.equal(paired.peer, reply.identity);
  assert.equal(reply.peer, paired.identity);
  assert.deepEqual(await call(a, 'pair', { link: reply.link }), paired);
  assert.equal(requests.length, 0);

  await b.close();
  const restarted = await connect(bob);
  assert.equal((await call(restarted, 'status')).fingerprint, paired.fingerprint);
  assert.equal((await call(restarted, 'invite')).link, reply.link);
  const sent = await call(a, 'send', { request_id: 'pasted-1', text: 'Paired using two pasted prompts.' });
  assert.equal(sent.delivery, 'relayed');
  assert.deepEqual((await call(restarted, 'receive')).messages, [{ cursor: 1, id: sent.id, text: 'Paired using two pasted prompts.' }]);
  await call(restarted, 'send', { request_id: 'reply-1', text: 'Ready to discuss the rounding bug.' });
  assert.equal((await call(a, 'receive')).messages[0].text, 'Ready to discuss the rounding bug.');
  assert.ok(requests.length > 0);
  assert.ok(requests.every(path => !path.includes('#') && !path.includes(token)));
});
