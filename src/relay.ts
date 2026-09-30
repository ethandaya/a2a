import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { openDatabase } from './store.ts';
import { BATCH, MAX_BODY, packetSchema, readLimited, tokenSchema } from './wire.ts';

export async function startRelay(directory: string, token: string, port = 8787, host = '127.0.0.1') {
  tokenSchema.parse(token);
  const expected = createHash('sha256').update(`Bearer ${token}`).digest();
  const db = openDatabase(directory, 'relay.sqlite');
  db.exec(`CREATE TABLE IF NOT EXISTS messages (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL, id TEXT NOT NULL,
    type INTEGER NOT NULL, body TEXT NOT NULL, UNIQUE(recipient, id)
  )`);
  const server = createServer({ requestTimeout: 10000, headersTimeout: 10000, maxHeaderSize: 8192 }, async (req, res) => {
    res.setHeader('cache-control', 'no-store');
    res.setHeader('content-type', 'application/json');
    res.setHeader('x-content-type-options', 'nosniff');
    const end = (status: number, body?: unknown) => { res.writeHead(status); res.end(body === undefined ? undefined : JSON.stringify(body)); };
    const actual = createHash('sha256').update(req.headers.authorization ?? '').digest();
    if (req.headers.origin !== undefined) { end(403); return; }
    if (!timingSafeEqual(expected, actual)) { end(401); return; }
    const match = /^\/v1\/messages\/([a-f0-9]{64})(?:\/([a-f0-9-]{36}))?$/.exec(req.url ?? '');
    if (!match) { end(404); return; }
    const recipient = match[1]!;
    const id = match[2];
    try {
      if (req.method === 'GET' && !id) {
        end(200, db.prepare('SELECT id, type, body FROM messages WHERE recipient = ? ORDER BY seq LIMIT ?').all(recipient, BATCH));
      } else if (req.method === 'PUT' && id) {
        if (req.headers['content-type'] !== 'application/json') { end(415); return; }
        const parsed = packetSchema.safeParse(JSON.parse(await readLimited(req, MAX_BODY)));
        if (!parsed.success || parsed.data.id !== id) { end(400); return; }
        const packet = parsed.data;
        const existing = db.prepare('SELECT type, body FROM messages WHERE recipient = ? AND id = ?').get(recipient, id);
        if (existing) { end(existing.type === packet.type && existing.body === packet.body ? 204 : 409); return; }
        if (Number(db.prepare('SELECT COUNT(*) AS n FROM messages').get()!.n) >= 1000) { end(507); return; }
        db.prepare('INSERT INTO messages (recipient, id, type, body) VALUES (?, ?, ?, ?)').run(recipient, id, packet.type, packet.body);
        end(204);
      } else if (req.method === 'DELETE' && id) {
        db.prepare('DELETE FROM messages WHERE recipient = ? AND id = ?').run(recipient, id);
        end(204);
      } else {
        end(405);
      }
    } catch {
      end(400);
    }
  });
  server.maxConnections = 64;
  server.listen(port, host);
  try { await once(server, 'listening'); } catch (error) { db.close(); throw error; }
  return {
    server,
    async close() {
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      db.close();
    },
  };
}
