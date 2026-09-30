import { createHash } from 'node:crypto';
import { z } from 'zod';

// 16 KiB text can expand to 128 KiB after JSON escaping and base64; allow 16 KiB for framing.
export const MAX_BODY = 144 * 1024;
export const BATCH = 32;
export const tokenSchema = z.string().regex(/^[a-f0-9]{64}$/);
export const textSchema = z.string().min(1)
  .refine(s => s.isWellFormed(), 'Message must contain well-formed Unicode')
  .refine(s => Buffer.byteLength(s) <= 16 * 1024, 'Maximum message size is 16 KiB');
const base64 = z.string().min(4).max(MAX_BODY).refine(s => Buffer.from(s, 'base64').toString('base64') === s, 'Invalid base64');

export const relaySchema = z.string().url().refine(value => {
  if (!URL.canParse(value)) return false;
  const u = new URL(value);
  const local = ['127.0.0.1', '[::1]', 'localhost'].includes(u.hostname);
  return (u.protocol === 'https:' || (u.protocol === 'http:' && local)) &&
    !u.username && !u.password && !u.search && !u.hash && u.pathname === '/';
}, 'Use an HTTPS origin, or HTTP on loopback only').transform(s => new URL(s).origin);

export const inviteSchema = z.object({
  version: z.literal(1),
  relay: relaySchema,
  token: tokenSchema,
  registration: z.number().int().min(1).max(16383),
  identity: base64,
  prekey: base64,
  signed: base64,
  signature: base64,
  kyber: base64,
  kyberSignature: base64,
}).strict();
export type Invite = z.infer<typeof inviteSchema>;

export function invitationLink(invite: Invite): string {
  const { relay, ...keys } = inviteSchema.parse(invite);
  return `${relay}/#a2a=${Buffer.from(JSON.stringify(keys)).toString('base64url')}`;
}

export function parseInvitationLink(link: string): Invite {
  try {
    if (link.length > MAX_BODY) throw new Error();
    const url = new URL(link);
    const encoded = /^#a2a=([A-Za-z0-9_-]+)$/.exec(url.hash)?.[1];
    if (!encoded) throw new Error();
    const bytes = Buffer.from(encoded, 'base64url');
    if (bytes.toString('base64url') !== encoded) throw new Error();
    url.hash = '';
    const relay = relaySchema.parse(url.href);
    const keys = inviteSchema.omit({ relay: true }).parse(JSON.parse(bytes.toString('utf8')));
    return { ...keys, relay };
  } catch {
    throw new Error('Invalid A2A pairing link');
  }
}

export const packetSchema = z.object({
  id: z.uuid(),
  type: z.union([z.literal(2), z.literal(3)]),
  body: base64,
}).strict();
export type Packet = z.infer<typeof packetSchema>;
export const payloadSchema = z.object({ version: z.literal(1), id: z.uuid(), text: textSchema }).strict();
export const encode = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
export const decode = (s: string) => Buffer.from(s, 'base64');
export const mailbox = (identity: string) => createHash('sha256').update(decode(identity)).digest('hex');

export async function readLimited(stream: AsyncIterable<Uint8Array>, limit: number): Promise<string> {
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > limit) throw new Error('Body too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}
