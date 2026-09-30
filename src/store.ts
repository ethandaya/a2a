import { chmodSync, closeSync, existsSync, lstatSync, mkdirSync, openSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  IdentityChange, IdentityKeyPair, IdentityKeyStore, KyberPreKeyRecord,
  PreKeyRecord, PrivateKey, PublicKey, SessionRecord, SignedPreKeyRecord,
} from '@signalapp/libsignal-client';
import type { KyberPreKeyStore, PreKeyStore, ProtocolAddress, SessionStore, SignedPreKeyStore } from '@signalapp/libsignal-client';
import { decode, inviteSchema, mailbox } from './wire.ts';
import type { Invite } from './wire.ts';

export function openDatabase(directory: string, filename: string): DatabaseSync {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const info = lstatSync(directory);
  if (!info.isDirectory() || (process.platform !== 'win32' && (info.mode & 0o077))) {
    throw new Error('State directory must be a real directory with permissions 0700');
  }
  const path = join(directory, filename);
  if (!existsSync(path)) closeSync(openSync(path, 'wx', 0o600));
  if (!lstatSync(path).isFile()) throw new Error('Database must be a regular file');
  chmodSync(path, 0o600);
  const db = new DatabaseSync(path);
  try {
    // Hold the SQLite file lock for this connection's lifetime, including between transactions.
    db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT;');
    return db;
  } catch (error) {
    db.close();
    throw new Error('Cannot lock database; stop the other process using this state directory', { cause: error });
  }
}

export class Store extends IdentityKeyStore implements SessionStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore {
  readonly db: DatabaseSync;

  constructor(directory: string) {
    super();
    this.db = openDatabase(directory, 'client.sqlite');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS records (key TEXT PRIMARY KEY, value BLOB NOT NULL);
      CREATE TABLE IF NOT EXISTS outbox (seq INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, packet TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS inbox (cursor INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, text TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY);
    `);
  }

  read(key: string): Buffer<ArrayBuffer> | undefined {
    const row = this.db.prepare('SELECT value FROM records WHERE key = ?').get(key) as { value: Uint8Array } | undefined;
    return row && Buffer.from(row.value);
  }

  require(key: string): Buffer<ArrayBuffer> {
    const value = this.read(key);
    if (!value) throw new Error(`Missing local record: ${key}`);
    return value;
  }

  write(key: string, value: Uint8Array): void {
    this.db.prepare('INSERT OR REPLACE INTO records VALUES (?, ?)').run(key, value);
  }

  get local(): Invite { return inviteSchema.parse(JSON.parse(this.require('local').toString())); }
  get peer(): Invite { return inviteSchema.parse(JSON.parse(this.require('peer').toString())); }

  async transaction<T>(fn: () => Promise<T>): Promise<T> {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = await fn();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  async getIdentityKey() { return PrivateKey.deserialize(this.require('identity')); }
  override async getIdentityKeyPair() {
    const key = await this.getIdentityKey();
    return new IdentityKeyPair(key.getPublicKey(), key);
  }
  async getLocalRegistrationId() { return this.local.registration; }
  async getIdentity(address: ProtocolAddress) {
    return address.name() === mailbox(this.peer.identity) && address.deviceId() === 1
      ? PublicKey.deserialize(decode(this.peer.identity)) : null;
  }
  async isTrustedIdentity(address: ProtocolAddress, key: PublicKey) {
    return (await this.getIdentity(address))?.equals(key) ?? false;
  }
  async saveIdentity(address: ProtocolAddress, key: PublicKey) {
    if (!await this.isTrustedIdentity(address, key)) throw new Error('Peer identity does not match the pinned key');
    return IdentityChange.NewOrUnchanged;
  }
  async saveSession(address: ProtocolAddress, record: SessionRecord) { this.write(`session:${address}`, record.serialize()); }
  async getSession(address: ProtocolAddress) {
    const value = this.read(`session:${address}`);
    return value ? SessionRecord.deserialize(value) : null;
  }
  async getExistingSessions(addresses: ProtocolAddress[]) {
    return Promise.all(addresses.map(async address => {
      const session = await this.getSession(address);
      if (!session) throw new Error('Missing session');
      return session;
    }));
  }
  async savePreKey(id: number, record: PreKeyRecord) { this.write(`prekey:${id}`, record.serialize()); }
  async getPreKey(id: number) { return PreKeyRecord.deserialize(this.require(`prekey:${id}`)); }
  async removePreKey(id: number) { this.db.prepare('DELETE FROM records WHERE key = ?').run(`prekey:${id}`); }
  async saveSignedPreKey(id: number, record: SignedPreKeyRecord) { this.write(`signed:${id}`, record.serialize()); }
  async getSignedPreKey(id: number) { return SignedPreKeyRecord.deserialize(this.require(`signed:${id}`)); }
  async saveKyberPreKey(id: number, record: KyberPreKeyRecord) { this.write(`kyber:${id}`, record.serialize()); }
  async getKyberPreKey(id: number) { return KyberPreKeyRecord.deserialize(this.require(`kyber:${id}`)); }
  async markKyberPreKeyUsed(id: number, signedId: number, baseKey: PublicKey) {
    const key = `used:${id}:${signedId}:${Buffer.from(baseKey.serialize()).toString('hex')}`;
    if (this.read(key)) throw new Error('Kyber prekey already used for this base key');
    this.write(key, Buffer.from([1]));
  }
}
