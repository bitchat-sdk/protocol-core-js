/**
 * TLV codec for BitChat REQUEST_SYNC payloads (gossip sync via GCS filters).
 *
 * Format: [Type:1][Length:2 big-endian][Value:n] — note the 16-bit length,
 * unlike the announcement / private-message TLVs which use a 1-byte length.
 *
 * RequestSyncPacket TLV types:
 *   0x01 = P (uint8) — Golomb-Rice parameter
 *   0x02 = M (uint32, big-endian) — hash range (N * 2^P)
 *   0x03 = data (opaque) — GR bitstream bytes (MSB-first)
 *   0x04 = types (1-8 bytes, little-endian) — sync-type flags bitmask (optional)
 *   0x05 = since timestamp (uint64, big-endian, ms since epoch) (optional)
 *   0x06 = fragment ID filter (UTF-8) (optional)
 *
 * The decoder is lenient about unknown tags (forward-compatible) and strict
 * about field validity: it rejects p outside 1..=MAX_P, m == 0, missing
 * required fields, and filter data above `maxAcceptBytes`.
 *
 * Wire-compatible with RequestSyncPacket.swift (BitchatProtocol) and
 * RequestSyncPacket.kt (bitchat-android-sdk; basic TLVs 0x01-0x03 only).
 */

import { MessageType, RequestSyncPacket } from './types.js';
import { TLVEncodeError } from './errors.js';

const enc = new TextEncoder();
const strictUtf8 = new TextDecoder('utf-8', { fatal: true });

/**
 * Maximum accepted Golomb-Rice parameter. Mirrors upstream GCSFilter.maxP;
 * values above this make no sense for a GCS filter and are rejected on decode.
 */
export const MAX_P = 32;

/** Receiver-side hard cap on filter data to avoid DoS via oversized filters. */
export const MAX_ACCEPT_FILTER_BYTES = 1024;

// Sync-type flags use at most 56 bits (mirrors SyncTypeFlags.swift).
const SYNC_TYPE_FLAGS_MASK = 0x00ff_ffff_ffff_ffffn;

const enum RSTag {
  P = 0x01,
  M = 0x02,
  Data = 0x03,
  Types = 0x04,
  Since = 0x05,
  FragmentID = 0x06,
}

/**
 * Named bits of the sync-type flags bitmask
 * (mirrors SyncTypeFlags in BitchatProtocol).
 */
export const SyncTypeFlag = {
  Announce: 1n << 0n,
  Message: 1n << 1n,
  Leave: 1n << 2n,
  NoiseHandshake: 1n << 3n,
  NoiseEncrypted: 1n << 4n,
  Fragment: 1n << 5n,
  RequestSync: 1n << 6n,
  FileTransfer: 1n << 7n,
} as const;

const SYNC_TYPE_BIT: ReadonlyMap<MessageType, bigint> = new Map([
  [MessageType.Announce, 0n],
  [MessageType.Message, 1n],
  [MessageType.Leave, 2n],
  [MessageType.NoiseHandshake, 3n],
  [MessageType.NoiseEncrypted, 4n],
  [MessageType.Fragment, 5n],
  [MessageType.RequestSync, 6n],
  [MessageType.FileTransfer, 7n],
]);

/** Build a sync-type flags bitmask from message types. */
export function syncTypeFlagsFromMessageTypes(types: MessageType[]): bigint {
  let raw = 0n;
  for (const t of types) {
    const bit = SYNC_TYPE_BIT.get(t);
    if (bit !== undefined) raw |= 1n << bit;
  }
  return raw & SYNC_TYPE_FLAGS_MASK;
}

/** Expand a sync-type flags bitmask into the message types it selects. */
export function syncTypeFlagsToMessageTypes(flags: bigint): MessageType[] {
  const masked = flags & SYNC_TYPE_FLAGS_MASK;
  const out: MessageType[] = [];
  for (const [type, bit] of SYNC_TYPE_BIT) {
    if ((masked & (1n << bit)) !== 0n) out.push(type);
  }
  return out;
}

/**
 * Encode a RequestSyncPacket to TLV bytes.
 *
 * Matches the Swift encoder byte-for-byte: `p` is masked to one byte
 * (validity is enforced on decode), optional fields are emitted only
 * when present, and `types === 0n` is omitted like Swift's nil `toData()`.
 */
export function encodeRequestSync(packet: RequestSyncPacket): Uint8Array {
  if (!Number.isInteger(packet.p)) {
    // Swift/Kotlin/Python can't express a fractional p; reject instead of masking.
    throw new TLVEncodeError('p must be an integer');
  }
  if (!Number.isInteger(packet.m) || packet.m < 0 || packet.m > 0xffff_ffff) {
    throw new TLVEncodeError('m out of range for uint32');
  }
  if (packet.data.length > 0xffff) {
    throw new TLVEncodeError('data too long (max 65535 bytes per TLV)');
  }

  const chunks: Uint8Array[] = [];
  chunks.push(makeTLV16(RSTag.P, Uint8Array.of(packet.p & 0xff)));
  chunks.push(makeTLV16(RSTag.M, uint32BE(packet.m)));
  chunks.push(makeTLV16(RSTag.Data, packet.data));

  if (packet.types !== undefined) {
    const typesBytes = syncTypeFlagsToBytes(packet.types);
    if (typesBytes !== null) chunks.push(makeTLV16(RSTag.Types, typesBytes));
  }
  if (packet.sinceTimestamp !== undefined) {
    if (packet.sinceTimestamp < 0n || packet.sinceTimestamp > 0xffff_ffff_ffff_ffffn) {
      throw new TLVEncodeError('sinceTimestamp out of range for uint64');
    }
    chunks.push(makeTLV16(RSTag.Since, uint64BE(packet.sinceTimestamp)));
  }
  if (packet.fragmentIdFilter !== undefined) {
    const fidBytes = enc.encode(packet.fragmentIdFilter);
    if (fidBytes.length > 0xffff) {
      throw new TLVEncodeError('fragmentIdFilter too long (max 65535 bytes UTF-8)');
    }
    chunks.push(makeTLV16(RSTag.FragmentID, fidBytes));
  }

  return concat(chunks);
}

/** Decode TLV bytes into a RequestSyncPacket. Returns null on failure. */
export function decodeRequestSync(
  data: Uint8Array,
  maxAcceptBytes: number = MAX_ACCEPT_FILTER_BYTES,
): RequestSyncPacket | null {
  let offset = 0;
  let p: number | undefined;
  let m: number | undefined;
  let payload: Uint8Array | undefined;
  let types: bigint | undefined;
  let sinceTimestamp: bigint | undefined;
  let fragmentIdFilter: string | undefined;

  while (offset + 3 <= data.length) {
    const tag = data[offset++];
    const length = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    if (offset + length > data.length) return null;
    const value = data.subarray(offset, offset + length);
    offset += length;

    switch (tag) {
      case RSTag.P:
        if (value.length === 1) p = value[0];
        break;
      case RSTag.M:
        if (value.length === 4) {
          m = ((value[0] << 24) >>> 0) + (value[1] << 16) + (value[2] << 8) + value[3];
        }
        break;
      case RSTag.Data:
        if (value.length > maxAcceptBytes) return null;
        payload = value.slice();
        break;
      case RSTag.Types:
        if (value.length >= 1 && value.length <= 8) {
          let raw = 0n;
          for (let i = value.length - 1; i >= 0; i--) {
            raw = (raw << 8n) | BigInt(value[i]);
          }
          types = raw & SYNC_TYPE_FLAGS_MASK;
        }
        break;
      case RSTag.Since:
        if (value.length === 8) {
          let raw = 0n;
          for (const byte of value) raw = (raw << 8n) | BigInt(byte);
          sinceTimestamp = raw;
        }
        break;
      case RSTag.FragmentID:
        try {
          fragmentIdFilter = strictUtf8.decode(value);
        } catch {
          // Invalid UTF-8 — field is skipped (mirrors Swift String(data:encoding:)).
        }
        break;
      default:
        // Unknown tag — skip (forward-compatible)
        break;
    }
  }

  if (p === undefined || m === undefined || payload === undefined) return null;
  if (p < 1 || p > MAX_P || m <= 0) return null;
  return { p, m, data: payload, types, sinceTimestamp, fragmentIdFilter };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeTLV16(tag: number, value: Uint8Array): Uint8Array {
  const out = new Uint8Array(3 + value.length);
  out[0] = tag;
  out[1] = (value.length >> 8) & 0xff;
  out[2] = value.length & 0xff;
  out.set(value, 3);
  return out;
}

function uint32BE(value: number): Uint8Array {
  return Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function uint64BE(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Minimal little-endian bytes for a flags bitmask; null when zero
 * (mirrors SyncTypeFlags.toData() returning nil for empty flags). */
function syncTypeFlagsToBytes(flags: bigint): Uint8Array | null {
  let v = flags & SYNC_TYPE_FLAGS_MASK;
  if (v === 0n) return null;
  const bytes: number[] = [];
  while (v > 0n && bytes.length < 8) {
    bytes.push(Number(v & 0xffn));
    v >>= 8n;
  }
  return Uint8Array.from(bytes);
}

function concat(arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}
