/**
 * TLV (Type-Length-Value) codec for BitChat announcement and private message packets.
 *
 * Format: [Type:1][Length:1][Value:n] — max 255 bytes per value.
 *
 * AnnouncementPacket TLV types:
 *   0x01 = nickname (UTF-8)
 *   0x02 = noisePublicKey (32 bytes Curve25519)
 *   0x03 = signingPublicKey (32 bytes Ed25519)
 *   0x04 = directNeighbors (multiples of 8 bytes, up to 10 neighbors)
 *
 * PrivateMessagePacket TLV types:
 *   0x00 = messageID (UTF-8)
 *   0x01 = content (UTF-8)
 *
 * AnnouncementPacket decoder is lenient: unknown tags are skipped.
 * PrivateMessagePacket decoder is strict: unknown tags return null.
 */

import { AnnouncementPacket, PrivateMessagePacket } from './types.js';
import { TLVDecodeError, TLVEncodeError } from './errors.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

// ─── AnnouncementPacket ───────────────────────────────────────────────────────

const enum AnnTag {
  Nickname = 0x01,
  NoisePublicKey = 0x02,
  SigningPublicKey = 0x03,
  DirectNeighbors = 0x04,
}

/** Encode an AnnouncementPacket to TLV bytes. */
export function encodeAnnouncement(packet: AnnouncementPacket): Uint8Array {
  const nicknameBytes = enc.encode(packet.nickname);
  if (nicknameBytes.length > 255) throw new TLVEncodeError('nickname too long (max 255 bytes UTF-8)');
  if (packet.noisePublicKey.length > 255) throw new TLVEncodeError('noisePublicKey too long');
  if (packet.signingPublicKey.length > 255) throw new TLVEncodeError('signingPublicKey too long');

  const chunks: Uint8Array[] = [];
  chunks.push(makeTLV(AnnTag.Nickname, nicknameBytes));
  chunks.push(makeTLV(AnnTag.NoisePublicKey, packet.noisePublicKey));
  chunks.push(makeTLV(AnnTag.SigningPublicKey, packet.signingPublicKey));

  if (packet.directNeighbors && packet.directNeighbors.length > 0) {
    const neighbors = packet.directNeighbors.slice(0, 10);
    const neighborData = concat(neighbors);
    if (neighborData.length % 8 === 0 && neighborData.length <= 255) {
      chunks.push(makeTLV(AnnTag.DirectNeighbors, neighborData));
    }
  }

  return concat(chunks);
}

/** Decode TLV bytes into an AnnouncementPacket. Returns null on failure. */
export function decodeAnnouncement(data: Uint8Array): AnnouncementPacket | null {
  let offset = 0;
  let nickname: string | undefined;
  let noisePublicKey: Uint8Array | undefined;
  let signingPublicKey: Uint8Array | undefined;
  let directNeighbors: Uint8Array[] | undefined;

  while (offset + 2 <= data.length) {
    const tag = data[offset++];
    const length = data[offset++];
    if (offset + length > data.length) return null;
    const value = data.subarray(offset, offset + length);
    offset += length;

    switch (tag) {
      case AnnTag.Nickname:
        nickname = dec.decode(value);
        break;
      case AnnTag.NoisePublicKey:
        noisePublicKey = value.slice();
        break;
      case AnnTag.SigningPublicKey:
        signingPublicKey = value.slice();
        break;
      case AnnTag.DirectNeighbors:
        if (length > 0 && length % 8 === 0) {
          const count = length / 8;
          directNeighbors = [];
          for (let i = 0; i < count; i++) {
            directNeighbors.push(value.slice(i * 8, (i + 1) * 8));
          }
        }
        break;
      default:
        // Unknown tag — skip (forward-compatible)
        break;
    }
  }

  if (!nickname || !noisePublicKey || !signingPublicKey) return null;
  return { nickname, noisePublicKey, signingPublicKey, directNeighbors };
}

// ─── PrivateMessagePacket ─────────────────────────────────────────────────────

const enum PMTag {
  MessageID = 0x00,
  Content = 0x01,
}

/** Encode a PrivateMessagePacket to TLV bytes. */
export function encodePrivateMessage(packet: PrivateMessagePacket): Uint8Array {
  const messageIDBytes = enc.encode(packet.messageID);
  const contentBytes = enc.encode(packet.content);
  if (messageIDBytes.length > 255) throw new TLVEncodeError('messageID too long (max 255 bytes UTF-8)');
  if (contentBytes.length > 255) throw new TLVEncodeError('content too long (max 255 bytes UTF-8)');

  return concat([
    makeTLV(PMTag.MessageID, messageIDBytes),
    makeTLV(PMTag.Content, contentBytes),
  ]);
}

/** Decode TLV bytes into a PrivateMessagePacket. Returns null on failure or unknown tags. */
export function decodePrivateMessage(data: Uint8Array): PrivateMessagePacket | null {
  let offset = 0;
  let messageID: string | undefined;
  let content: string | undefined;

  while (offset + 2 <= data.length) {
    const tag = data[offset++];
    if (tag !== PMTag.MessageID && tag !== PMTag.Content) {
      // Strict: unknown tag is a decode failure
      return null;
    }
    const length = data[offset++];
    if (offset + length > data.length) return null;
    const value = data.subarray(offset, offset + length);
    offset += length;

    if (tag === PMTag.MessageID) messageID = dec.decode(value);
    else content = dec.decode(value);
  }

  if (!messageID || content === undefined) return null;
  return { messageID, content };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeTLV(tag: number, value: Uint8Array): Uint8Array {
  if (value.length > 255) {
    throw new TLVEncodeError(`TLV value too long for tag 0x${tag.toString(16)}: ${value.length} bytes`);
  }
  const out = new Uint8Array(2 + value.length);
  out[0] = tag;
  out[1] = value.length;
  out.set(value, 2);
  return out;
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

// Re-export for convenience
export { TLVDecodeError, TLVEncodeError };
