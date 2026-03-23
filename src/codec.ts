/**
 * Binary encode/decode for BitChat protocol packets.
 *
 * Wire format (all multi-byte fields are big-endian / network byte order):
 *
 * v1 Header (14 bytes):
 *   version(1) type(1) ttl(1) timestamp(8) flags(1) payloadLen(2)
 *
 * v2 Header (16 bytes):
 *   version(1) type(1) ttl(1) timestamp(8) flags(1) payloadLen(4)
 *
 * Variable fields (in order):
 *   senderID(8)
 *   recipientID(8)          — only when flags & HasRecipient
 *   routeCount(1)           — only when flags & HasRoute AND version >= 2
 *   route[0..n](n*8)        — routeCount hops of 8 bytes each
 *   [originalSize(2 or 4)]  — only when flags & IsCompressed (same width as payloadLen field)
 *   payload(payloadLen - sizeof(originalSize if compressed))
 *   signature(64)           — only when flags & HasSignature
 *
 * Note: payloadLen in the header covers the payload section only
 *       (including the originalSize preamble when compressed).
 *       Route bytes are NOT counted in payloadLen.
 */

import * as zlib from 'zlib';
import { promisify } from 'util';
import {
  BitchatPacket,
  EncodeOptions,
  PacketFlag,
  type ProtocolVersion,
} from './types.js';
import {
  DecompressionError,
  PacketTooShortError,
  SuspiciousCompressionRatioError,
  TruncatedFieldError,
  UnsupportedVersionError,
} from './errors.js';

const deflateRaw = promisify(zlib.deflateRaw);
const inflateRaw = promisify(zlib.inflateRaw);

// Fixed sizes
const V1_HEADER_SIZE = 14;
const V2_HEADER_SIZE = 16;
const SENDER_ID_SIZE = 8;
const RECIPIENT_ID_SIZE = 8;
const SIGNATURE_SIZE = 64;
const COMPRESSION_THRESHOLD = 256;
const MAX_COMPRESSION_RATIO = 50_000;

function headerSize(version: ProtocolVersion): number {
  return version === 2 ? V2_HEADER_SIZE : V1_HEADER_SIZE;
}

function lengthFieldSize(version: ProtocolVersion): number {
  return version === 2 ? 4 : 2;
}

function writeUint16BE(buf: DataView, offset: number, value: number): void {
  buf.setUint16(offset, value, false /* big-endian */);
}

function writeUint32BE(buf: DataView, offset: number, value: number): void {
  buf.setUint32(offset, value, false);
}

function writeUint64BE(buf: DataView, offset: number, value: bigint): void {
  buf.setBigUint64(offset, value, false);
}

function readUint16BE(buf: DataView, offset: number): number {
  return buf.getUint16(offset, false);
}

function readUint32BE(buf: DataView, offset: number): number {
  return buf.getUint32(offset, false);
}

function readUint64BE(buf: DataView, offset: number): bigint {
  return buf.getBigUint64(offset, false);
}

/**
 * Encode a BitchatPacket to its binary wire representation.
 *
 * Returns a `Uint8Array`. Pass `options.padding = true` for network transmission
 * (adds PKCS7-style block padding to obscure message length). Default is no padding
 * which matches reference implementations when `padding: false` is passed.
 *
 * This function is async because payload compression (zlib) is async in Node.js.
 */
export async function encode(
  packet: BitchatPacket,
  options: EncodeOptions = {}
): Promise<Uint8Array> {
  const { version } = packet;
  if (version !== 1 && version !== 2) {
    throw new UnsupportedVersionError(version as number);
  }

  // Compress payload if beneficial
  let payload = packet.payload;
  let isCompressed = false;
  let originalPayloadSize = 0;

  if (payload.length > COMPRESSION_THRESHOLD) {
    try {
      const compressed = await deflateRaw(payload);
      if (compressed.length < payload.length) {
        originalPayloadSize = payload.length;
        payload = new Uint8Array(compressed);
        isCompressed = true;
      }
    } catch {
      // compression failed — send uncompressed
    }
  }

  const lenFieldBytes = lengthFieldSize(version);

  // Route (v2+ only)
  const route: Uint8Array[] = version >= 2 ? (packet.route ?? []) : [];
  const hasRoute = route.length > 0;
  const hasRecipient = packet.recipientID != null;
  const hasSignature = packet.signature != null;

  // payloadData = [originalSize? (compressed preamble)] + payload bytes
  const compressionPreambleSize = isCompressed ? lenFieldBytes : 0;
  const payloadDataSize = payload.length + compressionPreambleSize;

  if (version === 1 && payloadDataSize > 0xffff) {
    throw new Error('Payload too large for v1 packet (max 65535 bytes)');
  }
  if (version === 2 && payloadDataSize > 0xffffffff) {
    throw new Error('Payload too large for v2 packet');
  }

  // Estimate total size
  const hdrSize = headerSize(version);
  const routeBytes = hasRoute ? 1 + route.length * SENDER_ID_SIZE : 0;
  const recipientBytes = hasRecipient ? RECIPIENT_ID_SIZE : 0;
  const sigBytes = hasSignature ? SIGNATURE_SIZE : 0;
  const totalSize =
    hdrSize + SENDER_ID_SIZE + recipientBytes + routeBytes + payloadDataSize + sigBytes;

  const buf = new ArrayBuffer(totalSize);
  const view = new DataView(buf);
  const out = new Uint8Array(buf);
  let offset = 0;

  // Header
  out[offset++] = version;
  out[offset++] = packet.type;
  out[offset++] = packet.ttl;
  writeUint64BE(view, offset, packet.timestamp);
  offset += 8;

  let flags = packet.flags & ~PacketFlag.HasRecipient & ~PacketFlag.HasSignature &
    ~PacketFlag.IsCompressed & ~PacketFlag.HasRoute & ~PacketFlag.IsRSR;
  if (hasRecipient) flags |= PacketFlag.HasRecipient;
  if (hasSignature) flags |= PacketFlag.HasSignature;
  if (isCompressed) flags |= PacketFlag.IsCompressed;
  if (hasRoute && version >= 2) flags |= PacketFlag.HasRoute;
  if (packet.isRSR) flags |= PacketFlag.IsRSR;
  out[offset++] = flags;

  if (version === 2) {
    writeUint32BE(view, offset, payloadDataSize);
    offset += 4;
  } else {
    writeUint16BE(view, offset, payloadDataSize);
    offset += 2;
  }

  // SenderID (always 8 bytes, zero-padded if shorter)
  const senderID = packet.senderID;
  const senderBytes = senderID.length >= SENDER_ID_SIZE
    ? senderID.subarray(0, SENDER_ID_SIZE)
    : (() => { const b = new Uint8Array(SENDER_ID_SIZE); b.set(senderID); return b; })();
  out.set(senderBytes, offset);
  offset += SENDER_ID_SIZE;

  // RecipientID
  if (hasRecipient && packet.recipientID) {
    const rid = packet.recipientID;
    const ridBytes = rid.length >= RECIPIENT_ID_SIZE
      ? rid.subarray(0, RECIPIENT_ID_SIZE)
      : (() => { const b = new Uint8Array(RECIPIENT_ID_SIZE); b.set(rid); return b; })();
    out.set(ridBytes, offset);
    offset += RECIPIENT_ID_SIZE;
  }

  // Route (v2+ only)
  if (hasRoute) {
    out[offset++] = route.length;
    for (const hop of route) {
      const hopBytes = hop.length >= SENDER_ID_SIZE
        ? hop.subarray(0, SENDER_ID_SIZE)
        : (() => { const b = new Uint8Array(SENDER_ID_SIZE); b.set(hop); return b; })();
      out.set(hopBytes, offset);
      offset += SENDER_ID_SIZE;
    }
  }

  // Compression preamble (original size)
  if (isCompressed) {
    if (version === 2) {
      writeUint32BE(view, offset, originalPayloadSize);
      offset += 4;
    } else {
      writeUint16BE(view, offset, originalPayloadSize);
      offset += 2;
    }
  }

  // Payload
  out.set(payload, offset);
  offset += payload.length;

  // Signature
  if (hasSignature && packet.signature) {
    const sig = packet.signature.subarray(0, SIGNATURE_SIZE);
    out.set(sig, offset);
    offset += SIGNATURE_SIZE;
  }

  if (options.padding) {
    return applyPadding(out.subarray(0, offset));
  }
  return out.subarray(0, offset);
}

/**
 * Decode a binary buffer into a BitchatPacket.
 *
 * Returns `null` (never throws) on invalid/truncated input.
 * Tries to decode the raw buffer first; if that fails, tries after stripping padding.
 */
export async function decode(data: Uint8Array): Promise<BitchatPacket | null> {
  const result = await decodeCore(data);
  if (result !== null) return result;
  // Try after stripping padding
  const unpadded = stripPadding(data);
  if (unpadded.length === data.length) return null;
  return decodeCore(unpadded);
}

async function decodeCore(raw: Uint8Array): Promise<BitchatPacket | null> {
  try {
    return await decodeCoreThrows(raw);
  } catch {
    return null;
  }
}

async function decodeCoreThrows(raw: Uint8Array): Promise<BitchatPacket> {
  if (raw.length < V1_HEADER_SIZE + SENDER_ID_SIZE) {
    throw new PacketTooShortError(raw.length, V1_HEADER_SIZE + SENDER_ID_SIZE);
  }

  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  let offset = 0;

  const version = raw[offset++] as ProtocolVersion;
  if (version !== 1 && version !== 2) {
    throw new UnsupportedVersionError(version as number);
  }

  const hdrSize = headerSize(version);
  if (raw.length < hdrSize + SENDER_ID_SIZE) {
    throw new PacketTooShortError(raw.length, hdrSize + SENDER_ID_SIZE);
  }

  const type = raw[offset++];
  const ttl = raw[offset++];
  const timestamp = readUint64BE(view, offset);
  offset += 8;
  const flags = raw[offset++];

  const hasRecipient = (flags & PacketFlag.HasRecipient) !== 0;
  const hasSignature = (flags & PacketFlag.HasSignature) !== 0;
  const isCompressed = (flags & PacketFlag.IsCompressed) !== 0;
  const hasRoute = version >= 2 && (flags & PacketFlag.HasRoute) !== 0;
  const isRSR = (flags & PacketFlag.IsRSR) !== 0;

  const lenFieldBytes = lengthFieldSize(version);
  let payloadLength: number;
  if (version === 2) {
    payloadLength = readUint32BE(view, offset);
    offset += 4;
  } else {
    payloadLength = readUint16BE(view, offset);
    offset += 2;
  }

  // SenderID
  if (offset + SENDER_ID_SIZE > raw.length) throw new TruncatedFieldError('senderID');
  const senderID = raw.slice(offset, offset + SENDER_ID_SIZE);
  offset += SENDER_ID_SIZE;

  // RecipientID
  let recipientID: Uint8Array | undefined;
  if (hasRecipient) {
    if (offset + RECIPIENT_ID_SIZE > raw.length) throw new TruncatedFieldError('recipientID');
    recipientID = raw.slice(offset, offset + RECIPIENT_ID_SIZE);
    offset += RECIPIENT_ID_SIZE;
  }

  // Route (v2+ only)
  let route: Uint8Array[] | undefined;
  if (hasRoute) {
    if (offset + 1 > raw.length) throw new TruncatedFieldError('routeCount');
    const routeCount = raw[offset++];
    if (routeCount > 0) {
      const hops: Uint8Array[] = [];
      for (let i = 0; i < routeCount; i++) {
        if (offset + SENDER_ID_SIZE > raw.length) throw new TruncatedFieldError(`route[${i}]`);
        hops.push(raw.slice(offset, offset + SENDER_ID_SIZE));
        offset += SENDER_ID_SIZE;
      }
      route = hops;
    }
  }

  // Payload (with optional compression preamble)
  let payload: Uint8Array;
  if (isCompressed) {
    if (payloadLength < lenFieldBytes) throw new TruncatedFieldError('compressionPreamble');
    let originalSize: number;
    if (version === 2) {
      if (offset + 4 > raw.length) throw new TruncatedFieldError('originalSize');
      originalSize = readUint32BE(view, offset);
      offset += 4;
    } else {
      if (offset + 2 > raw.length) throw new TruncatedFieldError('originalSize');
      originalSize = readUint16BE(view, offset);
      offset += 2;
    }
    const compressedSize = payloadLength - lenFieldBytes;
    if (compressedSize <= 0) throw new TruncatedFieldError('compressedPayload');
    if (offset + compressedSize > raw.length) throw new TruncatedFieldError('compressedPayload');
    const compressed = raw.slice(offset, offset + compressedSize);
    offset += compressedSize;

    const ratio = originalSize / compressedSize;
    if (ratio > MAX_COMPRESSION_RATIO) {
      throw new SuspiciousCompressionRatioError(ratio);
    }

    let decompressed: Buffer;
    try {
      decompressed = await inflateRaw(compressed);
    } catch (err) {
      throw new DecompressionError(err);
    }
    if (decompressed.length !== originalSize) {
      throw new DecompressionError('decompressed size mismatch');
    }
    payload = new Uint8Array(decompressed);
  } else {
    if (offset + payloadLength > raw.length) throw new TruncatedFieldError('payload');
    payload = raw.slice(offset, offset + payloadLength);
    offset += payloadLength;
  }

  // Signature
  let signature: Uint8Array | undefined;
  if (hasSignature) {
    if (offset + SIGNATURE_SIZE > raw.length) throw new TruncatedFieldError('signature');
    signature = raw.slice(offset, offset + SIGNATURE_SIZE);
    offset += SIGNATURE_SIZE;
  }

  return {
    version,
    type,
    ttl,
    timestamp,
    flags,
    senderID,
    recipientID,
    route,
    payload,
    signature,
    isRSR,
  };
}

/** Apply PKCS7-style block padding to round up to a power-of-two block size. */
function applyPadding(data: Uint8Array): Uint8Array {
  const blockSizes = [32, 64, 128, 256, 512, 1024, 2048, 4096];
  const target = blockSizes.find((s) => s >= data.length) ?? data.length;
  if (target === data.length) return data;
  const padded = new Uint8Array(target);
  padded.set(data);
  const padValue = target - data.length;
  for (let i = data.length; i < target; i++) {
    padded[i] = padValue;
  }
  return padded;
}

/** Strip PKCS7-style block padding. Returns original if no valid padding found. */
function stripPadding(data: Uint8Array): Uint8Array {
  if (data.length === 0) return data;
  const padValue = data[data.length - 1];
  if (padValue === 0 || padValue > data.length) return data;
  for (let i = data.length - padValue; i < data.length; i++) {
    if (data[i] !== padValue) return data;
  }
  return data.subarray(0, data.length - padValue);
}

/** Convert a hex string to Uint8Array. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`Odd-length hex string: ${hex.length}`);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Convert a Uint8Array to a lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
