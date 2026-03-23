/**
 * PeerID utilities for the BitChat protocol.
 *
 * Peer IDs are derived from Noise static public keys:
 *   Short form (8 bytes): first 8 bytes of SHA-256(noisePublicKey) = 16 lowercase hex chars
 *
 * Nostr-backed variants:
 *   GeoDM:    "nostr_" + nostrPubkey.slice(0, 16)
 *   GeoChat:  "nostr:" + nostrPubkey.slice(0, 8)
 */

import { createHash } from 'crypto';

/** A 16-char lowercase hex string representing an 8-byte peer ID. */
export type PeerIDHex = string;

/**
 * Derive a short peer ID from a 32-byte Noise static public key.
 *
 * Matches Swift: `SHA256(noisePublicKey).hexString.prefix(16)`
 *
 * @param noisePublicKey  32-byte Curve25519 public key
 * @returns 16-char lowercase hex peer ID
 */
export function peerIDFromNoiseKey(noisePublicKey: Uint8Array): PeerIDHex {
  const hash = createHash('sha256').update(noisePublicKey).digest();
  return hash.subarray(0, 8).reduce((hex, b) => hex + b.toString(16).padStart(2, '0'), '');
}

/**
 * Convert a peer ID hex string to its 8-byte binary representation.
 *
 * @throws if the hex string is not exactly 16 lowercase hex characters
 */
export function peerIDToBytes(peerID: PeerIDHex): Uint8Array {
  if (!/^[0-9a-f]{16}$/.test(peerID)) {
    throw new Error(`Invalid peer ID: "${peerID}" (expected 16 hex chars)`);
  }
  const bytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    bytes[i] = parseInt(peerID.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert 8 bytes to a peer ID hex string.
 *
 * @throws if the buffer is not exactly 8 bytes
 */
export function peerIDFromBytes(bytes: Uint8Array): PeerIDHex {
  if (bytes.length < 8) throw new Error(`Peer ID buffer too short: ${bytes.length} bytes`);
  return Array.from(bytes.subarray(0, 8))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Derive a Nostr-backed peer ID for GeoDM messages.
 * Format: "nostr_" + nostrPubkey.slice(0, 16)
 */
export function nostrGeoDMPeerID(nostrPubkeyHex: string): string {
  return 'nostr_' + nostrPubkeyHex.slice(0, 16);
}

/**
 * Derive a Nostr-backed peer ID for GeoChat (public channel) messages.
 * Format: "nostr:" + nostrPubkey.slice(0, 8)
 */
export function nostrGeoChatPeerID(nostrPubkeyHex: string): string {
  return 'nostr:' + nostrPubkeyHex.slice(0, 8);
}
