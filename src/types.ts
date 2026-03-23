/**
 * Core types for the BitChat binary protocol.
 *
 * These mirror the wire-format structures from BinaryProtocol.swift / BitchatProtocol.swift.
 * No dependencies on platform APIs — safe for Node.js and browser (where zlib is available).
 */

/** Protocol version. 1 = 14-byte header. 2 = 16-byte header with 4-byte payload length and source routing. */
export type ProtocolVersion = 1 | 2;

/** Application-layer message types (outer packet type byte). */
export enum MessageType {
  /** Peer announcement — broadcasts nickname and public keys. */
  Announce = 0x01,
  /** Public broadcast chat message. */
  Message = 0x02,
  /** Peer departure notification. */
  Leave = 0x03,
  /** Noise Protocol handshake (init or response). */
  NoiseHandshake = 0x10,
  /** Noise-encrypted payload — carries all private messages, receipts, etc. */
  NoiseEncrypted = 0x11,
  /** Fragment of a multi-part large message. */
  Fragment = 0x20,
  /** Gossip sync request. */
  RequestSync = 0x21,
  /** Binary file / audio / image payload. */
  FileTransfer = 0x22,
}

/** Payload type — first byte inside a decrypted NoiseEncrypted payload. */
export enum NoisePayloadType {
  /** Private chat message. */
  PrivateMessage = 0x01,
  /** Read receipt (message was read by recipient). */
  ReadReceipt = 0x02,
  /** Delivery confirmation (message reached device). */
  Delivered = 0x03,
  /** In-band file transfer. */
  FileTransfer = 0x20,
  /** OOB verification challenge. */
  VerifyChallenge = 0x10,
  /** OOB verification response. */
  VerifyResponse = 0x11,
}

/** Bit flags used in the packet header flags byte. */
export const PacketFlag = {
  /** Packet has a RecipientID field (directed message). */
  HasRecipient: 0x01 as const,
  /** Packet has a 64-byte Ed25519 signature appended. */
  HasSignature: 0x02 as const,
  /** Payload is zlib-compressed; original size field precedes compressed data. */
  IsCompressed: 0x04 as const,
  /** Packet has a source-route list (v2+ only). */
  HasRoute: 0x08 as const,
  /** Packet is a Relay-Sync-Request (RSR). */
  IsRSR: 0x10 as const,
} as const;

/** @deprecated Use {@link PacketFlag} instead. */
export const PacketFlags = PacketFlag;

/**
 * A decoded BitChat protocol packet.
 *
 * All binary fields use `Uint8Array`. `timestamp` is in milliseconds since epoch (Unix time × 1000).
 */
export interface BitchatPacket {
  /** Wire format version (1 or 2). */
  version: ProtocolVersion;
  /** Message type byte. See `MessageType`. */
  type: number;
  /** Time-to-live hop limit. */
  ttl: number;
  /** Timestamp in milliseconds since Unix epoch. */
  timestamp: bigint;
  /** Flags byte. See `PacketFlag`. */
  flags: number;
  /** Sender peer ID — 8 bytes derived from SHA-256 of noise public key. */
  senderID: Uint8Array;
  /** Recipient peer ID — 8 bytes. Only present when `flags & HasRecipient`. */
  recipientID?: Uint8Array;
  /** Source route hops — each 8 bytes. Only present when `flags & HasRoute` and version >= 2. */
  route?: Uint8Array[];
  /** Decoded (decompressed if applicable) payload bytes. */
  payload: Uint8Array;
  /** 64-byte Ed25519 signature. Only present when `flags & HasSignature`. */
  signature?: Uint8Array;
  /** Whether this is a Relay-Sync-Request packet. */
  isRSR: boolean;
}

/** Options for `encode()`. */
export interface EncodeOptions {
  /**
   * When true, apply PKCS7-style block padding to obscure message length.
   * Defaults to `false` — set to `true` for actual network transmission.
   */
  padding?: boolean;
}

/** TLV-decoded AnnouncementPacket fields. */
export interface AnnouncementPacket {
  /** Human-readable peer nickname (UTF-8, max 255 bytes). */
  nickname: string;
  /** 32-byte Curve25519 noise static public key. */
  noisePublicKey: Uint8Array;
  /** 32-byte Ed25519 signing public key. */
  signingPublicKey: Uint8Array;
  /** Up to 10 direct BLE neighbor peer IDs (each 8 bytes). Optional. */
  directNeighbors?: Uint8Array[];
}

/** TLV-decoded PrivateMessagePacket fields. */
export interface PrivateMessagePacket {
  /** Message ID (UTF-8 string). */
  messageID: string;
  /** Message content (UTF-8 string). */
  content: string;
}
