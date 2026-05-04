# @bitchat-sdk/protocol-core

[![npm](https://img.shields.io/npm/v/@bitchat-sdk/protocol-core)](https://www.npmjs.com/package/@bitchat-sdk/protocol-core)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](https://unlicense.org)

BitChat binary protocol encode/decode for Node.js.

Implements the wire format from the BitChat mesh networking protocol:
binary packet encode/decode, TLV codec for announcement and private message
structures, and peer ID derivation utilities.

## Installation

```bash
npm install @bitchat-sdk/protocol-core
```

Requires Node.js 18+.

## Quick Start

```ts
import {
  encode,
  decode,
  MessageType,
  PacketFlag,
  encodeAnnouncement,
  decodeAnnouncement,
  peerIDFromNoiseKey,
  bytesToHex,
} from '@bitchat-sdk/protocol-core';

// Encode a broadcast message
const packet = {
  version: 1 as const,
  type: MessageType.Message,
  ttl: 7,
  timestamp: BigInt(Date.now()),
  flags: 0,
  senderID: peerIDBytes,           // 8-byte Uint8Array
  payload: new TextEncoder().encode('Hello, BitChat!'),
  isRSR: false,
};

const wire = await encode(packet, { padding: true }); // padded for BLE transmission

// Decode from bytes received over BLE or Nostr relay
const decoded = await decode(wire);
if (decoded) {
  console.log('type:', decoded.type);
  console.log('payload:', new TextDecoder().decode(decoded.payload));
}
```

## API

### Packet Encode/Decode

```ts
encode(packet: BitchatPacket, options?: { padding?: boolean }): Promise<Uint8Array>
decode(data: Uint8Array): Promise<BitchatPacket | null>
```

`decode()` returns `null` (never throws) on invalid or truncated input.
`encode()` is async because payload compression uses Node's `zlib`.

### TLV: AnnouncementPacket

```ts
encodeAnnouncement(packet: AnnouncementPacket): Uint8Array
decodeAnnouncement(data: Uint8Array): AnnouncementPacket | null
```

The decoder is **lenient**: unknown TLV tags are skipped (forward-compatible).

### TLV: PrivateMessagePacket

```ts
encodePrivateMessage(packet: PrivateMessagePacket): Uint8Array
decodePrivateMessage(data: Uint8Array): PrivateMessagePacket | null
```

The decoder is **strict**: returns `null` on any unknown TLV tag.

### Peer ID Utilities

```ts
peerIDFromNoiseKey(noisePublicKey: Uint8Array): string   // 16-char hex
peerIDToBytes(peerID: string): Uint8Array                // 8 bytes
peerIDFromBytes(bytes: Uint8Array): string               // 16-char hex
nostrGeoDMPeerID(nostrPubkeyHex: string): string         // "nostr_" + prefix
nostrGeoChatPeerID(nostrPubkeyHex: string): string       // "nostr:" + prefix
```

### Utilities

```ts
hexToBytes(hex: string): Uint8Array
bytesToHex(bytes: Uint8Array): string
```

## Wire Format Summary

### v1 Header (14 bytes)

```
[version:1][type:1][ttl:1][timestamp:8 BE uint64][flags:1][payloadLen:2 BE uint16]
[senderID:8]
[recipientID:8]         — if flags & HasRecipient
[payload:payloadLen]
[signature:64]          — if flags & HasSignature
```

### v2 Header (16 bytes)

Same as v1 but `payloadLen` is 4 bytes (BE uint32), and source routing is supported:

```
[version:1][type:1][ttl:1][timestamp:8 BE uint64][flags:1][payloadLen:4 BE uint32]
[senderID:8]
[recipientID:8]                  — if flags & HasRecipient
[routeCount:1][hop:8]×N          — if flags & HasRoute
[originalSize:4][compressed]     — if flags & IsCompressed
[payload:payloadLen-(4 if compressed)]
[signature:64]                   — if flags & HasSignature
```

### Flags Byte

| Bit | Value | Name |
|-----|-------|------|
| 0 | 0x01 | HasRecipient |
| 1 | 0x02 | HasSignature |
| 2 | 0x04 | IsCompressed |
| 3 | 0x08 | HasRoute (v2+ only) |
| 4 | 0x10 | IsRSR |

## Message Types

| Type | Value | Description |
|------|-------|-------------|
| Announce | 0x01 | Peer presence + public keys |
| Message | 0x02 | Public broadcast message |
| Leave | 0x03 | Peer departure |
| NoiseHandshake | 0x10 | Noise handshake frame |
| NoiseEncrypted | 0x11 | All encrypted payloads |
| Fragment | 0x20 | Large message fragment |
| RequestSync | 0x21 | Gossip sync request |
| FileTransfer | 0x22 | File/audio/image |

## Compatibility

This package implements the same binary wire format as:
- `ios/bitchat/Protocols/BinaryProtocol.swift`
- `android/app/src/main/java/com/bitchat/android/services/BinaryProtocol.kt`

Cross-language compatibility is verified against the
[`bitchat-sdk/spec-tests`](https://github.com/bitchat-sdk/spec-tests) golden
fixture suite. Clone that repo as a sibling of this one, then `npm test`
runs all cross-language vectors automatically — without it, the fixture
suite silently skips.

## Known Limitations

- **BLE transport is not included** — this package is protocol-only.
- **zlib compression** is Node.js `zlib.deflateRaw` / `inflateRaw`. Browser builds need a polyfill.
- **Signature verification** is not included — provide your own Ed25519 library.
- **v1 max payload: 65535 bytes**. v2 supports up to 4 GiB.

## License

Unlicense — public domain.
