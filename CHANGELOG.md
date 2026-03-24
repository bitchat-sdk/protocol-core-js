# Changelog — @bitchat-sdk/protocol-core

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — planned for 0.2.0

### Changed
- `PacketFlags` backward-compat alias removed; use `PacketFlag` (alias was added in 0.1.0, removal planned after one minor version)

---

## [0.1.0] — 2026-03-22

Initial GA release.

### Added
- `encode()` / `decode()` — binary packet encode/decode with v1 and v2 header support
- `encodeAnnouncement()` / `decodeAnnouncement()` — TLV codec for peer announcement packets
- `encodePrivateMessage()` / `decodePrivateMessage()` — TLV codec for private message packets
- `peerIDFromNoiseKey()` — derive 8-byte peer ID from 32-byte Noise static public key (SHA-256 prefix)
- `peerIDToBytes()` / `peerIDFromBytes()` — convert between hex string and binary peer IDs
- `nostrGeoDMPeerID()` / `nostrGeoChatPeerID()` — Nostr-backed peer ID variants
- `hexToBytes()` / `bytesToHex()` — hex conversion utilities
- `PacketFlag` const-object with flag bit values; `PacketFlags` deprecated alias kept for backward compat
- `MessageType` / `NoisePayloadType` enums mirroring the Swift/Kotlin wire types
- `BitchatPacket` / `AnnouncementPacket` / `PrivateMessagePacket` TypeScript interfaces
- `EncodeOptions` interface (`padding` flag)
- Full error taxonomy: `PacketTooShortError`, `UnsupportedVersionError`, `TruncatedFieldError`, `DecompressionError`, `SuspiciousCompressionRatioError`, `TLVDecodeError`, `TLVEncodeError`
- zlib deflate/inflate compression with 50,000:1 ratio safety limit
- PKCS7-style block padding support
- Unit tests with Node.js built-in test runner
- Fixture-based cross-language compatibility tests against spec-tests golden vectors

### Protocol Compatibility
Wire-format compatible with BitChat iOS (Swift) and BitChat Android (Kotlin) — protocol v1 and v2.

[Unreleased]: https://github.com/bitchat-sdk/protocol-core-js/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bitchat-sdk/protocol-core-js/releases/tag/v0.1.0
