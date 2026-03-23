import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { encode, decode, hexToBytes, bytesToHex } from '../codec.js';
import { MessageType, PacketFlag, type BitchatPacket } from '../types.js';

const SENDER = hexToBytes('abcdef0123456789');
const RECIPIENT = hexToBytes('0102030405060708');

function makePacket(overrides: Partial<BitchatPacket>): BitchatPacket {
  return {
    version: 1,
    type: MessageType.Message,
    ttl: 7,
    timestamp: 0n,
    flags: 0,
    senderID: SENDER,
    payload: new Uint8Array(0),
    isRSR: false,
    ...overrides,
  };
}

describe('encode/decode round-trip', () => {
  it('broadcast message with text payload', async () => {
    const payload = new TextEncoder().encode('Hello, BitChat!');
    const packet = makePacket({ payload });
    const encoded = await encode(packet, { padding: false });
    const decoded = await decode(encoded);

    assert.ok(decoded, 'should decode successfully');
    assert.equal(decoded.version, 1);
    assert.equal(decoded.type, MessageType.Message);
    assert.equal(decoded.ttl, 7);
    assert.equal(decoded.timestamp, 0n);
    assert.equal(bytesToHex(decoded.senderID), 'abcdef0123456789');
    assert.equal(new TextDecoder().decode(decoded.payload), 'Hello, BitChat!');
    assert.equal(decoded.recipientID, undefined);
    assert.equal(decoded.signature, undefined);
  });

  it('directed message with recipient', async () => {
    const payload = hexToBytes('01deadbeef');
    const packet = makePacket({
      type: MessageType.NoiseEncrypted,
      flags: PacketFlag.HasRecipient,
      recipientID: RECIPIENT,
      payload,
    });
    const encoded = await encode(packet, { padding: false });
    const decoded = await decode(encoded);

    assert.ok(decoded);
    assert.equal(decoded.type, MessageType.NoiseEncrypted);
    assert.equal(decoded.flags & PacketFlag.HasRecipient, PacketFlag.HasRecipient);
    assert.ok(decoded.recipientID);
    assert.equal(bytesToHex(decoded.recipientID), '0102030405060708');
    assert.equal(bytesToHex(decoded.payload), '01deadbeef');
  });

  it('message with signature', async () => {
    const payload = new TextEncoder().encode('signed');
    const signature = new Uint8Array(64).fill(0xab);
    const packet = makePacket({
      flags: PacketFlag.HasSignature,
      payload,
      signature,
    });
    const encoded = await encode(packet, { padding: false });
    const decoded = await decode(encoded);

    assert.ok(decoded);
    assert.ok(decoded.signature);
    assert.equal(decoded.signature.length, 64);
    assert.equal(decoded.signature[0], 0xab);
  });

  it('empty payload', async () => {
    const packet = makePacket({ payload: new Uint8Array(0) });
    const encoded = await encode(packet, { padding: false });
    assert.equal(encoded.length, 22); // 14 header + 8 senderID
    const decoded = await decode(encoded);
    assert.ok(decoded);
    assert.equal(decoded.payload.length, 0);
  });

  it('v2 packet round-trip', async () => {
    const payload = new TextEncoder().encode('v2 test');
    const packet = makePacket({ version: 2, payload });
    const encoded = await encode(packet, { padding: false });
    const decoded = await decode(encoded);

    assert.ok(decoded);
    assert.equal(decoded.version, 2);
    assert.equal(new TextDecoder().decode(decoded.payload), 'v2 test');
  });

  it('v2 packet with route', async () => {
    const hop1 = hexToBytes('aabbccddeeff0011');
    const hop2 = hexToBytes('2233445566778899');
    const payload = hexToBytes('deadbeef');
    const packet = makePacket({
      version: 2,
      type: MessageType.NoiseEncrypted,
      flags: PacketFlag.HasRecipient | PacketFlag.HasRoute,
      recipientID: RECIPIENT,
      route: [hop1, hop2],
      payload,
    });
    const encoded = await encode(packet, { padding: false });
    const decoded = await decode(encoded);

    assert.ok(decoded);
    assert.ok(decoded.route);
    assert.equal(decoded.route.length, 2);
    assert.equal(bytesToHex(decoded.route[0]), 'aabbccddeeff0011');
    assert.equal(bytesToHex(decoded.route[1]), '2233445566778899');
  });

  it('padding round-trip', async () => {
    const payload = new TextEncoder().encode('padded');
    const packet = makePacket({ payload });
    const withPadding = await encode(packet, { padding: true });
    const withoutPadding = await encode(packet, { padding: false });
    assert.ok(withPadding.length > withoutPadding.length, 'padding should increase size');
    const decoded = await decode(withPadding);
    assert.ok(decoded);
    assert.equal(new TextDecoder().decode(decoded.payload), 'padded');
  });
});

describe('decode failures', () => {
  it('returns null for empty buffer', async () => {
    assert.equal(await decode(new Uint8Array(0)), null);
  });

  it('returns null for too-short buffer', async () => {
    assert.equal(await decode(new Uint8Array(10)), null);
  });

  it('returns null for unknown version', async () => {
    const bad = new Uint8Array(30).fill(0);
    bad[0] = 3; // version 3 is unsupported
    assert.equal(await decode(bad), null);
  });

  it('returns null for truncated payload', async () => {
    // Build a valid packet then truncate it
    const payload = new TextEncoder().encode('Hello');
    const packet = makePacket({ payload });
    const encoded = await encode(packet, { padding: false });
    const truncated = encoded.subarray(0, encoded.length - 3);
    assert.equal(await decode(truncated), null);
  });
});

describe('hexToBytes / bytesToHex', () => {
  it('round-trips', () => {
    const hex = 'deadbeef0102030405060708';
    assert.equal(bytesToHex(hexToBytes(hex)), hex);
  });

  it('throws on odd-length hex', () => {
    assert.throws(() => hexToBytes('abc'));
  });
});
