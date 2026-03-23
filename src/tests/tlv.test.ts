import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { encodeAnnouncement, decodeAnnouncement, encodePrivateMessage, decodePrivateMessage } from '../tlv.js';

const ZERO_KEY = new Uint8Array(32);
const KEY_B = new Uint8Array(32).fill(0xab);

describe('AnnouncementPacket TLV', () => {
  it('round-trip minimal (no neighbors)', () => {
    const original = {
      nickname: 'Alice',
      noisePublicKey: ZERO_KEY,
      signingPublicKey: KEY_B,
    };
    const encoded = encodeAnnouncement(original);
    assert.ok(encoded.length > 0);
    const decoded = decodeAnnouncement(encoded);
    assert.ok(decoded);
    assert.equal(decoded.nickname, 'Alice');
    assert.deepEqual(decoded.noisePublicKey, ZERO_KEY);
    assert.deepEqual(decoded.signingPublicKey, KEY_B);
    assert.equal(decoded.directNeighbors, undefined);
  });

  it('round-trip with neighbors', () => {
    const n1 = Uint8Array.from([1,2,3,4,5,6,7,8]);
    const n2 = Uint8Array.from([9,10,11,12,13,14,15,16]);
    const original = {
      nickname: 'Bob',
      noisePublicKey: ZERO_KEY,
      signingPublicKey: ZERO_KEY,
      directNeighbors: [n1, n2],
    };
    const decoded = decodeAnnouncement(encodeAnnouncement(original));
    assert.ok(decoded);
    assert.ok(decoded.directNeighbors);
    assert.equal(decoded.directNeighbors.length, 2);
    assert.deepEqual(decoded.directNeighbors[0], n1);
    assert.deepEqual(decoded.directNeighbors[1], n2);
  });

  it('handles unicode nickname', () => {
    const original = {
      nickname: 'こんにちは',
      noisePublicKey: ZERO_KEY,
      signingPublicKey: ZERO_KEY,
    };
    const decoded = decodeAnnouncement(encodeAnnouncement(original));
    assert.ok(decoded);
    assert.equal(decoded.nickname, 'こんにちは');
  });

  it('skips unknown TLV tags (forward-compatible)', () => {
    const original = {
      nickname: 'Alice',
      noisePublicKey: ZERO_KEY,
      signingPublicKey: ZERO_KEY,
    };
    const valid = encodeAnnouncement(original);
    // Insert an unknown TLV (tag=0xff, len=3, value=0x112233) before the known fields
    const unknown = Uint8Array.from([0xff, 0x03, 0x11, 0x22, 0x33]);
    const withUnknown = new Uint8Array(unknown.length + valid.length);
    withUnknown.set(unknown);
    withUnknown.set(valid, unknown.length);
    const decoded = decodeAnnouncement(withUnknown);
    assert.ok(decoded, 'should decode despite unknown tag');
    assert.equal(decoded.nickname, 'Alice');
  });

  it('returns null when required fields missing', () => {
    // Only nickname TLV, no keys
    const partial = Uint8Array.from([0x01, 0x05, 0x41, 0x6c, 0x69, 0x63, 0x65]);
    assert.equal(decodeAnnouncement(partial), null);
  });

  it('returns null on truncated TLV', () => {
    const original = {
      nickname: 'Alice',
      noisePublicKey: ZERO_KEY,
      signingPublicKey: ZERO_KEY,
    };
    const encoded = encodeAnnouncement(original);
    assert.equal(decodeAnnouncement(encoded.subarray(0, 4)), null);
  });
});

describe('PrivateMessagePacket TLV', () => {
  it('round-trip basic', () => {
    const original = { messageID: 'msg-001', content: 'Hello' };
    const decoded = decodePrivateMessage(encodePrivateMessage(original));
    assert.ok(decoded);
    assert.equal(decoded.messageID, 'msg-001');
    assert.equal(decoded.content, 'Hello');
  });

  it('round-trip unicode content', () => {
    const original = { messageID: 'u-1', content: 'こんにちは' };
    const decoded = decodePrivateMessage(encodePrivateMessage(original));
    assert.ok(decoded);
    assert.equal(decoded.content, 'こんにちは');
  });

  it('round-trip empty content', () => {
    const original = { messageID: 'empty', content: '' };
    const decoded = decodePrivateMessage(encodePrivateMessage(original));
    assert.ok(decoded);
    assert.equal(decoded.content, '');
  });

  it('returns null on unknown tag (strict)', () => {
    const original = { messageID: 'id', content: 'hi' };
    const valid = encodePrivateMessage(original);
    // Prepend unknown tag
    const bad = Uint8Array.from([0xff, 0x01, 0xaa, ...valid]);
    assert.equal(decodePrivateMessage(bad), null);
  });

  it('returns null when fields missing', () => {
    // Only messageID, no content
    const onlyID = encodePrivateMessage({ messageID: 'x', content: '' }).subarray(0, 4);
    assert.equal(decodePrivateMessage(onlyID), null);
  });
});
