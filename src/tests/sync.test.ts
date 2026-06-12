/**
 * Tests for the REQUEST_SYNC TLV codec (sync.ts).
 *
 * The hex vectors here are the canonical cross-language golden vectors —
 * identical assertions exist in BitchatProtocol (Swift), bitchat-android-sdk
 * (Kotlin), and bitchat-protocol (Python), and they are exported to
 * spec-tests/fixtures/request_sync.json by spec-tests/scripts/generate.py.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { hexToBytes, bytesToHex } from '../codec.js';
import { MessageType, RequestSyncPacket } from '../types.js';
import { TLVEncodeError } from '../errors.js';
import {
  MAX_P,
  SyncTypeFlag,
  encodeRequestSync,
  decodeRequestSync,
  syncTypeFlagsFromMessageTypes,
  syncTypeFlagsToMessageTypes,
} from '../sync.js';

const GOLDEN_BASIC = '01000113020004000800000300050102030405';
const GOLDEN_MAX_P = '01000120020004ffffffff03000100';
const GOLDEN_EXTENDED =
  '0100010802000400000100030001ff0400010305000800000000000f4240060003616263';

function encodedWithP(p: number): Uint8Array {
  return encodeRequestSync({ p, m: 1024, data: Uint8Array.of(0x00) });
}

describe('RequestSync golden vectors', () => {
  it('encodes the basic vector', () => {
    const packet: RequestSyncPacket = {
      p: 19,
      m: 1 << 19,
      data: Uint8Array.of(1, 2, 3, 4, 5),
    };
    assert.equal(bytesToHex(encodeRequestSync(packet)), GOLDEN_BASIC);
  });

  it('decodes the basic vector', () => {
    const decoded = decodeRequestSync(hexToBytes(GOLDEN_BASIC));
    assert.ok(decoded);
    assert.equal(decoded.p, 19);
    assert.equal(decoded.m, 1 << 19);
    assert.deepEqual(decoded.data, Uint8Array.of(1, 2, 3, 4, 5));
    assert.equal(decoded.types, undefined);
    assert.equal(decoded.sinceTimestamp, undefined);
    assert.equal(decoded.fragmentIdFilter, undefined);
  });

  it('round-trips the max-p vector', () => {
    const packet: RequestSyncPacket = { p: MAX_P, m: 0xffff_ffff, data: Uint8Array.of(0) };
    assert.equal(bytesToHex(encodeRequestSync(packet)), GOLDEN_MAX_P);
    const decoded = decodeRequestSync(hexToBytes(GOLDEN_MAX_P));
    assert.ok(decoded);
    assert.equal(decoded.p, MAX_P);
    assert.equal(decoded.m, 0xffff_ffff);
  });

  it('round-trips the extended vector', () => {
    const packet: RequestSyncPacket = {
      p: 8,
      m: 256,
      data: Uint8Array.of(0xff),
      types: syncTypeFlagsFromMessageTypes([MessageType.Announce, MessageType.Message]),
      sinceTimestamp: 1_000_000n,
      fragmentIdFilter: 'abc',
    };
    assert.equal(bytesToHex(encodeRequestSync(packet)), GOLDEN_EXTENDED);

    const decoded = decodeRequestSync(hexToBytes(GOLDEN_EXTENDED));
    assert.ok(decoded);
    assert.equal(decoded.p, 8);
    assert.equal(decoded.m, 256);
    assert.deepEqual(decoded.data, Uint8Array.of(0xff));
    assert.equal(decoded.types, SyncTypeFlag.Announce | SyncTypeFlag.Message);
    assert.equal(decoded.sinceTimestamp, 1_000_000n);
    assert.equal(decoded.fragmentIdFilter, 'abc');
    assert.deepEqual(syncTypeFlagsToMessageTypes(decoded.types!), [
      MessageType.Announce,
      MessageType.Message,
    ]);
  });
});

describe('RequestSync validation', () => {
  it('rejects p = 0', () => {
    assert.equal(decodeRequestSync(encodedWithP(0)), null);
  });

  it('rejects p above MAX_P', () => {
    assert.equal(decodeRequestSync(encodedWithP(MAX_P + 1)), null);
  });

  it('accepts p at both bounds', () => {
    assert.ok(decodeRequestSync(encodedWithP(1)));
    assert.ok(decodeRequestSync(encodedWithP(MAX_P)));
  });

  it('rejects m = 0', () => {
    const encoded = encodeRequestSync({ p: 1, m: 0, data: Uint8Array.of(0) });
    assert.equal(decodeRequestSync(encoded), null);
  });

  it('rejects missing data TLV', () => {
    assert.equal(decodeRequestSync(hexToBytes('0100011302000400080000')), null);
  });

  it('rejects truncated TLV and empty input', () => {
    assert.equal(decodeRequestSync(hexToBytes('010001')), null);
    assert.equal(decodeRequestSync(new Uint8Array(0)), null);
  });

  it('rejects oversized filter data, configurable cap', () => {
    const encoded = encodeRequestSync({ p: 19, m: 1 << 19, data: new Uint8Array(1025) });
    assert.equal(decodeRequestSync(encoded), null);
    assert.ok(decodeRequestSync(encoded, 2048));
  });

  it('skips unknown TLVs (forward-compatible)', () => {
    const decoded = decodeRequestSync(hexToBytes('7f0002beef' + GOLDEN_BASIC));
    assert.ok(decoded);
    assert.equal(decoded.p, 19);
    assert.equal(decoded.m, 1 << 19);
  });

  it('skips fragment filter with invalid UTF-8', () => {
    const decoded = decodeRequestSync(hexToBytes(GOLDEN_BASIC + '060002fffe'));
    assert.ok(decoded);
    assert.equal(decoded.fragmentIdFilter, undefined);
  });

  it('throws on m out of uint32 range', () => {
    assert.throws(
      () => encodeRequestSync({ p: 1, m: 2 ** 32, data: Uint8Array.of(0) }),
      TLVEncodeError,
    );
  });

  it('omits types when zero (matches Swift nil toData)', () => {
    const encoded = encodeRequestSync({
      p: 19,
      m: 1 << 19,
      data: Uint8Array.of(1, 2, 3, 4, 5),
      types: 0n,
    });
    assert.equal(bytesToHex(encoded), GOLDEN_BASIC);
  });

  it('masks sync-type flags to 56 bits', () => {
    assert.deepEqual(syncTypeFlagsToMessageTypes(1n << 60n), []);
  });
});
