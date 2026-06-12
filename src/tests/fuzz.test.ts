/**
 * Fuzz and stress tests for the BitChat binary protocol codec.
 *
 * Verifies that:
 *   - decode() never throws on any input (only returns null)
 *   - encode/decode round-trips are lossless
 *   - adversarial inputs (truncations, bit flips, bombs) are safely rejected
 *   - high-volume throughput produces correct results
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';

import { encode, decode, hexToBytes } from '../codec.js';
import { MessageType, type BitchatPacket, type RequestSyncPacket } from '../types.js';
import { encodeRequestSync, decodeRequestSync, MAX_P } from '../sync.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function validPacket(overrides: Partial<BitchatPacket> = {}): BitchatPacket {
  return {
    version: 1,
    type: MessageType.Message,
    ttl: 7,
    timestamp: 1_711_123_456_789n,
    flags: 0,
    senderID: hexToBytes('0102030405060708'),
    payload: new TextEncoder().encode('hello fuzz'),
    isRSR: false,
    ...overrides,
  };
}

/** Deterministic LCG pseudo-random number generator (seed → sequence). */
function* lcg(seed: number): Generator<number> {
  let s = seed >>> 0;
  while (true) {
    s = (Math.imul(1_664_525, s) + 1_013_904_223) >>> 0;
    yield s;
  }
}

function randBytes(rng: Generator<number>, n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = rng.next().value & 0xff;
  return out;
}

async function wire(pkt: BitchatPacket): Promise<Uint8Array> {
  const result = await encode(pkt, { padding: false });
  assert.ok(result, 'encode should succeed for valid packet');
  return result;
}

// ---------------------------------------------------------------------------
// Basic rejection
// ---------------------------------------------------------------------------

describe('fuzz: basic rejection', () => {
  it('returns null for empty bytes', async () => {
    assert.equal(await decode(new Uint8Array(0)), null);
  });

  it('returns null for single byte (all values)', async () => {
    for (let b = 0; b < 256; b++) {
      assert.equal(await decode(new Uint8Array([b])), null, `byte 0x${b.toString(16)}`);
    }
  });

  it('returns null for all-zero buffers', async () => {
    for (const n of [0, 1, 7, 14, 21, 22, 64]) {
      assert.equal(await decode(new Uint8Array(n)), null, `length ${n}`);
    }
  });

  it('returns null for invalid version bytes', async () => {
    const base = await wire(validPacket());
    for (const bad of [0, 3, 10, 127, 255]) {
      const mutated = new Uint8Array(base);
      mutated[0] = bad;
      assert.equal(await decode(mutated), null, `version=${bad}`);
    }
  });

  it('returns null when claimed payload length exceeds data', async () => {
    // v1 header with payload length = 60000 but only 30 extra bytes
    const buf = new Uint8Array(3 + 8 + 1 + 2 + 8 + 30);
    buf[0] = 1;   // version
    buf[1] = 2;   // type
    buf[2] = 7;   // ttl
    // timestamp bytes 3..10: leave as zeros
    buf[11] = 0;  // flags
    buf[12] = 0xEA; // payload length MSB: 60000 = 0xEA60
    buf[13] = 0x60; // payload length LSB
    // sender ID bytes 14..21: zeros
    // remaining 30 bytes of "payload"
    assert.equal(await decode(buf), null);
  });
});

// ---------------------------------------------------------------------------
// Truncation fuzzing
// ---------------------------------------------------------------------------

describe('fuzz: truncation', () => {
  it('every prefix of a valid packet returns null', async () => {
    const w = await wire(validPacket());
    for (let i = 0; i < w.length; i++) {
      const prefix = w.slice(0, i);
      const result = await decode(prefix);
      assert.equal(result, null, `prefix length ${i} should return null`);
    }
  });

  it('full packet decodes correctly', async () => {
    const pkt = validPacket();
    const result = await decode(await wire(pkt));
    assert.ok(result);
    assert.deepEqual(result.payload, pkt.payload);
    assert.deepEqual(result.senderID, pkt.senderID);
  });

  it('every prefix of v2 packet returns null', async () => {
    const pkt = validPacket({ version: 2, payload: new TextEncoder().encode('v2 fuzz') });
    const w = await wire(pkt);
    for (let i = 0; i < w.length; i++) {
      assert.equal(await decode(w.slice(0, i)), null, `v2 prefix length ${i}`);
    }
  });
});

// ---------------------------------------------------------------------------
// Bit-flip fuzzing
// ---------------------------------------------------------------------------

describe('fuzz: bit flips', () => {
  it('single bit flip never throws', async () => {
    const w = await wire(validPacket({ payload: new TextEncoder().encode('bitflip') }));
    for (let byteIdx = 0; byteIdx < w.length; byteIdx++) {
      for (let bit = 0; bit < 8; bit++) {
        const flipped = new Uint8Array(w);
        flipped[byteIdx] ^= 1 << bit;
        try {
          await decode(flipped);
        } catch (err) {
          assert.fail(`decode() threw after flipping byte ${byteIdx} bit ${bit}: ${err}`);
        }
      }
    }
  });

  it('random multi-byte mutations never throw (50k iterations)', async () => {
    const w = await wire(validPacket());
    const rng = lcg(0xdeadbeef);
    for (let iter = 0; iter < 50_000; iter++) {
      const mutated = new Uint8Array(w);
      const mutations = (rng.next().value % 4) + 1;
      for (let m = 0; m < mutations; m++) {
        const idx = rng.next().value % mutated.length;
        mutated[idx] = rng.next().value & 0xff;
      }
      try {
        await decode(mutated);
      } catch (err) {
        assert.fail(`decode() threw at iteration ${iter}: ${err}`);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Random input fuzzing
// ---------------------------------------------------------------------------

describe('fuzz: random inputs', () => {
  for (const seed of [0, 1, 42, 999, 0xcafe]) {
    it(`random bytes never throw (seed=${seed}, 10k iterations)`, async () => {
      const rng = lcg(seed);
      for (let i = 0; i < 10_000; i++) {
        const n = rng.next().value % 257;
        const data = randBytes(rng, n);
        try {
          await decode(data);
        } catch (err) {
          assert.fail(`decode() threw on ${n}-byte random input (seed=${seed}, iter=${i}): ${err}`);
        }
      }
    });
  }

  it('large random blobs never throw (200 blobs up to 8KB)', async () => {
    const rng = lcg(0xabcd);
    for (let i = 0; i < 200; i++) {
      const n = (rng.next().value % 7000) + 1000;
      const data = randBytes(rng, n);
      try {
        await decode(data);
      } catch (err) {
        assert.fail(`decode() threw on ${n}-byte blob: ${err}`);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Decompression bomb
// ---------------------------------------------------------------------------

describe('fuzz: decompression bomb', () => {
  function makeCompressedV1Packet(originalSize: number, compressed: Uint8Array): Uint8Array {
    // IS_COMPRESSED flag = 0x04
    // payload in wire = originalSize(2 BE) + compressed
    const clampedSize = Math.min(originalSize, 0xffff);
    const payloadData = new Uint8Array(2 + compressed.length);
    payloadData[0] = (clampedSize >> 8) & 0xff;
    payloadData[1] = clampedSize & 0xff;
    payloadData.set(compressed, 2);

    const payloadLen = payloadData.length;
    const buf = new Uint8Array(3 + 8 + 1 + 2 + 8 + payloadLen);
    let off = 0;
    buf[off++] = 1;   // version
    buf[off++] = 2;   // type
    buf[off++] = 7;   // ttl
    off += 8;         // timestamp (zeros)
    buf[off++] = 0x04; // flags: IS_COMPRESSED
    buf[off++] = (payloadLen >> 8) & 0xff;
    buf[off++] = payloadLen & 0xff;
    off += 8;         // sender ID (zeros)
    buf.set(payloadData, off);
    return buf;
  }

  it('legitimate compression round-trips', async () => {
    const original = new Uint8Array(1024).fill(0x42); // 1 KB of 0x42
    const compressed = new Uint8Array(deflateRawSync(original));
    const raw = makeCompressedV1Packet(original.length, compressed);
    const result = await decode(raw);
    assert.ok(result, 'should decode legitimately compressed packet');
    assert.deepEqual(result.payload, original);
  });

  it('bomb ratio > 50000:1 returns null', async () => {
    const compressed = new Uint8Array(deflateRawSync(new Uint8Array(100).fill(0)));
    const bombOriginalSize = 50_001 * compressed.length + 1;
    // Clamp to uint16 max for v1
    const raw = makeCompressedV1Packet(
      Math.min(bombOriginalSize, 0xffff),
      compressed,
    );
    // Either rejected as bomb or decompressed length mismatch → null
    const result = await decode(raw);
    assert.equal(result, null);
  });

  it('claimed original size mismatch returns null', async () => {
    const original = new TextEncoder().encode('hello world hello world');
    const compressed = new Uint8Array(deflateRawSync(original));
    // Claim wrong original size
    const raw = makeCompressedV1Packet(original.length + 100, compressed);
    assert.equal(await decode(raw), null);
  });
});

// ---------------------------------------------------------------------------
// Edge-case values
// ---------------------------------------------------------------------------

describe('fuzz: edge-case field values', () => {
  it('max TTL (255) round-trips', async () => {
    const pkt = validPacket({ ttl: 255 });
    const result = await decode(await wire(pkt));
    assert.ok(result);
    assert.equal(result.ttl, 255);
  });

  it('zero TTL round-trips', async () => {
    const pkt = validPacket({ ttl: 0 });
    const result = await decode(await wire(pkt));
    assert.ok(result);
    assert.equal(result.ttl, 0);
  });

  it('max timestamp round-trips', async () => {
    const pkt = validPacket({ timestamp: 2n ** 64n - 1n });
    const result = await decode(await wire(pkt));
    assert.ok(result);
    assert.equal(result.timestamp, 2n ** 64n - 1n);
  });

  it('zero timestamp round-trips', async () => {
    const pkt = validPacket({ timestamp: 0n });
    const result = await decode(await wire(pkt));
    assert.ok(result);
    assert.equal(result.timestamp, 0n);
  });

  it('empty payload round-trips', async () => {
    const pkt = validPacket({ payload: new Uint8Array(0) });
    const result = await decode(await wire(pkt));
    assert.ok(result);
    assert.equal(result.payload.length, 0);
  });

  it('all MessageType values encode and decode', async () => {
    for (const [name, type] of Object.entries(MessageType)) {
      if (typeof type !== 'number') continue;
      const pkt = validPacket({ type });
      const result = await decode(await wire(pkt));
      assert.ok(result, `MessageType.${name} (${type}) should decode`);
      assert.equal(result.type, type);
    }
  });
});

// ---------------------------------------------------------------------------
// RequestSync TLV fuzzing
// ---------------------------------------------------------------------------

describe('fuzz: RequestSync decoder', () => {
  for (const seed of [0, 7, 0xfeed]) {
    it(`random bytes never throw (seed=${seed}, 10k iterations)`, () => {
      const rng = lcg(seed);
      for (let i = 0; i < 10_000; i++) {
        const n = rng.next().value % 257;
        const data = randBytes(rng, n);
        try {
          decodeRequestSync(data);
        } catch (err) {
          assert.fail(`decodeRequestSync threw on ${n}-byte input (seed=${seed}, iter=${i}): ${err}`);
        }
      }
    });
  }

  it('every prefix of a valid encoding never throws', () => {
    const w = encodeRequestSync({
      p: 19,
      m: 1 << 19,
      data: Uint8Array.of(1, 2, 3, 4, 5),
      types: 3n,
      sinceTimestamp: 1_000_000n,
      fragmentIdFilter: 'frag-01',
    });
    for (let i = 0; i < w.length; i++) {
      try {
        decodeRequestSync(w.slice(0, i));
      } catch (err) {
        assert.fail(`decodeRequestSync threw on prefix length ${i}: ${err}`);
      }
    }
  });

  it('single bit flips never throw', () => {
    const w = encodeRequestSync({ p: 19, m: 1 << 19, data: randBytes(lcg(5), 64) });
    for (let byteIdx = 0; byteIdx < w.length; byteIdx++) {
      for (let bit = 0; bit < 8; bit++) {
        const flipped = new Uint8Array(w);
        flipped[byteIdx] ^= 1 << bit;
        try {
          decodeRequestSync(flipped);
        } catch (err) {
          assert.fail(`decodeRequestSync threw after flipping byte ${byteIdx} bit ${bit}: ${err}`);
        }
      }
    }
  });

  it('10_000 random packets round-trip without loss', () => {
    const rng = lcg(0x5eed);
    for (let i = 0; i < 10_000; i++) {
      const pkt: RequestSyncPacket = {
        p: (rng.next().value % MAX_P) + 1,
        m: (rng.next().value % 0xffff_fffe) + 1,
        data: randBytes(rng, rng.next().value % 128),
      };
      if (rng.next().value % 2) pkt.types = BigInt(rng.next().value & 0xff || 1);
      if (rng.next().value % 2) pkt.sinceTimestamp = BigInt(rng.next().value) << BigInt(rng.next().value % 32);
      if (rng.next().value % 2) pkt.fragmentIdFilter = `frag-${rng.next().value % 1000}`;

      const w = encodeRequestSync(pkt);
      const result = decodeRequestSync(w);
      assert.ok(result, `decode failed at iteration ${i}`);
      assert.equal(result.p, pkt.p, `p mismatch at iteration ${i}`);
      assert.equal(result.m, pkt.m, `m mismatch at iteration ${i}`);
      assert.deepEqual(result.data, pkt.data, `data mismatch at iteration ${i}`);
      assert.equal(result.types, pkt.types, `types mismatch at iteration ${i}`);
      assert.equal(result.sinceTimestamp, pkt.sinceTimestamp, `since mismatch at iteration ${i}`);
      assert.equal(result.fragmentIdFilter, pkt.fragmentIdFilter, `fragment mismatch at iteration ${i}`);
    }
  });

  it('rejects non-integer p on encode', () => {
    for (const p of [NaN, 3.7, Infinity, -Infinity]) {
      assert.throws(() => encodeRequestSync({ p, m: 1024, data: Uint8Array.of(0) }));
    }
  });
});

// ---------------------------------------------------------------------------
// Stress: high-volume round-trip
// ---------------------------------------------------------------------------

describe('stress: high-volume round-trip', () => {
  it('10_000 random packets round-trip without loss', async () => {
    const rng = lcg(0x1337);
    for (let i = 0; i < 10_000; i++) {
      const payloadSize = rng.next().value % 65;
      const pkt = validPacket({
        type: (rng.next().value % 0x22) + 1,
        ttl: rng.next().value % 8,
        timestamp: BigInt(rng.next().value) * BigInt(rng.next().value),
        senderID: randBytes(rng, 8),
        payload: randBytes(rng, payloadSize),
      });
      const w = await encode(pkt, { padding: false });
      assert.ok(w, `encode failed at iteration ${i}`);
      const result = await decode(w);
      assert.ok(result, `decode failed at iteration ${i}`);
      assert.equal(result.type, pkt.type);
      assert.equal(result.ttl, pkt.ttl);
      assert.equal(result.timestamp, pkt.timestamp);
      assert.deepEqual(result.senderID, pkt.senderID);
      assert.deepEqual(result.payload, pkt.payload);
    }
  });

  it('32KB compressible payload round-trips', async () => {
    const payload = new Uint8Array(32_768);
    for (let i = 0; i < payload.length; i++) payload[i] = i & 0xff;
    const pkt = validPacket({ payload });
    const w = await encode(pkt, { padding: false });
    assert.ok(w);
    assert.ok(w.length < payload.length, 'compression should reduce size');
    const result = await decode(w);
    assert.ok(result);
    assert.deepEqual(result.payload, payload);
  });

  it('padded encode/decode round-trips', async () => {
    const pkt = validPacket({ payload: new TextEncoder().encode('padded stress test') });
    const wPadded = await encode(pkt, { padding: true });
    const wBare = await encode(pkt, { padding: false });
    assert.ok(wPadded && wBare);
    assert.ok(wPadded.length >= wBare.length);
    const result = await decode(wPadded);
    assert.ok(result);
    assert.deepEqual(result.payload, pkt.payload);
  });
});
