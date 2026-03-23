/**
 * Fixture-based compatibility tests.
 *
 * Loads JSON fixture files from spec-tests/fixtures/ and verifies that:
 *  - should_decode=true fixtures: decode succeeds and re-encodes to the same bytes
 *  - should_decode=false fixtures (malformed): decode returns null
 *
 * Only fixtures with a valid encoded_hex (no spaces, non-empty) are tested as hard vectors.
 * Fixtures with empty or annotated encoded_hex are skipped with a warning.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { decode, encode, hexToBytes, bytesToHex } from '../codec.js';
import {
  encodeAnnouncement, decodeAnnouncement,
  encodePrivateMessage, decodePrivateMessage,
} from '../tlv.js';

const FIXTURES_DIR = resolve(__dirname, '../../../../spec-tests/fixtures');

function loadFixtures(filename: string): unknown[] {
  const fp = join(FIXTURES_DIR, filename);
  if (!existsSync(fp)) return [];
  return JSON.parse(readFileSync(fp, 'utf-8')) as unknown[];
}

type FixtureEntry = {
  id: string;
  description: string;
  type: string;
  should_decode: boolean;
  no_roundtrip?: boolean;
  encoded_hex?: string;
  encoded_raw_hex?: string;
  tlv_input?: Record<string, unknown>;
};

function isValidHex(s: unknown): s is string {
  return typeof s === 'string' && s.length > 0 && /^[0-9a-f]+$/.test(s) && s.length % 2 === 0;
}

const TLV_TYPES = new Set(['announcement', 'private_message_tlv']);

const fixtureFiles = [
  'broadcast_message_v1.json',
  'directed_message_v1.json',
  'malformed_packets.json',
  'announcement_packet.json',
  'private_message_tlv.json',
];

describe('Spec fixture compatibility', () => {
  for (const file of fixtureFiles) {
    const entries = loadFixtures(file) as FixtureEntry[];
    if (entries.length === 0) {
      it.skip(`${file} — not found or empty`);
      continue;
    }

    for (const entry of entries) {
      const hex = entry.encoded_hex ?? entry.encoded_raw_hex;

      if (!isValidHex(hex)) {
        it.skip(`${entry.id} — no valid encoded_hex (illustrative fixture)`);
        continue;
      }

      const isTlvOnly = TLV_TYPES.has(entry.type) && entry.tlv_input !== undefined;

      it(`${entry.id}: ${entry.description}`, async () => {
        const bytes = hexToBytes(hex);

        if (entry.should_decode) {
          if (isTlvOnly) {
            if (entry.type === 'announcement') {
              const decoded = decodeAnnouncement(bytes);
              assert.ok(decoded, `Expected decodeAnnouncement success for ${entry.id}`);
              if (!entry.no_roundtrip) {
                const reEncoded = encodeAnnouncement(decoded);
                assert.equal(bytesToHex(reEncoded), hex, `Round-trip mismatch for ${entry.id}`);
              }
            } else {
              const decoded = decodePrivateMessage(bytes);
              assert.ok(decoded, `Expected decodePrivateMessage success for ${entry.id}`);
              if (!entry.no_roundtrip) {
                const reEncoded = encodePrivateMessage(decoded);
                assert.equal(bytesToHex(reEncoded), hex, `Round-trip mismatch for ${entry.id}`);
              }
            }
          } else {
            const decoded = await decode(bytes);
            assert.ok(decoded, `Expected successful decode for fixture ${entry.id}`);
            if (!entry.no_roundtrip) {
              const reEncoded = await encode(decoded, { padding: false });
              assert.equal(bytesToHex(reEncoded), hex, `Re-encoded bytes do not match fixture ${entry.id}`);
            }
          }
        } else {
          if (isTlvOnly) {
            const result = entry.type === 'announcement'
              ? decodeAnnouncement(bytes)
              : decodePrivateMessage(bytes);
            assert.equal(result, null, `Expected decode failure for ${entry.id}`);
          } else {
            const decoded = await decode(bytes);
            assert.equal(decoded, null, `Expected decode failure for malformed fixture ${entry.id}`);
          }
        }
      });
    }
  }
});
