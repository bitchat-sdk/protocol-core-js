/**
 * @bitchat/protocol-core
 *
 * BitChat binary protocol encode/decode for Node.js.
 *
 * ```ts
 * import { encode, decode, MessageType, encodeAnnouncement, decodeAnnouncement } from '@bitchat/protocol-core';
 * ```
 */

export * from './types.js';
export * from './errors.js';
export { encode, decode, hexToBytes, bytesToHex } from './codec.js';
export {
  encodeAnnouncement,
  decodeAnnouncement,
  encodePrivateMessage,
  decodePrivateMessage,
} from './tlv.js';
export {
  peerIDFromNoiseKey,
  peerIDToBytes,
  peerIDFromBytes,
  nostrGeoDMPeerID,
  nostrGeoChatPeerID,
} from './peer.js';
