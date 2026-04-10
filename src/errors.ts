/**
 * Error taxonomy for @bitchat-sdk/protocol-core.
 *
 * All errors extend `BitchatProtocolError` so callers can catch at any granularity.
 */

export class BitchatProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BitchatProtocolError';
  }
}

/** Input buffer is too short to contain a valid packet. */
export class PacketTooShortError extends BitchatProtocolError {
  constructor(received: number, minimum: number) {
    super(`Packet too short: ${received} bytes (minimum ${minimum})`);
    this.name = 'PacketTooShortError';
  }
}

/** Version field is not 1 or 2. */
export class UnsupportedVersionError extends BitchatProtocolError {
  constructor(version: number) {
    super(`Unsupported protocol version: ${version}`);
    this.name = 'UnsupportedVersionError';
  }
}

/** A required field is truncated or missing. */
export class TruncatedFieldError extends BitchatProtocolError {
  constructor(field: string) {
    super(`Truncated field: ${field}`);
    this.name = 'TruncatedFieldError';
  }
}

/** Payload decompression failed. */
export class DecompressionError extends BitchatProtocolError {
  constructor(cause?: unknown) {
    super(`Payload decompression failed${cause ? `: ${cause}` : ''}`);
    this.name = 'DecompressionError';
  }
}

/** Compression ratio exceeded the security limit (50,000:1). */
export class SuspiciousCompressionRatioError extends BitchatProtocolError {
  constructor(ratio: number) {
    super(`Suspicious compression ratio: ${ratio.toFixed(0)}:1 (limit 50000:1)`);
    this.name = 'SuspiciousCompressionRatioError';
  }
}

/** Payload length exceeds the maximum allowed. */
export class PayloadTooLargeError extends BitchatProtocolError {
  constructor(length: number, maximum: number) {
    super(`Payload length ${length} exceeds maximum allowed (${maximum})`);
    this.name = 'PayloadTooLargeError';
  }
}

/** TLV payload could not be decoded. */
export class TLVDecodeError extends BitchatProtocolError {
  constructor(reason: string) {
    super(`TLV decode error: ${reason}`);
    this.name = 'TLVDecodeError';
  }
}

/** TLV payload could not be encoded (field too long etc.). */
export class TLVEncodeError extends BitchatProtocolError {
  constructor(reason: string) {
    super(`TLV encode error: ${reason}`);
    this.name = 'TLVEncodeError';
  }
}
