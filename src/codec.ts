import { bytesToUuid, uuidToBytes } from "./uuid.js";

// Canonical signed message (DAT section 8.6): format version, member technical id,
// token id (for revocation), emission date, and the signing key version. Fixed
// length so the layout is unambiguous and tamper evident once signed.
//
// Layout (42 bytes):
//   [0]      formatVersion  uint8
//   [1..16]  membreId       16 bytes (uuid)
//   [17..32] jetonId        16 bytes (uuid)
//   [33..40] emisLe         uint64 big endian, milliseconds since epoch
//   [41]     versionCle     uint8 (Ed25519 key version)

export const MESSAGE_LENGTH = 42;
export const SIGNATURE_LENGTH = 64;
export const FORMAT_VERSION = 1;

export interface QrTokenFields {
  formatVersion: number;
  membreId: string;
  jetonId: string;
  emisLe: number;
  versionCle: number;
}

export function encodeMessage(fields: QrTokenFields): Uint8Array {
  if (!Number.isInteger(fields.emisLe) || fields.emisLe < 0) {
    throw new Error("emisLe must be a non negative integer (ms since epoch)");
  }
  if (fields.versionCle < 0 || fields.versionCle > 255) {
    throw new Error("versionCle must fit in a byte");
  }
  const message = new Uint8Array(MESSAGE_LENGTH);
  message[0] = fields.formatVersion & 0xff;
  message.set(uuidToBytes(fields.membreId), 1);
  message.set(uuidToBytes(fields.jetonId), 17);
  new DataView(message.buffer).setBigUint64(33, BigInt(fields.emisLe), false);
  message[41] = fields.versionCle & 0xff;
  return message;
}

export function decodeMessage(message: Uint8Array): QrTokenFields {
  if (message.length !== MESSAGE_LENGTH) {
    throw new Error(`message must be ${MESSAGE_LENGTH} bytes`);
  }
  const view = new DataView(message.buffer, message.byteOffset, message.byteLength);
  return {
    formatVersion: message[0] as number,
    membreId: bytesToUuid(message.slice(1, 17)),
    jetonId: bytesToUuid(message.slice(17, 33)),
    emisLe: Number(view.getBigUint64(33, false)),
    versionCle: message[41] as number,
  };
}
