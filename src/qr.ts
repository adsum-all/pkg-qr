import { ed25519 } from "@noble/curves/ed25519";

import { base64urlToBytes, bytesToBase64url } from "./base64url.js";
import {
  decodeMessage,
  encodeMessage,
  FORMAT_VERSION,
  MESSAGE_LENGTH,
  SIGNATURE_LENGTH,
  type QrTokenFields,
} from "./codec.js";

// A QR token is base64url(message || signature). The message is signed with the
// private key of its key version; terminals verify offline with the matching
// public key. Any change to the content invalidates the signature.

export interface SignInput {
  membreId: string;
  jetonId: string;
  versionCle: number;
  privateKey: Uint8Array;
  emisLe?: number;
}

export function signQrToken(input: SignInput): string {
  const fields: QrTokenFields = {
    formatVersion: FORMAT_VERSION,
    membreId: input.membreId,
    jetonId: input.jetonId,
    emisLe: input.emisLe ?? Date.now(),
    versionCle: input.versionCle,
  };
  const message = encodeMessage(fields);
  const signature = ed25519.sign(message, input.privateKey);
  const token = new Uint8Array(message.length + signature.length);
  token.set(message, 0);
  token.set(signature, message.length);
  return bytesToBase64url(token);
}

export type VerifyResult =
  | { valid: true; fields: QrTokenFields }
  | { valid: false; reason: "malformed" | "unknown_key_version" | "bad_signature" };

export function verifyQrToken(
  token: string,
  publicKeysByVersion: Readonly<Record<number, Uint8Array>>,
): VerifyResult {
  let raw: Uint8Array;
  try {
    raw = base64urlToBytes(token);
  } catch {
    return { valid: false, reason: "malformed" };
  }
  if (raw.length !== MESSAGE_LENGTH + SIGNATURE_LENGTH) {
    return { valid: false, reason: "malformed" };
  }
  const message = raw.slice(0, MESSAGE_LENGTH);
  const signature = raw.slice(MESSAGE_LENGTH);
  let fields: QrTokenFields;
  try {
    fields = decodeMessage(message);
  } catch {
    return { valid: false, reason: "malformed" };
  }
  const publicKey = publicKeysByVersion[fields.versionCle];
  if (!publicKey) {
    return { valid: false, reason: "unknown_key_version" };
  }
  const ok = ed25519.verify(signature, message, publicKey);
  return ok ? { valid: true, fields } : { valid: false, reason: "bad_signature" };
}
