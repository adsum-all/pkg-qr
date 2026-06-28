import { describe, expect, it } from "vitest";

import { base64urlToBytes, bytesToBase64url } from "../src/base64url.js";
import { generateKeyPair } from "../src/keys.js";
import { signQrToken, verifyQrToken } from "../src/qr.js";

const MEMBRE = "11111111-1111-4111-8111-111111111111";
const JETON = "22222222-2222-4222-8222-222222222222";

describe("signQrToken and verifyQrToken", () => {
  it("verifies a token signed with the matching key version", () => {
    const kp = generateKeyPair();
    const token = signQrToken({
      membreId: MEMBRE,
      jetonId: JETON,
      versionCle: 1,
      privateKey: kp.privateKey,
      emisLe: 1_700_000_000_000,
    });
    const result = verifyQrToken(token, { 1: kp.publicKey });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.fields.membreId).toBe(MEMBRE);
      expect(result.fields.jetonId).toBe(JETON);
      expect(result.fields.versionCle).toBe(1);
      expect(result.fields.emisLe).toBe(1_700_000_000_000);
    }
  });

  it("rejects a token whose content was tampered with", () => {
    const kp = generateKeyPair();
    const token = signQrToken({ membreId: MEMBRE, jetonId: JETON, versionCle: 1, privateKey: kp.privateKey });
    const bytes = base64urlToBytes(token);
    bytes[5] = (bytes[5] as number) ^ 0xff; // flip a byte inside the member id
    const tampered = bytesToBase64url(bytes);
    const result = verifyQrToken(tampered, { 1: kp.publicKey });
    expect(result).toEqual({ valid: false, reason: "bad_signature" });
  });

  it("rejects a token signed by a different key", () => {
    const signer = generateKeyPair();
    const other = generateKeyPair();
    const token = signQrToken({ membreId: MEMBRE, jetonId: JETON, versionCle: 1, privateKey: signer.privateKey });
    const result = verifyQrToken(token, { 1: other.publicKey });
    expect(result).toEqual({ valid: false, reason: "bad_signature" });
  });

  it("reports an unknown key version when no public key matches", () => {
    const kp = generateKeyPair();
    const token = signQrToken({ membreId: MEMBRE, jetonId: JETON, versionCle: 2, privateKey: kp.privateKey });
    const result = verifyQrToken(token, { 1: kp.publicKey });
    expect(result).toEqual({ valid: false, reason: "unknown_key_version" });
  });

  it("selects the correct public key when several versions exist", () => {
    const v1 = generateKeyPair();
    const v2 = generateKeyPair();
    const token = signQrToken({ membreId: MEMBRE, jetonId: JETON, versionCle: 2, privateKey: v2.privateKey });
    const result = verifyQrToken(token, { 1: v1.publicKey, 2: v2.publicKey });
    expect(result.valid).toBe(true);
  });

  it("reports malformed input", () => {
    const kp = generateKeyPair();
    expect(verifyQrToken("not a token!!", { 1: kp.publicKey })).toEqual({ valid: false, reason: "malformed" });
    expect(verifyQrToken("AAAA", { 1: kp.publicKey })).toEqual({ valid: false, reason: "malformed" });
  });
});
