import { describe, expect, it } from "vitest";

import { base64urlToBytes, bytesToBase64url } from "../src/base64url.js";
import { buildRevocationList, isJetonRevoked } from "../src/revocation.js";
import { bytesToUuid, isUuid, uuidToBytes } from "../src/uuid.js";

describe("uuid", () => {
  it("round trips a uuid through 16 bytes", () => {
    const id = "55555555-6666-4777-8888-999999999999";
    expect(bytesToUuid(uuidToBytes(id))).toBe(id);
  });

  it("validates the format", () => {
    expect(isUuid("not-a-uuid")).toBe(false);
    expect(() => uuidToBytes("nope")).toThrow();
  });
});

describe("base64url", () => {
  it("round trips bytes of every residue length", () => {
    for (let n = 0; n <= 8; n++) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + 11) & 0xff);
      expect(base64urlToBytes(bytesToBase64url(bytes))).toEqual(bytes);
    }
  });

  it("rejects an invalid character", () => {
    expect(() => base64urlToBytes("abc*")).toThrow();
  });
});

describe("revocation", () => {
  it("detects a revoked token id", () => {
    const revoked = buildRevocationList(["aaaa", "bbbb"]);
    expect(isJetonRevoked("aaaa", revoked)).toBe(true);
    expect(isJetonRevoked("cccc", revoked)).toBe(false);
  });
});
