import { describe, expect, it } from "vitest";

import { decodeMessage, encodeMessage, MESSAGE_LENGTH } from "../src/codec.js";

const FIELDS = {
  formatVersion: 1,
  membreId: "33333333-3333-4333-8333-333333333333",
  jetonId: "44444444-4444-4444-8444-444444444444",
  emisLe: 1_725_000_000_123,
  versionCle: 7,
};

describe("message codec", () => {
  it("round trips all fields exactly", () => {
    const bytes = encodeMessage(FIELDS);
    expect(bytes).toHaveLength(MESSAGE_LENGTH);
    expect(decodeMessage(bytes)).toEqual(FIELDS);
  });

  it("rejects a negative or non integer emisLe", () => {
    expect(() => encodeMessage({ ...FIELDS, emisLe: -1 })).toThrow();
    expect(() => encodeMessage({ ...FIELDS, emisLe: 1.5 })).toThrow();
  });

  it("rejects a message of the wrong length", () => {
    expect(() => decodeMessage(new Uint8Array(10))).toThrow();
  });

  it("preserves a large millisecond timestamp", () => {
    const fields = { ...FIELDS, emisLe: 2_524_608_000_000 };
    expect(decodeMessage(encodeMessage(fields)).emisLe).toBe(2_524_608_000_000);
  });
});
