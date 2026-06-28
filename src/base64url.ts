// Portable base64url for bytes, without Buffer or btoa, so it runs the same on
// Node, the browser and Capacitor (the QR is read on devices).

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) {
  LOOKUP[ALPHABET[i] as string] = i;
}

export function bytesToBase64url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] as number;
    const b1 = i + 1 < bytes.length ? (bytes[i + 1] as number) : undefined;
    const b2 = i + 2 < bytes.length ? (bytes[i + 2] as number) : undefined;
    out += ALPHABET[b0 >> 2];
    out += ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    if (b1 === undefined) break;
    out += ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    if (b2 === undefined) break;
    out += ALPHABET[b2 & 0x3f];
  }
  return out;
}

export function base64urlToBytes(value: string): Uint8Array {
  const clean = value.trim();
  for (const ch of clean) {
    if (!(ch in LOOKUP)) {
      throw new Error("invalid base64url character");
    }
  }
  const out: number[] = [];
  for (let i = 0; i < clean.length; i += 4) {
    const c0 = LOOKUP[clean[i] as string] as number;
    const c1 = LOOKUP[clean[i + 1] as string] as number;
    const c2 = i + 2 < clean.length ? (LOOKUP[clean[i + 2] as string] as number) : undefined;
    const c3 = i + 3 < clean.length ? (LOOKUP[clean[i + 3] as string] as number) : undefined;
    out.push((c0 << 2) | (c1 >> 4));
    if (c2 !== undefined) out.push(((c1 & 0x0f) << 4) | (c2 >> 2));
    if (c3 !== undefined) out.push(((c2 as number & 0x03) << 6) | c3);
  }
  return Uint8Array.from(out);
}
