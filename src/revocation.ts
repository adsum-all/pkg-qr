// Offline revocation. Terminals receive the set of revoked token ids at each
// synchronization and reject a scanned token whose jetonId is revoked, even if
// its signature is valid (DAT section 8.6).

export type RevocationList = ReadonlySet<string>;

export function buildRevocationList(jetonIds: Iterable<string>): RevocationList {
  return new Set(jetonIds);
}

export function isJetonRevoked(jetonId: string, revoked: RevocationList): boolean {
  return revoked.has(jetonId);
}
