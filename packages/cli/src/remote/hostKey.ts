import { createHash } from 'node:crypto';

/*
 * Host key check for the app SSH proxy, as the cf CLI does it
 * (`util/clissh/ssh.go` `fingerprintCallback`): the format of the published
 * fingerprint is told by its length, and the received key (the SSH wire
 * encoding of the public key) is hashed the same way and compared. Unlike
 * the cf CLI, an empty or unknown fingerprint is never accepted.
 */

export type FingerprintFormat = 'sha256-hex' | 'sha256-base64' | 'sha1-hex' | 'md5-hex';

/** Lengths from `util/clissh/ssh.go`: hex with colons for MD5 and SHA-1, plain hex or unpadded base64 for SHA-256. */
const FORMATS: Readonly<Record<number, FingerprintFormat>> = {
  64: 'sha256-hex',
  43: 'sha256-base64',
  59: 'sha1-hex',
  47: 'md5-hex',
};

export function fingerprintFormat(expected: string): FingerprintFormat | null {
  return FORMATS[expected.length] ?? null;
}

function colonHex(digest: Buffer): string {
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join(':');
}

export function hostKeyFingerprint(key: Buffer, format: FingerprintFormat): string {
  switch (format) {
    case 'sha256-hex':
      return createHash('sha256').update(key).digest('hex');
    case 'sha256-base64':
      return createHash('sha256').update(key).digest('base64').replace(/=+$/, '');
    case 'sha1-hex':
      return colonHex(createHash('sha1').update(key).digest());
    case 'md5-hex':
      return colonHex(createHash('md5').update(key).digest());
  }
}

/** Whether the received host key matches the published fingerprint; false for an unknown format. */
export function hostKeyMatches(key: Buffer, expected: string): boolean {
  const format = fingerprintFormat(expected);
  if (format === null) return false;
  const actual = hostKeyFingerprint(key, format);
  // Hex digests compare without regard to case; base64 is case-sensitive.
  return format === 'sha256-base64' ? actual === expected : actual === expected.toLowerCase();
}
