import type { KeyKind, SshKey } from './types';

/** Tile color per key type; Ed25519 carries the accent color. */
export const KEY_COLOR: Record<KeyKind, string> = { ed25519: 'var(--accent)', ecdsa: '#22C3A6', rsa: '#5B9DFF' };
export const IDENTITY_COLOR = '#8B5CF6';

export const KIND_NAME: Record<KeyKind, string> = { ed25519: 'Ed25519', ecdsa: 'ECDSA', rsa: 'RSA' };

/** Lengths offered when generating; the first is the default. */
export const KEY_BITS: Record<KeyKind, number[]> = { ed25519: [256], ecdsa: [256, 384, 521], rsa: [4096, 3072] };

/** Character sets available for a server; the same list as `CHARSETS` in the core. The first is the default. */
export const CHARSETS = ['utf-8', 'iso-8859-1', 'iso-8859-15', 'windows-1252', 'windows-1250', 'windows-1251', 'koi8-r', 'ibm866', 'gbk', 'big5', 'shift_jis', 'euc-kr'];

/** Short form for cards: “Ed25519”, “RSA 4096”, “ECDSA P-256”. */
export function keyLabel(key: Pick<SshKey, 'kind' | 'bits'>): string {
  if (key.kind === 'ed25519') return KIND_NAME.ed25519;
  return key.kind === 'rsa' ? `RSA ${key.bits}` : `ECDSA P-${key.bits}`;
}
