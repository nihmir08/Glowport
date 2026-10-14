import type { KeyKind, SshKey } from './types';

/** Farbe der Kachel je Schlüsselart; Ed25519 trägt die Akzentfarbe. */
export const KEY_COLOR: Record<KeyKind, string> = { ed25519: 'var(--accent)', ecdsa: '#22C3A6', rsa: '#5B9DFF' };
export const IDENTITY_COLOR = '#8B5CF6';

export const KIND_NAME: Record<KeyKind, string> = { ed25519: 'Ed25519', ecdsa: 'ECDSA', rsa: 'RSA' };

/** Längen, die beim Erzeugen angeboten werden; die erste ist die Vorgabe. */
export const KEY_BITS: Record<KeyKind, number[]> = { ed25519: [256], ecdsa: [256, 384, 521], rsa: [4096, 3072] };

/** Zeichensätze, die für einen Server zur Wahl stehen; dieselbe Liste wie `CHARSETS` im Kern. Der erste ist die Vorgabe. */
export const CHARSETS = ['utf-8', 'iso-8859-1', 'iso-8859-15', 'windows-1252', 'windows-1250', 'windows-1251', 'koi8-r', 'ibm866', 'gbk', 'big5', 'shift_jis', 'euc-kr'];

/** Kurzform für Karten: „Ed25519“, „RSA 4096“, „ECDSA P-256“. */
export function keyLabel(key: Pick<SshKey, 'kind' | 'bits'>): string {
  if (key.kind === 'ed25519') return KIND_NAME.ed25519;
  return key.kind === 'rsa' ? `RSA ${key.bits}` : `ECDSA P-${key.bits}`;
}
