// Mosh in der Oberfläche: der Befehl zum Installieren, je nach erkanntem Betriebssystem des Servers.

/** Kennungen aus `os.ts`, gruppiert nach Paketverwaltung. */
const APT = ['Ub', 'De', 'PVE', 'PBS', 'Rp', 'Mint', 'Pop', 'Kali'];
const EPEL = ['RH', 'Rocky', 'Alma', 'CentOS', 'Oracle', 'Amazon'];

/** Der Befehl, der `mosh` auf dem Server installiert; null, wenn sich das System nicht sicher bestimmen lässt. */
export function moshInstall(os: string | null | undefined): string | null {
  if (!os) return null;
  if (APT.includes(os)) return 'sudo apt install mosh';
  // Bei Red Hat und Verwandten liegt mosh in EPEL, bei Fedora im eigenen Bestand.
  if (os === 'Fedora') return 'sudo dnf install mosh';
  if (EPEL.includes(os)) return 'sudo dnf install epel-release && sudo dnf install mosh';
  if (os === 'Ar' || os === 'Manjaro') return 'sudo pacman -S mosh';
  if (os === 'Al') return 'sudo apk add mosh';
  if (os === 'SUSE') return 'sudo zypper install mosh';
  if (os === 'Void') return 'sudo xbps-install mosh';
  if (os === 'Gentoo') return 'sudo emerge net-misc/mosh';
  if (os === 'NixOS') return 'nix-env -iA nixpkgs.mosh';
  if (os === 'BSD') return 'pkg install mosh';
  if (os === 'macOS') return 'brew install mosh';
  return null;
}
