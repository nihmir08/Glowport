// Mosh in the interface: the command to install it, depending on the server's detected operating system.

/** IDs from `os.ts`, grouped by package manager. */
const APT = ['Ub', 'De', 'PVE', 'PBS', 'Rp', 'Mint', 'Pop', 'Kali'];
const EPEL = ['RH', 'Rocky', 'Alma', 'CentOS', 'Oracle', 'Amazon'];

/** The command that installs `mosh` on the server; null if the system cannot be determined reliably. */
export function moshInstall(os: string | null | undefined): string | null {
  if (!os) return null;
  if (APT.includes(os)) return 'sudo apt install mosh';
  // For Red Hat and relatives mosh is in EPEL, for Fedora in its own repositories.
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
