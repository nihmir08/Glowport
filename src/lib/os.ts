import {
  siAlmalinux,
  siAlpinelinux,
  siApple,
  siArchlinux,
  siCentos,
  siDebian,
  siFedora,
  siFreebsd,
  siGentoo,
  siKalilinux,
  siLinux,
  siLinuxmint,
  siManjaro,
  siNetbsd,
  siNixos,
  siOpenbsd,
  siOpensuse,
  siOpenwrt,
  siOpnsense,
  siPfsense,
  siPopos,
  siProxmox,
  siRaspberrypi,
  siRedhat,
  siRockylinux,
  siSynology,
  siTruenas,
  siUbuntu,
  siUnraid,
  siVoidlinux,
} from 'simple-icons';

/**
 * Betriebssysteme: Name, Farbe der Kachel und das Logo als Pfad im 24er-Raster.
 * Die Kennungen (`Ub`, `De`, `Rocky` …) stehen so im Tresor und kommen so aus der Erkennung beim Verbinden
 * (`crates/net/src/os.rs`); sie dürfen sich nicht ändern. Angezeigt wird immer das Logo, nie die Kennung.
 *
 * Die Logos stammen aus Simple Icons (CC0) und sind Marken ihrer Inhaber. Die Farben sind nicht die Markenfarben,
 * sondern so gewählt, dass sie im dunklen wie im hellen Modus zu erkennen sind.
 */
export interface OsEntry {
  name: string;
  color: string;
  icon: string;
}

/** Vier Kacheln. Simple Icons führt das Windows-Logo nicht mehr; dies ist eine eigene, schlichte Form. */
const WINDOWS = 'M0 0h11.4v11.4H0zM12.6 0H24v11.4H12.6zM0 12.6h11.4V24H0zM12.6 12.6H24V24H12.6z';
const TUX = siLinux.path;

export const OS: Record<string, OsEntry> = {
  Ub: { name: 'Ubuntu', color: '#E9622E', icon: siUbuntu.path },
  De: { name: 'Debian', color: '#D6336C', icon: siDebian.path },
  PVE: { name: 'Proxmox VE', color: '#F08A00', icon: siProxmox.path },
  PBS: { name: 'Proxmox Backup Server', color: '#F08A00', icon: siProxmox.path },
  Al: { name: 'Alpine', color: '#3B8FD9', icon: siAlpinelinux.path },
  Rp: { name: 'Raspberry Pi OS', color: '#C7365F', icon: siRaspberrypi.path },
  RH: { name: 'Red Hat Enterprise Linux', color: '#E0322D', icon: siRedhat.path },
  Rocky: { name: 'Rocky Linux', color: '#10B981', icon: siRockylinux.path },
  Alma: { name: 'AlmaLinux', color: '#4F8FE6', icon: siAlmalinux.path },
  CentOS: { name: 'CentOS', color: '#9C7BE8', icon: siCentos.path },
  Fedora: { name: 'Fedora', color: '#51A2DA', icon: siFedora.path },
  Oracle: { name: 'Oracle Linux', color: '#E0463C', icon: TUX },
  Amazon: { name: 'Amazon Linux', color: '#F29D38', icon: TUX },
  Ar: { name: 'Arch', color: '#1793D1', icon: siArchlinux.path },
  Manjaro: { name: 'Manjaro', color: '#35BFA4', icon: siManjaro.path },
  Mint: { name: 'Linux Mint', color: '#86BE43', icon: siLinuxmint.path },
  Pop: { name: 'Pop!_OS', color: '#48B9C7', icon: siPopos.path },
  Kali: { name: 'Kali Linux', color: '#6F9AB8', icon: siKalilinux.path },
  SUSE: { name: 'openSUSE / SUSE', color: '#73BA25', icon: siOpensuse.path },
  NixOS: { name: 'NixOS', color: '#5E8BD6', icon: siNixos.path },
  Gentoo: { name: 'Gentoo', color: '#8B7FC7', icon: siGentoo.path },
  Void: { name: 'Void Linux', color: '#5FA57D', icon: siVoidlinux.path },
  OpenWrt: { name: 'OpenWrt', color: '#00B5E2', icon: siOpenwrt.path },
  Synology: { name: 'Synology DSM', color: '#9AA0B4', icon: siSynology.path },
  TrueNAS: { name: 'TrueNAS', color: '#0095D5', icon: siTruenas.path },
  Unraid: { name: 'Unraid', color: '#F15A2C', icon: siUnraid.path },
  BSD: { name: 'FreeBSD', color: '#E0423B', icon: siFreebsd.path },
  OpenBSD: { name: 'OpenBSD', color: '#E0B92B', icon: siOpenbsd.path },
  NetBSD: { name: 'NetBSD', color: '#FF6600', icon: siNetbsd.path },
  OPNsense: { name: 'OPNsense', color: '#E44A20', icon: siOpnsense.path },
  pfSense: { name: 'pfSense', color: '#7C8CA8', icon: siPfsense.path },
  macOS: { name: 'macOS', color: '#A9AEC2', icon: siApple.path },
  Win: { name: 'Windows', color: '#3A96F0', icon: WINDOWS },
  Li: { name: 'Linux', color: '#8B90A8', icon: TUX },
};

/** Farbe für ein System, das (noch) nicht bekannt ist. Seine Kachel zeigt ein neutrales Server-Zeichen. */
export const UNKNOWN_COLOR = '#8B90A8';

export const osEntry = (os: string | null | undefined): OsEntry | undefined => (os ? OS[os] : undefined);
export const osColor = (os: string | null | undefined): string => osEntry(os)?.color ?? UNKNOWN_COLOR;

/** Alle Systeme nach Namen, für die Auswahl im Editor. */
export const OS_CHOICES = Object.entries(OS)
  .map(([id, entry]) => ({ id, name: entry.name }))
  .sort((a, b) => a.name.localeCompare(b.name));
