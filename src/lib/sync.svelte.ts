import { onSyncState, syncState } from './backend';
import { personalVault, vault } from './data.svelte';
import { formatDate, t } from './i18n.svelte';
import type { SyncState, VaultInfo, VaultRole } from './types';

const OFF: SyncState = { linked: false, server: '', username: '', admin: false, phase: 'synced', pending: 0, syncedAt: null, code: '', invitations: [], notices: 0, passwordChanged: false };

/** Stand des Abgleichs mit dem Sync-Server. Ohne Server bleibt alles, wie es ohne Abgleich ist. */
export const sync = $state<SyncState>({ ...OFF });

/** Welchen Tresor die Seiten zeigen: `all` oder die Kennung eines Tresors. */
export const scope = $state({ vault: 'all' });

export function applySync(next: SyncState) {
  Object.assign(sync, OFF, next);
}

/** Liest den Stand und folgt ihm. Liefert eine Funktion zum Abmelden. */
export function initSync(): () => void {
  void syncState()
    .then(applySync)
    .catch((e) => console.error('Stand des Abgleichs nicht lesbar', e));
  return onSyncState(applySync);
}

/** Gehört ein Eintrag zu dem, was gerade gezeigt wird? */
export function inScope(entry: { vault?: string }): boolean {
  if (scope.vault === 'all' || !vault.vaults.some((v) => v.id === scope.vault)) return true;
  return (entry.vault ?? personalVault()?.id) === scope.vault;
}

/** Der Tresor, in den ein neuer Eintrag kommt: der gezeigte, sonst der persönliche. Mit Leserecht nie. */
export function targetVault(): string | undefined {
  const shown = vault.vaults.find((v) => v.id === scope.vault);
  return shown && shown.role !== 'read' ? shown.id : undefined;
}

export const vaultLabel = (v: VaultInfo | undefined) => (!v || v.kind === 'personal' ? t('vault.personal') : v.name || t('vault.unnamed'));

const COLORS = ['#5B9DFF', '#8B5CF6', '#00C8E0', '#8BD613', '#FF2E63', '#F5B83D'];
/** Farbe eines geteilten Tresors, damit seine Marke überall dieselbe ist. Der persönliche bleibt neutral. */
export function vaultColor(v: VaultInfo | undefined): string {
  if (!v || v.kind === 'personal') return 'var(--text-3)';
  return COLORS[Math.max(0, vault.vaults.filter((x) => x.kind === 'shared').indexOf(v)) % COLORS.length];
}

export const roleLabel = (role: VaultRole) => t(role === 'owner' ? 'vault.role.owner' : role === 'write' ? 'vault.role.write' : 'vault.role.read');

/** Wie lange etwas her ist, grob: „gerade eben“, „vor 12 Min.“, sonst das Datum. */
export function ago(ms: number): string {
  const minutes = Math.floor((Date.now() - ms) / 60_000);
  if (minutes < 1) return t('sync.ago.now');
  if (minutes < 60) return t('sync.ago.minutes', { n: minutes });
  if (minutes < 24 * 60) return t('sync.ago.hours', { n: Math.floor(minutes / 60) });
  return formatDate(ms);
}

/** Größe in runden Einheiten. */
export function sizeLabel(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
