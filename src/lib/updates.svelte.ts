// Updates: nachsehen, ob es eine neuere Version gibt, und sie nach Rückfrage installieren.

import { appInfo, inApp, updateCheck, updateInstall } from './backend';
import { errorText } from './data.svelte';
import { t } from './i18n.svelte';
import { settings, toast } from './state.svelte';
import type { UpdateInfo, UpdateProgress } from './types';

export const updates = $state<{
  /** Kann diese Fassung überhaupt nach Updates suchen? Die Vorschau im Browser tut so, damit sich der Ablauf ansehen lässt. */
  enabled: boolean;
  available: UpdateInfo | null;
  /** Der Dialog mit der Rückfrage ist offen. */
  open: boolean;
  checking: boolean;
  /** Gesetzt, solange geladen und installiert wird. */
  progress: UpdateProgress | null;
  error: string;
}>({ enabled: !inApp, available: null, open: false, checking: false, progress: null, error: '' });

/** Im Betrieb wird stündlich nachgesehen, damit ein neues Release ohne Neustart auftaucht. */
const HOUR = 3_600_000;
/** Die zuletzt gemeldete Version: Der Hinweis kommt einmal je neuer Version, nicht bei jedem Nachsehen. */
let announced = '';

/** Fragt nach einer neueren Version. `manual`: Der Nutzer hat gefragt und bekommt in jedem Fall eine Antwort. */
export async function checkForUpdate(manual: boolean) {
  if (!updates.enabled || updates.checking) return;
  updates.checking = true;
  try {
    updates.available = await updateCheck();
    settings.updateChecked = Date.now();
    if (updates.available && manual) updates.open = true;
    else if (updates.available && updates.available.version !== announced) toast(t('upd.toast', { version: updates.available.version }), 'info');
    else if (!updates.available && manual) toast(t('upd.none'), 'ok');
    if (updates.available) announced = updates.available.version;
  } catch (e) {
    // Beim Start ohne Netz bleibt Glowport still; wer selbst gefragt hat, erfährt den Grund.
    if (manual) toast(errorText(e), 'err');
  }
  updates.checking = false;
}

/** Beim Start und danach stündlich nachsehen, solange es eingeschaltet ist; nicht während schon installiert wird. */
export async function initUpdates() {
  if (inApp) updates.enabled = !!(await appInfo().catch(() => null))?.updates;
  if (!inApp || !updates.enabled) return;
  const look = () => {
    if (settings.updateCheck && !updates.progress) void checkForUpdate(false);
  };
  look();
  setInterval(look, HOUR);
}

export async function installUpdate() {
  if (!updates.available || updates.progress) return;
  updates.error = '';
  updates.progress = { done: 0, total: null };
  try {
    await updateInstall((progress) => (updates.progress = progress));
    // Im Programm startet Glowport hier neu; in der Vorschau gibt es nichts zu installieren.
    if (!inApp) (toast(t('upd.preview'), 'info'), (updates.open = false));
  } catch (e) {
    updates.error = errorText(e);
  }
  updates.progress = null;
}
