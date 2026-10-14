// Updates: check whether there is a newer version and install it after asking.

import { appInfo, inApp, updateCheck, updateInstall } from './backend';
import { errorText } from './data.svelte';
import { t } from './i18n.svelte';
import { settings, toast } from './state.svelte';
import type { UpdateInfo, UpdateProgress } from './types';

export const updates = $state<{
  /** Can this version look for updates at all? The browser preview pretends to, so the flow can be looked at. */
  enabled: boolean;
  available: UpdateInfo | null;
  /** The dialog with the prompt is open. */
  open: boolean;
  checking: boolean;
  /** Set while downloading and installing. */
  progress: UpdateProgress | null;
  error: string;
}>({ enabled: !inApp, available: null, open: false, checking: false, progress: null, error: '' });

/** While running it checks hourly, so a new release shows up without a restart. */
const HOUR = 3_600_000;
/** The version last announced: the notice comes once per new version, not on every check. */
let announced = '';

/** Asks for a newer version. `manual`: the user asked and gets an answer in any case. */
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
    // On start without network Glowport stays quiet; whoever asked themselves learns the reason.
    if (manual) toast(errorText(e), 'err');
  }
  updates.checking = false;
}

/** Check on start and hourly afterwards as long as it is switched on; not while already installing. */
export async function initUpdates() {
  const info = inApp ? await appInfo().catch(() => null) : null;
  if (inApp) updates.enabled = !!info?.updates;
  // If a different version ran last, the update has arrived: say so once, then remember.
  const version = info?.version ?? __APP_VERSION__;
  if (settings.lastVersion && settings.lastVersion !== version) toast(t('upd.done', { version }), 'ok');
  settings.lastVersion = version;
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
    // In the program Glowport restarts here; in the preview there is nothing to install.
    if (!inApp) (toast(t('upd.preview'), 'info'), (updates.open = false));
  } catch (e) {
    updates.error = errorText(e);
  }
  updates.progress = null;
}
