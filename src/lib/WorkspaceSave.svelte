<script lang="ts">
  import { workspaceSave } from './backend';
  import { applySnapshot, errorText, vault } from './data.svelte';
  import { t } from './i18n.svelte';
  import { leaves, mapLeaves, type Layout } from './layout';
  import { savedTab, type Tab } from './sessions.svelte';
  import { toast } from './state.svelte';
  import type { SavedLayout, Target } from './types';
  import Button from './ui/Button.svelte';
  import LayoutPreview from './ui/LayoutPreview.svelte';
  import TextField from './ui/TextField.svelte';

  /** Legt die Anordnung eines Tabs als Arbeitsbereich in den Tresor. */
  let { tab, onclose }: { tab: Tab; onclose: () => void } = $props();

  // Der Dialog wird je Tab neu erzeugt; die Startwerte werden bewusst nur einmal gelesen.
  const saved = (() => savedTab(tab))();
  const total = leaves(saved.layout as Layout<Target>).length;
  // Gespeicherte Hosts und lokale Terminals lassen sich wieder öffnen; eingetippte Adressen fallen weg.
  const layout = mapLeaves<Target, Target>(saved.layout as Layout<Target>, (target) => (target.kind === 'host' || target.kind === 'local' ? target : null)) as SavedLayout | null;
  const kept = layout ? leaves(layout as Layout<Target>).length : 0;

  let name = $state(saved.name ?? '');
  let multi = $state(saved.multi && kept > 1);
  let busy = $state(false);
  let error = $state('');

  const existing = $derived(vault.workspaces.find((w) => w.name.toLowerCase() === name.trim().toLowerCase()));

  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (!layout || !name.trim()) return;
    busy = true;
    error = '';
    try {
      const changed = await workspaceSave({ id: existing?.id, name: name.trim(), multi, layout });
      applySnapshot(changed.data);
      if (!tab.name) tab.name = name.trim();
      toast(t('ws.saved', { name: name.trim() }), 'ok');
      onclose();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && onclose()} />

<div class="ov" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose()}>
  <form class="dlg" aria-label={t('ws.save.title')} onsubmit={save}>
    <h2>{t('ws.save.title')}</h2>
    <div class="dlg-b">
      <p>{t('ws.save.text')}</p>
      {#if layout}<LayoutPreview {layout} />{/if}
      <TextField label={t('edit.name')} bind:value={name} placeholder={t('ws.save.placeholder')} autofocus />
      {#if kept > 1}
        <label class="check"><input type="checkbox" bind:checked={multi} />{t('ws.save.multi')}</label>
      {/if}
      {#if kept < total}<div class="warnbox"><span>{t('ws.save.skipped', { n: total - kept })}</span></div>{/if}
      {#if existing}<p class="fld-h">{t('ws.save.replace', { name: existing.name })}</p>{/if}
      {#if error}<p class="errline" role="alert">{error}</p>{/if}
    </div>
    <div class="dlg-a">
      <Button onclick={onclose}>{t('common.cancel')}</Button>
      <button type="submit" class="btn primary" disabled={busy || !name.trim() || !layout}>{existing ? t('ws.save.overwrite') : t('common.save')}</button>
    </div>
  </form>
</div>
