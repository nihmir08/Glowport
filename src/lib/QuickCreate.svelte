<script lang="ts">
  import { groupSave, hostSave } from './backend';
  import { applySnapshot, errorText, pathLabel } from './data.svelte';
  import { t } from './i18n.svelte';
  import IdentityEditor from './pages/IdentityEditor.svelte';
  import KeyNew from './pages/KeyNew.svelte';
  import { closeQuick, quick } from './quick.svelte';
  import { toast } from './state.svelte';
  import type { Fields } from './types';
  import Button from './ui/Button.svelte';
  import TextField from './ui/TextField.svelte';

  /**
   * Die kleinen Dialoge zum Anlegen an Ort und Stelle (siehe `quick.svelte.ts`). Sie liegen über allem, auch
   * übereinander: Aus dem Dialog „Neue Identität“ heraus lässt sich wieder ein Schlüssel importieren.
   */
  let name = $state('');
  let address = $state('');
  let user = $state('');
  let port = $state('');
  let busy = $state(false);
  let error = $state('');

  const top = $derived(quick.stack.at(-1));

  // Jeder neue Dialog beginnt mit leeren Feldern.
  $effect(() => {
    void top?.n;
    name = address = user = port = error = '';
  });

  async function saveGroup(event: SubmitEvent, n: number, parent: string | null) {
    event.preventDefault();
    await save(n, () => groupSave({ name, parent, color: null, defs: {} }));
  }

  async function saveHost(event: SubmitEvent, n: number) {
    event.preventDefault();
    const own: Fields = {};
    if (user.trim()) own.user = user.trim();
    if (port.trim()) {
      const number = Number(port);
      if (!Number.isInteger(number) || number < 1 || number > 65535) return void (error = t('err.invalid.port_invalid'));
      own.port = number;
    }
    await save(n, () => hostSave({ name, address, group: null, color: null, os: null, own }));
  }

  async function save(n: number, work: () => Promise<{ id?: string; data: Parameters<typeof applySnapshot>[0] }>) {
    busy = true;
    error = '';
    try {
      const changed = await work();
      applySnapshot(changed.data);
      toast(t('common.saved'), 'ok');
      closeQuick(n, changed.id);
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }
</script>

<svelte:window
  onkeydowncapture={(e) => {
    if (e.key !== 'Escape' || !top) return;
    e.stopPropagation();
    closeQuick(top.n);
  }}
/>

{#each quick.stack as request (request.n)}
  <div class="ov quick" role="presentation" onclick={(e) => e.target === e.currentTarget && closeQuick(request.n)}>
    {#if request.kind === 'key'}
      <KeyNew mode={request.mode} file={request.file} onclose={() => closeQuick(request.n)} onsaved={(id) => closeQuick(request.n, id)} />
    {:else if request.kind === 'identity'}
      <IdentityEditor identity={null} onclose={() => closeQuick(request.n)} onsaved={(id) => closeQuick(request.n, id)} ondelete={() => {}} />
    {:else if request.kind === 'group'}
      <form class="dlg" aria-label={t('quick.group.title')} onsubmit={(e) => saveGroup(e, request.n, request.parent)}>
        <h2>{t('quick.group.title')}</h2>
        <div class="dlg-b">
          <p>{request.parent ? t('quick.group.in', { group: pathLabel(request.parent) }) : t('quick.group.root')}</p>
          <TextField label={t('edit.name')} bind:value={name} placeholder="Produktiv" autofocus />
          {#if error}<p class="errline" role="alert">{error}</p>{/if}
        </div>
        <div class="dlg-a">
          <Button onclick={() => closeQuick(request.n)}>{t('common.cancel')}</Button>
          <button type="submit" class="btn primary" disabled={busy || !name.trim()}>{t('common.save')}</button>
        </div>
      </form>
    {:else}
      <form class="dlg" aria-label={t('quick.host.title')} onsubmit={(e) => saveHost(e, request.n)}>
        <h2>{t('quick.host.title')}</h2>
        <div class="dlg-b">
          <p>{t('quick.host.text')}</p>
          <TextField label={t('edit.name')} bind:value={name} placeholder="bastion" autofocus />
          <TextField label={t('edit.address')} bind:value={address} placeholder="203.0.113.10" mono />
          <div style="display:grid;grid-template-columns:1fr 110px;gap:10px">
            <TextField label={t('detail.user')} bind:value={user} placeholder="root" mono />
            <TextField label={t('detail.port')} bind:value={port} placeholder="22" mono />
          </div>
          {#if error}<p class="errline" role="alert">{error}</p>{/if}
        </div>
        <div class="dlg-a">
          <Button onclick={() => closeQuick(request.n)}>{t('common.cancel')}</Button>
          <button type="submit" class="btn primary" disabled={busy || !name.trim() || !address.trim()}>{t('common.save')}</button>
        </div>
      </form>
    {/if}
  </div>
{/each}
