<script lang="ts">
  import { formatSize } from './files.svelte';
  import { formatDate, t } from './i18n.svelte';
  import { installUpdate, updates } from './updates.svelte';
  import Button from './ui/Button.svelte';
  import Dialog from './ui/Dialog.svelte';

  const info = $derived(updates.available);
  const busy = $derived(updates.progress !== null);
  const share = $derived(updates.progress?.total ? updates.progress.done / updates.progress.total : 0);
</script>

{#if info}
  <!-- While downloading the dialog cannot be dismissed: nobody should overlook a half-downloaded update. -->
  <Dialog bind:open={() => updates.open, (open) => (updates.open = open || busy)} title={t('upd.title', { version: info.version })} wide>
    <p>{t('upd.text', { current: __APP_VERSION__ })}{#if info.date}&nbsp;{t('upd.date', { date: formatDate(info.date) })}{/if}</p>
    {#if info.notes.trim()}
      <span class="fld-l">{t('upd.notes')}</span>
      <div class="upd-notes">{info.notes.trim()}</div>
    {/if}
    {#if updates.progress}
      <div class="upd-bar"><i style="width:{share * 100}%"></i></div>
      <span class="fld-h">
        {updates.progress.total ? t('upd.loading', { done: formatSize(updates.progress.done), total: formatSize(updates.progress.total) }) : t('upd.loading.open', { done: formatSize(updates.progress.done) })}
      </span>
    {:else}
      <span class="fld-h">{t('upd.hint')}</span>
    {/if}
    {#if updates.error}<p class="errline" role="alert">{updates.error}</p>{/if}
    {#snippet actions()}
      <Button disabled={busy} onclick={() => (updates.open = false)}>{t('upd.later')}</Button>
      <Button variant="primary" icon="download" disabled={busy} onclick={installUpdate}>{busy ? t('upd.installing') : t('upd.install')}</Button>
    {/snippet}
  </Dialog>
{/if}
