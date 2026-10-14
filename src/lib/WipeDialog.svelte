<script lang="ts">
  import { vaultWipe } from './backend';
  import { errorText, vault } from './data.svelte';
  import { t } from './i18n.svelte';
  import { sync } from './sync.svelte';
  import Button from './ui/Button.svelte';
  import Dialog from './ui/Dialog.svelte';

  /**
   * Prompt before “Sign out and delete data on this PC”. Works locked too (from the lock screen); then
   * Glowport cannot sign out at the sync server, because the access is stored encrypted in the vault.
   */
  let { open = $bindable(false) }: { open?: boolean } = $props();

  let understood = $state(false);
  let busy = $state(false);
  let error = $state('');
  /** Signing out at the server failed; the next click deletes anyway. */
  let force = $state(false);

  const linked = $derived(vault.state === 'open' && sync.linked);

  $effect(() => {
    if (open) return;
    understood = force = busy = false;
    error = '';
  });

  async function wipe() {
    busy = true;
    error = '';
    try {
      // If it succeeds, Glowport restarts; only an error comes back.
      await vaultWipe(force);
    } catch (e) {
      error = errorText(e);
      // Whatever went wrong while signing out: deleting may still go ahead, only deliberately.
      force = linked;
    } finally {
      busy = false;
    }
  }
</script>

<Dialog bind:open title={t('wipe.title')}>
  <p>{t('wipe.text')}</p>
  <div class="warnbox"><span>{t('wipe.warn')}</span></div>
  {#if linked}
    <p>{t('wipe.linked', { server: sync.server })}</p>
  {:else if vault.state !== 'open'}
    <p>{t('wipe.locked')}</p>
  {/if}
  <label class="check"><input type="checkbox" bind:checked={understood} disabled={busy} />{t('wipe.ack')}</label>
  {#if error}
    <p class="errline" role="alert">{error}</p>
    {#if force}<p>{t('wipe.force')}</p>{/if}
  {/if}
  {#snippet actions()}
    <Button onclick={() => (open = false)} disabled={busy}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" disabled={!understood || busy} onclick={wipe}>
      {busy ? t('wipe.busy') : force ? t('wipe.confirm.force') : t('wipe.confirm')}
    </Button>
  {/snippet}
</Dialog>
