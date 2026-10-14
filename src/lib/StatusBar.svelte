<script lang="ts">
  import { onMount } from 'svelte';
  import { appInfo } from './backend';
  import { vault } from './data.svelte';
  import { activeTransfers, formatSize, overallProgress, overallSpeed, showTransfers, transfers, transfersShown } from './files.svelte';
  import { activeForwards } from './forwards.svelte';
  import { view } from './sessions.svelte';
  import Icon from './ui/Icon.svelte';
  import { t, tn } from './i18n.svelte';
  import { settings, ui } from './state.svelte';
  import { sync } from './sync.svelte';
  import { updates } from './updates.svelte';

  // The development version calls itself “Glowport Dev”; that way the window shows which version is running.
  let name = $state(t('app.name'));
  onMount(() => void appInfo().then((info) => info && (name = info.name)));
</script>

<footer class="st">
  {#if vault.state === 'open'}
    <span><i class="d"></i>{t('status.unlocked')}</span>
    <span>{t('status.hosts', { n: vault.hosts.length })}</span>
  {:else if vault.state === 'locked'}
    <span><i class="d warn"></i>{t('status.locked')}</span>
  {:else if vault.state === 'missing'}
    <span><i class="d warn"></i>{t('status.missing')}</span>
  {/if}
  {#if vault.state === 'open' && sync.linked}
    <!-- Sync state; a click leads to the “Sync and sharing” page. -->
    <button type="button" class="st-x" class:on={ui.page === 'sync' && view.active === 'home'} title={sync.server} onclick={() => ((ui.page = 'sync'), (view.active = 'home'))}>
      <i class="sdot {sync.phase}"></i>
      <span>
        {#if sync.phase === 'syncing'}{t('status.sync.syncing')}{:else if sync.phase === 'offline'}{tn('status.sync.offline', sync.pending)}{:else if sync.phase === 'signedOut'}{t('status.sync.signedOut')}{:else if sync.phase === 'error'}{t(
            'status.sync.error',
          )}{:else}{t('status.sync.synced')}{/if}
      </span>
    </button>
    {#if sync.invitations.length}
      <button type="button" class="st-x on" onclick={() => ((ui.page = 'sync'), (view.active = 'home'))}>
        <Icon name="send" size={12} /><span>{tn('status.sync.invitations', sync.invitations.length)}</span>
      </button>
    {/if}
  {/if}
  <span class="grow"></span>
  {#if activeForwards().length}
    <!-- Port rules keep running without a terminal; here you can see that some are on. -->
    <button type="button" class="st-x" onclick={() => ((ui.page = 'fwd'), (view.active = 'home'))}>
      <Icon name="forward" size={12} /><span>{tn('fwd.status', activeForwards().length)}</span>
    </button>
  {/if}
  {#if transfers.list.length || transfers.watched.length}
    {@const running = activeTransfers().length}
    <button type="button" class="st-x" class:on={transfersShown()} onclick={() => showTransfers()}>
      <Icon name="transfer" size={12} />
      {#if running}
        <span>{t('transfers.summary', { n: running })} · {Math.round(overallProgress() * 100)} %{#if overallSpeed()}&nbsp;· {formatSize(overallSpeed())}/s{/if}</span>
        <i class="st-bar"><i style="width:{overallProgress() * 100}%"></i></i>
      {:else}
        <span>{t('transfers.title')}</span>
      {/if}
    </button>
  {/if}
  {#if updates.available}
    <button type="button" class="st-x on" onclick={() => (updates.open = true)}>
      <Icon name="download" size={12} /><span>{t('upd.available', { version: updates.available.version })}</span>
    </button>
  {/if}
  <span>{settings.lang.toUpperCase()}</span>
  <span>{name} {__APP_VERSION__}</span>
</footer>
