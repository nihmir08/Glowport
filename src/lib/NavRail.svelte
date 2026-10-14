<script lang="ts">
  import type { IconName } from './icons';
  import { t, type Key } from './i18n.svelte';
  import { ui, type PageId } from './state.svelte';
  import Icon from './ui/Icon.svelte';

  const items: { page: PageId; icon: IconName; label: Key }[] = [
    { page: 'hosts', icon: 'server', label: 'nav.hosts' },
    { page: 'keys', icon: 'key', label: 'nav.keys' },
    { page: 'fwd', icon: 'forward', label: 'nav.fwd' },
    { page: 'snip', icon: 'snippet', label: 'nav.snip' },
    { page: 'files', icon: 'folder', label: 'nav.files' },
    { page: 'known', icon: 'shield', label: 'nav.known' },
    { page: 'logs', icon: 'log', label: 'nav.logs' },
    { page: 'pve', icon: 'network', label: 'nav.pve' },
    { page: 'sync', icon: 'cloud', label: 'nav.sync' },
  ];
</script>

{#snippet entry(page: PageId, icon: IconName, label: Key)}
  <button class="nv" class:on={ui.page === page || (page === 'settings' && ui.page === 'kit')} aria-current={ui.page === page ? 'page' : undefined} onclick={() => (ui.page = page)}>
    <Icon name={icon} size={20} /><span>{t(label)}</span>
  </button>
{/snippet}

<nav class="nav isl">
  <div class="vault" title={t('nav.vault')}><span class="ava">G</span></div>
  {#each items as it (it.page)}{@render entry(it.page, it.icon, it.label)}{/each}
  <span class="grow"></span>
  {@render entry('settings', 'gear', 'nav.settings')}
</nav>
