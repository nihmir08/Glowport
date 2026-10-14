<script lang="ts">
  import { t } from './i18n.svelte';
  import { defaultShell, local, shellName } from './local.svelte';
  import { openLocal } from './sessions.svelte';
  import { ui } from './state.svelte';
  import Icon from './ui/Icon.svelte';
  import ShellIcon from './ui/ShellIcon.svelte';

  /**
   * Menu at the tab bar's “+”: search a host and connect, or open a local terminal with one of the
   * shells available on this PC. `onhosts` leads to the hosts overview; a window of its own has none.
   */
  let { x, y, onclose, onhosts }: { x: number; y: number; onclose: () => void; onhosts?: () => void } = $props();

  const WIDTH = 320;
  const left = $derived(Math.max(8, Math.min(x, innerWidth - WIDTH - 8)));
  const usual = $derived(defaultShell());

  function run(action: () => void) {
    onclose();
    action();
  }
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && onclose()} />

<div class="menu-ov" role="presentation" onpointerdown={(e) => e.target === e.currentTarget && onclose()} oncontextmenu={(e) => (e.preventDefault(), onclose())}>
  <div class="menu newtab" role="menu" aria-label={t('tab.new')} style="left:{left}px;top:{y}px;width:{WIDTH}px">
    <button type="button" class="mi" role="menuitem" onclick={() => run(() => (ui.palette = true))}>
      <Icon name="search" size={15} /><span>{t('newtab.connect')}</span><kbd>{t('search.kbd')}</kbd>
    </button>
    {#if onhosts}
      <button type="button" class="mi" role="menuitem" onclick={() => run(onhosts)}>
        <Icon name="server" size={15} /><span>{t('newtab.hosts')}</span>
      </button>
    {/if}
    <hr />
    <div class="mlabel">{t('local.title')}</div>
    {#each local.shells as shell (shell.id)}
      <button type="button" class="mi" role="menuitem" data-shell={shell.id} onclick={() => run(() => openLocal(shell.id))}>
        <ShellIcon {shell} size="sm" bare /><span>{shellName(shell)}</span>
        {#if shell.id === usual?.id}<kbd>{t('local.kbd')}</kbd>{/if}
      </button>
    {:else}
      <div class="mnote">{local.loaded ? t('local.none') : t('local.loading')}</div>
    {/each}
  </div>
</div>
