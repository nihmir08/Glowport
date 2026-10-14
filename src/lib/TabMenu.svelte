<script lang="ts">
  import { detached } from './backend';
  import { vault } from './data.svelte';
  import { detachToWindow } from './drag.svelte';
  import type { IconName } from './icons';
  import { t } from './i18n.svelte';
  import { closeOtherTabs, closeTab, duplicateTab, panesOf, tabs, type Tab } from './sessions.svelte';
  import Icon from './ui/Icon.svelte';

  /** A tab's menu (right-click): rename, color, duplicate, into a window of its own, save as workspace, close. */
  let {
    tab,
    x,
    y,
    onclose,
    onrename,
    onworkspace,
  }: { tab: Tab; x: number; y: number; onclose: () => void; onrename: () => void; onworkspace: () => void } = $props();

  const COLORS = ['#FF5D6C', '#F59E0B', '#8BD613', '#22C3A6', '#5B9DFF', '#8B5CF6'];
  const WIDTH = 300;

  // Workspaces consist of saved hosts and local terminals; typed addresses cannot be stored.
  const savable = $derived(vault.state === 'open' && panesOf(tab).some((pane) => pane.target.kind === 'host' || pane.target.kind === 'local'));
  const left = $derived(Math.max(8, Math.min(x, innerWidth - WIDTH - 8)));

  function run(action: () => void) {
    // Act first, then close: the action needs the tab the menu belongs to.
    action();
    onclose();
  }
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && onclose()} />

{#snippet item(icon: IconName, label: string, action: () => void, options: { disabled?: boolean; danger?: boolean; hint?: string } = {})}
  <button type="button" class="mi" class:danger={options.danger} disabled={options.disabled} role="menuitem" onclick={() => run(action)}>
    <Icon name={icon} size={15} /><span>{label}</span>{#if options.hint}<kbd>{options.hint}</kbd>{/if}
  </button>
{/snippet}

<div class="menu-ov" role="presentation" onpointerdown={(e) => e.target === e.currentTarget && onclose()} oncontextmenu={(e) => (e.preventDefault(), onclose())}>
  <div class="menu" role="menu" aria-label={t('tabmenu.title')} style="left:{left}px;top:{y}px;width:{WIDTH}px">
    {@render item('edit', t('tabmenu.rename'), onrename)}
    <div class="mrow">
      <span>{t('tabmenu.color')}</span>
      <div class="sws">
        <button type="button" class:on={!tab.color} style="background:var(--text-3)" title={t('tabmenu.color.host')} aria-label={t('tabmenu.color.host')} onclick={() => (tab.color = null)}></button>
        {#each COLORS as c (c)}
          <button type="button" class:on={tab.color === c} style="background:{c}" title={c} aria-label={c} onclick={() => (tab.color = c)}></button>
        {/each}
      </div>
    </div>
    <hr />
    {@render item('copy', t('tabmenu.duplicate'), () => duplicateTab(tab.key))}
    {#if detached}
      {@render item('home', t('tabmenu.back'), () => void detachToWindow({ kind: 'tab', key: tab.key }, { to: 'main' }))}
    {/if}
    {#if !detached || tabs.length > 1}
      {@render item('external', t('tabmenu.window'), () => void detachToWindow({ kind: 'tab', key: tab.key }))}
    {/if}
    {@render item('layout', t('tabmenu.workspace'), onworkspace, { disabled: !savable })}
    <hr />
    {@render item('x', t('session.closeTab'), () => closeTab(tab.key), { hint: t('tabmenu.close.kbd') })}
    {@render item('x', t('tabmenu.closeOthers'), () => closeOtherTabs(tab.key), { disabled: tabs.length < 2 })}
  </div>
</div>
