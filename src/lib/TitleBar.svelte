<script lang="ts">
  import { onMount } from 'svelte';
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import { detached, inApp, vaultLock } from './backend';
  import { applyStatus, vault } from './data.svelte';
  import { drag, startDrag, tabbarIndex } from './drag.svelte';
  import { t } from './i18n.svelte';
  import NewTabMenu from './NewTabMenu.svelte';
  import { askingPane, closeTab, tabByKey, tabColor, tabPhase, tabs, tabTitle, view, type Tab } from './sessions.svelte';
  import { ui } from './state.svelte';
  import TabMenu from './TabMenu.svelte';
  import Icon from './ui/Icon.svelte';
  import WorkspaceSave from './WorkspaceSave.svelte';

  let maximized = $state(false);
  let menu = $state<{ key: string; x: number; y: number } | null>(null);
  let renaming = $state<string | null>(null);
  let renameText = $state('');
  let workspaceOf = $state<string | null>(null);

  onMount(() => {
    if (!inApp) return;
    const win = getCurrentWindow();
    const sync = () => void win.isMaximized().then((m) => (maximized = m));
    sync();
    const stop = win.onResized(sync);
    return () => void stop.then((f) => f());
  });

  const win = () => (inApp ? getCurrentWindow() : null);
  const lock = async () => applyStatus(await vaultLock());
  const showTabs = $derived(vault.state === 'open' || tabs.length > 0);
  const marker = $derived(tabbarIndex());
  const menuTab = $derived(menu ? tabByKey(menu.key) : undefined);
  const workspaceTab = $derived(workspaceOf ? tabByKey(workspaceOf) : undefined);

  /** Das Menü am Plus: Host verbinden oder lokales Terminal. */
  let adding = $state<{ x: number; y: number } | null>(null);

  function openAdd(event: MouseEvent) {
    const button = (event.currentTarget as HTMLElement).getBoundingClientRect();
    adding = { x: button.left, y: button.bottom + 6 };
  }

  function home() {
    view.active = 'home';
    ui.page = 'hosts';
  }

  function openMenu(event: MouseEvent, tab: Tab) {
    event.preventDefault();
    const pill = (event.currentTarget as HTMLElement).getBoundingClientRect();
    menu = { key: tab.key, x: pill.left, y: pill.bottom + 6 };
  }

  function startRename(tab: Tab) {
    renaming = tab.key;
    renameText = tab.name ?? tabTitle(tab);
  }

  /** Ein leerer Name gibt dem Tab wieder den Namen seines Hosts. */
  function commitRename() {
    const tab = renaming ? tabByKey(renaming) : undefined;
    if (tab) tab.name = renameText.trim() || null;
    renaming = null;
  }

  function selectAll(node: HTMLInputElement) {
    node.select();
  }
</script>

<header class="tb" data-tauri-drag-region>
  <span class="logo">&gt;_</span>
  <div class="tabs" data-tauri-drag-region>
    {#if showTabs}
      {#if !detached}
        <button class="tab home" class:on={view.active === 'home'} onclick={() => (view.active = 'home')}>
          <Icon name="home" size={15} /><span class="nm">{t('tab.start')}</span>
        </button>
      {/if}
      {#each tabs as tab, i (tab.key)}
        {@const color = tabColor(tab) ?? 'var(--accent)'}
        {#if marker === i}<i class="tab-mark"></i>{/if}
        <div
          class="tab {tabPhase(tab)}"
          class:on={view.active === tab.key}
          class:ask={!!askingPane(tab) && view.active !== tab.key}
          class:multi={tab.multi}
          class:dragged={drag.item?.kind === 'tab' && drag.item.key === tab.key}
          style="--c:{color}"
          data-tab={tab.key}
          role="tab"
          tabindex="0"
          aria-selected={view.active === tab.key}
          title={tabTitle(tab)}
          onclick={() => (view.active = tab.key)}
          ondblclick={() => startRename(tab)}
          onkeydown={(e) => e.key === 'Enter' && renaming !== tab.key && (view.active = tab.key)}
          onauxclick={(e) => e.button === 1 && closeTab(tab.key)}
          oncontextmenu={(e) => openMenu(e, tab)}
          onpointerdown={(e) => startDrag(e, { kind: 'tab', key: tab.key }, tabTitle(tab), color)}
        >
          <i class="dot"></i>
          {#if renaming === tab.key}
            <input
              class="tab-name"
              bind:value={renameText}
              aria-label={t('tabmenu.rename')}
              spellcheck="false"
              use:selectAll
              onblur={commitRename}
              onkeydown={(e) => {
                e.stopPropagation();
                if (e.key === 'Enter') commitRename();
                if (e.key === 'Escape') renaming = null;
              }}
            />
          {:else}
            <span class="nm">{tabTitle(tab)}</span>
            {#if tab.multi}<Icon name="cast" size={12} />{/if}
          {/if}
          <button
            class="x"
            title={t('session.closeTab')}
            aria-label={t('session.closeTab')}
            onclick={(e) => {
              e.stopPropagation();
              closeTab(tab.key);
            }}><Icon name="x" size={12} /></button
          >
        </div>
      {/each}
      {#if marker === tabs.length}<i class="tab-mark"></i>{/if}
      <button class="tab-add" class:on={!!adding} title={t('tab.new')} aria-label={t('tab.new')} aria-haspopup="menu" onclick={openAdd}><Icon name="plus" size={15} /></button>
    {/if}
  </div>
  {#if showTabs}
    <button class="srch" title={t('search.kbd.hint')} onclick={() => (ui.palette = true)}>
      <Icon name="search" size={14} /><span>{t('search.placeholder')}</span><kbd>{t('search.kbd')}</kbd>
    </button>
  {/if}
  {#if vault.state === 'open' && !detached}
    <button class="tb-ic" title={t('title.lock')} aria-label={t('title.lock')} onclick={lock}><Icon name="lock" /></button>
  {/if}
  {#if inApp}
    <div class="wc">
      <button title={t('win.min')} aria-label={t('win.min')} onclick={() => win()?.minimize()}><Icon name="min" size={14} /></button>
      <button title={maximized ? t('win.restore') : t('win.max')} aria-label={maximized ? t('win.restore') : t('win.max')} onclick={() => win()?.toggleMaximize()}>
        <Icon name={maximized ? 'restore' : 'max'} size={13} />
      </button>
      <button class="cl" title={t('win.close')} aria-label={t('win.close')} onclick={() => win()?.close()}><Icon name="x" size={14} /></button>
    </div>
  {/if}
</header>

{#if menu && menuTab}
  <TabMenu tab={menuTab} x={menu.x} y={menu.y} onclose={() => (menu = null)} onrename={() => startRename(menuTab)} onworkspace={() => (workspaceOf = menuTab.key)} />
{/if}
{#if adding}
  <NewTabMenu x={adding.x} y={adding.y} onclose={() => (adding = null)} onhosts={detached || vault.state !== 'open' ? undefined : home} />
{/if}
{#if workspaceTab}
  {#key workspaceTab.key}<WorkspaceSave tab={workspaceTab} onclose={() => (workspaceOf = null)} />{/key}
{/if}
{#if drag.item}
  <div class="dragchip" style="left:{drag.x}px;top:{drag.y}px;--c:{drag.color}">
    <i class="dot"></i>{drag.label}
    {#if drag.drop?.kind === 'outside'}<span>{t('drag.window')}</span>{/if}
  </div>
{/if}
