<script lang="ts">
  import { fileDrag, fileUi, formatSize, formatWhen, iconFor, modeText, openFile, startFileDrag, type Browser } from '../files.svelte';
  import { t } from '../i18n.svelte';
  import type { FileEntry } from '../types';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';

  /**
   * A folder's content as a list. `compact` is the narrow version of the file bar at the terminal;
   * `other` is the neighbouring column you can transfer into; `pane` the terminal pane the list belongs to.
   */
  let { browser, compact = false, other = null, pane = null }: { browser: Browser; compact?: boolean; other?: Browser | null; pane?: string | null } = $props();

  const entries = $derived(browser.entries);
  /** Something from another list is hovering over this list right now. */
  const target = $derived(!!fileDrag.item && fileDrag.item.from !== browser && fileDrag.over === browser);

  function activate(entry: FileEntry) {
    // A link to a file opens the file; everything else is a folder you go into.
    if (entry.kind === 'file' || (entry.kind === 'link' && entry.linksToDir === false)) openFile(browser, entry);
    else void browser.go(entry.path);
  }

  function menu(event: MouseEvent, entry: FileEntry | null) {
    event.preventDefault();
    event.stopPropagation();
    if (entry) browser.include(entry);
    else browser.selected = [];
    fileUi.menu = { browser, entry, x: event.clientX, y: event.clientY, other, pane };
  }

  function sortBy(by: 'name' | 'size' | 'modified') {
    browser.sort = { by, desc: browser.sort.by === by ? !browser.sort.desc : by !== 'name' };
  }

  function keydown(event: KeyboardEvent) {
    const chosen = browser.chosen;
    const index = entries.findIndex((e) => e.path === browser.selected.at(-1));
    const move = (to: number) => {
      const next = entries[Math.max(0, Math.min(entries.length - 1, to))];
      if (!next) return;
      browser.pick(next, { ctrlKey: false, shiftKey: event.shiftKey });
      document.querySelector(`[data-file="${CSS.escape(next.path)}"]`)?.scrollIntoView({ block: 'nearest' });
    };
    const actions: Record<string, () => void> = {
      ArrowDown: () => move(index + 1),
      ArrowUp: () => move(index < 0 ? 0 : index - 1),
      Home: () => move(0),
      End: () => move(entries.length - 1),
      Enter: () => chosen.length === 1 && activate(chosen[0]),
      Backspace: () => void browser.up(),
      F5: () => void browser.refresh(),
      F2: () => chosen.length === 1 && (fileUi.naming = { browser, entry: chosen[0] }),
      Delete: () => chosen.length && (fileUi.removing = { browser, entries: chosen }),
    };
    const action = event.ctrlKey && event.key.toLowerCase() === 'a' ? () => (browser.selected = entries.map((e) => e.path)) : actions[event.key];
    if (!action || event.altKey) return;
    event.preventDefault();
    action();
  }
</script>

{#snippet head(by: 'name' | 'size' | 'modified', label: string, cls: string)}
  <button type="button" class={cls} class:on={browser.sort.by === by} onclick={() => sortBy(by)}>
    {label}{#if browser.sort.by === by}<Icon name={browser.sort.desc ? 'chevD' : 'up'} size={11} />{/if}
  </button>
{/snippet}

<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div
  class="flist"
  class:compact
  class:local={browser.place?.kind === 'local'}
  class:target
  class:busy={browser.loading}
  role="listbox"
  aria-multiselectable="true"
  aria-label={browser.path ?? ''}
  tabindex="0"
  onkeydown={keydown}
  oncontextmenu={(e) => browser.listing && menu(e, null)}
  onpointerenter={() => fileDrag.item && (fileDrag.over = browser)}
  onpointerleave={() => fileDrag.over === browser && ((fileDrag.over = null), (fileDrag.dir = null))}
>
  {#if !compact && browser.listing}
    <div class="fhead">
      {@render head('name', t('files.col.name'), 'fn')}
      {@render head('size', t('files.col.size'), 'fs')}
      {@render head('modified', t('files.col.modified'), 'fm')}
      {#if browser.place?.kind !== 'local'}<span class="fp">{t('files.col.mode')}</span><span class="fo">{t('files.col.owner')}</span>{/if}
    </div>
  {/if}

  {#if browser.error}
    <div class="fnote"><Icon name="alert" size={20} /><p>{browser.error}</p><Button size="sm" icon="refresh" onclick={() => browser.go()}>{t('files.retry')}</Button></div>
  {:else if !browser.listing}
    <div class="fnote"><p>{t('files.loading')}</p></div>
  {:else if !entries.length}
    <div class="fnote"><p>{browser.filter.trim() ? t('hosts.noresults', { q: browser.filter.trim() }) : t('files.empty')}</p></div>
  {:else}
    <div class="frows">
      {#each entries as entry (entry.path)}
        <!-- The keyboard operates the list as a whole (see keydown). -->
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <div
          class="frow"
          class:sel={browser.selected.includes(entry.path)}
          class:dim={entry.hidden ?? entry.name.startsWith('.')}
          class:into={target && fileDrag.dir === entry.path}
          role="option"
          aria-selected={browser.selected.includes(entry.path)}
          tabindex="-1"
          data-file={entry.path}
          title={compact ? `${entry.name}\n${formatWhen(entry.modified, true)}${entry.mode !== null ? `\n${modeText(entry)}  ${entry.owner}:${entry.group}` : ''}` : undefined}
          onpointerdown={(e) => {
            if (e.button !== 0) return;
            // A click into an existing multi-selection keeps it, so it can be dragged.
            if (!(browser.selected.length > 1 && browser.selected.includes(entry.path) && !e.ctrlKey && !e.shiftKey)) browser.pick(entry, e);
            startFileDrag(e, browser);
          }}
          onclick={(e) => !e.ctrlKey && !e.shiftKey && !fileDrag.moved && browser.pick(entry, e)}
          ondblclick={() => activate(entry)}
          oncontextmenu={(e) => menu(e, entry)}
          onpointerenter={() => fileDrag.item && (fileDrag.dir = entry.kind === 'dir' ? entry.path : null)}
        >
          <span class="fi {entry.kind}"><Icon name={iconFor(entry)} size={compact ? 15 : 16} /></span>
          <span class="fn">{entry.name}{#if entry.target}<i>&nbsp;→ {entry.target}</i>{/if}</span>
          <span class="fs">{entry.kind === 'file' ? formatSize(entry.size) : ''}</span>
          {#if !compact}
            <span class="fm">{formatWhen(entry.modified)}</span>
            {#if browser.place?.kind !== 'local'}<span class="fp">{modeText(entry)}</span><span class="fo">{entry.owner}:{entry.group}</span>{/if}
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>
