<script lang="ts">
  import { onMount } from 'svelte';
  import { clipboardWrite, logDelete, logList, logRead, logRename, logReveal } from '../backend';
  import { errorText } from '../data.svelte';
  import { t } from '../i18n.svelte';
  import { settings, toast, ui } from '../state.svelte';
  import type { Recording } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';

  /** Recordings: the list by day and on the right the chosen one's text for reading and searching. */
  let list = $state<Recording[]>([]);
  let loaded = $state(false);
  let query = $state('');
  let selected = $state<string | null>(null);
  let text = $state<string | null>(null);
  let find = $state('');
  let removing = $state<Recording | null>(null);
  /** The open recording's name is being edited right now. */
  let renaming = $state(false);
  let renameText = $state('');

  const locale = $derived(settings.lang === 'de' ? 'de-DE' : 'en-GB');
  const needle = $derived(query.trim().toLowerCase());
  const label = (r: Recording) => r.title || r.name;
  const shown = $derived(needle ? list.filter((r) => `${r.title ?? ''} ${r.name} ${r.address}`.toLowerCase().includes(needle)) : list);
  const current = $derived(list.find((r) => r.id === selected));

  /** Recordings by day, the most recent day first. */
  const days = $derived.by(() => {
    const groups: { label: string; items: Recording[] }[] = [];
    const startOfDay = (ms: number) => new Date(ms).setHours(0, 0, 0, 0);
    const today = startOfDay(Date.now());
    for (const r of shown) {
      const day = startOfDay(r.startedAt);
      const label = day === today ? t('logs.today') : day === today - 86_400_000 ? t('logs.yesterday') : new Date(day).toLocaleDateString(locale, { weekday: 'long', day: '2-digit', month: '2-digit', year: 'numeric' });
      const last = groups[groups.length - 1];
      if (last?.label === label) last.items.push(r);
      else groups.push({ label, items: [r] });
    }
    return groups;
  });

  const clock = (ms: number) => new Date(ms).toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' });
  const minutes = (r: Recording) => Math.max(1, Math.round(((r.endedAt ?? Date.now()) - r.startedAt) / 60_000));
  const size = (bytes: number) => (bytes >= 1_048_576 ? `${(bytes / 1_048_576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`);
  const span = (r: Recording) => (r.endedAt ? t('logs.span', { from: clock(r.startedAt), to: clock(r.endedAt), n: minutes(r) }) : t('logs.since', { from: clock(r.startedAt) }));

  /** Lines of the chosen recording; with a search word only the matching ones, with line number. */
  const lines = $derived.by(() => {
    const all = (text ?? '').split('\n').map((line, i) => ({ n: i + 1, line }));
    const word = find.trim().toLowerCase();
    return word ? all.filter((entry) => entry.line.toLowerCase().includes(word)) : all;
  });

  async function refresh() {
    try {
      list = await logList();
    } catch (e) {
      toast(errorText(e), 'err');
    } finally {
      loaded = true;
    }
  }
  onMount(() => void refresh());

  async function open(r: Recording) {
    renaming = false;
    if (selected === r.id && text !== null) return;
    selected = r.id;
    text = null;
    find = '';
    try {
      const content = await logRead(r.id);
      if (selected === r.id) text = content;
    } catch (e) {
      toast(errorText(e), 'err');
      selected = null;
    }
  }

  async function remove() {
    const entry = removing!;
    removing = null;
    if (selected === entry.id) selected = null;
    try {
      list = await logDelete(entry.id);
      toast(t('common.deleted'), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }

  const copy = () => text && void clipboardWrite(text).then(() => toast(t('logs.copied'), 'ok'));

  /** Renaming in place. While a recording runs, its file is being written; then it is not possible yet. */
  function startRename(r: Recording) {
    if (!r.endedAt) return void toast(t('err.log_running'), 'err');
    renameText = r.title ?? '';
    renaming = true;
  }

  async function commitRename() {
    const entry = current;
    if (!renaming || !entry) return;
    renaming = false;
    const title = renameText.trim();
    if (title === (entry.title ?? '')) return;
    try {
      // With the name the file changes and thus the ID; the open text stays the same.
      const done = await logRename(entry.id, title);
      list = done.list;
      selected = done.id;
      toast(t('common.saved'), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }

  function selectAll(node: HTMLInputElement) {
    node.focus();
    node.select();
  }
</script>

<section class="pg isl" style={loaded && !list.length ? 'display:flex;flex-direction:column' : ''}>
  <div class="crumbs"></div>
  <div class="ph">
    <div>
      <h1>{t('page.logs.title')}</h1>
      <div class="sub">{t('logs.sub')}</div>
    </div>
    <div class="acts">
      <label class="search">
        <Icon name="search" size={14} />
        <input type="text" placeholder={t('logs.search')} aria-label={t('logs.search')} bind:value={query} spellcheck="false" />
      </label>
      <Button icon="folder" onclick={() => logReveal()}>{t('logs.folder')}</Button>
    </div>
  </div>

  {#if loaded && !list.length}
    <div class="empty">
      <span class="ei"><Icon name="log" size={28} /></span>
      <h2>{t('logs.empty.title')}</h2>
      <p>{t('logs.empty.text')}</p>
      <Button icon="gear" onclick={() => (ui.page = 'settings')}>{t('logs.empty.settings')}</Button>
    </div>
  {:else if loaded && !shown.length}
    <div class="empty"><p>{t('hosts.noresults', { q: query.trim() })}</p></div>
  {/if}

  {#each days as day (day.label)}
    <div class="sec">{day.label}</div>
    <div class="rows">
      {#each day.items as r (r.id)}
        <button type="button" class="row pick-row" class:sel={selected === r.id} onclick={() => open(r)} ondblclick={() => startRename(r)}>
          <span class="ri"><Icon name="log" size={16} /></span>
          <div class="rt">
            <b>{label(r)}</b>
            <span>{#if r.title}{r.name} · {/if}{span(r)} · <span class="mono">{r.address}</span></span>
          </div>
          {#if !r.endedAt}<i class="chip rec"><i class="recdot"></i>{t('logs.running')}</i>{/if}
          <span class="rm">{size(r.bytes)}</span>
        </button>
      {/each}
    </div>
  {/each}
</section>

{#if current}
  <aside class="logview isl">
    <header class="ed-h">
      <span class="ri"><Icon name="log" size={16} /></span>
      <div style="min-width:0;flex:1">
        {#if renaming}
          <input
            class="tab-name title"
            bind:value={renameText}
            placeholder={current.name}
            aria-label={t('logs.rename')}
            spellcheck="false"
            use:selectAll
            onblur={commitRename}
            onkeydown={(e) => {
              if (e.key === 'Enter') void commitRename();
              if (e.key === 'Escape') renaming = false;
            }}
          />
        {:else}
          <div class="d-name" role="presentation" ondblclick={() => startRename(current)}>{label(current)}</div>
        {/if}
        <div class="d-sub">{#if current.title}{current.name} · {/if}{new Date(current.startedAt).toLocaleDateString(locale, { day: '2-digit', month: '2-digit', year: 'numeric' })} · {span(current)} · {size(current.bytes)}</div>
      </div>
      <Button variant="ghost" size="sm" icon="edit" title={current.endedAt ? t('logs.rename') : t('err.log_running')} disabled={!current.endedAt} onclick={() => startRename(current)} />
      <Button variant="ghost" size="sm" icon="x" title={t('common.close')} onclick={() => (selected = null)} />
    </header>
    <div class="log-tools">
      <label class="search">
        <Icon name="search" size={14} />
        <input type="text" placeholder={t('logs.find')} aria-label={t('logs.find')} bind:value={find} spellcheck="false" />
      </label>
      {#if find.trim()}<span class="rm">{t('logs.find.count', { n: lines.length })}</span>{/if}
      <span class="grow"></span>
      <Button size="sm" icon="copy" title={t('logs.copy')} onclick={copy} disabled={text === null} />
      <Button size="sm" icon="folder" title={t('logs.reveal')} onclick={() => logReveal(current.id)} />
      <Button size="sm" variant="danger" icon="trash" title={t('common.delete')} onclick={() => (removing = current)} />
    </div>
    <div class="log-text selectable">
      {#if text === null}
        <p class="fld-h">{t('logs.loading')}</p>
      {:else}
        {#each lines as entry (entry.n)}<div><span class="ln">{entry.n}</span>{entry.line || ' '}</div>{/each}
      {/if}
    </div>
    <div class="log-foot mono selectable">{current.file}</div>
  </aside>
{/if}

<Dialog open={!!removing} title={t('logs.remove.title')}>
  <p>{t('logs.remove.text', { name: removing?.name ?? '' })}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (removing = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" onclick={remove}>{t('common.delete')}</Button>
  {/snippet}
</Dialog>
