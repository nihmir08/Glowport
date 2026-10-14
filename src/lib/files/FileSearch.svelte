<script lang="ts">
  import { fsSearch } from '../backend';
  import { errorText } from '../data.svelte';
  import { fileUi, formatSize, iconFor, openFile } from '../files.svelte';
  import { t } from '../i18n.svelte';
  import { toast } from '../state.svelte';
  import type { SearchHit } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import Segmented from '../ui/Segmented.svelte';

  /** Suche am Server unterhalb des offenen Ordners: nach Namen oder im Inhalt der Dateien. */
  const { browser } = fileUi.search!;
  const start = browser.path ?? '/';

  let query = $state('');
  let mode = $state<'name' | 'content'>('name');
  let hits = $state<SearchHit[]>([]);
  let busy = $state(false);
  let done = $state(false);
  /** Nur die Treffer der jüngsten Suche zählen. */
  let run = 0;

  const close = () => (run++, (fileUi.search = null));

  async function search() {
    const word = query.trim();
    if (!word) return;
    const mine = ++run;
    hits = [];
    busy = true;
    done = false;
    try {
      await fsSearch(browser.place!, start, word, mode === 'content', (hit) => mine === run && hits.push(hit));
    } catch (e) {
      if (mine === run) toast(errorText(e), 'err');
    } finally {
      if (mine === run) (busy = false), (done = true);
    }
  }

  /** Geht in den Ordner des Treffers und wählt ihn dort aus. */
  async function reveal(hit: SearchHit) {
    close();
    if (await browser.go(hit.dir)) browser.selected = [hit.path];
  }

  function open(hit: SearchHit) {
    if (hit.kind !== 'file') return void reveal(hit);
    close();
    openFile(browser, { name: hit.name, path: hit.path, kind: hit.kind, size: hit.size, modified: 0, mode: null, owner: '', group: '' });
  }

  function focus(node: HTMLInputElement) {
    node.focus();
  }
</script>

<Dialog bind:open={() => true, (v) => void (!v && close())} wide title={t('search.title')}>
  <form
    class="fsearch-q"
    onsubmit={(e) => {
      e.preventDefault();
      void search();
    }}
  >
    <label class="search">
      <Icon name="search" size={14} />
      <input type="text" placeholder={mode === 'name' ? t('search.name.ph') : t('search.content.ph')} aria-label={t('search.title')} bind:value={query} spellcheck="false" use:focus />
    </label>
    <!-- FTP kann nicht im Inhalt suchen: Dafür müsste jede Datei erst heruntergeladen werden. -->
    {#if !browser.listing?.ftp}<Segmented label={t('search.mode')} bind:value={mode} options={[{ value: 'name', label: t('search.name') }, { value: 'content', label: t('search.content') }]} />{/if}
    {#if busy}
      <Button icon="x" onclick={() => (run++, (busy = false), (done = true))}>{t('search.stop')}</Button>
    {:else}
      <button type="submit" class="btn primary md" disabled={!query.trim()}><Icon name="search" size={15} />{t('search.go')}</button>
    {/if}
  </form>
  <p class="fld-h">{t('search.in')} <span class="mono">{start}</span></p>

  <div class="fsearch-r">
    {#each hits as hit, i (i)}
      <button type="button" class="row pick-row" onclick={() => reveal(hit)} ondblclick={() => open(hit)}>
        <span class="fi {hit.kind}"><Icon name={iconFor(hit)} size={16} /></span>
        <div class="rt">
          <b>{hit.name}{#if hit.line}<span class="ln">:{hit.line}</span>{/if}</b>
          {#if hit.text !== undefined}<span class="mono hit">{hit.text}</span>{/if}
          <span class="mono">{hit.dir}</span>
        </div>
        {#if hit.kind === 'file' && hit.text === undefined}<span class="rm">{formatSize(hit.size)}</span>{/if}
      </button>
    {/each}
    {#if !hits.length}
      <p class="fnote">{busy ? t('search.busy') : done ? t('search.none') : t('search.hint')}</p>
    {/if}
  </div>

  {#snippet actions()}
    <span class="rm">{#if busy}{t('search.busy')}{#if hits.length}&nbsp;·&nbsp;{/if}{/if}{#if hits.length}{t('search.count', { n: hits.length })}{/if}</span>
    <span class="grow"></span>
    <Button onclick={close}>{t('common.close')}</Button>
  {/snippet}
</Dialog>
