<script lang="ts">
  import { untrack } from 'svelte';
  import { activeTransfers, barFor, fileUi, formatSize, overallProgress, pruneBars, transfers, upload } from '../files.svelte';
  import { t } from '../i18n.svelte';
  import { panes, paneTitle, type Pane } from '../sessions.svelte';
  import { settings } from '../state.svelte';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';
  import FileList from './FileList.svelte';
  import FilePath from './FilePath.svelte';

  /** Dateileiste neben dem Terminal: die Dateien des Servers, an dem der Bereich mit der Tastatur hängt. */
  let { pane }: { pane: Pane } = $props();

  const browser = $derived(barFor(pane.key));
  const connected = $derived(pane.sessionId !== null && pane.phase === 'connected');
  const chosen = $derived(browser.chosen);
  const running = $derived(activeTransfers().length);

  // Die Leiste hängt an der Verbindung des Bereichs: Steht sie, öffnet sich der Ordner des Terminals; endet sie, ist die Leiste leer.
  $effect(() => {
    const session = connected ? pane.sessionId : null;
    const current = untrack(() => browser.place);
    if (session === null) return void (current && untrack(() => browser.reset()));
    if (current?.kind !== 'session' || current.id !== session) void untrack(() => browser.open({ kind: 'session', id: session }, pane.cwd ?? undefined));
  });

  // „Dem Terminal folgen“: Wechselt die Shell den Ordner, geht die Leiste mit.
  $effect(() => {
    const cwd = pane.cwd;
    if (!settings.fileFollow || !cwd || !connected) return;
    untrack(() => browser.place && browser.listing && browser.path !== cwd && void browser.go(cwd));
  });

  $effect(() => pruneBars(panes.map((p) => p.key)));

  /** Zieht die Breite der Leiste an ihrem rechten Rand. */
  function resize(event: PointerEvent) {
    if (event.button !== 0) return;
    event.preventDefault();
    const grip = event.currentTarget as HTMLElement;
    const start = event.clientX - settings.fileBarWidth;
    grip.setPointerCapture(event.pointerId);
    const move = (e: PointerEvent) => (settings.fileBarWidth = Math.round(Math.max(220, Math.min(520, e.clientX - start))));
    const stop = () => (grip.removeEventListener('pointermove', move), grip.removeEventListener('pointerup', stop), grip.removeEventListener('pointercancel', stop));
    grip.addEventListener('pointermove', move);
    grip.addEventListener('pointerup', stop);
    grip.addEventListener('pointercancel', stop);
  }
</script>

<aside class="fbar isl" style="width:{settings.fileBarWidth}px" aria-label={t('files.bar')}>
  <header class="fbar-h">
    <Icon name="folder" size={15} />
    <b>{paneTitle(pane)}</b>
    <span class="grow"></span>
    <Button variant="ghost" size="sm" icon="target" active={settings.fileFollow} title={t('files.follow.hint')} onclick={() => (settings.fileFollow = !settings.fileFollow)}>{t('files.follow')}</Button>
    <Button variant="ghost" size="sm" icon="x" title={t('files.bar.hide')} onclick={() => (settings.fileBar = false)} />
  </header>

  {#if !connected}
    <div class="fnote"><Icon name="folder" size={22} /><p>{t('files.bar.offline')}</p></div>
  {:else}
    <div class="ftools">
      <Button variant="ghost" size="sm" icon="up" title={t('files.up')} disabled={browser.listing?.parent == null} onclick={() => browser.up()} />
      <Button variant="ghost" size="sm" icon="home" title={t('files.home')} onclick={() => browser.go()} />
      <Button variant="ghost" size="sm" icon="refresh" title={t('files.refresh')} onclick={() => browser.refresh()} />
      <span class="grow"></span>
      <Button variant="ghost" size="sm" icon="folderPlus" title={t('files.mkdir')} disabled={!browser.listing?.writable} onclick={() => (fileUi.naming = { browser, entry: null })} />
      <Button variant="ghost" size="sm" icon="upload" title={t('files.upload')} disabled={!browser.listing?.writable} onclick={() => browser.place && browser.listing && upload(browser.place, browser.listing.path)} />
      <Button variant="ghost" size="sm" icon="search" title={t('files.search')} disabled={!browser.listing} onclick={() => (fileUi.search = { browser })} />
      <Button variant="ghost" size="sm" icon="eye" active={settings.fileHidden} title={t('files.hidden')} onclick={() => (settings.fileHidden = !settings.fileHidden)} />
    </div>
    <FilePath {browser} />
    <FileList {browser} compact pane={pane.key} />
    <footer class="ffoot">
      {#if chosen.length}
        <span>{t('files.selected', { n: chosen.length })}{#if chosen.some((e) => e.kind === 'file')}&nbsp;· {formatSize(chosen.reduce((n, e) => n + e.size, 0))}{/if}</span>
      {:else}
        <span>{t('files.count', { n: browser.entries.length })}</span>
      {/if}
      {#if browser.listing && !browser.listing.writable}<i class="chip" title={t('files.readonly.hint')}>{t('files.readonly')}</i>{/if}
      <span class="grow"></span>
      {#if running}
        <button type="button" class="fmini" title={t('transfers.title')} onclick={() => (transfers.panel = !transfers.panel)}>
          <Icon name="transfer" size={12} />{Math.round(overallProgress() * 100)} %
        </button>
      {/if}
    </footer>
  {/if}
  <div class="fgrip" role="separator" aria-orientation="vertical" onpointerdown={resize}></div>
</aside>
