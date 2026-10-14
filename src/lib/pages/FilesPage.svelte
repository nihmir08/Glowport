<script lang="ts">
  import { onMount } from 'svelte';
  import { fileHosts, ftpOpen, groupPath, hostById, isFtp } from '../data.svelte';
  import { columns, fileUi, formatSize, placeName, send, sendLabel, transfers, upload, type Browser, ftpPlaceName } from '../files.svelte';
  import FileList from '../files/FileList.svelte';
  import FilePath from '../files/FilePath.svelte';
  import Transfers from '../files/Transfers.svelte';
  import { t } from '../i18n.svelte';
  import SessionPrompt from '../SessionPrompt.svelte';
  import { settings } from '../state.svelte';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';
  import OsIcon from '../ui/OsIcon.svelte';

  /** Files in two columns: this PC and a server, or two servers. Transfers and syncing happen between them. */
  const { left, right } = columns;
  const LOCAL = 'local';

  onMount(() => {
    if (!left.place) void left.open({ kind: 'local' });
  });

  /** Hosts for a column's choice, sorted by their group path. */
  const hosts = $derived(
    fileHosts()
      .map((host) => ({ id: host.id, name: host.name, group: groupPath(host.group).map((g) => g.name).join(' / ') }))
      .sort((a, b) => a.group.localeCompare(b.group) || a.name.localeCompare(b.name)),
  );
  const groups = $derived([...new Set(hosts.map((h) => h.group))]);

  /** A server from quick connect is in the choice as long as it is open. */
  const DIRECT = 'direct';
  const valueOf = (browser: Browser) => (browser.place?.kind === 'host' ? browser.place.id : browser.place?.kind === 'ftp' ? DIRECT : browser.place ? LOCAL : '');
  /** For FTP: whether the connection to this location runs unencrypted. `null` for everything else. */
  const ftpPlain = (browser: Browser): boolean | null => {
    const place = browser.place;
    if (place?.kind === 'ftp') return place.security === 'none';
    const host = place?.kind === 'host' ? hostById(place.id) : undefined;
    return isFtp(host) ? ftpOpen(host) : null;
  };
  const choose = (browser: Browser, value: string) => void (value === DIRECT ? null : value === LOCAL ? browser.open({ kind: 'local' }) : value ? browser.open({ kind: 'host', id: value }) : browser.reset());
  const ready = (browser: Browser) => !!browser.place && !!browser.listing;
  const both = $derived(ready(left) && ready(right));

  function transfer(from: Browser, to: Browser) {
    if (from.place && to.place && to.listing) void send(from.place, from.chosen, to.place, to.listing.path);
  }
</script>

{#snippet column(browser: Browser, other: Browser, side: 'left' | 'right')}
  {@const host = browser.place?.kind === 'host' ? hostById(browser.place.id) : undefined}
  {@const plain = ftpPlain(browser)}
  {@const chosen = browser.chosen}
  <section class="fcol isl" aria-label={t(side === 'left' ? 'files.side.left' : 'files.side.right')}>
    <header class="fcol-h">
      {#if browser.place?.kind === 'local'}
        <span class="ri"><Icon name="monitor" size={16} /></span>
      {:else}
        <OsIcon os={host?.os} size="sm" />
      {/if}
      <select class="dropdown" aria-label={t('files.place')} value={valueOf(browser)} onchange={(e) => choose(browser, e.currentTarget.value)}>
        {#if !browser.place}<option value="">{t('files.place.choose')}</option>{/if}
        <option value={LOCAL}>{t('files.local')}</option>
        {#if browser.place?.kind === 'ftp'}<option value={DIRECT}>{ftpPlaceName(browser.place)}</option>{/if}
        {#each groups as group (group)}
          <optgroup label={group || t('files.place.hosts')}>
            {#each hosts.filter((h) => h.group === group) as h (h.id)}<option value={h.id}>{h.name}</option>{/each}
          </optgroup>
        {/each}
      </select>
      {#if plain !== null}
        <i class="chip {plain ? 'err' : 'ok'}" title={t(plain ? 'ftp.chip.open.hint' : 'ftp.chip.secure.hint')}><Icon name={plain ? 'unlock' : 'lock'} size={12} />{t(plain ? 'ftp.chip.open' : 'ftp.chip.secure')}</i>
      {/if}
      <label class="search">
        <Icon name="search" size={14} />
        <input type="text" placeholder={t('files.filter')} aria-label={t('files.filter')} bind:value={browser.filter} spellcheck="false" disabled={!browser.listing} />
      </label>
    </header>

    {#if !browser.place}
      <div class="empty">
        <span class="ei"><Icon name="server" size={28} /></span>
        <h2>{t('files.pick.title')}</h2>
        <p>{t('files.pick.text')}</p>
      </div>
    {:else}
      <div class="ftools">
        <Button variant="ghost" size="sm" icon="up" title={t('files.up')} disabled={browser.listing?.parent == null} onclick={() => browser.up()} />
        <Button variant="ghost" size="sm" icon="home" title={t('files.home')} onclick={() => browser.go()} />
        <Button variant="ghost" size="sm" icon="refresh" title={t('files.refresh')} onclick={() => browser.refresh()} />
        <FilePath {browser} />
        <Button variant="ghost" size="sm" icon="folderPlus" title={t('files.mkdir')} disabled={!browser.listing?.writable} onclick={() => (fileUi.naming = { browser, entry: null })} />
        {#if browser.place.kind !== 'local'}
          <Button variant="ghost" size="sm" icon="upload" title={t('files.upload')} disabled={!browser.listing?.writable} onclick={() => browser.place && browser.listing && upload(browser.place, browser.listing.path)} />
          <Button variant="ghost" size="sm" icon="search" title={t('files.search')} disabled={!browser.listing} onclick={() => (fileUi.search = { browser })} />
        {/if}
        <Button variant="ghost" size="sm" icon="eye" active={settings.fileHidden} title={t('files.hidden')} onclick={() => (settings.fileHidden = !settings.fileHidden)} />
      </div>
      <FileList {browser} {other} />
      <footer class="ffoot">
        {#if chosen.length}
          <span>{t('files.selected', { n: chosen.length })}{#if chosen.some((e) => e.kind === 'file')}&nbsp;· {formatSize(chosen.reduce((n, e) => n + e.size, 0))}{/if}</span>
        {:else}
          <span>{t('files.count', { n: browser.entries.length })}</span>
        {/if}
        {#if browser.listing && !browser.listing.writable}<i class="chip" title={t('files.readonly.hint')}>{t('files.readonly')}</i>{/if}
        <span class="grow"></span>
        {#if chosen.length && ready(other)}
          <Button size="sm" variant="primary" icon={side === 'left' ? 'arrowR' : 'arrowL'} disabled={!other.listing?.writable} onclick={() => transfer(browser, other)}>{sendLabel(other.place)}</Button>
        {/if}
      </footer>
    {/if}
  </section>
{/snippet}

<div class="fpage">
  <div class="fcols">
    {@render column(left, right, 'left')}
    <div class="fmid">
      <Button icon="arrowR" title={t('files.send.right')} disabled={!both || !left.chosen.length || !right.listing?.writable} onclick={() => transfer(left, right)} />
      <Button icon="arrowL" title={t('files.send.left')} disabled={!both || !right.chosen.length || !left.listing?.writable} onclick={() => transfer(right, left)} />
      <span class="fmid-line"></span>
      <Button icon="forward" title={t('compare.open')} disabled={!both} onclick={() => (fileUi.compare = { left, right })} />
      <span class="grow"></span>
      <Button icon="transfer" active={transfers.dock} title={t('transfers.title')} onclick={() => (transfers.dock = !transfers.dock)} />
    </div>
    {@render column(right, left, 'right')}
  </div>
  {#if transfers.dock}<Transfers dock />{/if}
</div>

<!-- A host that cannot sign in silently asks here as in the terminal: server key, password. -->
{#each [left, right] as browser (browser)}
  {#if browser.prompt}<SessionPrompt prompt={browser.prompt} name={placeName(browser.place)} onanswer={(reply) => browser.answer(reply)} />{/if}
{/each}
