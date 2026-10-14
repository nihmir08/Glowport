<script lang="ts">
  import { clipboardWrite } from '../backend';
  import { download, fileUi, isImage, openFile, send, sendLabel, upload } from '../files.svelte';
  import type { IconName } from '../icons';
  import { t } from '../i18n.svelte';
  import { input } from '../sessions.svelte';
  import { settings, toast } from '../state.svelte';
  import Icon from '../ui/Icon.svelte';

  /** Menu of a file list's entry (right-click) or of its empty area. */
  const menu = $derived(fileUi.menu!);
  const browser = $derived(menu.browser);
  const entry = $derived(menu.entry);
  const chosen = $derived(browser.chosen);
  const single = $derived(chosen.length === 1);
  const remote = $derived(browser.place?.kind !== 'local');
  const writable = $derived(!!browser.listing?.writable);
  const other = $derived(menu.other?.place && menu.other.listing ? menu.other : null);

  const WIDTH = 280;
  let box = $state<HTMLDivElement>();
  let height = $state(0);
  $effect(() => void (height = box?.offsetHeight ?? 0));
  const left = $derived(Math.max(8, Math.min(menu.x, innerWidth - WIDTH - 8)));
  const top = $derived(Math.max(8, Math.min(menu.y, innerHeight - height - 8)));

  const close = () => (fileUi.menu = null);
  function run(action: () => void) {
    action();
    close();
  }
  /** A path as one word for the shell. */
  const quoted = (path: string) => `'${path.replaceAll("'", `'\\''`)}'`;
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && close()} />

{#snippet item(icon: IconName, label: string, action: () => void, options: { disabled?: boolean; danger?: boolean; hint?: string } = {})}
  <button type="button" class="mi" class:danger={options.danger} disabled={options.disabled} role="menuitem" onclick={() => run(action)}>
    <Icon name={icon} size={15} /><span>{label}</span>{#if options.hint}<kbd>{options.hint}</kbd>{/if}
  </button>
{/snippet}

<div class="menu-ov" role="presentation" onpointerdown={(e) => e.target === e.currentTarget && close()} oncontextmenu={(e) => (e.preventDefault(), close())}>
  <div class="menu" role="menu" aria-label={t('files.menu')} bind:this={box} style="left:{left}px;top:{top}px;width:{WIDTH}px">
    {#if entry}
      {#if single && entry.kind !== 'file'}
        {@render item('folder', t('files.open'), () => void browser.go(entry.path), { hint: '↵' })}
      {:else if single}
        {@render item('edit', settings.fileEditor ? t('files.edit') : t('files.edit.external'), () => openFile(browser, entry, true), { hint: isImage(entry.name) ? undefined : '↵' })}
        {@render item('eye', t('files.preview'), () => (fileUi.viewer = { place: browser.place!, entry, edit: false, browser }))}
      {/if}
      {#if single}<hr />{/if}
      {#if other}
        {@render item('arrowR', sendLabel(other.place), () => void send(browser.place!, chosen, other.place!, other.listing!.path), { disabled: !other.listing?.writable })}
      {/if}
      {#if remote}
        {@render item('download', t('files.download'), () => void download(browser.place!, chosen))}
      {/if}
      {#if menu.pane && single && entry.kind === 'dir'}
        {@render item('terminal', t('files.cd'), () => input(menu.pane!, `cd ${quoted(entry.path)}\r`))}
      {/if}
      {#if single}
        {@render item('copy', t('files.copyPath'), () => void clipboardWrite(entry.path).then(() => toast(t('files.copied'), 'ok')))}
      {/if}
      <hr />
      {@render item('edit', t('files.rename'), () => (fileUi.naming = { browser, entry }), { disabled: !single || !writable, hint: 'F2' })}
      {#if remote && browser.listing?.ftp?.chmod !== false}
        {@render item('lock', t('perms.open'), () => (fileUi.perms = { browser, entries: chosen }))}
      {/if}
      <hr />
      {@render item('trash', chosen.length > 1 ? t('files.delete.n', { n: chosen.length }) : t('common.delete'), () => (fileUi.removing = { browser, entries: chosen }), { danger: true, disabled: !writable, hint: t('files.kbd.delete') })}
    {:else}
      {@render item('folderPlus', t('files.mkdir'), () => (fileUi.naming = { browser, entry: null }), { disabled: !writable })}
      {#if remote}
        {@render item('upload', t('files.upload'), () => void upload(browser.place!, browser.listing!.path), { disabled: !writable })}
        {@render item('search', t('files.search'), () => (fileUi.search = { browser }))}
      {/if}
      {@render item('refresh', t('files.refresh'), () => void browser.refresh(), { hint: 'F5' })}
      <hr />
      {@render item('eye', settings.fileHidden ? t('files.hidden.off') : t('files.hidden.on'), () => (settings.fileHidden = !settings.fileHidden))}
      {#if browser.path}
        {@render item('copy', t('files.copyPath'), () => void clipboardWrite(browser.path!).then(() => toast(t('files.copied'), 'ok')))}
      {/if}
    {/if}
  </div>
</div>
