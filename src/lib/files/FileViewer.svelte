<script lang="ts">
  import { onMount } from 'svelte';
  import { fsRead, fsWrite } from '../backend';
  import { errorText } from '../data.svelte';
  import { download, fileUi, formatSize, iconFor, isImage, modeText, placeName } from '../files.svelte';
  import { t } from '../i18n.svelte';
  import { paneTitle, panes } from '../sessions.svelte';
  import { toast } from '../state.svelte';
  import type { FileContent } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import { createEditor, languageName, type EditorHandle } from './editor';

  /** View or edit a file: text in the built-in editor, images as images. Saved back to the location it came from. */
  const { place, entry, browser } = fileUi.viewer!;
  let edit = $state(fileUi.viewer!.edit);

  let content = $state<FileContent | null>(null);
  let failed = $state<string | null>(null);
  let dirty = $state(false);
  let saving = $state(false);
  let leaving = $state(false);
  let cursor = $state({ line: 1, column: 1 });
  let host = $state<HTMLDivElement>();
  let editor: EditorHandle | null = null;

  const where = $derived(place.kind === 'session' ? (panes.find((p) => p.sessionId === place.id) ? paneTitle(panes.find((p) => p.sessionId === place.id)!) : '') : placeName(place));
  const language = languageName(entry.name, entry.path);
  /** Saving would damage the file: only the beginning loaded or not UTF-8. Then it stays read-only. */
  const locked = $derived(content?.kind === 'text' && !content.editable);

  async function load() {
    failed = null;
    try {
      content = await fsRead(place, entry.path);
    } catch (e) {
      failed = errorText(e);
    }
  }
  onMount(() => {
    void load();
    return () => {
      editor?.destroy();
      if (content?.kind === 'image' && content.url.startsWith('blob:')) URL.revokeObjectURL(content.url);
    };
  });

  // The editor is created as soon as text is there, and anew when switching between viewing and editing.
  $effect(() => {
    const text = content?.kind === 'text' ? content.text : null;
    const readOnly = !edit || locked;
    if (text === null || !host) return;
    let current = true;
    let made: EditorHandle | null = null;
    const keep = editor?.text() ?? text;
    editor?.destroy();
    editor = null;
    void createEditor(host, { text: keep, name: entry.name, path: entry.path, readOnly, onChange: () => (dirty = true), onSave: () => void save(), onCursor: (line, column) => (cursor = { line, column }) }).then((handle) => {
      if (!current) return handle.destroy();
      made = editor = handle;
      if (!readOnly) handle.focus();
    });
    return () => {
      current = false;
      if (made && editor === made) (made.destroy(), (editor = null));
    };
  });

  async function save() {
    if (!editor || !dirty || saving || !edit || locked) return;
    saving = true;
    try {
      await fsWrite(place, entry.path, editor.text());
      dirty = false;
      toast(t('viewer.saved', { name: entry.name }), 'ok');
      void browser?.refresh();
    } catch (e) {
      toast(errorText(e), 'err');
    } finally {
      saving = false;
    }
  }

  async function reload() {
    await load();
    if (content?.kind === 'text') editor?.load(content.text);
    dirty = false;
  }

  const close = () => (dirty ? (leaving = true) : (fileUi.viewer = null));

  function keydown(event: KeyboardEvent) {
    if (event.key !== 'Escape' || leaving) return;
    // Esc first closes the editor's search; only without it the window.
    if ((event.target as HTMLElement).closest?.('.cm-search')) return;
    event.preventDefault();
    close();
  }
</script>

<svelte:window onkeydown={keydown} />

<div class="ov" role="presentation" onpointerdown={(e) => e.target === e.currentTarget && close()}>
  <div class="fview isl" role="dialog" aria-modal="true" aria-label={entry.name}>
    <header class="ed-h">
      <span class="ri"><Icon name={iconFor(entry)} size={16} /></span>
      <div style="min-width:0;flex:1">
        <div class="d-name">{entry.name}{#if dirty}<i class="chip a">{t('viewer.dirty')}</i>{/if}{#if (!edit || locked) && content?.kind === 'text'}<i class="chip">{t('viewer.readonly')}</i>{/if}</div>
        <div class="d-sub mono">{where}{where ? ':' : ''}{entry.path}</div>
      </div>
      {#if content?.kind === 'text'}
        {#if locked}
          <span class="rm warn">{t(content.truncated ? 'viewer.locked.long' : 'viewer.locked.charset')}</span>
        {:else if edit}
          <Button size="sm" icon="refresh" title={t('viewer.reload')} onclick={reload} />
          <Button size="sm" variant="primary" icon="save" disabled={!dirty || saving} onclick={save}>{saving ? t('viewer.saving') : t('common.save')}</Button>
        {:else}
          <Button size="sm" icon="edit" onclick={() => (edit = true)}>{t('files.edit')}</Button>
        {/if}
      {/if}
      {#if place.kind !== 'local'}<Button size="sm" icon="download" title={t('files.download')} onclick={() => download(place, [entry])} />{/if}
      <Button variant="ghost" size="sm" icon="x" title={t('common.close')} onclick={close} />
    </header>

    <div class="fview-b" class:image={content?.kind === 'image'}>
      {#if failed}
        <div class="fnote"><Icon name="alert" size={22} /><p>{failed}</p><Button size="sm" icon="refresh" onclick={load}>{t('files.retry')}</Button></div>
      {:else if !content}
        <div class="fnote"><p>{t('files.loading')}</p></div>
      {:else if content.kind === 'image'}
        <img src={content.url} alt={entry.name} />
      {:else if content.kind === 'binary'}
        <div class="fnote">
          <Icon name={isImage(entry.name) ? 'image' : 'file'} size={24} />
          <p>{t('viewer.binary')}</p>
          {#if place.kind !== 'local'}<Button icon="download" onclick={() => download(place, [entry])}>{t('files.download')}</Button>{/if}
        </div>
      {:else}
        <div class="fview-cm selectable" bind:this={host}></div>
      {/if}
    </div>

    <footer class="fview-f">
      {#if content?.kind === 'text'}
        <span>{language ?? t('viewer.plain')}</span>
        <span>{t('viewer.cursor', { line: cursor.line, column: cursor.column })}</span>
        <span>UTF-8</span>
        {#if content.truncated}<span class="warn">{t('viewer.truncated')}</span>{/if}
      {/if}
      <span class="grow"></span>
      {#if entry.size}<span>{formatSize(entry.size)}</span>{/if}
      {#if entry.mode !== null}<span class="mono">{modeText(entry)} {entry.owner}:{entry.group}</span>{/if}
      {#if edit && !locked && content?.kind === 'text'}<span>{t('viewer.kbd')}</span>{/if}
    </footer>
  </div>
</div>

<Dialog bind:open={leaving} title={t('viewer.leave.title')}>
  <p>{t('viewer.leave.text', { name: entry.name })}</p>
  {#snippet actions()}
    <Button onclick={() => (leaving = false)}>{t('common.cancel')}</Button>
    <Button variant="danger" onclick={() => (fileUi.viewer = null)}>{t('viewer.leave.discard')}</Button>
    <Button variant="primary" icon="save" onclick={() => save().then(() => !dirty && (fileUi.viewer = null))}>{t('common.save')}</Button>
  {/snippet}
</Dialog>
