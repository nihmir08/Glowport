<script lang="ts">
  import { fsMkdir, fsRemove, fsRename } from '../backend';
  import { errorText } from '../data.svelte';
  import { fileDrag, fileUi, iconFor } from '../files.svelte';
  import { t } from '../i18n.svelte';
  import { toast } from '../state.svelte';
  import type { Policy } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import FileMenu from './FileMenu.svelte';
  import FileSearch from './FileSearch.svelte';
  import FileViewer from './FileViewer.svelte';
  import FolderCompare from './FolderCompare.svelte';
  import PermsDialog from './PermsDialog.svelte';

  /** Everything around files that lies over the interface: menu, dialogs, editor and the badge while dragging. Mounted once in the window. */
  let name = $state('');
  let busy = $state(false);

  const naming = $derived(fileUi.naming);
  const conflict = $derived(fileUi.conflict);

  /** Answers the prompt about existing names; `null` cancels the transfer. */
  function settle(policy: Policy | null) {
    fileUi.conflict?.resolve(policy);
    fileUi.conflict = null;
  }
  const removing = $derived(fileUi.removing);

  $effect(() => {
    if (naming) name = naming.entry?.name ?? '';
  });

  async function commitName() {
    const job = naming;
    const wanted = name.trim();
    if (!job || !wanted || busy) return;
    if (job.entry && wanted === job.entry.name) return void (fileUi.naming = null);
    busy = true;
    try {
      if (job.entry) await fsRename(job.browser.place!, job.entry.path, wanted);
      else await fsMkdir(job.browser.place!, job.browser.path!, wanted);
      fileUi.naming = null;
      await job.browser.refresh();
    } catch (e) {
      toast(errorText(e), 'err');
    } finally {
      busy = false;
    }
  }

  async function remove() {
    const job = removing;
    if (!job || busy) return;
    busy = true;
    try {
      await fsRemove(job.browser.place!, job.entries.map((e) => e.path));
      toast(t('common.deleted'), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    } finally {
      busy = false;
      fileUi.removing = null;
      void job.browser.refresh();
    }
  }

  /** When renaming, selects the name without extension. */
  function selectStem(node: HTMLInputElement) {
    node.focus();
    const dot = node.value.lastIndexOf('.');
    node.setSelectionRange(0, naming?.entry?.kind === 'file' && dot > 0 ? dot : node.value.length);
  }
</script>

{#if fileUi.menu}<FileMenu />{/if}
{#if fileUi.viewer}{#key fileUi.viewer}<FileViewer />{/key}{/if}
{#if fileUi.perms}{#key fileUi.perms}<PermsDialog />{/key}{/if}
{#if fileUi.search}{#key fileUi.search}<FileSearch />{/key}{/if}
{#if fileUi.compare}{#key fileUi.compare}<FolderCompare />{/key}{/if}

<Dialog bind:open={() => !!naming, (v) => void (!v && (fileUi.naming = null))} title={naming?.entry ? t('files.rename') : t('files.mkdir')}>
  <form
    onsubmit={(e) => {
      e.preventDefault();
      void commitName();
    }}
  >
    <label class="fld">
      <span class="fld-l">{naming?.entry ? t('files.rename.label') : t('files.mkdir.label')}</span>
      {#key naming}<input type="text" class="mono" bind:value={name} spellcheck="false" autocomplete="off" use:selectStem />{/key}
      {#if !naming?.entry}<span class="fld-h mono">{naming?.browser.path}</span>{/if}
    </label>
  </form>
  {#snippet actions()}
    <Button onclick={() => (fileUi.naming = null)}>{t('common.cancel')}</Button>
    <Button variant="primary" icon="check" disabled={busy || !name.trim()} onclick={commitName}>{naming?.entry ? t('files.rename') : t('files.mkdir.create')}</Button>
  {/snippet}
</Dialog>

<Dialog bind:open={() => !!removing, (v) => void (!v && (fileUi.removing = null))} title={t('files.delete.title')}>
  {#if removing}
    <p>{removing.entries.length === 1 ? t('files.delete.one', { name: removing.entries[0].name }) : t('files.delete.many', { n: removing.entries.length })}</p>
    {#if removing.entries.some((e) => e.kind === 'dir')}<p class="warnline">{t('files.delete.dirs')}</p>{/if}
    <p class="fld-h">{t(removing.browser.place?.kind === 'local' ? 'files.delete.bin' : 'files.delete.final')}</p>
  {/if}
  {#snippet actions()}
    <Button variant="primary" onclick={() => (fileUi.removing = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" disabled={busy} onclick={remove}>{t('common.delete')}</Button>
  {/snippet}
</Dialog>

<Dialog wide bind:open={() => !!conflict, (v) => void (!v && settle(null))} title={t('conflict.title')}>
  {#if conflict}
    <p>{conflict.names.length === 1 ? t('conflict.one') : t('conflict.many', { n: conflict.names.length })} <span class="mono">{conflict.dest}</span></p>
    <ul class="conflict-names mono">
      {#each conflict.names.slice(0, 6) as name (name)}<li>{name}</li>{/each}
      {#if conflict.names.length > 6}<li class="more">{t('conflict.more', { n: conflict.names.length - 6 })}</li>{/if}
    </ul>
    <p class="fld-h">{t('conflict.hint')}</p>
  {/if}
  {#snippet actions()}
    <Button onclick={() => settle(null)}>{t('common.cancel')}</Button>
    <span class="grow"></span>
    <Button onclick={() => settle('skip')}>{t('set.files.conflict.skip')}</Button>
    <Button onclick={() => settle('rename')}>{t('conflict.keepBoth')}</Button>
    <Button variant="primary" onclick={() => settle('overwrite')}>{t('set.files.conflict.overwrite')}</Button>
  {/snippet}
</Dialog>

{#if fileDrag.staging !== null}
  <!-- The pointer is outside the window; so the notice sits fixed at the bottom edge. -->
  <div class="dragchip files pinned"><Icon name="download" size={14} /><b>{t('files.dragout.staging', { n: Math.round(fileDrag.staging * 100) })}</b></div>
{:else if fileDrag.item}
  <div class="dragchip files" style="left:{fileDrag.x}px;top:{fileDrag.y}px">
    <Icon name={iconFor(fileDrag.item.entries[0])} size={14} />
    <b>{fileDrag.item.entries.length === 1 ? fileDrag.item.entries[0].name : t('files.selected', { n: fileDrag.item.entries.length })}</b>
  </div>
{/if}
