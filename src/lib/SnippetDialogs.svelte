<script lang="ts">
  import { snippetDelete, snippetSave } from './backend';
  import { applySnapshot, errorText, vault } from './data.svelte';
  import { t } from './i18n.svelte';
  import SnippetEditor from './pages/SnippetEditor.svelte';
  import SnippetRun from './pages/SnippetRun.svelte';
  import { fill, macroDuration, macroKeys, showKeys, variablesOf } from './snippets';
  import { answerVariables, lastValues, snipUi } from './snippets.svelte';
  import { focusTerminal } from './sessions.svelte';
  import { toast } from './state.svelte';
  import Button from './ui/Button.svelte';
  import Dialog from './ui/Dialog.svelte';
  import Icon from './ui/Icon.svelte';
  import TextField from './ui/TextField.svelte';

  /**
   * The dialogs around snippets that can open from anywhere: values for variables, the name of a freshly
   * recorded macro, the editor from the sidebar at the terminal and running on many hosts.
   */
  let values = $state<Record<string, string>>({});
  let name = $state('');
  let pack = $state('');
  let busy = $state(false);
  let error = $state('');

  const asking = $derived(snipUi.asking);
  const variables = $derived(asking ? variablesOf(asking.snippet.command) : []);
  const packs = $derived([...new Set(vault.snippets.map((s) => s.package).filter(Boolean))].sort((a, b) => a.localeCompare(b)));

  // Every query starts with the values from last time; a new macro with empty fields.
  $effect(() => {
    values = asking ? { ...lastValues(asking.snippet.id) } : {};
  });
  $effect(() => {
    void snipUi.naming;
    name = pack = error = '';
  });

  function cancelAsking() {
    const pane = asking?.pane;
    snipUi.asking = null;
    if (pane) focusTerminal(pane);
  }

  async function saveMacro(event: SubmitEvent) {
    event.preventDefault();
    const steps = snipUi.naming;
    if (!steps) return;
    busy = true;
    error = '';
    try {
      applySnapshot((await snippetSave({ name, package: pack, kind: 'macro', command: '', steps, hotkey: null })).data);
      snipUi.naming = null;
      toast(t('macro.saved'), 'ok');
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function remove() {
    const snippet = snipUi.editing?.snippet;
    snipUi.editing = null;
    if (!snippet) return;
    try {
      applySnapshot((await snippetDelete(snippet.id)).data);
      toast(t('common.deleted'), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }
</script>

<svelte:window
  onkeydowncapture={(e) => {
    if (e.key !== 'Escape' || !snipUi.editing) return;
    e.stopPropagation();
    snipUi.editing = null;
  }}
/>

{#if asking}
  <Dialog bind:open={() => true, (open) => !open && cancelAsking()} title={asking.snippet.name}>
    <form id="snippet-vars" class="run-vars one" onsubmit={(e) => (e.preventDefault(), answerVariables(values, asking.mode))}>
      {#each variables as v, i (v.name)}
        <label class="fld">
          <span class="fld-l">{v.name}</span>
          <!-- svelte-ignore a11y_autofocus -->
          <input class="mono" type="text" placeholder={v.fallback} value={values[v.name] ?? ''} autofocus={i === 0} spellcheck="false" autocomplete="off" oninput={(e) => (values[v.name] = e.currentTarget.value)} />
        </label>
      {/each}
    </form>
    <pre class="run-cmd selectable">{fill(asking.snippet.command, values)}</pre>
    {#snippet actions()}
      <Button onclick={cancelAsking}>{t('common.cancel')}</Button>
      {#if asking.mode === 'run'}
        <Button icon="paste" onclick={() => answerVariables(values, 'paste')}>{t('snip.paste')}</Button>
        <button type="submit" form="snippet-vars" class="btn primary"><Icon name="play" size={15} />{t('snip.run')}</button>
      {:else}
        <Button icon="play" onclick={() => answerVariables(values, 'run')}>{t('snip.run')}</Button>
        <button type="submit" form="snippet-vars" class="btn primary"><Icon name="paste" size={15} />{t('snip.paste')}</button>
      {/if}
    {/snippet}
  </Dialog>
{/if}

{#if snipUi.naming}
  {@const steps = snipUi.naming}
  <div class="ov" role="presentation">
    <form class="dlg" aria-label={t('macro.save.title')} onsubmit={saveMacro}>
      <h2>{t('macro.save.title')}</h2>
      <div class="dlg-b">
        <p>{t('macro.save.text', { n: steps.length, s: Math.max(1, Math.round(macroDuration(steps) / 1000)) })}</p>
        <code class="snip-c wrap">{#each showKeys(macroKeys(steps)) as part, i (i)}{#if part.key}<i class="keycap">{part.key}</i>{:else}{part.text}{/if}{/each}</code>
        <TextField label={t('edit.name')} bind:value={name} placeholder={t('macro.name.placeholder')} autofocus />
        <label class="fld">
          <span class="fld-l">{t('snip.package')}</span>
          <input type="text" list="macro-packages" placeholder={t('snip.package.placeholder')} value={pack} spellcheck="false" autocomplete="off" oninput={(e) => (pack = e.currentTarget.value)} />
          <datalist id="macro-packages">{#each packs as p (p)}<option value={p}></option>{/each}</datalist>
        </label>
        <div class="warnbox"><Icon name="alert" size={16} /><span>{t('macro.save.warn')}</span></div>
        {#if error}<p class="errline" role="alert">{error}</p>{/if}
      </div>
      <div class="dlg-a">
        <Button onclick={() => (snipUi.naming = null)}>{t('macro.discard')}</Button>
        <button type="submit" class="btn primary" disabled={busy || !name.trim()}>{t('common.save')}</button>
      </div>
    </form>
  </div>
{/if}

{#if snipUi.editing}
  {@const editing = snipUi.editing}
  <div class="ov quick" role="presentation" onclick={(e) => e.target === e.currentTarget && (snipUi.editing = null)}>
    {#key editing.snippet?.id}
      <SnippetEditor snippet={editing.snippet} onclose={() => (snipUi.editing = null)} onsaved={() => (snipUi.editing = null)} ondelete={editing.snippet ? remove : undefined} />
    {/key}
  </div>
{/if}

{#if snipUi.running}
  {#key snipUi.running.id}
    <SnippetRun snippet={snipUi.running} onclose={() => (snipUi.running = null)} />
  {/key}
{/if}
