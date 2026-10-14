<script lang="ts">
  import { snippetDelete } from '../backend';
  import { applySnapshot, errorText, snippetById, vault } from '../data.svelte';
  import { inScope, scope } from '../sync.svelte';
  import VaultBadge from '../ui/VaultBadge.svelte';
  import VaultSwitch from '../ui/VaultSwitch.svelte';
  import { t, tn } from '../i18n.svelte';
  import { firstLine, hotkeyLabel, lineCount, macroKeys, showKeys, variablesOf } from '../snippets';
  import { packages, snipUi } from '../snippets.svelte';
  import { settings, toast } from '../state.svelte';
  import type { Snippet } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import SnippetEditor from './SnippetEditor.svelte';

  /** Snippets and macros, ordered by package. A click opens the editor on the right. */
  let panel = $state<{ id: string | null } | null>(null);
  let query = $state('');
  let removing = $state<Snippet | null>(null);

  // If the snippet shown disappears (deleted, vault reloaded), the editor closes.
  $effect(() => {
    if (panel?.id && !snippetById(panel.id)) panel = null;
  });

  const needle = $derived(query.trim().toLowerCase());
  // What is in the chosen vault is shown; the search finds everything.
  const shown = $derived(vault.snippets.filter((s) => (needle ? [s.name, s.package, s.command].some((text) => text.toLowerCase().includes(needle)) : inScope(s))));
  const groups = $derived(packages(shown));
  const empty = $derived(!vault.snippets.length);

  async function confirmDelete() {
    const snippet = removing!;
    removing = null;
    panel = null;
    try {
      applySnapshot((await snippetDelete(snippet.id)).data);
      toast(t('common.deleted'), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }
</script>

<section class="pg isl" style={empty ? 'display:flex;flex-direction:column' : ''}>
  <div class="crumbs"></div>
  <div class="ph">
    <div>
      <h1>{t('page.snip.title')}</h1>
      <div class="sub">{t('page.snip.text')}</div>
    </div>
    <div class="acts">
      <label class="search">
        <Icon name="search" size={14} />
        <input type="text" placeholder={t('snip.search')} aria-label={t('snip.search')} bind:value={query} spellcheck="false" />
      </label>
      <Button variant="primary" icon="plus" onclick={() => (panel = { id: null })}>{t('snip.new')}</Button>
    </div>
  </div>

  <VaultSwitch />

  {#if empty}
    <div class="empty">
      <span class="ei"><Icon name="snippet" size={28} /></span>
      <h2>{t('snip.empty.title')}</h2>
      <p>{t('snip.empty.text')}</p>
      <Button variant="primary" icon="plus" onclick={() => (panel = { id: null })}>{t('snip.new')}</Button>
    </div>
  {:else if !shown.length && needle}
    <div class="empty"><p>{t('snip.noresults', { q: query.trim() })}</p></div>
  {:else}
    {#each groups as group (group.name)}
      <div class="sec">{group.name ? t('snip.sec.package', { name: group.name }) : t('snip.nopackage')}</div>
      <div class="rows">
        {#each group.items as s (s.id)}
          {@const variables = s.kind === 'command' ? variablesOf(s.command).length : 0}
          <div class="row pick-row" class:sel={panel?.id === s.id} role="button" tabindex="0" onclick={() => (panel = { id: s.id })} onkeydown={(e) => e.key === 'Enter' && (panel = { id: s.id })}>
            <span class="ri"><Icon name={s.kind === 'macro' ? 'rec' : 'snippet'} size={16} /></span>
            <div class="rt">
              <b>{s.name}</b>
              {#if s.kind === 'macro'}
                <span class="mono snip-l">{#each showKeys(macroKeys(s.steps)).slice(0, 24) as part, i (i)}{#if part.key}<i class="keycap">{part.key}</i>{:else}{part.text}{/if}{/each}</span>
              {:else}
                <span class="mono snip-l">{firstLine(s.command)}{#if lineCount(s.command) > 1}<i class="more">{tn('snip.morelines', lineCount(s.command) - 1)}</i>{/if}</span>
              {/if}
            </div>
            {#if scope.vault === 'all' || needle}<VaultBadge entry={s} />{/if}
            {#if s.kind === 'macro'}<i class="chip">{t('macro.label')}</i>{/if}
            {#if variables}<i class="chip a">{tn('snip.vars', variables)}</i>{/if}
            {#if s.hotkey}<kbd>{hotkeyLabel(s.hotkey, settings.lang)}</kbd>{/if}
            {#if s.kind === 'command'}
              <Button size="sm" icon="cast" title={t('snip.runhosts.hint')} onclick={(e) => (e.stopPropagation(), (snipUi.running = s))}>{t('snip.runhosts')}</Button>
            {/if}
          </div>
        {/each}
      </div>
    {/each}
    <p class="fld-h" style="margin-top:12px;max-width:80ch">{t('snip.page.hint')}</p>
  {/if}
</section>

{#if panel}
  {#key panel.id}
    <SnippetEditor
      snippet={snippetById(panel.id) ?? null}
      onclose={() => (panel = null)}
      onsaved={() => (panel = null)}
      ondelete={(snippet) => (removing = snippet)}
      onrun={(snippet) => (snipUi.running = snippet)}
    />
  {/key}
{/if}

<Dialog open={!!removing} title={t('snip.del.title')}>
  <p>{t('snip.del.text', { name: removing?.name ?? '' })}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (removing = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" onclick={confirmDelete}>{t('common.delete')}</Button>
  {/snippet}
</Dialog>
