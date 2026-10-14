<script lang="ts">
  import { vault } from '../data.svelte';
  import { t, tn } from '../i18n.svelte';
  import type { Pane } from '../sessions.svelte';
  import { firstLine, hotkeyLabel, lineCount, macroKeys, showKeys, variablesOf } from '../snippets';
  import { packages, snipUi, startRecording, stopMacro, stopRecording, useSnippet } from '../snippets.svelte';
  import { settings, ui } from '../state.svelte';
  import { view } from '../sessions.svelte';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';

  /** Snippets am Terminal: mit einem Klick ausführen oder nur einfügen, dazu Makros aufzeichnen und abspielen. */
  let { pane }: { pane: Pane } = $props();

  let query = $state('');

  const needle = $derived(query.trim().toLowerCase());
  const shown = $derived(vault.snippets.filter((s) => !needle || [s.name, s.package, s.command].some((text) => text.toLowerCase().includes(needle))));
  const groups = $derived(packages(shown));
  const connected = $derived(pane.sessionId !== null && pane.phase === 'connected');
  const recording = $derived(snipUi.recording?.pane === pane.key ? snipUi.recording : null);
  const playing = $derived(snipUi.playing?.pane === pane.key ? snipUi.playing : null);
  const locked = $derived(vault.state !== 'open');

  /** Öffnet die Seite „Snippets“ im Start-Tab. */
  function manage() {
    ui.page = 'snip';
    view.active = 'home';
  }
</script>

<div class="side-b snips">
  {#if locked}
    <div class="fnote"><Icon name="lock" size={22} /><p>{t('snip.locked')}</p></div>
  {:else}
    <div class="snip-top">
      <label class="search">
        <Icon name="search" size={14} />
        <input type="text" placeholder={t('snip.search')} aria-label={t('snip.search')} bind:value={query} spellcheck="false" />
      </label>
      <Button size="sm" icon="plus" title={t('snip.new')} onclick={() => (snipUi.editing = { snippet: null })} />
    </div>

    {#if !vault.snippets.length}
      <div class="fnote">
        <Icon name="snippet" size={22} />
        <p>{t('snip.bar.empty')}</p>
        <Button size="sm" variant="primary" icon="plus" onclick={() => (snipUi.editing = { snippet: null })}>{t('snip.new')}</Button>
      </div>
    {:else if !shown.length}
      <div class="fnote"><p>{t('snip.noresults', { q: query.trim() })}</p></div>
    {/if}

    {#each groups as group (group.name)}
      <div class="snip-p">{group.name || t('snip.nopackage')}</div>
      {#each group.items as s (s.id)}
        {@const variables = s.kind === 'command' ? variablesOf(s.command).length : 0}
        <div class="snip">
          <div class="snip-h">
            <b>{s.name}</b>
            {#if s.hotkey}<kbd>{hotkeyLabel(s.hotkey, settings.lang)}</kbd>{/if}
            <button type="button" class="mini" title={t('common.edit')} aria-label={t('common.edit')} onclick={() => (snipUi.editing = { snippet: s })}><Icon name="edit" size={12} /></button>
          </div>
          {#if s.kind === 'macro'}
            <code class="snip-c">{#each showKeys(macroKeys(s.steps)).slice(0, 14) as part, i (i)}{#if part.key}<i class="keycap">{part.key}</i>{:else}{part.text}{/if}{/each}</code>
          {:else}
            <code class="snip-c">{firstLine(s.command)}{#if lineCount(s.command) > 1}<i class="more">{tn('snip.morelines', lineCount(s.command) - 1)}</i>{/if}</code>
          {/if}
          <div class="snip-a">
            {#if s.kind === 'macro'}
              <Button size="sm" variant="primary" icon="play" disabled={!connected || !!snipUi.playing} onclick={() => useSnippet(s, pane.key, 'run')}>{t('macro.play')}</Button>
              <i class="chip">{t('macro.label')}</i>
            {:else}
              <Button size="sm" variant="primary" icon="play" disabled={!connected} onclick={() => useSnippet(s, pane.key, 'run')}>{t('snip.run')}</Button>
              <Button size="sm" icon="paste" disabled={!connected} title={t('snip.paste.hint')} onclick={() => useSnippet(s, pane.key, 'paste')}>{t('snip.paste')}</Button>
              {#if variables}<i class="chip a">{tn('snip.vars', variables)}</i>{/if}
            {/if}
          </div>
        </div>
      {/each}
    {/each}
  {/if}
</div>

{#if !locked}
  <footer class="side-f">
    {#if recording}
      <div class="macrobox rec">
        <span class="recdot"></span>
        <span class="grow">{tn('macro.recording', recording.steps.length)}</span>
        <Button size="sm" onclick={() => stopRecording(false)}>{t('macro.discard')}</Button>
        <Button size="sm" variant="primary" icon="stop" onclick={() => stopRecording()}>{t('macro.finish')}</Button>
      </div>
    {:else if playing}
      <div class="macrobox">
        <Icon name="play" size={13} />
        <span class="grow">{t('macro.playing', { name: playing.name })}</span>
        <Button size="sm" icon="stop" onclick={stopMacro}>{t('macro.stop')}</Button>
      </div>
    {:else}
      <Button size="sm" icon="rec" disabled={!connected} title={t('macro.record.hint')} onclick={() => startRecording(pane.key)}>{t('macro.record')}</Button>
      <span class="grow"></span>
      <Button size="sm" variant="ghost" icon="external" onclick={manage}>{t('snip.manage')}</Button>
    {/if}
  </footer>
{/if}
