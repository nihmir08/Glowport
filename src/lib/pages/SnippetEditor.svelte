<script lang="ts">
  import { snippetSave } from '../backend';
  import { applySnapshot, errorText, vault } from '../data.svelte';
  import { targetVault } from '../sync.svelte';
  import { t } from '../i18n.svelte';
  import { hotkeyLabel, hotkeyOf, hotkeyProblem, macroDuration, showKeys, variablesOf } from '../snippets';
  import { settings, toast } from '../state.svelte';
  import type { Snippet, SnippetInput } from '../types';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';
  import TextField from '../ui/TextField.svelte';

  /** Anlegen und Bearbeiten eines Snippets. Ein Makro lässt sich umbenennen, einordnen und mit einem Kürzel versehen; seine Tasten bleiben, wie sie aufgezeichnet wurden. */
  let {
    snippet,
    onclose,
    onsaved,
    ondelete,
    onrun,
  }: { snippet: Snippet | null; onclose: () => void; onsaved: (id: string) => void; ondelete?: (snippet: Snippet) => void; onrun?: (snippet: Snippet) => void } = $props();

  // Der Editor wird je Snippet neu erzeugt ({#key}); die Startwerte werden bewusst nur einmal gelesen.
  const start = (() => snippet)();
  const macro = start?.kind === 'macro';

  let name = $state(start?.name ?? '');
  let pack = $state(start?.package ?? '');
  let command = $state(start?.command ?? '');
  let hotkey = $state(start?.hotkey ?? '');
  /** Wartet das Feld „Tastenkürzel“ gerade auf einen Tastendruck? */
  let listening = $state(false);
  let hotkeyNote = $state('');
  let busy = $state(false);
  let error = $state('');

  const variables = $derived(variablesOf(command));
  const packs = $derived([...new Set(vault.snippets.map((s) => s.package).filter(Boolean))].sort((a, b) => a.localeCompare(b)));
  const changed = $derived(name !== (start?.name ?? '') || pack !== (start?.package ?? '') || command !== (start?.command ?? '') || hotkey !== (start?.hotkey ?? ''));

  /** Nimmt den nächsten Tastendruck als Kürzel. Esc bricht ab, ohne etwas zu ändern. */
  function capture(event: KeyboardEvent) {
    if (!listening) return;
    event.preventDefault();
    event.stopPropagation();
    if (event.key === 'Escape') return void (listening = false);
    // Strg, Alt und Umschalt allein sind noch kein Kürzel.
    if (['Control', 'Alt', 'Shift', 'Meta', 'AltGraph'].includes(event.key)) return;
    const pressed = hotkeyOf(event);
    const problem = pressed ? hotkeyProblem(pressed) : 'invalid';
    const taken = pressed ? vault.snippets.find((other) => other.hotkey === pressed && other.id !== start?.id) : undefined;
    if (problem === 'invalid') hotkeyNote = t('snip.hotkey.invalid');
    else if (problem === 'reserved') hotkeyNote = t('snip.hotkey.reserved', { key: hotkeyLabel(pressed!, settings.lang) });
    else if (taken) hotkeyNote = t('snip.hotkey.taken', { key: hotkeyLabel(pressed!, settings.lang), name: taken.name });
    else {
      hotkey = pressed!;
      hotkeyNote = '';
      listening = false;
    }
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    const input: SnippetInput = { id: start?.id, name, package: pack, kind: macro ? 'macro' : 'command', command: macro ? '' : command, steps: macro ? start!.steps : [], hotkey: hotkey || null };
    if (!start) input.vault = targetVault();
    busy = true;
    try {
      const result = await snippetSave(input);
      applySnapshot(result.data);
      toast(t('common.saved'), 'ok');
      onsaved(result.id!);
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }
</script>

<svelte:window onkeydowncapture={capture} />

<form class="editor isl" onsubmit={save}>
  <header class="ed-h">
    <span class="os lg" style="--c:var(--accent)"><Icon name={macro ? 'rec' : 'snippet'} size={22} /></span>
    <div style="min-width:0">
      <div class="d-name">{name || t('snip.title.new')}</div>
      <div class="d-sub">{macro ? t('macro.title.edit') : start ? t('snip.title.edit') : t('snip.title.new')}</div>
    </div>
    <span class="grow"></span>
    <Button variant="ghost" size="sm" icon="x" title={t('common.close')} onclick={onclose} />
  </header>

  <div class="ed-b">
    <TextField label={t('edit.name')} bind:value={name} placeholder={t('snip.name.placeholder')} autofocus={!start} />
    <label class="fld">
      <span class="fld-l">{t('snip.package')}</span>
      <input type="text" list="snippet-packages" placeholder={t('snip.package.placeholder')} value={pack} spellcheck="false" autocomplete="off" oninput={(e) => (pack = e.currentTarget.value)} />
      <datalist id="snippet-packages">{#each packs as p (p)}<option value={p}></option>{/each}</datalist>
      <span class="fld-h">{t('snip.package.hint')}</span>
    </label>

    {#if macro}
      <div class="fld">
        <span class="fld-l">{t('macro.steps', { n: start!.steps.length, s: Math.max(1, Math.round(macroDuration(start!.steps) / 1000)) })}</span>
        <div class="steps">
          {#each start!.steps as step, i (i)}
            <div class="step">
              <span class="step-w">{step.wait >= 100 ? `+${(step.wait / 1000).toFixed(1).replace('.', settings.lang === 'de' ? ',' : '.')} s` : ''}</span>
              <code>{#each showKeys(step.keys) as part, j (j)}{#if part.key}<i class="keycap">{part.key}</i>{:else}{part.text}{/if}{/each}</code>
            </div>
          {/each}
        </div>
        <span class="fld-h">{t('macro.steps.hint')}</span>
      </div>
    {:else}
      <label class="fld">
        <span class="fld-l">{t('snip.command')}</span>
        <textarea class="codearea" rows="5" placeholder={'sudo systemctl restart {{dienst}}'} value={command} spellcheck="false" autocomplete="off" oninput={(e) => (command = e.currentTarget.value)}></textarea>
        <span class="fld-h">{t('snip.command.hint')}</span>
      </label>
      {#if variables.length}
        <div class="fld">
          <span class="fld-l">{t('snip.variables')}</span>
          <div class="tags">
            {#each variables as v (v.name)}<i class="chip a">{v.name}{#if v.fallback}&nbsp;= {v.fallback}{/if}</i>{/each}
          </div>
          <span class="fld-h">{t('snip.variables.hint')}</span>
        </div>
      {/if}
    {/if}

    <div class="fld">
      <span class="fld-l">{t('snip.hotkey')}</span>
      <div class="hotkey" class:on={listening}>
        {#if listening}
          <span class="grow">{t('snip.hotkey.press')}</span>
          <Button size="sm" onclick={() => ((listening = false), (hotkeyNote = ''))}>{t('common.cancel')}</Button>
        {:else}
          <span class="grow">{#if hotkey}<kbd>{hotkeyLabel(hotkey, settings.lang)}</kbd>{:else}{t('snip.hotkey.none')}{/if}</span>
          {#if hotkey}<Button size="sm" variant="ghost" icon="x" title={t('snip.hotkey.clear')} onclick={() => (hotkey = '')} />{/if}
          <Button size="sm" icon="keyboard" onclick={() => ((listening = true), (hotkeyNote = ''))}>{t('snip.hotkey.record')}</Button>
        {/if}
      </div>
      <span class="fld-h" class:errline={!!hotkeyNote}>{hotkeyNote || t('snip.hotkey.hint')}</span>
    </div>
    {#if start && !macro && onrun}
      <div class="fld">
        <span class="fld-l">{t('snip.runhosts.label')}</span>
        <div style="display:grid"><Button icon="cast" disabled={changed} onclick={() => onrun(start)}>{t('snip.runhosts')}</Button></div>
        <span class="fld-h">{changed ? t('snip.runhosts.save') : t('snip.runhosts.hint')}</span>
      </div>
    {/if}
    {#if error}<p class="errline" role="alert">{error}</p>{/if}
  </div>

  <footer class="ed-f">
    {#if start && ondelete}<Button variant="danger" icon="trash" title={t('common.delete')} onclick={() => ondelete(start)} />{/if}
    <span class="grow"></span>
    <Button onclick={onclose}>{t('common.cancel')}</Button>
    <button type="submit" class="btn primary" disabled={busy}>{t('common.save')}</button>
  </footer>
</form>
