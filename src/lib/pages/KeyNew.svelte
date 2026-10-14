<script lang="ts">
  import { keyGenerate, keyImport, keyInspect, keyPickFile } from '../backend';
  import { applySnapshot, errorText } from '../data.svelte';
  import { targetVault } from '../sync.svelte';
  import { t } from '../i18n.svelte';
  import { KEY_BITS, KEY_COLOR, KIND_NAME, keyLabel } from '../keys';
  import { toast } from '../state.svelte';
  import type { KeyFile, KeyInfo, KeyKind } from '../types';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import TextField from '../ui/TextField.svelte';

  /** `file`: a key file already chosen, e.g. dragged into the window or from the “Key file” field. */
  let { mode: startMode, file = null, onclose, onsaved }: { mode: 'generate' | 'import'; file?: KeyFile | null; onclose: () => void; onsaved: (id: string) => void } = $props();

  const FORMATS = { openssh: 'OpenSSH', pem: 'PEM', ppk: 'PuTTY' };

  // The initial value is deliberately read only once; after that the user switches themselves.
  const start = (() => ({ mode: startMode, file }))();
  const baseName = (path: string) => path.split(/[\\/]/).pop() ?? '';

  let mode = $state(start.mode);
  let name = $state(start.file ? baseName(start.file.path) : '');
  let kind = $state<KeyKind>('ed25519');
  let bits = $state<Record<KeyKind, number>>({ ed25519: KEY_BITS.ed25519[0], ecdsa: KEY_BITS.ecdsa[0], rsa: KEY_BITS.rsa[0] });
  let picked = $state<KeyFile | null>(start.file);
  let pasted = $state('');
  let passphrase = $state('');
  let info = $state<KeyInfo | null>(null);
  let unreadable = $state('');
  let busy = $state(false);
  let error = $state('');

  const text = $derived((picked?.text ?? pasted).trim());
  const typeHint = $derived(t(kind === 'ed25519' ? 'keys.new.type.ed25519' : kind === 'ecdsa' ? 'keys.new.type.ecdsa' : 'keys.new.type.rsa'));

  // Says even before importing what is in the file and whether it needs a passphrase.
  $effect(() => {
    const current = text;
    info = null;
    unreadable = '';
    if (!current) return;
    const timer = setTimeout(() => {
      keyInspect(current).then(
        (found) => text === current && (info = found),
        (e) => text === current && (unreadable = errorText(e)),
      );
    }, 250);
    return () => clearTimeout(timer);
  });

  async function pick() {
    const file = await keyPickFile();
    if (!file) return;
    picked = file;
    passphrase = '';
    if (!name.trim()) name = baseName(file.path);
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    busy = true;
    try {
      const vault = targetVault();
      const changed = mode === 'generate' ? await keyGenerate({ name, kind, bits: bits[kind], vault }) : await keyImport({ name, text, passphrase: passphrase || undefined, vault });
      applySnapshot(changed.data);
      toast(t('common.saved'), 'ok');
      onsaved(changed.id!);
    } catch (e) {
      error = errorText(e);
    } finally {
      passphrase = '';
      busy = false;
    }
  }
</script>

<form class="editor isl" onsubmit={save}>
  <header class="ed-h">
    <span class="os lg" style="--c:{KEY_COLOR[mode === 'generate' ? kind : (info?.kind ?? 'ed25519')]}"><Icon name="key" size={22} /></span>
    <div style="min-width:0">
      <div class="d-name">{name || t('keys.new.title')}</div>
      <div class="d-sub">{t('keys.new.title')}</div>
    </div>
    <span class="grow"></span>
    <Button variant="ghost" size="sm" icon="x" title={t('common.close')} onclick={onclose} />
  </header>

  <div class="ed-b">
    <Segmented
      label={t('keys.new.title')}
      bind:value={mode}
      options={[
        { value: 'generate', label: t('keys.new.generate') },
        { value: 'import', label: t('keys.new.import') },
      ]}
    />

    {#if mode === 'generate'}
      <TextField label={t('edit.name')} bind:value={name} placeholder="arbeit-2026" hint={t('keys.new.name.hint')} autofocus />
      <div class="fld">
        <span class="fld-l">{t('keys.type')}</span>
        <Segmented
          label={t('keys.type')}
          bind:value={kind}
          options={[
            { value: 'ed25519', label: KIND_NAME.ed25519 },
            { value: 'ecdsa', label: KIND_NAME.ecdsa },
            { value: 'rsa', label: KIND_NAME.rsa },
          ]}
        />
        <span class="fld-h">{typeHint}</span>
      </div>
      {#if KEY_BITS[kind].length > 1}
        <label class="fld">
          <span class="fld-l">{t('keys.new.bits')}</span>
          <select class="dropdown" bind:value={bits[kind]}>
            {#each KEY_BITS[kind] as n (n)}<option value={n}>{keyLabel({ kind, bits: n })}</option>{/each}
          </select>
        </label>
      {/if}
    {:else}
      {#if picked}
        <div class="filebox">
          <Icon name="log" size={14} />
          <span class="mono" title={picked.path}>{picked.path}</span>
          <button type="button" class="mini" title={t('keys.imp.file.clear')} aria-label={t('keys.imp.file.clear')} onclick={() => (picked = null)}><Icon name="x" size={13} /></button>
        </div>
      {:else}
        <div style="display:flex;gap:8px;align-items:center">
          <Button icon="folder" onclick={pick}>{t('keys.imp.file')}</Button>
          <span class="fld-h">{t('keys.imp.formats')}</span>
        </div>
        <label class="fld">
          <span class="fld-l">{t('keys.imp.text')}</span>
          <textarea bind:value={pasted} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" spellcheck="false" autocomplete="off"></textarea>
        </label>
      {/if}

      {#if info}
        <div class="tags">
          <i class="chip a">{FORMATS[info.format]}</i>
          {#if info.kind && info.bits}<i class="chip">{keyLabel({ kind: info.kind, bits: info.bits })}</i>{/if}
          {#if info.encrypted}<i class="chip"><Icon name="lock" size={10} />{t('keys.imp.encrypted')}</i>{/if}
          {#if info.comment}<i class="chip">{info.comment}</i>{/if}
        </div>
      {:else if unreadable}
        <p class="errline" role="alert">{unreadable}</p>
      {/if}

      <TextField label={t('edit.name')} bind:value={name} placeholder="arbeit-2026" />
      {#if info?.encrypted}
        <TextField label={t('keys.imp.passphrase')} bind:value={passphrase} hint={t('keys.imp.passphrase.hint')} password />
      {/if}
    {/if}
    {#if error}<p class="errline" role="alert">{error}</p>{/if}
  </div>

  <footer class="ed-f">
    <span class="grow"></span>
    <Button onclick={onclose}>{t('common.cancel')}</Button>
    <button type="submit" class="btn primary" disabled={busy || (mode === 'import' && !info)}>{mode === 'generate' ? t('keys.new.submit') : t('keys.import')}</button>
  </footer>
</form>
