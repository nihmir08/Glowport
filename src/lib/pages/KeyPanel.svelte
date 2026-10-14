<script lang="ts">
  import { clipboardWrite, keyExport, keyPickFile, keyRename, keySetCertificate } from '../backend';
  import { applySnapshot, errorText, hostsUsingKey, vault } from '../data.svelte';
  import { formatDate, t } from '../i18n.svelte';
  import { KEY_COLOR, KIND_NAME, keyLabel } from '../keys';
  import { toast } from '../state.svelte';
  import type { SshKey } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import TextField from '../ui/TextField.svelte';

  let { key, onclose, ondeploy, ondelete }: { key: SshKey; onclose: () => void; ondeploy: () => void; ondelete: () => void } = $props();

  // The panel is created anew per key ({#key} in KeysPage); the initial value is deliberately read only once.
  const start = (() => key)();

  let name = $state(start.name);
  let busy = $state(false);
  let error = $state('');
  let exporting = $state(false);
  let passphrase = $state('');
  let certifying = $state(false);
  let certificateText = $state('');
  let certificateError = $state('');

  const certificate = $derived(key.certificate ?? null);
  const expired = $derived(!!certificate?.validBefore && certificate.validBefore * 1000 < Date.now());
  const identities = $derived(vault.identities.filter((i) => i.key === key.id));
  const hosts = $derived(hostsUsingKey(key.id));

  async function copyPublic() {
    try {
      await clipboardWrite(key.publicKey);
      toast(t('keys.copied'), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    busy = true;
    try {
      applySnapshot((await keyRename(key.id, name)).data);
      toast(t('common.saved'), 'ok');
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function pickCertificate() {
    const file = await keyPickFile();
    if (file) certificateText = file.text;
  }

  /** Stores the pasted certificate; without text the existing one is removed. */
  async function setCertificate(text: string | null) {
    certificateError = '';
    try {
      applySnapshot((await keySetCertificate(key.id, text)).data);
      certifying = false;
      certificateText = '';
      toast(t('common.saved'), 'ok');
    } catch (e) {
      if (text) certificateError = errorText(e);
      else toast(errorText(e), 'err');
    }
  }

  async function exportKey() {
    exporting = false;
    try {
      const path = await keyExport(key.id, passphrase || null);
      if (path) toast(t('keys.export.done', { path }), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    } finally {
      passphrase = '';
    }
  }
</script>

<form class="editor isl" onsubmit={save}>
  <header class="ed-h">
    <span class="os lg" style="--c:{KEY_COLOR[key.kind]}"><Icon name="key" size={22} /></span>
    <div style="min-width:0">
      <div class="d-name">{key.name}</div>
      <div class="d-sub">{keyLabel(key)}</div>
    </div>
    <span class="grow"></span>
    <Button variant="ghost" size="sm" icon="x" title={t('common.close')} onclick={onclose} />
  </header>

  <div class="ed-b">
    <div style="display:flex;gap:8px">
      <div style="flex:1;display:grid">
        <Button variant="primary" icon="send" onclick={ondeploy}>{t('keys.deploy')}</Button>
      </div>
      <Button icon="copy" title={t('keys.copyPublic')} onclick={copyPublic} />
      <Button icon="upload" title={t('keys.export')} onclick={() => (exporting = true)} />
    </div>

    <TextField label={t('edit.name')} bind:value={name} />

    <div class="fld">
      <span class="fld-l">{t('keys.public')}</span>
      <div class="pubkey mono selectable">{key.publicKey}</div>
      <span class="fld-h">{t('keys.public.hint')}</span>
    </div>

    <dl class="kv">
      <div>
        <dt>{t('keys.type')}</dt>
        <dd>{KIND_NAME[key.kind]} · {t('keys.bits', { n: key.bits })}</dd>
      </div>
      <div>
        <dt>{t('keys.fingerprint')}</dt>
        <dd><span class="mono selectable" style="word-break:break-all">{key.fingerprint}</span></dd>
      </div>
      <div>
        <dt>{t('keys.origin')}</dt>
        <dd>{t(key.origin === 'generated' ? 'keys.origin.generated' : 'keys.origin.imported', { date: formatDate(key.addedAt) })}</dd>
      </div>
    </dl>

    <div class="fld">
      <span class="fld-l">{t('keys.cert')}</span>
      {#if certificate}
        <div class="tags">
          <i class="chip a"><Icon name="badge" size={10} />{certificate.keyId}</i>
          <i class="chip" class:err={expired}>
            {#if !certificate.validBefore}{t('keys.cert.forever')}{:else}{t(expired ? 'keys.cert.expired' : 'keys.cert.until', { date: formatDate(certificate.validBefore * 1000) })}{/if}
          </i>
        </div>
        <span class="fld-h">{t('keys.cert.for')}: {certificate.principals.join(', ') || t('keys.cert.anyone')}</span>
        <span class="fld-h mono selectable" style="word-break:break-all">{t('keys.cert.authority')}: {certificate.authority}</span>
        <div><Button size="sm" variant="danger" icon="trash" onclick={() => setCertificate(null)}>{t('keys.cert.remove')}</Button></div>
      {:else}
        <span class="fld-h">{t('keys.cert.none')}</span>
        <div><Button size="sm" icon="badge" onclick={() => (certifying = true)}>{t('keys.cert.add')}</Button></div>
      {/if}
    </div>

    <div class="fld">
      <span class="fld-l">{t('keys.usedBy')}</span>
      {#if identities.length || hosts.length}
        <div class="tags">
          {#each identities as i (i.id)}<i class="chip a"><Icon name="user" size={10} />{i.name}</i>{/each}
          {#each hosts as h (h.id)}<i class="chip">{h.name}</i>{/each}
        </div>
      {:else}
        <span class="fld-h">{t('keys.usedBy.none')}</span>
      {/if}
    </div>
    {#if error}<p class="errline" role="alert">{error}</p>{/if}
  </div>

  <footer class="ed-f">
    <Button variant="danger" icon="trash" onclick={ondelete}>{t('common.delete')}</Button>
    <span class="grow"></span>
    <Button onclick={onclose}>{t('common.close')}</Button>
    <button type="submit" class="btn primary" disabled={busy || name.trim() === key.name}>{t('common.save')}</button>
  </footer>
</form>

<Dialog bind:open={exporting} title={t('keys.export')}>
  <div class="warnbox"><Icon name="alert" size={16} /><span>{t('keys.export.text')}</span></div>
  <TextField label={t('keys.export.passphrase')} bind:value={passphrase} hint={t('keys.export.passphrase.hint')} password />
  {#snippet actions()}
    <Button variant="primary" onclick={() => (exporting = false)}>{t('common.cancel')}</Button>
    <Button icon="upload" onclick={exportKey}>{t('keys.export.confirm')}</Button>
  {/snippet}
</Dialog>

<Dialog bind:open={certifying} title={t('keys.cert.title', { name: key.name })}>
  <div style="display:flex;gap:8px;align-items:center">
    <Button icon="folder" onclick={pickCertificate}>{t('keys.imp.file')}</Button>
  </div>
  <label class="fld">
    <span class="fld-l">{t('keys.cert.paste')}</span>
    <textarea bind:value={certificateText} placeholder="ssh-ed25519-cert-v01@openssh.com AAAA…" spellcheck="false" autocomplete="off"></textarea>
  </label>
  {#if certificateError}<p class="errline" role="alert">{certificateError}</p>{/if}
  {#snippet actions()}
    <Button onclick={() => (certifying = false)}>{t('common.cancel')}</Button>
    <Button variant="primary" icon="badge" disabled={!certificateText.trim()} onclick={() => setCertificate(certificateText)}>{t('keys.cert.submit')}</Button>
  {/snippet}
</Dialog>
