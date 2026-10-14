<script lang="ts">
  import { authorityAdd, authorityDelete, knownHostDelete, pickTextFile } from '../backend';
  import { applySnapshot, errorText, vault } from '../data.svelte';
  import { formatDate, t } from '../i18n.svelte';
  import { toast } from '../state.svelte';
  import type { Authority, Changed, KnownHost } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import TextField from '../ui/TextField.svelte';

  let removing = $state<KnownHost | null>(null);
  let removingAuthority = $state<Authority | null>(null);
  let adding = $state(false);
  let name = $state('');
  let pattern = $state('*');
  let key = $state('');
  let error = $state('');

  const address = (k: KnownHost) => (k.port === 22 ? k.host : `${k.host}:${k.port}`);
  const empty = $derived(!vault.knownHosts.length && !vault.authorities.length);

  async function drop(work: () => Promise<Changed>) {
    try {
      applySnapshot((await work()).data);
      toast(t('common.deleted'), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }

  function remove() {
    const entry = removing!;
    removing = null;
    void drop(() => knownHostDelete(entry.id));
  }

  function removeAuthority() {
    const entry = removingAuthority!;
    removingAuthority = null;
    void drop(() => authorityDelete(entry.id));
  }

  /** The authority's public key from a file instead of the clipboard. */
  async function pickAuthorityKey() {
    try {
      const file = await pickTextFile('.pub');
      if (file) key = file.text.trim();
    } catch (e) {
      error = errorText(e);
    }
  }

  async function addAuthority(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    try {
      applySnapshot((await authorityAdd(name, pattern, key)).data);
      adding = false;
      name = '';
      pattern = '*';
      key = '';
      toast(t('common.saved'), 'ok');
    } catch (e) {
      error = errorText(e);
    }
  }
</script>

<section class="pg isl" style={empty ? 'display:flex;flex-direction:column' : ''}>
  <div class="crumbs"></div>
  <div class="ph">
    <div>
      <h1>{t('page.known.title')}</h1>
      <div class="sub">{t('page.known.text')}</div>
    </div>
    <div class="acts">
      <Button icon="badge" onclick={() => (adding = true)}>{t('known.ca.add')}</Button>
    </div>
  </div>

  {#if empty}
    <div class="empty">
      <span class="ei"><Icon name="shield" size={28} /></span>
      <p>{t('known.empty')}</p>
    </div>
  {/if}

  {#if vault.authorities.length}
    <div class="sec">{t('known.sec.authorities')}</div>
    <div class="rows">
      {#each vault.authorities as a (a.id)}
        <div class="row">
          <span class="ri"><Icon name="badge" size={16} /></span>
          <div class="rt">
            <b class="selectable">{a.name}</b>
            <span class="mono selectable" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{a.kind} · {a.fingerprint}</span>
          </div>
          <span class="rm">{t('known.ca.for', { pattern: a.pattern })}</span>
          <Button size="sm" variant="danger" icon="trash" title={t('known.remove')} onclick={() => (removingAuthority = a)} />
        </div>
      {/each}
    </div>
  {/if}

  {#if vault.knownHosts.length}
    <div class="sec">{t('known.sec.hosts')}</div>
    <div class="rows">
      {#each vault.knownHosts as k (k.id)}
        <div class="row">
          <span class="ri"><Icon name="shield" size={16} /></span>
          <div class="rt">
            <b class="selectable">{address(k)}</b>
            <span class="mono selectable" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{k.algorithm} · {k.fingerprint}</span>
          </div>
          <span class="rm">{t('known.since', { date: formatDate(k.addedAt) })}</span>
          <Button size="sm" variant="danger" icon="trash" title={t('known.remove')} onclick={() => (removing = k)} />
        </div>
      {/each}
    </div>
  {/if}
</section>

<Dialog open={!!removing} title={t('known.remove.title')}>
  <p>{t('known.remove.text', { host: removing ? address(removing) : '' })}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (removing = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" onclick={remove}>{t('known.remove')}</Button>
  {/snippet}
</Dialog>

<Dialog open={!!removingAuthority} title={t('known.ca.remove.title')}>
  <p>{t('known.ca.remove.text', { name: removingAuthority?.name ?? '' })}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (removingAuthority = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" onclick={removeAuthority}>{t('known.remove')}</Button>
  {/snippet}
</Dialog>

<Dialog bind:open={adding} title={t('known.ca.title')}>
  <form id="authority" style="display:contents" onsubmit={addAuthority}>
    <p>{t('known.ca.text')}</p>
    <TextField label={t('edit.name')} bind:value={name} placeholder="Firma" autofocus />
    <TextField label={t('known.ca.pattern')} bind:value={pattern} hint={t('known.ca.pattern.hint')} mono />
    <label class="fld">
      <span class="fld-l">{t('known.ca.key')}</span>
      <textarea bind:value={key} placeholder="ssh-ed25519 AAAA…" spellcheck="false" autocomplete="off"></textarea>
    </label>
    <div><Button size="sm" icon="folder" onclick={pickAuthorityKey}>{t('keys.imp.file')}</Button></div>
    {#if error}<p class="errline" role="alert">{error}</p>{/if}
  </form>
  {#snippet actions()}
    <Button onclick={() => (adding = false)}>{t('common.cancel')}</Button>
    <button type="submit" form="authority" class="btn primary" disabled={!key.trim()}>{t('known.ca.submit')}</button>
  {/snippet}
</Dialog>
