<script lang="ts">
  import { onMount } from 'svelte';
  import { identitySave } from '../backend';
  import { applySnapshot, errorText, hostsUsingIdentity, reachable, vault } from '../data.svelte';
  import { targetVault } from '../sync.svelte';
  import { t } from '../i18n.svelte';
  import { IDENTITY_COLOR, keyLabel } from '../keys';
  import { keyActions, takeKeys } from '../quick.svelte';
  import { toast } from '../state.svelte';
  import type { Identity, IdentityInput } from '../types';
  import ActionSelect from '../ui/ActionSelect.svelte';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';
  import TextField from '../ui/TextField.svelte';

  let { identity, onclose, onsaved, ondelete }: { identity: Identity | null; onclose: () => void; onsaved: (id: string) => void; ondelete: (identity: Identity) => void } = $props();

  // The editor is created anew per identity ({#key} in KeysPage); the initial values are deliberately read only once.
  const start = (() => identity)();

  let name = $state(start?.name ?? '');
  let user = $state(start?.user ?? '');
  let key = $state(start?.key ?? '');
  let password = $state('');
  let removePassword = $state(false);
  let busy = $state(false);
  let error = $state('');

  const hosts = $derived(start ? hostsUsingIdentity(start.id) : []);

  // A key dragged into the window while this editor is open is selected right away.
  onMount(() => takeKeys((id) => (key = id)));

  async function save(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    const input: IdentityInput = { id: start?.id, name, user, key: key || null };
    if (!start) input.vault = targetVault();
    if (password) input.password = password;
    else if (removePassword) input.password = null;

    busy = true;
    try {
      const changed = await identitySave(input);
      applySnapshot(changed.data);
      toast(t('common.saved'), 'ok');
      onsaved(changed.id!);
    } catch (e) {
      error = errorText(e);
    } finally {
      password = '';
      busy = false;
    }
  }
</script>

<form class="editor isl" onsubmit={save}>
  <header class="ed-h">
    <span class="os lg" style="--c:{IDENTITY_COLOR}"><Icon name="user" size={22} /></span>
    <div style="min-width:0">
      <div class="d-name">{name || t('ident.title.new')}</div>
      <div class="d-sub">{start ? t('ident.title.edit') : t('ident.title.new')}</div>
    </div>
    <span class="grow"></span>
    <Button variant="ghost" size="sm" icon="x" title={t('common.close')} onclick={onclose} />
  </header>

  <div class="ed-b">
    <div class="inhb" style="margin-top:0"><Icon name="link" size={14} /><span style="flex:1">{t('ident.hint')}</span></div>
    <TextField label={t('edit.name')} bind:value={name} placeholder="Deploy" autofocus={!start} />
    <TextField label={t('detail.user')} bind:value={user} placeholder="deploy" mono />
    <label class="fld">
      <span class="fld-l">{t('detail.key')}</span>
      <ActionSelect bind:value={key} options={[{ value: '', label: t('ident.key.none') }, ...vault.keys.filter((k) => reachable(start ? start.vault : targetVault(), k)).map((k) => ({ value: k.id, label: `${k.name} · ${keyLabel(k)}` }))]} actions={keyActions((id) => (key = id))} />
    </label>
    {#if !removePassword}
      <TextField label={t('detail.password')} bind:value={password} hint={start?.hasPassword ? t('edit.password.keep') : t('edit.password.hint')} password />
    {/if}
    {#if start?.hasPassword}
      <label class="check"><input type="checkbox" bind:checked={removePassword} />{t('edit.password.remove')}</label>
    {/if}

    {#if start}
      <div class="fld">
        <span class="fld-l">{t('keys.usedBy')}</span>
        {#if hosts.length}
          <div class="tags">{#each hosts as h (h.id)}<i class="chip">{h.name}</i>{/each}</div>
        {:else}
          <span class="fld-h">{t('keys.usedBy.none')}</span>
        {/if}
      </div>
    {/if}
    {#if error}<p class="errline" role="alert">{error}</p>{/if}
  </div>

  <footer class="ed-f">
    {#if start}<Button variant="danger" icon="trash" onclick={() => ondelete(start)}>{t('common.delete')}</Button>{/if}
    <span class="grow"></span>
    <Button onclick={onclose}>{t('common.cancel')}</Button>
    <button type="submit" class="btn primary" disabled={busy}>{t('common.save')}</button>
  </footer>
</form>
