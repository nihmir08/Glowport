<script lang="ts">
  import { onMount } from 'svelte';
  import { adminAccountDelete, adminAccountDisable, adminAccounts, adminInviteCreate, adminInviteRevoke, adminInvites, clipboardWrite } from '../backend';
  import { errorText } from '../data.svelte';
  import { formatDate, t, tn } from '../i18n.svelte';
  import { toast } from '../state.svelte';
  import { ago, sizeLabel } from '../sync.svelte';
  import type { SyncAccount, SyncInviteCode } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';

  // Was das Konto sieht, das den Server verwaltet: Konten, Speicher, Einladungscodes. In keinen Tresor hinein.
  let invites = $state<SyncInviteCode[]>([]);
  let accounts = $state<SyncAccount[]>([]);
  let busy = $state(false);
  let deleting = $state<SyncAccount | null>(null);

  async function run<T>(work: () => Promise<T>, apply: (result: T) => void, done?: string) {
    busy = true;
    try {
      apply(await work());
      if (done) toast(done, 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    void run(adminInvites, (list) => (invites = list));
    void run(adminAccounts, (list) => (accounts = list));
  });

  const copy = (code: string) => clipboardWrite(code).then(() => toast(t('admin.invite.copied'), 'ok'));
  function remove() {
    const account = deleting;
    deleting = null;
    if (account) void run(() => adminAccountDelete(account.id), (list) => (accounts = list), t('common.deleted'));
  }
</script>

<div class="sec sec-a">
  <span>{t('admin.title')}</span>
  <Button size="sm" icon="plus" disabled={busy} onclick={() => run(adminInviteCreate, (list) => (invites = list), t('admin.invite.created'))}>{t('admin.invite.create')}</Button>
</div>
<p class="sec-h">{t('admin.text')}</p>
<div class="rows">
  {#each invites as invite (invite.code)}
    <div class="row">
      <span class="ri"><Icon name="key" size={15} /></span>
      <div class="rt"><b class="mono selectable">{invite.code}</b><span>{t('admin.invite.until', { date: formatDate(invite.expiresAt) })}</span></div>
      <Button size="sm" icon="copy" title={t('admin.invite.copy')} onclick={() => copy(invite.code)} />
      <Button size="sm" variant="danger" disabled={busy} onclick={() => run(() => adminInviteRevoke(invite.code), (list) => (invites = list))}>{t('admin.invite.revoke')}</Button>
    </div>
  {:else}
    <div class="row"><div class="rt"><span>{t('admin.invite.none')}</span></div></div>
  {/each}
</div>

<div class="rows" style="margin-top:10px">
  {#each accounts as account (account.id)}
    <div class="row">
      <span class="ri" class:warn={account.disabled}><Icon name="user" size={15} /></span>
      <div class="rt">
        <b>{account.username}</b>
        <span>{tn('admin.account.devices', account.devices)} · {sizeLabel(account.bytes)} · {t('sync.devices.seen', { when: ago(account.seenAt) })}</span>
      </div>
      {#if account.admin}
        <i class="chip a">{t('sync.admin.badge')}</i>
      {:else}
        {#if account.disabled}<i class="chip warn">{t('admin.account.disabled')}</i>{/if}
        <Button size="sm" disabled={busy} onclick={() => run(() => adminAccountDisable(account.id, !account.disabled), (list) => (accounts = list))}>{t(account.disabled ? 'admin.account.enable' : 'admin.account.disable')}</Button>
        <Button size="sm" variant="danger" icon="trash" title={t('common.delete')} onclick={() => (deleting = account)} />
      {/if}
    </div>
  {/each}
</div>

<Dialog open={!!deleting} title={t('admin.account.delete.title', { name: deleting?.username ?? '' })}>
  <p>{t('admin.account.delete.text')}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (deleting = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" onclick={remove}>{t('common.delete')}</Button>
  {/snippet}
</Dialog>
