<script lang="ts">
  import { clipboardWrite, invitationAccept, invitationDecline, sharedCreate, syncDeviceRemove, syncDeviceRename, syncDevices, syncNotices, syncNoticesClear, syncNow, syncResync, syncUnlink } from '../backend';
  import { errorText, personalVault, vault } from '../data.svelte';
  import { t, tn } from '../i18n.svelte';
  import { toast } from '../state.svelte';
  import { ago, applySync, roleLabel, scope, sync, vaultColor, vaultLabel } from '../sync.svelte';
  import AdminSection from '../sync/AdminSection.svelte';
  import SyncSetup from '../sync/SyncSetup.svelte';
  import VaultDetail from '../sync/VaultDetail.svelte';
  import type { SyncDevice, SyncInvitation, SyncNotice, VaultInfo } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import TextField from '../ui/TextField.svelte';

  let selected = $state<string | null>(null);
  const shown = $derived(vault.vaults.find((v) => v.id === selected));

  let devices = $state<SyncDevice[]>([]);
  let notices = $state<SyncNotice[]>([]);
  let busy = $state(false);

  // Devices and notices come from the server and the vault; after every round they can look different.
  $effect(() => {
    void sync.syncedAt;
    void sync.notices;
    if (!sync.linked) return;
    void syncDevices()
      .then((list) => (devices = list))
      .catch(() => {});
    void syncNotices()
      .then((list) => (notices = list))
      .catch(() => {});
  });

  /** Runs something that changes on the server and, on an error, says what caused it. */
  async function run<T>(work: () => Promise<T>, done?: string): Promise<T | undefined> {
    busy = true;
    try {
      const result = await work();
      if (done) toast(done, 'ok');
      return result;
    } catch (e) {
      toast(errorText(e), 'err');
    } finally {
      busy = false;
    }
  }

  const hostsIn = (v: VaultInfo) => vault.hosts.filter((h) => (h.vault ?? personalVault()?.id) === v.id).length;
  const phaseText = $derived(
    sync.phase === 'syncing'
      ? t('sync.phase.syncing')
      : sync.phase === 'offline'
        ? tn('sync.phase.offline', sync.pending)
        : sync.phase === 'signedOut'
          ? t('sync.phase.signedOut')
          : sync.phase === 'error'
            ? t('sync.phase.error')
            : sync.syncedAt
              ? t('sync.phase.synced', { when: ago(sync.syncedAt) })
              : t('sync.phase.never'),
  );

  let creating = $state(false);
  let newName = $state('');
  async function create(event: SubmitEvent) {
    event.preventDefault();
    const id = await run(() => sharedCreate(newName), t('vault.created'));
    if (!id) return;
    creating = false;
    newName = '';
    selected = id;
  }

  /** The invitation whose safety code is currently expanded. */
  let checking = $state<string | null>(null);
  const accept = (invitation: SyncInvitation) => run(() => invitationAccept(invitation.vault), t('sync.invitation.accepted', { name: invitation.name ?? '' })).then(() => (selected = invitation.vault));
  const decline = (invitation: SyncInvitation) => run(async () => applySync(await invitationDecline(invitation.vault)));

  let renaming = $state<SyncDevice | null>(null);
  let deviceName = $state('');
  async function renameDevice(event: SubmitEvent) {
    event.preventDefault();
    const device = renaming;
    if (!device) return;
    const list = await run(() => syncDeviceRename(device.id, deviceName));
    if (list) (devices = list), (renaming = null);
  }
  let removing = $state<SyncDevice | null>(null);
  async function removeDevice() {
    const device = removing;
    removing = null;
    if (!device) return;
    const list = await run(() => syncDeviceRemove(device.id), t('sync.devices.removed', { name: device.name }));
    if (list) devices = list;
  }

  let unlinking = $state(false);
  async function unlink() {
    unlinking = false;
    selected = null;
    scope.vault = 'all';
    await run(async () => applySync(await syncUnlink()), t('sync.unlink.done'));
  }

  const noticeText = (n: SyncNotice): string => {
    const vaultName = n.vaultName || t('vault.personal');
    switch (n.kind) {
      case 'clash':
        return t(n.mine ? 'sync.notice.clash.mine' : 'sync.notice.clash.theirs', { record: n.recordName ?? '?', path: n.path ?? '', vault: vaultName });
      case 'restored':
        return t('sync.notice.restored', { record: n.recordName ?? '?', vault: vaultName });
      case 'discarded':
        return tn('sync.notice.discarded', n.count ?? 0, { vault: vaultName });
      case 'vault_removed':
        return t('sync.notice.removed', { vault: vaultName });
      default:
        return tn('sync.notice.rejected', n.count ?? 0, { vault: vaultName });
    }
  };
</script>

<section class="pg isl">
  <div class="crumbs"></div>
  <div class="ph">
    <h1>{t('sync.title')}</h1>
    {#if sync.linked}
      <div class="acts">
        <span class="sync-line"><i class="sdot {sync.phase}"></i>{phaseText}</span>
        <Button icon="refresh" disabled={busy || sync.phase === 'syncing'} onclick={() => run(async () => applySync(await syncNow()))}>{t('sync.now')}</Button>
      </div>
    {/if}
  </div>

  {#if !sync.linked}
    <div class="setup-wrap">
      <div class="setup-intro">
        <span class="ei"><Icon name="cloud" size={26} /></span>
        <h2>{t('sync.intro.title')}</h2>
        <p>{t('sync.intro.text')}</p>
        <ul class="sync-facts">
          <li><Icon name="lock" size={14} />{t('sync.intro.fact.e2e')}</li>
          <li><Icon name="server" size={14} />{t('sync.intro.fact.own')}</li>
          <li><Icon name="user" size={14} />{t('sync.intro.fact.share')}</li>
          <li><Icon name="alert" size={14} />{t('sync.intro.fact.reset')}</li>
        </ul>
      </div>
      <div class="setup-card"><SyncSetup /></div>
    </div>
  {:else}
    {#if sync.phase === 'signedOut'}
      <div class="warnbox" style="margin-top:14px"><Icon name="alert" size={16} /><span>{t('sync.signedOut.text')}</span></div>
    {/if}
    {#if sync.passwordChanged}
      <div class="infobox" style="margin-top:14px"><Icon name="key" size={16} /><span>{t('sync.passwordChanged')}</span></div>
    {/if}

    {#if sync.invitations.length}
      <div class="sec">{t('sync.invitations')}</div>
      <div class="rows">
        {#each sync.invitations as invitation (invitation.vault)}
          <div class="row">
            <span class="ri"><Icon name="send" size={15} /></span>
            <div class="rt">
              <b>{invitation.name ?? t('vault.unnamed')}</b>
              <span>{t('sync.invitation.from', { owner: invitation.owner, role: roleLabel(invitation.role) })}</span>
            </div>
            <Button size="sm" icon="shield" active={checking === invitation.vault} onclick={() => (checking = checking === invitation.vault ? null : invitation.vault)}>{t('sync.code')}</Button>
            <Button size="sm" disabled={busy} onclick={() => decline(invitation)}>{t('sync.invitation.decline')}</Button>
            <Button size="sm" variant="primary" icon="check" disabled={busy} onclick={() => accept(invitation)}>{t('sync.invitation.accept')}</Button>
          </div>
          {#if checking === invitation.vault}
            <div class="row block">
              <div class="rt"><b>{t('sync.code.of', { name: invitation.owner })}</b><span>{t('sync.code.compare', { name: invitation.owner })}</span></div>
              <div class="codewords" class:warn={invitation.known === 'changed'}>{invitation.code}</div>
              {#if invitation.known === 'changed'}<div class="warnbox danger"><Icon name="alert" size={16} /><span>{t('sync.code.changed', { name: invitation.owner })}</span></div>{/if}
            </div>
          {/if}
        {/each}
      </div>
    {/if}

    <div class="sec">{t('sync.vaults')}</div>
    <div class="grid">
      {#each vault.vaults as v (v.id)}
        <button class="host" class:sel={selected === v.id} style="--c:{v.kind === 'personal' ? 'var(--accent)' : vaultColor(v)}" onclick={() => (selected = selected === v.id ? null : v.id)}>
          <span class="os" style="--c:{v.kind === 'personal' ? 'var(--accent)' : vaultColor(v)}"><Icon name={v.kind === 'personal' ? 'lock' : 'network'} size={18} /></span>
          <span class="h-name">{vaultLabel(v)}</span>
          <span class="h-addr">{v.kind === 'personal' ? t('vault.personal.sub') : tn('vault.members', v.members.length)}</span>
          <span class="h-meta">
            {#if v.kind === 'shared'}<i class="chip" class:a={v.role === 'owner'}>{roleLabel(v.role)}</i>{/if}
            <i class="chip">{tn('status.hosts', hostsIn(v))}</i>
            {#if v.rolledBack}<i class="chip warn">{t('vault.rolledBack.chip')}</i>{/if}
          </span>
        </button>
      {/each}
      <button class="host add" onclick={() => (creating = true)}>
        <span class="os" style="--c:var(--text-3)"><Icon name="plus" size={18} /></span>
        <span class="h-name">{t('vault.create')}</span>
        <span class="h-addr">{t('vault.create.sub')}</span>
      </button>
    </div>

    <div class="sec">{t('sync.account')}</div>
    <div class="rows">
      <div class="row">
        <div class="rt"><b>{sync.username}</b><span class="mono selectable">{sync.server}</span></div>
        {#if sync.admin}<i class="chip a">{t('sync.admin.badge')}</i>{/if}
        <Button size="sm" variant="danger" onclick={() => (unlinking = true)}>{t('sync.unlink')}</Button>
      </div>
      <div class="row">
        <div class="rt"><b>{t('sync.code.own')}</b><span>{t('sync.code.own.sub')}</span></div>
        <div class="codewords sm">{sync.code}</div>
        <Button size="sm" icon="copy" title={t('sync.code.copy')} onclick={() => clipboardWrite(sync.code).then(() => toast(t('sync.code.copied'), 'ok'))} />
      </div>
    </div>

    <div class="sec">{t('sync.devices')}</div>
    <div class="rows">
      {#each devices as device (device.id)}
        <div class="row">
          <span class="ri"><Icon name="monitor" size={15} /></span>
          <div class="rt">
            <b>{device.name || t('sync.devices.unnamed')}</b>
            <span>{device.current ? t('sync.devices.current') : t('sync.devices.seen', { when: ago(device.seenAt) })}</span>
          </div>
          <Button size="sm" icon="edit" title={t('sync.devices.rename')} onclick={() => ((renaming = device), (deviceName = device.name))} />
          {#if !device.current}<Button size="sm" variant="danger" onclick={() => (removing = device)}>{t('sync.devices.remove')}</Button>{/if}
        </div>
      {/each}
    </div>

    {#if notices.length}
      <div class="sec sec-a">
        <span>{t('sync.notices')}</span>
        <Button size="sm" variant="ghost" icon="trash" onclick={() => run(syncNoticesClear).then(() => (notices = []))}>{t('sync.notices.clear')}</Button>
      </div>
      <div class="rows">
        {#each notices as notice (notice.id)}
          <div class="row">
            <span class="ri" class:warn={notice.kind === 'rejected' || notice.kind === 'vault_removed'}><Icon name={notice.kind === 'clash' ? 'equal' : notice.kind === 'restored' ? 'undo' : 'alert'} size={15} /></span>
            <div class="rt"><b class="wrap">{noticeText(notice)}</b><span>{ago(notice.at)}</span></div>
          </div>
        {/each}
      </div>
    {/if}

    {#if sync.admin}<AdminSection />{/if}
  {/if}
</section>

{#if shown}
  {#key shown.id}
    <VaultDetail info={shown} onclose={() => (selected = null)} onresync={() => run(async () => applySync(await syncResync(shown.id)), t('vault.rolledBack.done'))} />
  {/key}
{/if}

{#if creating}
  <div class="ov" role="presentation" onclick={(e) => e.target === e.currentTarget && (creating = false)}>
    <form class="dlg" aria-label={t('vault.create')} onsubmit={create}>
      <h2>{t('vault.create')}</h2>
      <div class="dlg-b">
        <p>{t('vault.create.text')}</p>
        <TextField label={t('edit.name')} bind:value={newName} placeholder={t('vault.create.example')} autofocus />
      </div>
      <div class="dlg-a">
        <Button onclick={() => (creating = false)}>{t('common.cancel')}</Button>
        <button type="submit" class="btn primary" disabled={busy || !newName.trim()}>{t('vault.create')}</button>
      </div>
    </form>
  </div>
{/if}

{#if renaming}
  <div class="ov" role="presentation" onclick={(e) => e.target === e.currentTarget && (renaming = null)}>
    <form class="dlg" aria-label={t('sync.devices.rename')} onsubmit={renameDevice}>
      <h2>{t('sync.devices.rename')}</h2>
      <div class="dlg-b"><TextField label={t('edit.name')} bind:value={deviceName} hint={t('sync.setup.device.hint')} autofocus /></div>
      <div class="dlg-a">
        <Button onclick={() => (renaming = null)}>{t('common.cancel')}</Button>
        <button type="submit" class="btn primary" disabled={busy || !deviceName.trim()}>{t('common.save')}</button>
      </div>
    </form>
  </div>
{/if}

<Dialog open={!!removing} title={t('sync.devices.remove.title', { name: removing?.name ?? '' })}>
  <p>{t('sync.devices.remove.text')}</p>
  <div class="warnbox"><Icon name="alert" size={16} /><span>{t('sync.devices.remove.warn')}</span></div>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (removing = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" onclick={removeDevice}>{t('sync.devices.remove')}</Button>
  {/snippet}
</Dialog>

<Dialog open={unlinking} title={t('sync.unlink.title')}>
  <p>{t('sync.unlink.text')}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (unlinking = false)}>{t('common.cancel')}</Button>
    <Button variant="danger" onclick={unlink}>{t('sync.unlink')}</Button>
  {/snippet}
</Dialog>
