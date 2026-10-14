<script lang="ts">
  import { untrack } from 'svelte';
  import { sharedDelete, sharedInvite, sharedLeave, sharedLookup, sharedRemove, sharedRename, sharedSetRole, sharedTransfer } from '../backend';
  import { authFor, errorText, vault } from '../data.svelte';
  import { t, tn } from '../i18n.svelte';
  import { toast } from '../state.svelte';
  import { roleLabel, vaultColor, vaultLabel } from '../sync.svelte';
  import type { SyncCandidate, VaultInfo, VaultMember, VaultRole } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import TextField from '../ui/TextField.svelte';

  let { info, onclose, onresync }: { info: VaultInfo; onclose: () => void; onresync: () => void } = $props();

  const owner = $derived(info.kind === 'shared' && info.role === 'owner');
  // The name in the field starts with the saved one; the panel is created anew for every vault.
  let name = $state(untrack(() => info.name));
  let busy = $state(false);

  async function run(work: () => Promise<unknown>, done?: string): Promise<boolean> {
    busy = true;
    try {
      await work();
      if (done) toast(done, 'ok');
      return true;
    } catch (e) {
      toast(errorText(e), 'err');
      return false;
    } finally {
      busy = false;
    }
  }

  const rename = (event: SubmitEvent) => (event.preventDefault(), run(() => sharedRename(info.id, name), t('common.saved')));

  /** The member whose safety code is currently expanded. */
  let opened = $state<string | null>(null);

  let inviting = $state(false);
  let who = $state('');
  let as = $state<VaultRole>('read');
  let candidate = $state<SyncCandidate | null>(null);
  let lookupError = $state('');
  // Another name is another account: the safety code shown no longer applies.
  $effect(() => {
    void who;
    candidate = null;
    lookupError = '';
  });
  function closeInvite() {
    inviting = false;
    who = '';
    as = 'read';
  }
  async function invite(event: SubmitEvent) {
    event.preventDefault();
    if (!candidate) {
      busy = true;
      try {
        candidate = await sharedLookup(who);
      } catch (e) {
        lookupError = errorText(e);
      } finally {
        busy = false;
      }
      return;
    }
    const found = candidate;
    if (await run(() => sharedInvite(info.id, found.account, as), t('vault.invite.done', { name: found.username }))) closeInvite();
  }

  /** Fewer rights swap the vault's key; that takes a moment and is said so. */
  const setRole = (member: VaultMember, role: VaultRole) => run(() => sharedSetRole(info.id, member.account, role), t(role === 'read' ? 'vault.role.lowered' : 'vault.role.raised', { name: member.name }));

  let removing = $state<VaultMember | null>(null);
  let handing = $state<VaultMember | null>(null);
  let leaving = $state(false);
  let deleting = $state(false);
  /** Hosts of this vault with a saved password or key: every member knows these credentials. */
  const exposed = $derived(vault.hosts.filter((h) => h.vault === info.id && (h.hasPassword || !!authFor(h.group, h.own).key || authFor(h.group, h.own).identityPassword)));

  async function remove() {
    const member = removing;
    removing = null;
    if (member) await run(() => sharedRemove(info.id, member.account), t('vault.remove.done', { name: member.name }));
  }
  async function handOver() {
    const member = handing;
    handing = null;
    if (member) await run(() => sharedTransfer(info.id, member.account), t('vault.transfer.done', { name: member.name }));
  }
  async function leave() {
    leaving = false;
    if (await run(() => sharedLeave(info.id), t('vault.leave.done'))) onclose();
  }
  async function destroy() {
    deleting = false;
    if (await run(() => sharedDelete(info.id), t('common.deleted'))) onclose();
  }
</script>

<aside class="detail isl vault-detail">
  <div class="d-head">
    <span class="os lg" style="--c:{info.kind === 'personal' ? 'var(--accent)' : vaultColor(info)}"><Icon name={info.kind === 'personal' ? 'lock' : 'network'} size={22} /></span>
    <div style="min-width:0">
      <div class="d-name">{vaultLabel(info)}</div>
      <div class="d-sub">{info.kind === 'personal' ? t('vault.personal.sub') : t('vault.role.yours', { role: roleLabel(info.role) })}</div>
    </div>
    <span class="grow"></span>
    <Button variant="ghost" size="sm" icon="x" title={t('common.close')} onclick={onclose} />
  </div>

  {#if info.rolledBack}
    <div class="warnbox" style="margin-top:14px"><Icon name="alert" size={16} /><span>{t('vault.rolledBack.text')}</span></div>
    {#if info.role !== 'read'}
      <div style="display:grid;margin-top:8px"><Button icon="upload" disabled={busy} onclick={onresync}>{t('vault.rolledBack.upload')}</Button></div>
    {/if}
  {/if}

  {#if info.kind === 'personal'}
    <p class="fld-h" style="margin-top:14px">{t('vault.personal.text')}</p>
  {:else}
    {#if owner}
      <form style="display:flex;gap:8px;align-items:flex-end;margin-top:14px" onsubmit={rename}>
        <div style="flex:1;min-width:0"><TextField label={t('edit.name')} bind:value={name} /></div>
        <button type="submit" class="btn" disabled={busy || !name.trim() || name.trim() === info.name}>{t('common.save')}</button>
      </form>
    {/if}
    {#if info.role === 'read'}
      <div class="infobox" style="margin-top:14px"><Icon name="eye" size={16} /><span>{t('vault.read.text')}</span></div>
    {/if}

    <div class="sec sec-a">
      <span>{tn('vault.members', info.members.length)}</span>
      {#if owner}<Button size="sm" variant="primary" icon="plus" onclick={() => (inviting = true)}>{t('vault.invite')}</Button>{/if}
    </div>
    <div class="members">
      {#each info.members as member (member.account)}
        <div class="member">
          <span class="ava sm" style="--c:{vaultColor(info)}">{member.name.slice(0, 1).toUpperCase()}</span>
          <div class="m-t">
            <b>{member.name}{#if member.me}<i>{t('vault.member.you')}</i>{/if}</b>
            <span>{member.invited ? t('vault.member.invited', { role: roleLabel(member.role) }) : roleLabel(member.role)}</span>
          </div>
          {#if owner && !member.me}
            <select class="dropdown sm" aria-label={t('vault.role')} value={member.role} disabled={busy} onchange={(e) => setRole(member, e.currentTarget.value as VaultRole)}>
              <option value="write">{t('vault.role.write')}</option>
              <option value="read">{t('vault.role.read')}</option>
            </select>
          {/if}
          <Button variant="ghost" size="sm" icon="shield" title={t('sync.code')} active={opened === member.account} onclick={() => (opened = opened === member.account ? null : member.account)} />
          {#if owner && !member.me}
            {#if !member.invited}<Button variant="ghost" size="sm" icon="badge" title={t('vault.transfer')} onclick={() => (handing = member)} />{/if}
            <Button variant="ghost" size="sm" icon="x" title={t('vault.remove')} onclick={() => (removing = member)} />
          {/if}
        </div>
        {#if opened === member.account}
          <div class="member-code">
            <div class="codewords sm">{member.code}</div>
            <p class="fld-h">{member.me ? t('sync.code.own.sub') : t('sync.code.compare', { name: member.name })}</p>
          </div>
        {/if}
      {/each}
    </div>

    <div style="display:grid;margin-top:16px">
      {#if owner}
        <Button variant="danger" icon="trash" onclick={() => (deleting = true)}>{t('vault.delete')}</Button>
      {:else}
        <Button variant="danger" onclick={() => (leaving = true)}>{t('vault.leave')}</Button>
      {/if}
    </div>
  {/if}
</aside>

{#if inviting}
  <div class="ov" role="presentation" onclick={(e) => e.target === e.currentTarget && closeInvite()}>
    <form class="dlg" aria-label={t('vault.invite')} onsubmit={invite}>
      <h2>{t('vault.invite.title', { vault: vaultLabel(info) })}</h2>
      <div class="dlg-b">
        <TextField label={t('sync.setup.username')} bind:value={who} hint={t('vault.invite.hint')} autofocus />
        <div class="fld">
          <span class="fld-l">{t('vault.role')}</span>
          <Segmented
            label={t('vault.role')}
            bind:value={as}
            options={[
              { value: 'read', label: t('vault.role.read'), icon: 'eye' },
              { value: 'write', label: t('vault.role.write'), icon: 'edit' },
            ]}
          />
          <span class="fld-h">{t(as === 'read' ? 'vault.role.read.hint' : 'vault.role.write.hint')}</span>
        </div>
        {#if lookupError}<p class="errline" role="alert">{lookupError}</p>{/if}
        {#if candidate}
          <div class="fld">
            <span class="fld-l">{t('sync.code.of', { name: candidate.username })}</span>
            <div class="codewords" class:warn={candidate.known === 'changed'}>{candidate.code}</div>
            <span class="fld-h">{t(candidate.known === 'same' ? 'sync.code.known' : 'sync.code.compare', { name: candidate.username })}</span>
          </div>
          {#if candidate.known === 'changed'}<div class="warnbox danger"><Icon name="alert" size={16} /><span>{t('sync.code.changed', { name: candidate.username })}</span></div>{/if}
        {/if}
      </div>
      <div class="dlg-a">
        <Button onclick={closeInvite}>{t('common.cancel')}</Button>
        <button type="submit" class="btn primary" disabled={busy || !who.trim()}>{candidate ? t('vault.invite') : t('vault.invite.find')}</button>
      </div>
    </form>
  </div>
{/if}

<Dialog open={!!removing} title={t('vault.remove.title', { name: removing?.name ?? '' })}>
  <p>{t('vault.remove.text', { name: removing?.name ?? '', vault: vaultLabel(info) })}</p>
  <div class="warnbox">
    <Icon name="alert" size={16} />
    <span>
      {t('vault.remove.warn', { name: removing?.name ?? '' })}
      {#if exposed.length}
        <br />{tn('vault.remove.exposed', exposed.length)}
        <b>{exposed
            .slice(0, 6)
            .map((h) => h.name)
            .join(', ')}{exposed.length > 6 ? ' …' : ''}</b>
      {/if}
    </span>
  </div>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (removing = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" onclick={remove}>{t('vault.remove.confirm')}</Button>
  {/snippet}
</Dialog>

<Dialog open={!!handing} title={t('vault.transfer.title', { name: handing?.name ?? '' })}>
  <p>{t('vault.transfer.text', { name: handing?.name ?? '', vault: vaultLabel(info) })}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (handing = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" onclick={handOver}>{t('vault.transfer')}</Button>
  {/snippet}
</Dialog>

<Dialog open={leaving} title={t('vault.leave.title', { vault: vaultLabel(info) })}>
  <p>{t('vault.leave.text')}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (leaving = false)}>{t('common.cancel')}</Button>
    <Button variant="danger" onclick={leave}>{t('vault.leave')}</Button>
  {/snippet}
</Dialog>

<Dialog open={deleting} title={t('vault.delete.title', { vault: vaultLabel(info) })}>
  <p>{t('vault.delete.text')}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (deleting = false)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" onclick={destroy}>{t('vault.delete')}</Button>
  {/snippet}
</Dialog>
