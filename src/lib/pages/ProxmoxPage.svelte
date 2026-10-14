<script lang="ts">
  import { proxmoxDelete, proxmoxImport, proxmoxProbe, proxmoxSave } from '../backend';
  import { applySnapshot, authFor, DEFAULT_USER, errorText, hostById, pathLabel, personalVault, sameVault, vault } from '../data.svelte';
  import { formatSize } from '../files.svelte';
  import { t, tn } from '../i18n.svelte';
  import { span } from '../manage.svelte';
  import { isSwitching, loginOf, powerGuest, pveOf, refreshPve, statusText, statusTone, watchPve, type Power } from '../proxmox.svelte';
  import { openTab } from '../sessions.svelte';
  import { toast } from '../state.svelte';
  import type { ProxmoxConnection, ProxmoxGuest, ProxmoxProbe } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import OsIcon from '../ui/OsIcon.svelte';
  import TextField from '../ui/TextField.svelte';

  const key = (guest: { node: string; vmid: number }) => `${guest.node}/${guest.vmid}`;

  // Re-read only while this page is open.
  $effect(() => watchPve());

  // ── Create and edit a connection ────────────────────────────────────────────────────────────────
  let editing = $state<{ id?: string } | null>(null);
  let name = $state('');
  let address = $state('');
  let tokenId = $state('');
  let secret = $state('');
  /** ID of the identity for this connection's machines; empty = none. */
  let identity = $state('');
  let probe = $state<ProxmoxProbe | null>(null);
  /** The user explicitly confirms a self-signed certificate's fingerprint. */
  let confirmed = $state(false);
  let probing = $state(false);
  let saving = $state(false);
  let error = $state('');
  let removing = $state<ProxmoxConnection | null>(null);
  /** The fingerprint the edited connection already knows: if the server still shows the same certificate, Glowport does not ask again. */
  let known = $state<{ address: string; fingerprint?: string; tokenId: string } | null>(null);
  const tidy = (text: string) => text.trim().replace(/\/+$/, '');

  function edit(connection?: ProxmoxConnection) {
    editing = { id: connection?.id };
    known = connection ? { address: connection.address, fingerprint: connection.fingerprint, tokenId: connection.tokenId } : null;
    name = connection?.name ?? '';
    address = connection?.address ?? '';
    tokenId = connection?.tokenId ?? '';
    secret = '';
    identity = connection?.identity ?? '';
    probe = null;
    confirmed = false;
    error = '';
  }
  // Other details are another connection: what the check found no longer applies.
  $effect(() => {
    void [address, tokenId, secret];
    probe = null;
    confirmed = false;
  });
  /** The fingerprint used for checking and saving: the one just confirmed, otherwise the one already known. */
  const pinned = () => (probe ? (probe.trusted ? undefined : confirmed ? probe.fingerprint : undefined) : known?.address === tidy(address) ? known.fingerprint : undefined);
  const input = () => ({ id: editing?.id, name, address, tokenId, secret: secret || undefined, fingerprint: pinned(), identity: identity || undefined });
  const filled = $derived(name.trim() !== '' && address.trim() !== '' && tokenId.trim() !== '' && (secret !== '' || !!editing?.id));
  /** Checked only once Proxmox has answered with the token. Before that, with a self-signed certificate only the fingerprint is shown. */
  const proven = $derived(!!probe?.version);
  /** The certificate is the one already confirmed for this connection: no reason to ask about it again. */
  const settled = $derived(proven && !!probe && probe.fingerprint === known?.fingerprint && known?.address === tidy(address));
  /** Nothing changed about the edited connection's address and token: name and identity can be saved without a new check. */
  const untouched = $derived(!!editing?.id && !!known && known.address === tidy(address) && known.tokenId === tokenId.trim() && secret === '');
  const ready = $derived(filled && (proven || untouched) && !saving);

  async function check() {
    probing = true;
    error = '';
    try {
      const found = await proxmoxProbe(input());
      probe = found;
      // Checked with the confirmed fingerprint: the tick stays, so exactly this one is saved.
      confirmed = !found.trusted && !!found.version;
    } catch (e) {
      error = errorText(e);
    } finally {
      probing = false;
    }
  }

  async function save() {
    if (!ready) return;
    saving = true;
    try {
      const changed = await proxmoxSave(input());
      applySnapshot(changed.data);
      editing = null;
      toast(t('pve.saved'), 'ok');
      if (changed.id) void refreshPve(changed.id);
    } catch (e) {
      error = errorText(e);
    } finally {
      saving = false;
    }
  }

  async function remove() {
    const target = removing;
    removing = null;
    if (!target) return;
    try {
      applySnapshot((await proxmoxDelete(target.id)).data);
      toast(t('pve.removed', { name: target.name }), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }

  // ── Start, stop, restart ─────────────────────────────────────────────────────────────────────────────
  let asking = $state<{ connection: ProxmoxConnection; guest: ProxmoxGuest; action: Exclude<Power, 'start'> } | null>(null);

  const power = (connection: ProxmoxConnection, guest: ProxmoxGuest, action: Power) => powerGuest(connection.id, guest, action);

  async function answered() {
    const pending = asking;
    asking = null;
    if (pending) await power(pending.connection, pending.guest, pending.action);
  }

  /** Connects to the machine's host; without a host directly to its address, with the key from Cloud-Init or the connection's identity. */
  function connect(connection: ProxmoxConnection, guest: ProxmoxGuest) {
    if (guest.host && hostById(guest.host)) return openTab({ kind: 'host', id: guest.host });
    if (!guest.address) return;
    const login = loginOf(connection, guest);
    openTab({ kind: 'direct', user: login.user ?? 'root', host: guest.address, port: 22, identity: login.identity, key: login.key });
  }

  // ── Create as hosts ────────────────────────────────────────────────────────────────────────────────
  let importing = $state<ProxmoxConnection | null>(null);
  let picked = $state<Record<string, boolean>>({});
  let group = $state('');
  const candidates = $derived(importing ? (pveOf(importing.id)?.overview?.guests ?? []).filter((guest) => !guest.host) : []);
  /** The hosts live in the personal vault, like the connection; so does their group. */
  const groups = $derived(vault.groups.filter((g) => sameVault(personalVault()?.id, g)));
  const chosen = $derived(candidates.filter((guest) => picked[key(guest)]));
  const fresh = (connection: ProxmoxConnection) => (pveOf(connection.id)?.overview?.guests ?? []).filter((guest) => !guest.host && !guest.template).length;

  function startImport(connection: ProxmoxConnection) {
    importing = connection;
    group = '';
    // Templates and machines without an address are not preselected.
    picked = Object.fromEntries((pveOf(connection.id)?.overview?.guests ?? []).filter((guest) => !guest.host).map((guest) => [key(guest), !guest.template && !!guest.address]));
  }

  async function runImport() {
    const connection = importing;
    if (!connection || !chosen.length) return;
    // Record first, then close the dialog: the selection disappears with it.
    const picks = chosen.map((guest) => ({ node: guest.node, vmid: guest.vmid, kind: guest.kind }));
    const count = picks.length;
    importing = null;
    try {
      applySnapshot((await proxmoxImport(connection.id, picks, group || null)).data);
      toast(tn('pve.import.done', count), 'ok');
      void refreshPve(connection.id);
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }

  const percent = (part: number | undefined) => (part === undefined ? '–' : `${Math.round(part * 100)} %`);
  const sourceText = (guest: ProxmoxGuest) => (guest.source ? t(`pve.source.${guest.source}`) : '');
</script>

<section class="pg isl">
  <div class="crumbs"></div>
  <div class="ph">
    <h1>{t('pve.title')}</h1>
    <div class="acts"><Button variant="primary" icon="plus" onclick={() => edit()}>{t('pve.add')}</Button></div>
  </div>

  {#if !vault.proxmox.length}
    <div class="pve-intro">
      <span class="ei"><Icon name="network" size={26} /></span>
      <h2>{t('pve.intro.title')}</h2>
      <p>{t('pve.intro.text')}</p>
      <ul class="sync-facts">
        <li><Icon name="list" size={14} />{t('pve.intro.fact.list')}</li>
        <li><Icon name="play" size={14} />{t('pve.intro.fact.power')}</li>
        <li><Icon name="server" size={14} />{t('pve.intro.fact.hosts')}</li>
        <li><Icon name="key" size={14} />{t('pve.intro.fact.token')}</li>
      </ul>
      <Button variant="primary" icon="plus" onclick={() => edit()}>{t('pve.add')}</Button>
    </div>
  {/if}

  {#each vault.proxmox as connection (connection.id)}
    {@const state = pveOf(connection.id)}
    {@const overview = state?.overview}
    <div class="pve">
      <header class="pve-h">
        <span class="pve-ico"><Icon name="network" size={18} /></span>
        <div class="pve-t">
          <b>{connection.name}</b>
          <span class="mono">{connection.address.replace(/^https:\/\//, '')}{#if overview}{' · '}Proxmox VE {overview.version}{/if}</span>
        </div>
        <span class="grow"></span>
        {#if overview && fresh(connection) > 0}
          <Button size="sm" variant="primary" icon="plus" onclick={() => startImport(connection)}>{tn('pve.import.open', fresh(connection))}</Button>
        {/if}
        <Button size="sm" variant="ghost" icon="refresh" title={t('pve.refresh')} onclick={() => refreshPve(connection.id, true)} />
        <Button size="sm" variant="ghost" icon="edit" title={t('common.edit')} onclick={() => edit(connection)} />
        <Button size="sm" variant="ghost" icon="trash" title={t('pve.remove')} onclick={() => (removing = connection)} />
      </header>

      {#if state?.error}
        <div class="warnbox"><Icon name="alert" size={16} /><span>{state.error}</span></div>
      {:else if !overview}
        <div class="fnote"><Icon name="network" size={22} /><p>{t('manage.loading')}</p></div>
      {:else}
        {#each overview.nodes as node (node.node)}
          <div class="pve-node">
            <span class="mg-dot {node.online ? 'ok' : 'err'}"></span>
            <b>{node.node}</b>
            {#if node.online}
              <span>{t('pve.node.cpu', { cpu: percent(node.cpu), cores: node.cores ?? 0 })}</span>
              {#if node.memory}<span>{t('pve.node.memory', { used: formatSize(node.memory.used), total: formatSize(node.memory.total) })}</span>{/if}
              {#if node.uptime}<span>{t('pve.node.uptime', { time: span(node.uptime) })}</span>{/if}
            {:else}
              <span>{t('pve.node.offline')}</span>
            {/if}
          </div>
          <div class="pve-list">
            {#each overview.guests.filter((guest) => guest.node === node.node) as guest (guest.vmid)}
              {@const host = guest.host ? hostById(guest.host) : undefined}
              {@const login = loginOf(connection, guest)}
              <!-- If the machine belongs to a host, “Connect” connects through it: then its sign-in counts. -->
              {@const user = host ? (authFor(host.group, host.own).user?.value ?? DEFAULT_USER) : login.user}
              <div class="pve-row" class:muted={guest.status !== 'running'}>
                <OsIcon os={guest.os ?? null} size="sm" protocol="ssh" />
                <div class="pve-name">
                  <b>{guest.name}</b>
                  <span>{guest.kind === 'qemu' ? t('pve.kind.vm') : t('pve.kind.ct')} {guest.vmid}{#if guest.template}{' · '}{t('pve.template')}{/if}</span>
                </div>
                <div class="pve-state"><span class="mg-dot {statusTone(guest.status)}"></span>{statusText(guest.status)}{#if guest.uptime}<i>{span(guest.uptime)}</i>{/if}</div>
                <div class="pve-load">
                  {#if guest.status === 'running'}
                    <span>{percent(guest.cpu)}</span>
                    {#if guest.memory}<i>{formatSize(guest.memory.used)} / {formatSize(guest.memory.total)}</i>{/if}
                  {/if}
                </div>
                <div class="pve-addr">
                  {#if guest.address}
                    <span class="mono selectable">{user ? `${user}@` : ''}{guest.address}</span>
                    <i>{sourceText(guest)}</i>
                  {:else if !guest.template}
                    <i>{t('pve.noaddress')}</i>
                  {/if}
                </div>
                <div class="pve-tags">
                  {#if host}<i class="chip on" title={t('pve.linked', { name: host.name })}><Icon name="link" size={11} />{t('pve.host')}</i>{/if}
                  {#each guest.tags as tag (tag)}<i class="chip">{tag}</i>{/each}
                </div>
                <div class="pve-acts">
                  {#if !guest.template}
                    {#if guest.status === 'running'}
                      <Button size="sm" icon="terminal" disabled={!guest.address && !host} onclick={() => connect(connection, guest)}>{t('pve.connect')}</Button>
                      <Button size="sm" variant="ghost" icon="refresh" title={t('pve.reboot')} disabled={isSwitching(connection.id, guest.vmid)} onclick={() => (asking = { connection, guest, action: 'reboot' })} />
                      <Button size="sm" variant="ghost" icon="stop" title={t('pve.shutdown')} disabled={isSwitching(connection.id, guest.vmid)} onclick={() => (asking = { connection, guest, action: 'shutdown' })} />
                    {:else}
                      <Button size="sm" icon="play" disabled={isSwitching(connection.id, guest.vmid)} onclick={() => power(connection, guest, 'start')}>{t('manage.start')}</Button>
                    {/if}
                  {/if}
                </div>
              </div>
            {/each}
          </div>
        {/each}
      {/if}
    </div>
  {/each}
</section>

<Dialog open={!!editing} title={editing?.id ? t('pve.edit.title') : t('pve.add')}>
  <form class="setup" onsubmit={(e) => (e.preventDefault(), void save())}>
    <TextField label={t('pve.field.name')} bind:value={name} placeholder={t('pve.field.name.example')} autofocus />
    <TextField label={t('pve.field.address')} bind:value={address} placeholder="https://pve.example.de:8006" mono />
    <TextField label={t('pve.field.token')} bind:value={tokenId} placeholder="glowport@pve!glowport" hint={t('pve.field.token.hint')} mono />
    <TextField label={t('pve.field.secret')} bind:value={secret} placeholder={editing?.id ? t('pve.field.secret.keep') : 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'} hint={t('pve.field.secret.hint')} password />
    <label class="fld">
      <span class="fld-l">{t('pve.field.identity')}</span>
      <select class="dropdown" bind:value={identity}>
        <option value="">{t('pve.field.identity.none')}</option>
        {#each vault.identities as i (i.id)}<option value={i.id}>{i.name} ({i.user})</option>{/each}
      </select>
      <span class="fld-h">{t('pve.field.identity.hint')}</span>
    </label>

    {#if probe}
      {#if proven}
        <div class="okline"><Icon name="check" size={14} />{t('pve.probe.ok', { version: probe.version })}</div>
        {#if probe.missing.length}
          <div class="warnbox"><Icon name="alert" size={16} /><span>{t('pve.probe.missing')} {probe.missing.map((right) => t(`pve.right.${right}`)).join(', ')}</span></div>
        {/if}
      {/if}
      {#if !probe.trusted && !settled}
        <div class="warnbox"><Icon name="shield" size={16} /><span>{probe.changed ? t('pve.cert.changed') : t('pve.cert.text')}</span></div>
        <p class="pve-finger mono selectable">{probe.fingerprint}</p>
        <!-- After checking with the token the tick is fixed: exactly this fingerprint is saved. -->
        <label class="check"><input type="checkbox" bind:checked={confirmed} disabled={proven} />{t('pve.cert.confirm')}</label>
      {/if}
    {/if}
    {#if error}<p class="errline" role="alert">{error}</p>{/if}
  </form>
  {#snippet actions()}
    <Button onclick={() => (editing = null)}>{t('common.cancel')}</Button>
    {#if !proven}
      <!-- Second step: only with the confirmed fingerprint does the token go to the server. -->
      <Button variant={untouched ? 'default' : 'primary'} icon="refresh" disabled={!filled || probing || (!!probe && !confirmed)} onclick={check}>{probing ? t('sync.setup.probing') : probe ? t('pve.probe.token') : t('pve.probe')}</Button>
    {/if}
    {#if proven || untouched}
      <Button variant="primary" icon="check" disabled={!ready} onclick={save}>{t('common.save')}</Button>
    {/if}
  {/snippet}
</Dialog>

<Dialog open={!!removing} title={t('pve.remove.title', { name: removing?.name ?? '' })}>
  <p>{t('pve.remove.text')}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (removing = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" onclick={remove}>{t('pve.remove')}</Button>
  {/snippet}
</Dialog>

<Dialog open={!!asking} title={asking ? t(`pve.confirm.${asking.action}.title`, { name: asking.guest.name }) : ''}>
  <p>{asking ? t(`pve.confirm.${asking.action}.text`) : ''}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (asking = null)}>{t('common.cancel')}</Button>
    {#if asking?.action === 'shutdown'}
      <Button onclick={() => asking && (asking = { ...asking, action: 'stop' })}>{t('pve.stop')}</Button>
    {/if}
    <Button variant="danger" onclick={answered}>{asking ? t(`pve.${asking.action}`) : ''}</Button>
  {/snippet}
</Dialog>

<Dialog open={!!importing} title={t('pve.import.title', { name: importing?.name ?? '' })} wide>
  <p>{t('pve.import.text')}</p>
  <div class="pve-pick">
    {#each candidates as guest (key(guest))}
      {@const login = importing ? loginOf(importing, guest) : {}}
      <label class="pve-prow" class:muted={!picked[key(guest)]}>
        <input type="checkbox" bind:checked={picked[key(guest)]} />
        <OsIcon os={guest.os ?? null} size="sm" protocol="ssh" />
        <span class="pve-name"><b>{guest.name}</b><span>{guest.kind === 'qemu' ? t('pve.kind.vm') : t('pve.kind.ct')} {guest.vmid}{#if guest.template}{' · '}{t('pve.template')}{/if}</span></span>
        <span class="pve-addr">
          {#if guest.address}<span class="mono">{login.user ? `${login.user}@` : ''}{guest.address}</span><i>{sourceText(guest)}</i>{:else}<i class="warn">{t('pve.import.noaddress')}</i>{/if}
        </span>
        <span class="pve-key">{#if login.keyName}<Icon name="key" size={12} />{login.keyName}{:else if login.identityName}<Icon name="user" size={12} />{login.identityName}{:else}<i>{t('pve.import.nokey')}</i>{/if}</span>
      </label>
    {/each}
  </div>
  <label class="fld">
    <span class="fld-l">{t('pve.import.group')}</span>
    <select class="dropdown" bind:value={group}>
      <option value="">{t('pve.import.group.none')}</option>
      {#each groups as g (g.id)}<option value={g.id}>{pathLabel(g.id)}</option>{/each}
    </select>
  </label>
  {#snippet actions()}
    <Button onclick={() => (importing = null)}>{t('common.cancel')}</Button>
    <Button variant="primary" icon="plus" disabled={!chosen.length} onclick={runImport}>{tn('pve.import.run', chosen.length)}</Button>
  {/snippet}
</Dialog>
