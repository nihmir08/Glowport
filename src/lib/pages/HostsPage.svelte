<script lang="ts">
  import { groupDelete, hostDelete, hostDuplicate, hostMove, hostSave, proxmoxUnlink, workspaceDelete, workspaceSave } from '../backend';
  import { usesMosh, addressOf, applySnapshot, authFor, canEdit, childGroups, colorOf, DEFAULT_PORT, DEFAULT_SERIAL, DEFAULT_TELNET_PORT, DEFAULT_USER, errorText, forwardsOf, groupById, groupColor, groupPath, hostById, hostCount, hostsIn, identityById, inherited, jumpOf, keyById, pathLabel, protocolOf, serialLabel, type From, vault, vaultOf, ftpOf, ftpOpen, ftpPort } from '../data.svelte';
  import { forwardRoute, stateOf, toggleForward } from '../forwards.svelte';
  import { openImport } from '../import.svelte';
  import { t, tn } from '../i18n.svelte';
  import { leaves, type Layout } from '../layout';
  import { schemeName } from '../look.svelte';
  import { osColor } from '../os';
  import { guestGone, guestOf, isSwitching, isWaiting, powerGuest, startAndConnect, statusText, statusTone, stopWaiting, watchPve, type Power } from '../proxmox.svelte';
  import { span } from '../manage.svelte';
  import { openSaved, openTab } from '../sessions.svelte';
  import { settings, toast } from '../state.svelte';
  import type { Group, Host, Target, Workspace } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import LayoutPreview from '../ui/LayoutPreview.svelte';
  import OsIcon from '../ui/OsIcon.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import VaultBadge from '../ui/VaultBadge.svelte';
  import VaultSwitch from '../ui/VaultSwitch.svelte';
  import { inScope, scope, vaultColor, vaultLabel } from '../sync.svelte';
  import Switch from '../ui/Switch.svelte';
  import TextField from '../ui/TextField.svelte';
  import GroupEditor from './GroupEditor.svelte';
  import HostEditor from './HostEditor.svelte';

  type Panel = { kind: 'detail'; id: string } | { kind: 'host'; id: string | null } | { kind: 'group'; id: string | null } | { kind: 'workspace'; id: string } | null;

  let group = $state<string | null>(null);
  // Der Zustand verknüpfter Maschinen wird nachgelesen, solange diese Seite offen ist und es Verbindungen gibt.
  $effect(() => {
    if (vault.proxmox.length) return watchPve();
  });

  let query = $state('');
  let panel = $state<Panel>(null);
  let deleteHost = $state<Host | null>(null);
  /** Der Host, der gerade in einen anderen Tresor verschoben wird. */
  let moving = $state<Host | null>(null);
  let moveTo = $state('');
  let moveCarry = $state(true);
  /** Wohin sich ein Host verschieben lässt: jeder andere Tresor, in dem man schreiben darf. */
  const moveTargets = (h: Host) => vault.vaults.filter((v) => v.id !== vaultOf(h)?.id && v.role !== 'read');
  function startMove(h: Host) {
    moving = h;
    moveTo = moveTargets(h)[0]?.id ?? '';
    moveCarry = true;
  }
  async function confirmMove() {
    const host = moving;
    moving = null;
    if (!host || !moveTo) return;
    const target = vault.vaults.find((v) => v.id === moveTo);
    const id = await run(() => hostMove(host.id, moveTo, moveCarry), t('move.done', { vault: vaultLabel(target) }));
    if (id) panel = { kind: 'detail', id };
  }
  /** Rückfrage vor dem Herunterfahren, Stoppen oder Neustarten der Maschine eines Hosts. */
  let pveAsk = $state<{ host: Host; action: Exclude<Power, 'start'> } | null>(null);
  let unlinking = $state<Host | null>(null);

  /** Schaltet die Maschine, zu der ein Host gehört. */
  function powerHost(host: Host, action: Power) {
    const guest = guestOf(host);
    if (host.proxmox && guest) void powerGuest(host.proxmox.connection, guest, action);
  }
  function pveAnswered() {
    const pending = pveAsk;
    pveAsk = null;
    if (pending) powerHost(pending.host, pending.action);
  }
  async function confirmUnlink() {
    const host = unlinking;
    unlinking = null;
    if (host) await run(() => proxmoxUnlink(host.id), t('pve.unlinked'));
  }

  let deleteGroup = $state<Group | null>(null);
  let deleteWorkspace = $state<Workspace | null>(null);
  let workspaceName = $state('');

  // Verschwindet die offene Gruppe oder der gezeigte Host (gelöscht, Tresor neu geladen), zurück auf festen Boden.
  $effect(() => {
    if (group && !groupById(group)) group = null;
    if (panel?.kind === 'detail' && !hostById(panel.id)) panel = null;
    if (panel?.kind === 'workspace' && !workspaceById(panel.id)) panel = null;
  });

  const current = $derived(groupById(group));
  const path = $derived(groupPath(group));
  // Gezeigt wird, was im gewählten Tresor liegt; „Alle“ zeigt alles.
  const subgroups = $derived(childGroups(group).filter(inScope));
  const hosts = $derived(hostsIn(group).filter(inScope));
  const defs = $derived(inherited(group));
  const needle = $derived(query.trim().toLowerCase());
  const results = $derived(
    // Die Suche findet immer alles, in welchem Tresor es auch liegt.
    needle ? vault.hosts.filter((h) => [h.name, h.address, h.own.user ?? '', h.protocol, pathLabel(h.group), vaultLabel(vaultOf(h))].some((text) => text.toLowerCase().includes(needle))) : null,
  );
  const shownVault = $derived(vault.vaults.find((v) => v.id === scope.vault));
  /** Im gezeigten Tresor darf man nur lesen: Dort lässt sich nichts anlegen. */
  const readOnly = $derived(shownVault?.role === 'read');
  /** Arbeitsbereiche liegen immer im persönlichen Tresor. */
  const personalShown = $derived(!shownVault || shownVault.kind === 'personal');
  const selected = $derived(panel?.kind === 'detail' ? hostById(panel.id) : undefined);
  const workspaceById = (id: string) => vault.workspaces.find((w) => w.id === id);
  const workspace = $derived(panel?.kind === 'workspace' ? workspaceById(panel.id) : undefined);
  /** Die Hosts eines Arbeitsbereichs in der Reihenfolge ihrer Bereiche. */
  const workspaceHosts = (w: Workspace) =>
    leaves(w.layout as Layout<Target>)
      .map((target) => (target.kind === 'host' ? hostById(target.id) : undefined))
      .filter((h): h is Host => !!h);

  /** Ein Arbeitsbereich kann neben Hosts auch lokale Terminals enthalten. */
  const paneCount = (w: Workspace) => leaves(w.layout as Layout<Target>).length;

  function showWorkspace(w: Workspace) {
    panel = { kind: 'workspace', id: w.id };
    workspaceName = w.name;
  }

  function openWorkspace(w: Workspace) {
    if (!openSaved({ name: w.name, color: null, multi: w.multi, layout: $state.snapshot(w.layout) })) toast(t('ws.gone'), 'err');
  }

  async function renameWorkspace(event: SubmitEvent, w: Workspace) {
    event.preventDefault();
    if (!workspaceName.trim() || workspaceName.trim() === w.name) return;
    await run(() => workspaceSave({ id: w.id, name: workspaceName.trim(), multi: w.multi, layout: $state.snapshot(w.layout) }), t('common.saved'));
  }

  async function setWorkspaceMulti(w: Workspace, multi: boolean) {
    await run(() => workspaceSave({ id: w.id, name: w.name, multi, layout: $state.snapshot(w.layout) }), t('common.saved'));
  }

  async function confirmDeleteWorkspace() {
    const target = deleteWorkspace!;
    deleteWorkspace = null;
    panel = null;
    await run(() => workspaceDelete(target.id), t('common.deleted'));
  }
  const empty = $derived(!vault.hosts.length && !vault.groups.length);

  function openGroup(id: string | null) {
    group = id;
    panel = null;
    query = '';
  }

  const reconnectLabel = (r: 'notice' | 'auto') => (r === 'auto' ? t('edit.reconnect.auto') : t('edit.reconnect.notice'));
  const jumpName = (id: string) => (id ? (hostById(id)?.name ?? '?') : t('detail.none'));

  async function run(work: () => Promise<{ data: Parameters<typeof applySnapshot>[0]; id?: string }>, done: string) {
    try {
      const changed = await work();
      applySnapshot(changed.data);
      toast(done, 'ok');
      return changed.id;
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }

  /** Ein Host, der gerade mit der Maus gezogen wird. `over`: die Gruppe unter dem Zeiger, null = oberste Ebene, undefined = kein Ziel. */
  let carried = $state<{ host: Host; x: number; y: number; over: string | null | undefined } | null>(null);

  /**
   * Verschieben per Ziehen: einen Host auf eine Gruppe oder auf einen Eintrag der Brotkrumen legen.
   * Wird die Maus kaum bewegt, bleibt es ein Klick.
   */
  function grabHost(event: PointerEvent, host: Host) {
    if (event.button !== 0) return;
    const origin = { x: event.clientX, y: event.clientY };
    const source = event.currentTarget as HTMLElement;
    const pointer = event.pointerId;
    let active = false;
    const groupAt = (x: number, y: number) => {
      const found = document.elementsFromPoint(x, y).find((el): el is HTMLElement => el instanceof HTMLElement && el.dataset.group !== undefined);
      return found ? found.dataset.group || null : undefined;
    };
    const move = (e: PointerEvent) => {
      if (!active) {
        if (Math.hypot(e.clientX - origin.x, e.clientY - origin.y) < 6) return;
        active = true;
        source.setPointerCapture(pointer);
      }
      const over = groupAt(e.clientX, e.clientY);
      // Die eigene Gruppe ist kein Ziel.
      carried = { host, x: e.clientX, y: e.clientY, over: over === host.group ? undefined : over };
    };
    const finish = (e: PointerEvent) => {
      removeEventListener('pointermove', move, true);
      removeEventListener('pointerup', finish, true);
      removeEventListener('pointercancel', finish, true);
      if (!active) return;
      const over = e.type === 'pointerup' ? carried?.over : undefined;
      carried = null;
      // Der Klick, der auf das Loslassen folgt, soll den Host nicht auswählen.
      const swallow = (click: Event) => click.stopPropagation();
      addEventListener('click', swallow, { capture: true, once: true });
      setTimeout(() => removeEventListener('click', swallow, true), 0);
      if (over === undefined) return;
      const input = { id: host.id, name: host.name, address: host.address, group: over, color: host.color, os: host.os, own: $state.snapshot(host.own) };
      void run(() => hostSave(input), over ? t('hosts.moved', { group: groupById(over)?.name ?? '' }) : t('hosts.moved.root'));
    };
    addEventListener('pointermove', move, true);
    addEventListener('pointerup', finish, true);
    addEventListener('pointercancel', finish, true);
  }

  async function duplicate(host: Host) {
    const id = await run(() => hostDuplicate(host.id, t('detail.copy', { name: host.name })), t('common.saved'));
    if (id) panel = { kind: 'detail', id };
  }

  async function confirmDeleteHost() {
    const host = deleteHost!;
    deleteHost = null;
    panel = null;
    await run(() => hostDelete(host.id), t('common.deleted'));
  }

  async function confirmDeleteGroup(withContents: boolean) {
    const target = deleteGroup!;
    deleteGroup = null;
    panel = null;
    if (group && groupPath(group).some((g) => g.id === target.id)) group = target.parent;
    await run(() => groupDelete(target.id, withContents), t('common.deleted'));
  }
</script>

{#snippet hostCard(h: Host)}
  {@const tint = colorOf(h)}
  {@const jump = protocolOf(h) === 'ssh' ? jumpOf(h) : undefined}
  <button
    class="host"
    class:sel={selected?.id === h.id}
    class:carried={carried?.host.id === h.id}
    style="--c:{tint ?? osColor(h.os)};--hc:{tint}"
    onpointerdown={(e) => grabHost(e, h)}
    onclick={() => (panel = { kind: 'detail', id: h.id })}
    ondblclick={() => openTab({ kind: 'host', id: h.id })}
  >
    <OsIcon os={h.os} protocol={h.protocol} />
    <span class="h-name">{#if tint}<i class="cdot"></i>{/if}{h.name}</span>
    <span class="h-addr">{addressOf(h)}</span>
    <span class="h-meta">
      {#if h.proxmox}
        {@const guest = guestOf(h)}
        <i class="chip pve-chip" title={t('pve.chip')}>
          <b class="mg-dot {guest ? statusTone(guest.status) : guestGone(h) ? 'err' : 'idle'}"></b>{guest ? statusText(guest.status) : guestGone(h) ? t('pve.gone') : 'Proxmox'}
        </i>
      {/if}
      {#if protocolOf(h) === 'ftp'}
        <i class="chip {ftpOpen(h) ? 'err' : ''}" title={t(ftpOpen(h) ? 'ftp.chip.open.hint' : 'ftp.chip.secure.hint')}><Icon name={ftpOpen(h) ? 'unlock' : 'lock'} size={12} />{ftpOpen(h) ? `FTP · ${t('ftp.chip.open')}` : t('ftp.chip.secure')}</i>
      {:else}
        <i class="chip">{h.protocol.toUpperCase()}</i>
        {#if usesMosh(h)}<i class="chip a" title={t('hosts.mosh.hint')}>Mosh</i>{/if}
      {/if}
      {#if jump}<i class="chip">{t('hosts.via', { host: jump.name })}</i>{/if}
      {#if results && h.group}<i class="chip">{pathLabel(h.group)}</i>{/if}
      {#if scope.vault === 'all' || results}<VaultBadge entry={h} />{/if}
    </span>
  </button>
{/snippet}

<section class="pg isl" class:list={settings.hostView === 'list'} style={empty ? 'display:flex;flex-direction:column' : ''}>
  <div class="crumbs">
    {#if group && !results}
      <button data-group="" class:drop={carried?.over === null} onclick={() => openGroup(null)}>{t('hosts.all')}</button>
      {#each path as g, i (g.id)}
        <Icon name="chev" size={12} />
        {#if i < path.length - 1}<button data-group={g.id} class:drop={carried?.over === g.id} onclick={() => openGroup(g.id)}>{g.name}</button>{:else}<span>{g.name}</span>{/if}
      {/each}
    {/if}
  </div>
  <div class="ph">
    <h1>{results ? t('hosts.results', { n: results.length }) : (current?.name ?? t('hosts.title'))}</h1>
    <div class="acts">
      <label class="search">
        <Icon name="search" size={14} />
        <input type="text" placeholder={t('hosts.search')} aria-label={t('hosts.search')} bind:value={query} spellcheck="false" />
      </label>
      <Segmented
        label={t('hosts.title')}
        bind:value={settings.hostView}
        options={[
          { value: 'cards', icon: 'grid', title: t('hosts.view.cards') },
          { value: 'list', icon: 'list', title: t('hosts.view.list') },
        ]}
      />
      <Button icon="down" title={t('imp.open.hint')} onclick={() => openImport()}>{t('imp.open')}</Button>
      <Button icon="folder" disabled={readOnly} title={readOnly ? t('err.read_only') : undefined} onclick={() => (panel = { kind: 'group', id: null })}>{t('hosts.newGroup')}</Button>
      <Button variant="primary" icon="plus" disabled={readOnly} title={readOnly ? t('err.read_only') : undefined} onclick={() => (panel = { kind: 'host', id: null })}>{t('hosts.newHost')}</Button>
    </div>
  </div>

  <VaultSwitch />

  {#if vault.damaged}
    <div class="warnbox" style="margin-top:14px"><Icon name="alert" size={16} /><span>{t('hosts.damaged', { n: vault.damaged })}</span></div>
  {/if}

  {#if results}
    {#if results.length}
      <div class="sec">{t('hosts.sec.hosts')}</div>
      <div class="grid">{#each results as h (h.id)}{@render hostCard(h)}{/each}</div>
    {:else}
      <div class="empty"><p>{t('hosts.noresults', { q: query.trim() })}</p></div>
    {/if}
  {:else if empty}
    <div class="empty">
      <span class="ei"><Icon name="server" size={28} /></span>
      <h2>{t('hosts.empty.title')}</h2>
      <p>{t('hosts.empty.text')}</p>
      <div class="acts">
        <Button variant="primary" icon="plus" onclick={() => (panel = { kind: 'host', id: null })}>{t('hosts.newHost')}</Button>
        <Button icon="down" onclick={() => openImport()}>{t('imp.open.long')}</Button>
      </div>
    </div>
  {:else}
    {#if current}
      <div class="inhb">
        <Icon name="link" size={14} />
        {#if Object.keys(defs).length}
          <span>{t('hosts.inherit', { n: hostCount(current.id) })}</span>
          {#snippet def(label: string, value: string, source: Group)}
            <i class="chip">{label}: <b>{value}</b>{#if source.id !== current.id}&nbsp;· {t('hosts.from', { src: source.name })}{/if}</i>
          {/snippet}
          {#if defs.identity}{@render def(t('detail.identity'), identityById(defs.identity.value)?.name ?? t('detail.identity.none'), defs.identity.source)}{/if}
          {#if defs.user}{@render def(t('detail.user'), defs.user.value, defs.user.source)}{/if}
          {#if defs.key}{@render def(t('detail.key'), keyById(defs.key.value)?.name ?? t('ident.key.none'), defs.key.source)}{/if}
          {#if defs.port}{@render def(t('detail.port'), String(defs.port.value), defs.port.source)}{/if}
          {#if defs.jump}{@render def(t('detail.jump'), jumpName(defs.jump.value), defs.jump.source)}{/if}
          {#if defs.keyFile}{@render def(t('edit.keyfile'), defs.keyFile.value, defs.keyFile.source)}{/if}
          {#if defs.startcmd}{@render def(t('detail.startcmd'), defs.startcmd.value, defs.startcmd.source)}{/if}
          {#if defs.env}{@render def(t('detail.env'), defs.env.value, defs.env.source)}{/if}
          {#if defs.proxy}{@render def(t('detail.proxy'), defs.proxy.value || t('detail.none'), defs.proxy.source)}{/if}
          {#if defs.legacy?.value}{@render def(t('detail.legacy'), t('edit.on'), defs.legacy.source)}{/if}
          {#if defs.mosh}{@render def('Mosh', defs.mosh.value ? t('edit.on') : t('edit.off'), defs.mosh.source)}{/if}
          {#if defs.agent}{@render def(t('detail.agent'), defs.agent.value ? t('edit.on') : t('edit.off'), defs.agent.source)}{/if}
          {#if defs.agentForward}{@render def(t('detail.agentForward'), defs.agentForward.value ? t('edit.on') : t('edit.off'), defs.agentForward.source)}{/if}
          {#if defs.reconnect}{@render def(t('detail.reconnect'), reconnectLabel(defs.reconnect.value), defs.reconnect.source)}{/if}
          {#if defs.scheme}{@render def(t('detail.scheme'), schemeName(defs.scheme.value) ?? t('set.scheme.auto'), defs.scheme.source)}{/if}
        {:else}
          <span>{t('hosts.inherit.none')}</span>
        {/if}
        <span class="grow"></span>
        <Button size="sm" icon="edit" onclick={() => (panel = { kind: 'group', id: current.id })}>{t('hosts.group.edit')}</Button>
      </div>
    {/if}

    {#if !group && vault.workspaces.length && personalShown}
      <div class="sec">{t('hosts.sec.workspaces')}</div>
      <div class="grid">
        {#each vault.workspaces as w (w.id)}
          {@const inside = workspaceHosts(w)}
          <button class="group ws" class:sel={workspace?.id === w.id} style="--c:var(--accent)" onclick={() => showWorkspace(w)} ondblclick={() => openWorkspace(w)}>
            <span class="os"><LayoutPreview layout={w.layout} small /></span>
            <span class="h-name">{w.name}</span>
            <span class="h-addr">{t('ws.count', { n: paneCount(w) })}{#if w.multi}&nbsp;· {t('multi.title')}{/if}</span>
          </button>
        {/each}
      </div>
    {/if}

    {#if subgroups.length}
      <div class="sec">{t('hosts.sec.groups')}</div>
      <div class="grid">
        {#each subgroups as g (g.id)}
          <button class="group" class:drop={carried?.over === g.id} data-group={g.id} style="--c:{groupColor(g) ?? 'var(--accent)'}" onclick={() => openGroup(g.id)}>
            <span class="os"><Icon name="folder" size={18} /></span>
            <span class="h-name">{g.name}</span>
            <span class="h-addr">{t('hosts.count', { n: hostCount(g.id) })}{#if childGroups(g.id).length}&nbsp;· {t('hosts.subgroups')}{/if}</span>
          </button>
        {/each}
      </div>
    {/if}

    {#if hosts.length}
      <div class="sec">{group ? t('hosts.sec.hosts') : t('hosts.sec.ungrouped')}</div>
      <div class="grid">{#each hosts as h (h.id)}{@render hostCard(h)}{/each}</div>
    {:else if group && !subgroups.length}
      <div class="empty" style="min-height:200px"><p>{t('hosts.empty.group')}</p></div>
    {/if}
  {/if}
</section>

{#if panel?.kind === 'host'}
  {#key panel.id}
    <HostEditor
      host={hostById(panel.id) ?? null}
      startGroup={group}
      onclose={() => (panel = panel?.kind === 'host' && panel.id ? { kind: 'detail', id: panel.id } : null)}
      onsaved={(id) => (panel = { kind: 'detail', id })}
      ondelete={(host) => (deleteHost = host)}
    />
  {/key}
{:else if panel?.kind === 'group'}
  {#key panel.id}
    <GroupEditor group={groupById(panel.id) ?? null} startParent={group} onclose={() => (panel = null)} onsaved={() => (panel = null)} ondelete={(g) => (deleteGroup = g)} />
  {/key}
{:else if workspace}
  {@const w = workspace}
  {@const inside = workspaceHosts(w)}
  <aside class="detail isl">
    <div class="d-head">
      <span class="os lg" style="--c:var(--accent)"><Icon name="layout" size={22} /></span>
      <div style="min-width:0">
        <div class="d-name">{w.name}</div>
        <div class="d-sub">{t('ws.title')}</div>
      </div>
      <span class="grow"></span>
      <Button variant="ghost" size="sm" icon="x" title={t('common.close')} onclick={() => (panel = null)} />
    </div>
    <div style="display:flex;gap:8px;margin-top:14px">
      <div style="flex:1;display:grid">
        <Button variant="primary" icon="play" onclick={() => openWorkspace(w)}>{t('ws.open')}</Button>
      </div>
      <Button variant="danger" icon="trash" title={t('common.delete')} onclick={() => (deleteWorkspace = w)} />
    </div>
    <div style="margin-top:14px"><LayoutPreview layout={w.layout} /></div>
    <form style="display:flex;gap:8px;align-items:flex-end;margin-top:14px" onsubmit={(e) => renameWorkspace(e, w)}>
      <div style="flex:1;min-width:0"><TextField label={t('edit.name')} bind:value={workspaceName} /></div>
      <button type="submit" class="btn" disabled={!workspaceName.trim() || workspaceName.trim() === w.name}>{t('common.save')}</button>
    </form>
    <dl class="kv" style="margin-top:6px">
      <div>
        <dt>{t('multi.title')}</dt>
        <dd>
          <button type="button" class="swt" class:on={w.multi} role="switch" aria-checked={w.multi} aria-label={t('multi.title')} disabled={paneCount(w) < 2} onclick={() => setWorkspaceMulti(w, !w.multi)}></button>
          <span class="fld-h">{t('ws.multi.hint')}</span>
        </dd>
      </div>
      <div>
        <dt>{t('ws.hosts', { n: inside.length })}</dt>
        {#each inside as h, i (i)}
          <dd style="margin-top:4px"><OsIcon os={h.os} protocol={h.protocol} size="sm" />{h.name}<span class="mono" style="color:var(--text-3)">{addressOf(h)}</span></dd>
        {/each}
      </div>
    </dl>
    <p class="fld-h" style="margin-top:12px">{t('ws.hint')}</p>
  </aside>
{:else if selected}
  {@const h = selected}
  {@const eff = inherited(h.group)}
  {@const jump = jumpOf(h)}
  {@const auth = authFor(h.group, h.own)}
  {@const proto = protocolOf(h)}
  <aside class="detail isl">
    <div class="d-head">
      <OsIcon os={h.os} protocol={h.protocol} size="lg" />
      <div style="min-width:0">
        <div class="d-name">{h.name}</div>
        <div class="d-sub">{pathLabel(h.group) || t('detail.nogroup')}</div>
      </div>
      <span class="grow"></span>
      <Button variant="ghost" size="sm" icon="x" title={t('common.close')} onclick={() => (panel = null)} />
    </div>
    <div style="display:flex;gap:8px;margin-top:14px">
      <div style="flex:1;display:grid">
        <Button variant="primary" icon={proto === 'ftp' ? 'folder' : 'play'} onclick={() => openTab({ kind: 'host', id: h.id })}>{t(proto === 'ftp' ? 'ftp.open' : 'detail.connect')}</Button>
      </div>
      <!-- In einem Tresor mit Leserecht lässt sich verbinden, aber nichts ändern. -->
      {#if canEdit(h)}
        <Button icon="edit" title={t('common.edit')} onclick={() => (panel = { kind: 'host', id: h.id })} />
        <Button icon="copy" title={t('detail.duplicate')} onclick={() => duplicate(h)} />
        <Button variant="danger" icon="trash" title={t('common.delete')} onclick={() => (deleteHost = h)} />
      {/if}
    </div>
    {#if vault.vaults.length > 1}
      <div class="d-vault" style="--vc:{vaultColor(vaultOf(h))}">
        <i class="vdot"></i><span>{t('hosts.vault')}: <b>{vaultLabel(vaultOf(h))}</b></span>
        {#if !canEdit(h)}
          <i class="chip"><Icon name="eye" size={11} />{t('hosts.readonly')}</i>
        {:else if moveTargets(h).length}
          <Button size="sm" variant="ghost" icon="arrowR" title={t('move.open.hint')} onclick={() => startMove(h)}>{t('move.open')}</Button>
        {/if}
      </div>
    {/if}

    {#if h.proxmox}
      {@const link = h.proxmox}
      {@const guest = guestOf(h)}
      {@const busy = isSwitching(link.connection, link.vmid)}
      <div class="d-pve">
        <div class="d-pve-h">
          <b class="mg-dot {guest ? statusTone(guest.status) : guestGone(h) ? 'err' : 'idle'}"></b>
          <span>
            <b>{guest ? statusText(guest.status) : guestGone(h) ? t('pve.gone') : 'Proxmox'}</b>{#if guest?.status === 'running' && guest.uptime}{' '}{t('pve.since', { time: span(guest.uptime) })}{/if}
            <i>{link.kind === 'qemu' ? t('pve.kind.vm') : t('pve.kind.ct')} {link.vmid} · {vault.proxmox.find((c) => c.id === link.connection)?.name ?? ''}</i>
          </span>
          {#if canEdit(h)}<Button size="sm" variant="ghost" icon="x" title={t('pve.unlink')} onclick={() => (unlinking = h)} />{/if}
        </div>
        {#if guest && !guest.template}
          <div class="d-pve-a">
            {#if guest.status === 'running'}
              <Button size="sm" icon="refresh" disabled={busy} onclick={() => (pveAsk = { host: h, action: 'reboot' })}>{t('pve.reboot')}</Button>
              <Button size="sm" icon="stop" disabled={busy} onclick={() => (pveAsk = { host: h, action: 'shutdown' })}>{t('pve.shutdown')}</Button>
            {:else if isWaiting(h.id)}
              <Button size="sm" icon="x" onclick={() => stopWaiting(h.id)}>{t('pve.waiting')}</Button>
            {:else}
              <Button size="sm" icon="play" disabled={busy} onclick={() => powerHost(h, 'start')}>{t('manage.start')}</Button>
              {#if proto === 'ssh'}<Button size="sm" variant="primary" icon="terminal" disabled={busy} onclick={() => startAndConnect(h)}>{t('pve.startconnect')}</Button>{/if}
            {/if}
          </div>
        {/if}
      </div>
    {/if}

    {#snippet origin(own: unknown, source: Group | undefined)}
      {#if own === undefined}<span class="inh">{source ? t('hosts.from', { src: source.name }) : t('detail.default')}</span>{/if}
    {/snippet}
    <!-- Herkunft eines Werts der Anmeldung: am Host selbst eingetragen (nichts), aus einer Identität, von einer Gruppe oder die feste Vorgabe. -->
    {#snippet via(from: From<unknown> | undefined)}
      {#if !from}
        <span class="inh">{t('detail.default')}</span>
      {:else if from.identity}
        <span class="inh">{t('auth.from.identity', { name: from.identity.name })}</span>
      {:else if from.group}
        <span class="inh">{t('hosts.from', { src: from.group.name })}</span>
      {/if}
    {/snippet}
    <dl class="kv" style="margin-top:10px">
      {#if proto !== 'ssh'}
        <div>
          <dt>{t('detail.protocol')}</dt>
          <dd>{proto === 'serial' ? t('proto.serial.long') : 'Telnet'}</dd>
        </div>
      {/if}
      {#if proto === 'serial'}
        {@const line = h.serial ?? DEFAULT_SERIAL}
        <div>
          <dt>{t('edit.serial.port')}</dt>
          <dd><span class="mono selectable">{h.address}</span></dd>
        </div>
        <div>
          <dt>{t('edit.sec.line')}</dt>
          <dd><span class="mono">{serialLabel(line)}</span><span class="inh">{t('serial.summary', { baud: line.baud, data: line.dataBits, parity: t(`serial.parity.${line.parity}`), stop: line.stopBits })}</span></dd>
        </div>
        <div>
          <dt>{t('serial.flow')}</dt>
          <dd>{t(`serial.flow.${line.flow}`)}</dd>
        </div>
      {:else}
        <div>
          <dt>{t('detail.address')}</dt>
          <dd><span class="mono selectable">{h.address}</span></dd>
        </div>
      {/if}
      {#if proto === 'ftp'}
        {@const ftp = ftpOf(h)}
        <div>
          <dt>{t('ftp.security')}</dt>
          <dd>
            {#if ftp.security === 'none'}<span class="errline"><Icon name="unlock" size={13} /> {t('ftp.security.none')}</span>{:else}{t(`ftp.security.${ftp.security}`)}{/if}
          </dd>
        </div>
        <div>
          <dt>{t('detail.port')}</dt>
          <dd><span class="mono">{h.own.port ?? ftpPort(ftp)}</span>{#if h.own.port === undefined}<span class="inh">{t('detail.default')}</span>{/if}</dd>
        </div>
        <div>
          <dt>{t('detail.user')}</dt>
          <dd>
            {#if ftp.anonymous}{t('ftp.anonymous')}{:else if h.own.identity}{identityById(h.own.identity)?.name ?? ''}{:else}<span class="mono selectable">{h.own.user ?? ''}</span>{/if}
          </dd>
        </div>
        <div>
          <dt>{t('ftp.dir')}</dt>
          <dd>{#if ftp.dir}<span class="mono selectable">{ftp.dir}</span>{:else}{t('ftp.detail.dir.default')}{/if}</dd>
        </div>
        {#if ftp.security === 'none'}<div class="warnbox danger" style="grid-column:1/-1"><span>{t('ftp.plain.warning')}</span></div>{/if}
      {/if}
      {#if proto === 'telnet'}
        <div>
          <dt>{t('detail.port')}</dt>
          <dd><span class="mono">{h.own.port ?? DEFAULT_TELNET_PORT}</span>{#if h.own.port === undefined}<span class="inh">{t('detail.default')}</span>{/if}</dd>
        </div>
        <div>
          <dt>{t('detail.user')}</dt>
          <dd>{#if h.own.user}<span class="mono selectable">{h.own.user}</span>{:else}{t('edit.telnet.user.none')}{/if}</dd>
        </div>
      {/if}
      {#if proto === 'ssh'}
      <div>
        <dt>{t('detail.port')}</dt>
        <dd><span class="mono">{h.own.port ?? eff.port?.value ?? DEFAULT_PORT}</span>{@render origin(h.own.port, eff.port?.source)}</dd>
      </div>
      {#if auth.identity}
        <div>
          <dt>{t('detail.identity')}</dt>
          <dd>{auth.identity.value.name}{@render via(auth.identity)}</dd>
        </div>
      {/if}
      <div>
        <dt>{t('detail.user')}</dt>
        <dd><span class="mono selectable">{auth.user?.value ?? DEFAULT_USER}</span>{@render via(auth.user)}</dd>
      </div>
      {#if auth.key}
        <div>
          <dt>{t('detail.key')}</dt>
          <dd>{auth.key.value.name}{@render via(auth.key)}</dd>
        </div>
      {/if}
      <div>
        <dt>{t('detail.password')}</dt>
        <dd>{h.hasPassword ? t('detail.password.set') : auth.identityPassword ? t('detail.password.identity') : t('detail.password.none')}</dd>
      </div>
      {#if h.own.agent ?? eff.agent?.value}
        <div>
          <dt>{t('detail.agent')}</dt>
          <dd>{(h.own.agentForward ?? eff.agentForward?.value) ? t('detail.agentForward') : t('edit.on')}{@render origin(h.own.agent, eff.agent?.source)}</dd>
        </div>
      {/if}
      {#if usesMosh(h)}
        <div>
          <dt>Mosh</dt>
          <dd>{t('edit.on')} · {t(`edit.mosh.predict.${h.own.moshPredict ?? eff.moshPredict?.value ?? 'adaptive'}`)}{@render origin(h.own.mosh, eff.mosh?.source)}</dd>
        </div>
      {/if}
      <div>
        <dt>{t('detail.jump')}</dt>
        <dd>{jump?.name ?? t('detail.none')}{#if h.own.jump === undefined && eff.jump}{@render origin(undefined, eff.jump.source)}{/if}</dd>
      </div>
      {#if h.own.keyFile ?? eff.keyFile}
        <div>
          <dt>{t('edit.keyfile')}</dt>
          <dd><span class="mono selectable" style="word-break:break-all">{h.own.keyFile ?? eff.keyFile?.value}</span>{@render origin(h.own.keyFile, eff.keyFile?.source)}</dd>
        </div>
      {/if}
      {#if h.own.proxy ?? eff.proxy?.value}
        <div>
          <dt>{t('detail.proxy')}</dt>
          <dd><span class="mono selectable" style="word-break:break-all">{h.own.proxy ?? eff.proxy?.value}</span>{@render origin(h.own.proxy, eff.proxy?.source)}</dd>
        </div>
      {/if}
      {#if h.own.startcmd ?? eff.startcmd}
        <div>
          <dt>{t('detail.startcmd')}</dt>
          <dd><span class="mono selectable">{h.own.startcmd ?? eff.startcmd?.value}</span>{@render origin(h.own.startcmd, eff.startcmd?.source)}</dd>
        </div>
      {/if}
      {#if h.own.env ?? eff.env}
        <div>
          <dt>{t('detail.env')}</dt>
          <dd><span class="mono selectable" style="word-break:break-all">{h.own.env ?? eff.env?.value}</span>{@render origin(h.own.env, eff.env?.source)}</dd>
        </div>
      {/if}
      {/if}
      {#if h.own.reconnect ?? eff.reconnect}
        <div>
          <dt>{t('detail.reconnect')}</dt>
          <dd>{reconnectLabel((h.own.reconnect ?? eff.reconnect?.value)!)}{@render origin(h.own.reconnect, eff.reconnect?.source)}</dd>
        </div>
      {/if}
      {#if h.own.scheme ?? eff.scheme}
        <div>
          <dt>{t('detail.scheme')}</dt>
          <dd>{schemeName((h.own.scheme ?? eff.scheme?.value)!) ?? t('set.scheme.auto')}{@render origin(h.own.scheme, eff.scheme?.source)}</dd>
        </div>
      {/if}
    </dl>
    {#if forwardsOf(h.id).length}
      <div class="sec">{t('fwd.sec.host')}</div>
      <div class="rows">
        {#each forwardsOf(h.id) as rule (rule.id)}
          <div class="row">
            <div class="rt"><b>{rule.name}</b><span class="mono">{forwardRoute(rule)}</span></div>
            <Switch label={t('fwd.switch')} bind:checked={() => !!stateOf(rule.id), (on) => void toggleForward(rule.id, on)} />
          </div>
        {/each}
      </div>
    {/if}
  </aside>
{/if}

{#if carried}
  <div class="dragchip" style="left:{carried.x}px;top:{carried.y}px;--c:{colorOf(carried.host) ?? 'var(--accent)'}">
    <i class="dot"></i>{carried.host.name}
    {#if carried.over !== undefined}<span>{carried.over ? t('hosts.move.to', { group: groupById(carried.over)?.name ?? '' }) : t('hosts.move.root')}</span>{/if}
  </div>
{/if}

<Dialog open={!!deleteHost} title={t('del.host.title')}>
  <p>{t('del.host.text', { name: deleteHost?.name ?? '' })}</p>
  {#if deleteHost && forwardsOf(deleteHost.id).length}
    <div class="warnbox"><Icon name="alert" size={16} /><span>{tn('del.host.forwards', forwardsOf(deleteHost.id).length)}</span></div>
  {/if}
  {#snippet actions()}
    <Button variant="primary" onclick={() => (deleteHost = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" onclick={confirmDeleteHost}>{t('common.delete')}</Button>
  {/snippet}
</Dialog>

<Dialog open={!!pveAsk} title={pveAsk ? t(`pve.confirm.${pveAsk.action}.title`, { name: guestOf(pveAsk.host)?.name ?? pveAsk.host.name }) : ''}>
  <p>{pveAsk ? t(`pve.confirm.${pveAsk.action}.text`) : ''}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (pveAsk = null)}>{t('common.cancel')}</Button>
    {#if pveAsk?.action === 'shutdown'}
      <Button onclick={() => pveAsk && (pveAsk = { ...pveAsk, action: 'stop' })}>{t('pve.stop')}</Button>
    {/if}
    <Button variant="danger" onclick={pveAnswered}>{pveAsk ? t(`pve.${pveAsk.action}`) : ''}</Button>
  {/snippet}
</Dialog>

<Dialog open={!!unlinking} title={t('pve.unlink.title', { name: unlinking?.name ?? '' })}>
  <p>{t('pve.unlink.text')}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (unlinking = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" onclick={confirmUnlink}>{t('pve.unlink')}</Button>
  {/snippet}
</Dialog>

<Dialog open={!!moving} title={t('move.title', { name: moving?.name ?? '' })}>
  {@const target = vault.vaults.find((v) => v.id === moveTo)}
  <label class="fld">
    <span class="fld-l">{t('move.target')}</span>
    <select class="dropdown" bind:value={moveTo}>
      {#each moving ? moveTargets(moving) : [] as v (v.id)}<option value={v.id}>{vaultLabel(v)}</option>{/each}
    </select>
  </label>
  <p class="fld-h">{t('move.text')}</p>
  {#if target?.kind === 'shared'}
    <div class="warnbox"><Icon name="alert" size={16} /><span>{t('move.shared', { vault: vaultLabel(target) })}{#if moving?.proxmox}{' '}{t('move.shared.pve')}{/if}</span></div>
    <label class="check"><input type="checkbox" bind:checked={moveCarry} />{t('move.carry')}</label>
  {/if}
  {#snippet actions()}
    <Button onclick={() => (moving = null)}>{t('common.cancel')}</Button>
    <Button variant="primary" icon="arrowR" onclick={confirmMove}>{t('move.confirm')}</Button>
  {/snippet}
</Dialog>

<Dialog open={!!deleteWorkspace} title={t('ws.delete.title')}>
  <p>{t('ws.delete.text', { name: deleteWorkspace?.name ?? '' })}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (deleteWorkspace = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" onclick={confirmDeleteWorkspace}>{t('common.delete')}</Button>
  {/snippet}
</Dialog>

<Dialog open={!!deleteGroup} title={t('del.group.title')}>
  <p>{t('del.group.text', { name: deleteGroup?.name ?? '', n: deleteGroup ? hostCount(deleteGroup.id) : 0 })}</p>
  <div class="choice">
    <button onclick={() => confirmDeleteGroup(false)}><b>{t('del.group.dissolve')}</b><small>{t('del.group.dissolve.hint')}</small></button>
    <button class="danger" onclick={() => confirmDeleteGroup(true)}><b>{t('del.group.all')}</b></button>
  </div>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (deleteGroup = null)}>{t('common.cancel')}</Button>
  {/snippet}
</Dialog>
