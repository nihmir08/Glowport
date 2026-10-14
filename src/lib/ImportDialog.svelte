<script lang="ts">
  import { importApply, importDiscard, importPick, importRead, importScan } from './backend';
  import { applySnapshot, errorText, pathLabel, vault } from './data.svelte';
  import { has, t, tn, type Key } from './i18n.svelte';
  import { importUi, isWarning, noteText, SOURCES, sourceInfo, sourceName } from './import.svelte';
  import { toast, ui } from './state.svelte';
  import type { DraftForward, DraftHost, DraftKey, ImportDraft, ImportExisting, ImportFound, ImportReport, ImportSource } from './types';
  import Button from './ui/Button.svelte';
  import Icon from './ui/Icon.svelte';
  import Segmented from './ui/Segmented.svelte';

  type Part = 'hosts' | 'keys' | 'forwards' | 'snippets' | 'knownHosts';

  let found = $state<ImportFound[] | null>(null);
  /** What is being read right now: a source, a chosen file or nothing. */
  let reading = $state<ImportSource | 'file' | null>(null);
  let draft = $state<ImportDraft | null>(null);
  let part = $state<Part>('hosts');
  let picked = $state<Record<Part, string[]>>({ hosts: [], keys: [], forwards: [], snippets: [], knownHosts: [] });
  let query = $state('');
  /** Destination of the hosts: empty = top level, NEW = new group, otherwise a group's ID. */
  const NEW = '\u0000new';
  let into = $state('');
  let newGroup = $state('');
  let existing = $state<ImportExisting>('skip');
  let keysToVault = $state(true);
  let passwords = $state(true);
  let applying = $state(false);
  let report = $state<ImportReport | null>(null);

  const step = $derived(report ? 'done' : draft ? 'preview' : 'source');

  $effect(() => {
    if (!importUi.open) return;
    if (importUi.draft) show(importUi.draft);
    importUi.draft = null;
    if (!found) void importScan().then((list) => (found = list), () => (found = []));
  });

  function show(next: ImportDraft) {
    draft = next;
    report = null;
    query = '';
    picked = {
      hosts: next.hosts.map((h) => h.ref),
      keys: next.keys.filter((k) => k.state !== 'missing' && k.state !== 'unreadable').map((k) => k.ref),
      forwards: next.forwards.map((f) => f.ref),
      snippets: next.snippets.filter((s) => !s.existing).map((s) => s.ref),
      knownHosts: next.knownHosts.filter((k) => !k.existing).map((k) => k.ref),
    };
    part = PARTS.find((p) => next[p].length) ?? 'hosts';
    // Sources without folders of their own land in a group named after them; that keeps the overview tidy.
    into = next.hosts.length && !next.groups.length ? NEW : '';
    newGroup = next.source === 'csv' || next.source === 'glowport' ? t('imp.into.default') : sourceInfo(next.source).name;
    existing = 'skip';
  }

  async function read(source: ImportSource) {
    reading = source;
    try {
      show(await importRead(source));
    } catch (e) {
      toast(errorText(e), 'err');
    }
    reading = null;
  }

  async function pick(source: ImportSource | null) {
    reading = source ?? 'file';
    try {
      const next = await importPick(source);
      if (next) show(next);
    } catch (e) {
      toast(errorText(e), 'err');
    }
    reading = null;
  }

  function discard() {
    if (draft) void importDiscard(draft.token).catch(() => {});
    draft = null;
    report = null;
  }

  function close() {
    discard();
    importUi.open = false;
    // Look again on the next opening: a program may have been added in the meantime.
    found = null;
  }

  const PARTS: Part[] = ['hosts', 'keys', 'forwards', 'snippets', 'knownHosts'];
  const parts = $derived(draft ? PARTS.filter((p) => draft![p].length) : []);
  const isPicked = (p: Part, ref: string) => picked[p].includes(ref);
  function toggle(p: Part, ref: string) {
    picked[p] = isPicked(p, ref) ? picked[p].filter((r) => r !== ref) : [...picked[p], ref];
  }
  const selectable = (p: Part): string[] => (p === 'keys' ? draft!.keys.filter((k) => k.state !== 'missing' && k.state !== 'unreadable') : draft![p]).map((x) => x.ref);

  const needle = $derived(query.trim().toLowerCase());
  const hit = (...texts: (string | null)[]) => !needle || texts.some((text) => text?.toLowerCase().includes(needle));

  /** Path of a draft group from top to bottom. */
  function draftPath(ref: string | null): string {
    const names: string[] = [];
    for (let g = draft?.groups.find((x) => x.ref === ref), n = 0; g && n < 20; g = draft?.groups.find((x) => x.ref === g!.parent), n++) names.unshift(g.name);
    return names.join(' › ');
  }

  /** Hosts by their group, hosts without a group first. */
  const sections = $derived.by(() => {
    if (!draft) return [];
    const by = new Map<string, DraftHost[]>();
    for (const h of draft.hosts) {
      if (!hit(h.name, h.address, h.user, draftPath(h.group))) continue;
      const key = draftPath(h.group);
      by.set(key, [...(by.get(key) ?? []), h]);
    }
    return [...by.entries()].sort(([a], [b]) => (a === '' ? -1 : b === '' ? 1 : a.localeCompare(b))).map(([path, hosts]) => ({ path, hosts }));
  });

  const hostByRef = (ref: string | null) => draft?.hosts.find((h) => h.ref === ref);
  const keyByRef = (ref: string | null) => draft?.keys.find((k) => k.ref === ref);
  /** Where a source's host leads. The usual port (22, for Telnet 23) is left out; a serial line has none. */
  const target = (h: DraftHost) => {
    if (h.protocol === 'serial') return h.address;
    const usual = h.protocol === 'telnet' ? 23 : h.protocol === 'ftp' ? 21 : 22;
    return `${h.user ? `${h.user}@` : ''}${h.address}${h.port && h.port !== usual ? `:${h.port}` : ''}`;
  };
  const route = (f: DraftForward) => {
    const host = hostByRef(f.host)?.name ?? '?';
    const here = `${f.bindAddress}:${f.bindPort}`;
    if (f.kind === 'dynamic') return `SOCKS ${here} → ${host}`;
    return f.kind === 'local' ? `${here} → ${host} → ${f.destHost}:${f.destPort}` : `${host} ${here} → ${f.destHost}:${f.destPort}`;
  };
  const keyFate = (k: DraftKey): { text: string; kind: '' | 'ok' | 'err' } => {
    if (k.state === 'missing') return { text: t('imp.key.missing'), kind: 'err' };
    if (k.state === 'unreadable') return { text: t('imp.key.unreadable'), kind: 'err' };
    if (k.existing) return { text: t('imp.key.existing'), kind: '' };
    if (k.state === 'encrypted') return { text: t('imp.key.encrypted'), kind: '' };
    return keysToVault ? { text: t('imp.key.vault'), kind: 'ok' } : { text: t('imp.key.file'), kind: '' };
  };

  const chosenHosts = $derived(draft ? draft.hosts.filter((h) => picked.hosts.includes(h.ref)) : []);
  const known = $derived(chosenHosts.filter((h) => h.existing).length);
  /** Hosts the import creates or changes. */
  const effective = $derived(existing === 'skip' ? chosenHosts.length - known : chosenHosts.length);
  const others = $derived(picked.keys.length + picked.forwards.length + picked.snippets.length + picked.knownHosts.length);
  const hasPasswords = $derived(!!draft?.hosts.some((h) => h.hasPassword && !h.notes.some((n) => n.code === 'password_unreadable')));
  const groups = $derived([...vault.groups].sort((a, b) => pathLabel(a.id).localeCompare(pathLabel(b.id))));
  const ready = $derived(!applying && (effective > 0 || others > 0) && (into !== NEW || newGroup.trim() !== ''));

  async function apply() {
    if (!draft || !ready) return;
    applying = true;
    try {
      const result = await importApply(draft.token, {
        ...picked,
        into: into === NEW ? { name: newGroup.trim() } : into ? { id: into } : null,
        existing,
        keysToVault,
        passwords: passwords && hasPasswords,
      });
      applySnapshot(result.data);
      report = result.report;
    } catch (e) {
      toast(errorText(e), 'err');
    }
    applying = false;
  }

  function finish() {
    close();
    ui.page = 'hosts';
  }

  const skipText = (reason: string) => (has(`imp.skip.${reason}`) ? t(`imp.skip.${reason}` as Key) : reason);
  const failText = (reason: string) => (has(`err.invalid.${reason}`) ? t(`err.invalid.${reason}` as Key) : has(`imp.fail.${reason}`) ? t(`imp.fail.${reason}` as Key) : reason);
  const foundCount = (f: ImportFound) => (f.count === null ? '' : f.source === 'knownhosts' ? tn('imp.count.known', f.count) : tn('imp.count', f.count));
</script>

<svelte:window onkeydown={(e) => importUi.open && e.key === 'Escape' && !applying && close()} />

{#snippet tile(id: ImportSource, size: 'md' | 'sm' = 'md')}
  {@const info = sourceInfo(id)}
  <span class="os logo imp-tile" class:sm={size === 'sm'} style="--c:{info.color}">
    <Icon name={info.icon} size={size === 'sm' ? 15 : 19} />
  </span>
{/snippet}

{#if importUi.open}
  <div class="ov" role="presentation" onclick={(e) => e.target === e.currentTarget && !applying && close()}>
    <div class="dlg imp" role="dialog" aria-modal="true" aria-label={t('imp.title')}>
      <div class="imp-head">
        <h2>{t('imp.title')}</h2>
        <ol class="imp-steps" aria-label={t('imp.steps')}>
          {#each ['source', 'preview', 'done'] as s, i (s)}
            <li class:on={step === s} class:past={['source', 'preview', 'done'].indexOf(step) > i}><i>{i + 1}</i>{t(`imp.step.${s}` as Key)}</li>
          {/each}
        </ol>
        <Button variant="ghost" size="sm" icon="x" title={t('common.close')} onclick={close} />
      </div>

      {#if step === 'source'}
        <div class="imp-body">
          <p>{t('imp.intro')}</p>
          <div class="sec">{t('imp.found')}</div>
          {#if !found}
            <div class="imp-none">{t('imp.scanning')}</div>
          {:else if !found.length}
            <div class="imp-none">{t('imp.found.none')}</div>
          {:else}
            <div class="rows imp-found">
              {#each found as f (f.source + f.where)}
                <div class="row">
                  {@render tile(f.source)}
                  <div class="rt">
                    <b>{sourceName(f.source)}</b>
                    <span class="mono">{f.where || t('imp.where.registry')}</span>
                  </div>
                  {#if f.count !== null}<i class="chip">{foundCount(f)}</i>{/if}
                  <Button size="sm" icon="eye" disabled={reading !== null} onclick={() => read(f.source)}>{reading === f.source ? t('imp.reading') : t('imp.look')}</Button>
                </div>
              {/each}
            </div>
          {/if}

          <div class="sec">{t('imp.files')}</div>
          <div class="imp-grid">
            {#each SOURCES as s (s.id)}
              <button type="button" class="imp-src" disabled={reading !== null} onclick={() => pick(s.id)}>
                {@render tile(s.id, 'sm')}
                <b>{sourceName(s.id)}</b>
                <span>{t(`imp.file.${s.id}` as Key)}</span>
              </button>
            {/each}
          </div>
        </div>
        <div class="dlg-a">
          <span class="imp-foot">{t('imp.drop')}</span>
          <Button onclick={close}>{t('common.cancel')}</Button>
          <Button variant="primary" icon="file" disabled={reading !== null} onclick={() => pick(null)}>{reading === 'file' ? t('imp.reading') : t('imp.pick')}</Button>
        </div>
      {:else if step === 'preview' && draft}
        <div class="imp-body">
          <div class="imp-origin">
            {@render tile(draft.source, 'sm')}
            <b>{sourceName(draft.source)}</b>
            <span class="mono">{draft.origin || t('imp.where.registry')}</span>
          </div>

          <div class="pickbar">
            <Segmented label={t('imp.parts')} bind:value={part} options={parts.map((p) => ({ value: p, label: `${t(`imp.part.${p}` as Key)} · ${draft![p].length}` }))} />
            <span class="grow"></span>
            {#if part === 'hosts'}
              <label class="search">
                <Icon name="search" size={14} />
                <input type="text" placeholder={t('imp.search')} aria-label={t('imp.search')} bind:value={query} spellcheck="false" />
              </label>
            {/if}
            <Button size="sm" onclick={() => (picked[part] = selectable(part))}>{t('deploy.all')}</Button>
            <Button size="sm" onclick={() => (picked[part] = [])}>{t('deploy.none')}</Button>
          </div>

          <div class="picklist imp-list">
            {#if part === 'hosts'}
              {#each sections as section (section.path)}
                {#if draft.groups.length}
                  <div class="imp-group">
                    <Icon name="folder" size={13} />
                    <b>{section.path || t('imp.nogroup')}</b>
                    <span>{tn('imp.count.hosts', section.hosts.length)}</span>
                  </div>
                {/if}
                {#each section.hosts as h (h.ref)}
                  {@const key = keyByRef(h.key)}
                  <label class="pick">
                    <input type="checkbox" checked={isPicked('hosts', h.ref)} onchange={() => toggle('hosts', h.ref)} />
                    <b>{h.name}</b>
                    <span class="mono">{target(h)}</span>
                    {#if h.protocol === 'telnet' || h.protocol === 'serial' || h.protocol === 'ftp'}<i class="chip">{h.protocol.toUpperCase()}</i>{/if}
                    {#if h.jump}<i class="chip"><Icon name="link" size={10} />{t('imp.via', { name: hostByRef(h.jump)?.name ?? '?' })}</i>{/if}
                    {#if key}
                      <i class="chip" class:err={key.state === 'missing'}><Icon name="key" size={10} />{key.name}</i>
                    {:else if h.hasPassword}
                      <i class="chip"><Icon name="lock" size={10} />{t('imp.auth.password')}</i>
                    {:else if h.auth === 'agent'}
                      <i class="chip"><Icon name="agent" size={10} />{t('imp.auth.agent')}</i>
                    {/if}
                    {#each h.notes as note (note.code)}
                      <i class="chip" class:warn={isWarning(note)} title={note.detail ?? undefined}>{noteText(note)}</i>
                    {/each}
                    {#if h.existing}<i class="chip a">{t(`imp.existing.${existing}` as Key)}</i>{/if}
                  </label>
                {/each}
              {:else}
                <div class="imp-none">{t('imp.nohits')}</div>
              {/each}
            {:else if part === 'keys'}
              {#each draft.keys as k (k.ref)}
                {@const fate = keyFate(k)}
                <label class="pick">
                  <input type="checkbox" checked={isPicked('keys', k.ref)} disabled={k.state === 'missing' || k.state === 'unreadable'} onchange={() => toggle('keys', k.ref)} />
                  <b>{k.name}</b>
                  <span class="mono">{k.path ?? k.fingerprint ?? ''}</span>
                  {#if k.kind}<i class="chip">{k.kind === 'ed25519' ? 'Ed25519' : `${k.kind.toUpperCase()} ${k.bits ?? ''}`}</i>{/if}
                  <i class="chip">{tn('imp.key.uses', k.uses)}</i>
                  <i class="chip {fate.kind}">{fate.text}</i>
                </label>
              {/each}
            {:else if part === 'forwards'}
              {#each draft.forwards as f (f.ref)}
                <label class="pick">
                  <input type="checkbox" checked={isPicked('forwards', f.ref)} onchange={() => toggle('forwards', f.ref)} />
                  <b>{f.name}</b>
                  <span class="mono">{route(f)}</span>
                  <i class="chip">{t(`fwd.kind.${f.kind}` as Key)}</i>
                </label>
              {/each}
            {:else if part === 'snippets'}
              {#each draft.snippets as s (s.ref)}
                <label class="pick">
                  <input type="checkbox" checked={isPicked('snippets', s.ref)} onchange={() => toggle('snippets', s.ref)} />
                  <b>{s.name}</b>
                  <span class="mono">{s.command.split('\n')[0]}</span>
                  {#if s.package}<i class="chip">{s.package}</i>{/if}
                  {#if s.existing}<i class="chip a">{t('imp.snippet.existing')}</i>{/if}
                </label>
              {/each}
            {:else}
              {#each draft.knownHosts as k (k.ref)}
                <label class="pick">
                  <input type="checkbox" checked={isPicked('knownHosts', k.ref)} onchange={() => toggle('knownHosts', k.ref)} />
                  <b class="mono">{k.host}{k.port !== 22 ? `:${k.port}` : ''}</b>
                  <span class="mono">{k.fingerprint}</span>
                  <i class="chip">{k.algorithm}</i>
                  {#if k.existing}<i class="chip a">{t('imp.known.existing')}</i>{/if}
                </label>
              {/each}
            {/if}
          </div>

          <div class="imp-opts">
            {#if draft.hosts.length}
              <label class="imp-opt">
                <span>{t('imp.into')}</span>
                <select class="dropdown" bind:value={into}>
                  <option value="">{t('imp.into.top')}</option>
                  <option value={NEW}>{t('imp.into.new')}</option>
                  {#each groups as g (g.id)}<option value={g.id}>{pathLabel(g.id)}</option>{/each}
                </select>
                {#if into === NEW}<input class="imp-name" type="text" aria-label={t('imp.into.name')} placeholder={t('imp.into.name')} bind:value={newGroup} spellcheck="false" />{/if}
              </label>
            {/if}
            {#if known > 0}
              <label class="imp-opt">
                <span>{tn('imp.dup', known)}</span>
                <select class="dropdown" bind:value={existing}>
                  <option value="skip">{t('imp.dup.skip')}</option>
                  <option value="update">{t('imp.dup.update')}</option>
                  <option value="add">{t('imp.dup.add')}</option>
                </select>
              </label>
            {/if}
            {#if draft.keys.some((k) => k.state === 'ready' && !k.existing)}
              <label class="check" title={t('imp.keys.hint')}><input type="checkbox" bind:checked={keysToVault} />{t('imp.keys.vault')}</label>
            {/if}
            {#if hasPasswords}
              <label class="check"><input type="checkbox" bind:checked={passwords} />{t('imp.passwords')}</label>
            {/if}
          </div>

          {#if draft.skipped.length}
            <details class="imp-skipped">
              <summary><Icon name="alert" size={14} />{tn('imp.skipped', draft.skipped.length)}</summary>
              <ul>
                {#each draft.skipped as s (s.name)}<li><b>{s.name}</b><span>{skipText(s.reason)}</span></li>{/each}
              </ul>
            </details>
          {/if}
        </div>
        <div class="dlg-a">
          <span class="imp-foot">{t('imp.nothing')}</span>
          <Button icon="arrowL" disabled={applying} onclick={discard}>{t('imp.back')}</Button>
          <Button variant="primary" icon="down" disabled={!ready} onclick={apply}>
            {applying ? t('imp.applying') : effective > 0 ? tn('imp.apply', effective) : t('imp.apply.other')}
          </Button>
        </div>
      {:else if report}
        <div class="imp-body imp-done">
          <span class="ei"><Icon name="check" size={28} /></span>
          <h3>{t('imp.done.title')}</h3>
          <div class="imp-sum">
            {#each [['hosts', report.hosts], ['updated', report.updated], ['groups', report.groups], ['keys', report.keys], ['keyFiles', report.keyFiles], ['forwards', report.forwards], ['snippets', report.snippets], ['knownHosts', report.knownHosts], ['skipped', report.skipped]] as [what, n] (what)}
              {#if (n as number) > 0}<div><b>{n}</b><span>{tn(`imp.done.${what}` as Key, n as number)}</span></div>{/if}
            {/each}
          </div>
          {#if report.keyFiles > 0}<p class="imp-hint">{t('imp.done.keyFiles.hint')}</p>{/if}
          {#if report.failed.length}
            <div class="warnbox">
              <Icon name="alert" size={16} />
              <span>
                {tn('imp.done.failed', report.failed.length)}
                {#each report.failed as f (f.name)}<br /><b>{f.name}</b>: {failText(f.reason)}{/each}
              </span>
            </div>
          {/if}
        </div>
        <div class="dlg-a">
          <Button icon="plus" onclick={discard}>{t('imp.more')}</Button>
          <Button variant="primary" icon="check" onclick={finish}>{t('imp.finish')}</Button>
        </div>
      {/if}
    </div>
  </div>
{/if}
