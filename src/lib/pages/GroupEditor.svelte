<script lang="ts">
  import { onMount } from 'svelte';
  import { groupSave, pickKeyFile } from '../backend';
  import { applySnapshot, authFor, descendants, MOSH_PORT, errorText, groupById, hostById, identityById, inherited, pathLabel, personalVault, reachable, sameVault, sshHosts, vault, type From } from '../data.svelte';
  import { targetVault } from '../sync.svelte';
  import { t } from '../i18n.svelte';
  import { CHARSETS, keyLabel } from '../keys';
  import { allSchemes, schemeName } from '../look.svelte';
  import { groupActions, hostActions, identityActions, importKeyFile, keyActions, schemeActions, takeKeys } from '../quick.svelte';
  import { settings, toast } from '../state.svelte';
  import type { Fields, Group, GroupInput, MoshPredict, Reconnect } from '../types';
  import ActionSelect from '../ui/ActionSelect.svelte';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';
  import InheritField from '../ui/InheritField.svelte';
  import TextField from '../ui/TextField.svelte';

  let {
    group,
    startParent,
    onclose,
    onsaved,
    ondelete,
  }: { group: Group | null; startParent: string | null; onclose: () => void; onsaved: (id: string) => void; ondelete: (group: Group) => void } = $props();

  const COLORS = ['', '#FF5D6C', '#F59E0B', '#22C3A6', '#5B9DFF', '#8B5CF6'];
  const NONE = 'none';
  /** Auswahlfelder kennen drei Zustände: geerbt (leer), ausdrücklich nichts, oder ein bestimmter Eintrag. */
  const tri = (value: string | undefined) => (value === undefined ? '' : value === '' ? NONE : value);
  const untri = (value: string) => (value === NONE ? '' : value);
  /** Schalter kennen ebenfalls drei Zustände: geerbt (leer), ein oder aus. */
  const flag = (value: boolean | undefined) => (value === undefined ? '' : value ? 'on' : 'off');
  const onOff = (value: boolean) => (value ? t('edit.on') : t('edit.off'));

  // Der Editor wird je Gruppe neu erzeugt ({#key} in HostsPage); die Startwerte werden bewusst nur einmal gelesen.
  const start = (() => ({ group, parent: group ? group.parent : startParent }))();

  let name = $state(start.group?.name ?? '');
  let parent = $state(start.parent ?? '');
  let color = $state(start.group?.color ?? '');
  let user = $state(start.group?.defs.user ?? '');
  let port = $state(start.group?.defs.port?.toString() ?? '');
  let jump = $state(tri(start.group?.defs.jump));
  let identity = $state(tri(start.group?.defs.identity));
  let key = $state(tri(start.group?.defs.key));
  let startcmd = $state(start.group?.defs.startcmd ?? '');
  let env = $state(start.group?.defs.env ?? '');
  let agent = $state(flag(start.group?.defs.agent));
  let agentForward = $state(flag(start.group?.defs.agentForward));
  let proxy = $state(tri(start.group?.defs.proxy));
  let keepalive = $state(start.group?.defs.keepalive?.toString() ?? '');
  let timeout = $state(start.group?.defs.timeout?.toString() ?? '');
  let term = $state(start.group?.defs.term ?? '');
  let charset = $state(start.group?.defs.charset ?? '');
  let proxyPassword = $state('');
  let removeProxyPassword = $state(false);
  let legacy = $state(flag(start.group?.defs.legacy));
  let mosh = $state(flag(start.group?.defs.mosh));
  let moshPredict = $state<string>(start.group?.defs.moshPredict ?? '');
  let moshPort = $state(start.group?.defs.moshPort ?? '');
  let moshServer = $state(start.group?.defs.moshServer ?? '');
  let keyFile = $state(start.group?.defs.keyFile ?? '');
  let reconnect = $state<string>(start.group?.defs.reconnect ?? '');
  let scheme = $state(start.group?.defs.scheme ?? '');
  let busy = $state(false);
  let error = $state('');

  // Eine Gruppe kann nicht in sich selbst oder eine ihrer Untergruppen wandern; diese Ziele werden gar nicht angeboten.
  const blocked = start.group ? descendants(start.group.id) : [];
  // Der Tresor der Gruppe: wo sie liegt, sonst der zum Anlegen gewählte, sonst der ihrer Elterngruppe.
  const fixed = start.group ? (start.group.vault ?? personalVault()?.id) : targetVault();
  const home = $derived(fixed ?? groupById(parent || null)?.vault);
  const parents = $derived(vault.groups.filter((g) => !blocked.includes(g.id) && (!fixed || sameVault(fixed, g))));
  // Was von weiter oben kommt, falls diese Gruppe selbst nichts vorgibt.
  const above = $derived(inherited(parent || null));
  const moshOn = $derived(mosh ? mosh === 'on' : (above.mosh?.value ?? false));
  const predictLabel = (p: MoshPredict) => t(`edit.mosh.predict.${p}`);
  const reconnectLabel = (r: Reconnect) => (r === 'auto' ? t('edit.reconnect.auto') : t('edit.reconnect.notice'));
  // Was gilt, wenn Benutzer und Schlüssel hier leer bleiben: die Vorgaben von weiter oben und die hier gewählte Identität.
  const auth = $derived(authFor(parent || null, identity ? { identity: untri(identity) } : {}));
  const origin = (from: From<unknown>) => (from.identity ? { source: from.identity.name, from: t('auth.from.identity', { name: from.identity.name }) } : { source: from.group?.name ?? null });
  const aboveIdentity = $derived(above.identity && { value: identityById(above.identity.value)?.name ?? t('detail.identity.none'), source: above.identity.source.name });
  const identityOptions = $derived([
    ...(above.identity?.value ? [{ value: NONE, label: t('detail.identity.none') }] : []),
    ...vault.identities.filter((i) => reachable(home, i)).map((i) => ({ value: i.id, label: `${i.name} · ${i.user}` })),
  ]);
  const keyOptions = $derived([...(auth.key ? [{ value: NONE, label: t('ident.key.none') }] : []), ...vault.keys.filter((k) => reachable(home, k)).map((k) => ({ value: k.id, label: `${k.name} · ${keyLabel(k)}` }))]);
  const aboveJump = $derived(above.jump && { value: above.jump.value ? (hostById(above.jump.value)?.name ?? '?') : t('detail.none'), source: above.jump.source.name });
  const jumpOptions = $derived([...(above.jump?.value ? [{ value: NONE, label: t('detail.none') }] : []), ...sshHosts().filter((h) => reachable(home, h)).map((h) => ({ value: h.id, label: h.name }))]);

  async function browseKey() {
    const path = await pickKeyFile();
    if (path) keyFile = path;
  }

  /** Ein Schlüssel aus dem Tresor ersetzt die Schlüsseldatei: Das Feld für die Datei wird dabei geleert. */
  function useVaultKey(id: string) {
    key = id;
    keyFile = '';
  }

  // Ein Schlüssel, der ins Fenster gezogen wird, während dieser Editor offen ist, ist gleich ausgewählt.
  onMount(() => takeKeys((id) => (key = id)));

  async function save(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    const defs: Fields = {};
    if (user.trim()) defs.user = user.trim();
    if (port.trim()) {
      const n = Number(port);
      if (!Number.isInteger(n) || n < 1 || n > 65535) return void (error = t('err.invalid.port_invalid'));
      defs.port = n;
    }
    if (jump) defs.jump = untri(jump);
    if (identity) defs.identity = untri(identity);
    if (key) defs.key = untri(key);
    if (startcmd.trim()) defs.startcmd = startcmd.trim();
    if (env.trim()) defs.env = env.trim();
    if (agent) defs.agent = agent === 'on';
    if (agentForward) defs.agentForward = agentForward === 'on';
    // Beim Proxy heißt „Keiner“ ausdrücklich keiner; ein eingetippter Wert wird gespeichert, wie er ist.
    if (proxy) defs.proxy = untri(proxy).trim();
    for (const [text, set] of [
      [keepalive, (n: number) => (defs.keepalive = n)],
      [timeout, (n: number) => (defs.timeout = n)],
    ] as const) {
      if (!text.trim()) continue;
      const n = Number(text);
      if (!Number.isInteger(n) || n < 0) return void (error = t('err.invalid.number_invalid'));
      set(n);
    }
    if (term.trim()) defs.term = term.trim();
    if (charset) defs.charset = charset;
    if (legacy) defs.legacy = legacy === 'on';
    if (mosh) defs.mosh = mosh === 'on';
    if (moshPredict) defs.moshPredict = moshPredict as MoshPredict;
    if (moshPort.trim()) {
      if (!MOSH_PORT.test(moshPort.trim())) return void (error = t('err.invalid.mosh_port_invalid'));
      defs.moshPort = moshPort.trim();
    }
    if (moshServer.trim()) defs.moshServer = moshServer.trim();
    if (keyFile.trim()) defs.keyFile = keyFile.trim();
    if (reconnect) defs.reconnect = reconnect as Reconnect;
    if (scheme) defs.scheme = scheme;

    const input: GroupInput = { id: start.group?.id, name, parent: parent || null, color: color || null, defs };
    if (!start.group) input.vault = targetVault();
    if (proxyPassword) input.proxyPassword = proxyPassword;
    else if (removeProxyPassword) input.proxyPassword = null;
    busy = true;
    try {
      const changed = await groupSave(input);
      applySnapshot(changed.data);
      toast(t('common.saved'), 'ok');
      onsaved(changed.id!);
    } catch (e) {
      error = errorText(e);
    } finally {
      proxyPassword = '';
      busy = false;
    }
  }
</script>

<form class="editor isl" onsubmit={save}>
  <header class="ed-h">
    <span class="os lg" style="--c:{color || 'var(--accent)'}"><Icon name="folder" size={22} /></span>
    <div style="min-width:0">
      <div class="d-name">{name || t('edit.title.group.new')}</div>
      <div class="d-sub">{start.group ? t('edit.title.group.edit') : t('edit.title.group.new')}</div>
    </div>
    <span class="grow"></span>
    <Button variant="ghost" size="sm" icon="x" title={t('common.close')} onclick={onclose} />
  </header>

  <div class="ed-b">
    <div class="ed-sec">{t('edit.sec.general')}</div>
    <TextField label={t('edit.name')} bind:value={name} placeholder="Produktiv" autofocus={!start.group} />
    <label class="fld">
      <span class="fld-l">{t('edit.parent')}</span>
      <ActionSelect bind:value={parent} options={[{ value: '', label: t('edit.parent.none') }, ...parents.map((g) => ({ value: g.id, label: pathLabel(g.id) }))]} actions={groupActions(() => parent || null, (id) => (parent = id))} />
    </label>
    <div class="fld">
      <span class="fld-l">{t('edit.color')}</span>
      <div class="sws">
        {#each COLORS as c (c)}
          <button type="button" class:on={color.toUpperCase() === c} style="background:{c || 'var(--text-3)'}" title={c || t('edit.color.inherit')} aria-label={c || t('edit.color.inherit')} onclick={() => (color = c)}></button>
        {/each}
      </div>
    </div>

    <div class="ed-sec">{t('edit.sec.defaults')}</div>
    <span class="fld-h">{t('edit.defaults.hint')}</span>
    <InheritField label={t('detail.identity')} bind:value={identity} inherited={aboveIdentity} options={identityOptions} actions={identityActions((id) => (identity = id))} />
    <InheritField label={t('detail.user')} bind:value={user} inherited={auth.user && { value: auth.user.value, ...origin(auth.user) }} mono />
    <InheritField label={t('detail.port')} bind:value={port} inherited={above.port && { value: String(above.port.value), source: above.port.source.name }} mono />
    <InheritField label={t('detail.key')} bind:value={key} inherited={auth.key && { value: auth.key.value.name, ...origin(auth.key) }} options={keyOptions} actions={keyActions((id) => (key = id))} />
    <InheritField label={t('edit.keyfile')} bind:value={keyFile} inherited={above.keyFile && { value: above.keyFile.value, source: above.keyFile.source.name }} mono />
    <div style="display:flex;gap:8px;align-items:center">
      <Button size="sm" icon="folder" onclick={browseKey}>{t('edit.keyfile.browse')}</Button>
      <Button size="sm" icon="download" title={t('edit.keyfile.import.hint')} onclick={() => importKeyFile(keyFile, useVaultKey)}>{t('edit.keyfile.import')}</Button>
      <span class="fld-h">{t('edit.keyfile.hint')}</span>
    </div>
    <InheritField
      label={t('detail.agent')}
      bind:value={agent}
      inherited={above.agent ? { value: onOff(above.agent.value), source: above.agent.source.name } : undefined}
      options={[
        { value: 'on', label: t('edit.on') },
        { value: 'off', label: t('edit.off') },
      ]}
    />
    <span class="fld-h">{t('edit.agent.hint')}</span>
    <InheritField
      label={t('detail.agentForward')}
      bind:value={agentForward}
      inherited={above.agentForward ? { value: onOff(above.agentForward.value), source: above.agentForward.source.name } : undefined}
      options={[
        { value: 'on', label: t('edit.on') },
        { value: 'off', label: t('edit.off') },
      ]}
    />
    <span class="fld-h">{t('edit.agentForward.hint')}</span>
    <InheritField label={t('detail.jump')} bind:value={jump} inherited={aboveJump} options={jumpOptions} actions={hostActions((id) => (jump = id))} />
    <InheritField label={t('detail.proxy')} bind:value={proxy} inherited={above.proxy ? { value: above.proxy.value || t('detail.none'), source: above.proxy.source.name } : undefined} mono />
    <span class="fld-h">{t('edit.proxy.hint')}</span>
    {#if proxy && proxy !== NONE}
      {#if !removeProxyPassword}
        <TextField label={t('edit.proxyPassword')} bind:value={proxyPassword} hint={start.group?.hasProxyPassword ? t('edit.password.keep') : t('edit.proxyPassword.hint')} password />
      {/if}
      {#if start.group?.hasProxyPassword}
        <label class="check"><input type="checkbox" bind:checked={removeProxyPassword} />{t('edit.password.remove')}</label>
      {/if}
    {/if}
    <InheritField label={t('detail.startcmd')} bind:value={startcmd} inherited={above.startcmd && { value: above.startcmd.value, source: above.startcmd.source.name }} mono />
    <InheritField label={t('detail.env')} bind:value={env} inherited={above.env && { value: above.env.value, source: above.env.source.name }} mono />
    <span class="fld-h">{t('edit.env.hint')}</span>
    <InheritField
      label={t('detail.reconnect')}
      bind:value={reconnect}
      inherited={above.reconnect && { value: reconnectLabel(above.reconnect.value), source: above.reconnect.source.name }}
      options={[
        { value: 'notice', label: t('edit.reconnect.notice') },
        { value: 'auto', label: t('edit.reconnect.auto') },
      ]}
    />
    <InheritField
      label={t('detail.scheme')}
      bind:value={scheme}
      inherited={above.scheme ? { value: schemeName(above.scheme.value) ?? t('set.scheme.auto'), source: above.scheme.source.name } : { value: schemeName(settings.termScheme) ?? t('set.scheme.auto'), source: null }}
      options={allSchemes().map((s) => ({ value: s.id, label: s.name }))}
      actions={schemeActions((id) => (scheme = id))}
    />
    <div class="ed-sec">Mosh</div>
    <InheritField
      label={t('edit.mosh')}
      bind:value={mosh}
      inherited={above.mosh ? { value: onOff(above.mosh.value), source: above.mosh.source.name } : undefined}
      options={[
        { value: 'on', label: t('edit.on') },
        { value: 'off', label: t('edit.off') },
      ]}
    />
    <span class="fld-h">{t('edit.mosh.hint')}</span>
    {#if moshOn}
      <InheritField
        label={t('edit.mosh.predict')}
        bind:value={moshPredict}
        inherited={above.moshPredict ? { value: predictLabel(above.moshPredict.value), source: above.moshPredict.source.name } : undefined}
        options={(['adaptive', 'always', 'never'] as const).map((p) => ({ value: p, label: predictLabel(p) }))}
      />
      <InheritField label={t('edit.mosh.port')} bind:value={moshPort} inherited={above.moshPort ? { value: above.moshPort.value, source: above.moshPort.source.name } : undefined} mono />
      <InheritField label={t('edit.mosh.server')} bind:value={moshServer} inherited={above.moshServer ? { value: above.moshServer.value, source: above.moshServer.source.name } : undefined} mono />
    {/if}
    <div class="ed-sec">{t('edit.sec.advanced')}</div>
    <InheritField label={t('detail.keepalive')} bind:value={keepalive} inherited={above.keepalive ? { value: String(above.keepalive.value), source: above.keepalive.source.name } : undefined} mono />
    <span class="fld-h">{t('edit.keepalive.hint')}</span>
    <InheritField label={t('detail.timeout')} bind:value={timeout} inherited={above.timeout ? { value: String(above.timeout.value), source: above.timeout.source.name } : undefined} mono />
    <InheritField label={t('detail.term')} bind:value={term} inherited={above.term ? { value: above.term.value, source: above.term.source.name } : undefined} mono />
    <InheritField
      label={t('detail.charset')}
      bind:value={charset}
      inherited={above.charset ? { value: above.charset.value.toUpperCase(), source: above.charset.source.name } : undefined}
      options={CHARSETS.map((value) => ({ value, label: value.toUpperCase() }))}
    />
    <InheritField
      label={t('detail.legacy')}
      bind:value={legacy}
      inherited={above.legacy ? { value: onOff(above.legacy.value), source: above.legacy.source.name } : undefined}
      options={[
        { value: 'on', label: t('edit.on') },
        { value: 'off', label: t('edit.off') },
      ]}
    />
    <span class="fld-h">{t('edit.legacy.hint')}</span>
    {#if error}<p class="errline" role="alert">{error}</p>{/if}
  </div>

  <footer class="ed-f">
    {#if start.group}<Button variant="danger" icon="trash" onclick={() => ondelete(start.group!)}>{t('common.delete')}</Button>{/if}
    <span class="grow"></span>
    <Button onclick={onclose}>{t('common.cancel')}</Button>
    <button type="submit" class="btn primary" disabled={busy}>{t('common.save')}</button>
  </footer>
</form>
