<script lang="ts">
  import { onMount } from 'svelte';
  import { hostSave, pickKeyFile, serialPorts } from '../backend';
  import { applySnapshot, authFor, DEFAULT_FTP, MOSH_PORT, DEFAULT_PORT, DEFAULT_SERIAL, DEFAULT_TELNET_PORT, DEFAULT_USER, errorText, ftpPort, groupById, groupColor, hostById, identityById, inherited, pathLabel, personalVault, protocolOf, reachable, sameVault, sshHosts, vault, type From } from '../data.svelte';
  import { targetVault } from '../sync.svelte';
  import { t } from '../i18n.svelte';
  import { CHARSETS, keyLabel } from '../keys';
  import { allSchemes, schemeName } from '../look.svelte';
  import { OS_CHOICES } from '../os';
  import { groupActions, hostActions, identityActions, importKeyFile, keyActions, schemeActions, takeKeys } from '../quick.svelte';
  import { settings, toast } from '../state.svelte';
  import type { Fields, Host, HostInput, MoshPredict, Protocol, Reconnect, SerialPortInfo, SerialSettings, FtpSettings } from '../types';
  import ActionSelect from '../ui/ActionSelect.svelte';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';
  import InheritField from '../ui/InheritField.svelte';
  import OsIcon from '../ui/OsIcon.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import TextField from '../ui/TextField.svelte';

  let {
    host,
    startGroup,
    onclose,
    onsaved,
    ondelete,
  }: { host: Host | null; startGroup: string | null; onclose: () => void; onsaved: (id: string) => void; ondelete: (host: Host) => void } = $props();

  const COLORS = ['', '#FF5D6C', '#F59E0B', '#22C3A6', '#5B9DFF', '#8B5CF6'];
  const NONE = 'none';
  const OTHER = 'other';
  const BAUDS = [300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600];
  /** Auswahlfelder kennen drei Zustände: geerbt (leer), ausdrücklich nichts, oder ein bestimmter Eintrag. */
  const tri = (value: string | undefined) => (value === undefined ? '' : value === '' ? NONE : value);
  const untri = (value: string) => (value === NONE ? '' : value);
  /** Schalter kennen ebenfalls drei Zustände: geerbt (leer), ein oder aus. */
  const flag = (value: boolean | undefined) => (value === undefined ? '' : value ? 'on' : 'off');
  const onOff = (value: boolean) => (value ? t('edit.on') : t('edit.off'));

  // Der Editor wird je Host neu erzeugt ({#key} in HostsPage); die Startwerte werden bewusst nur einmal gelesen.
  const start = (() => ({ host, group: host ? host.group : startGroup, line: host?.serial ?? DEFAULT_SERIAL }))();

  let protocol = $state<Protocol>(start.host ? protocolOf(start.host) : 'ssh');
  let name = $state(start.host?.name ?? '');
  let address = $state(start.host?.address ?? '');
  let group = $state(start.group ?? '');
  /**
   * Der Tresor dieses Hosts steht fest, wenn es ihn schon gibt oder ein Tresor zum Anlegen gewählt ist. Sonst
   * folgt er der Gruppe. Davon hängt ab, in welche Gruppen er kann und worauf er verweisen darf.
   */
  const fixed = start.host ? (start.host.vault ?? personalVault()?.id) : targetVault();
  const home = $derived(fixed ?? groupById(group || null)?.vault);
  let color = $state(start.host?.color ?? '');
  let os = $state(start.host?.os ?? '');
  let user = $state(start.host?.own.user ?? '');
  let port = $state(start.host?.own.port?.toString() ?? '');
  let password = $state('');
  let removePassword = $state(false);
  const ftpStart: FtpSettings = start.host?.ftp ?? DEFAULT_FTP;
  let ftpSecurity = $state<FtpSettings['security']>(ftpStart.security);
  let ftpAnonymous = $state(ftpStart.anonymous);
  let ftpDir = $state(ftpStart.dir ?? '');
  /** Bei FTP gibt es nichts zu erben: Eine Identität ist gewählt oder nicht. */
  let ftpIdentity = $state(start.host && protocolOf(start.host) === 'ftp' ? (start.host.own.identity ?? '') : '');
  let jump = $state(tri(start.host?.own.jump));
  let identity = $state(tri(start.host?.own.identity));
  let key = $state(tri(start.host?.own.key));
  let startcmd = $state(start.host?.own.startcmd ?? '');
  let env = $state(start.host?.own.env ?? '');
  let agent = $state(flag(start.host?.own.agent));
  let agentForward = $state(flag(start.host?.own.agentForward));
  let proxy = $state(tri(start.host?.own.proxy));
  let keepalive = $state(start.host?.own.keepalive?.toString() ?? '');
  let timeout = $state(start.host?.own.timeout?.toString() ?? '');
  let term = $state(start.host?.own.term ?? '');
  let charset = $state(start.host?.own.charset ?? '');
  let proxyPassword = $state('');
  let removeProxyPassword = $state(false);
  let legacy = $state(flag(start.host?.own.legacy));
  let mosh = $state(flag(start.host?.own.mosh));
  let moshPredict = $state<string>(start.host?.own.moshPredict ?? '');
  let moshPort = $state(start.host?.own.moshPort ?? '');
  let moshServer = $state(start.host?.own.moshServer ?? '');
  let keyFile = $state(start.host?.own.keyFile ?? '');
  let reconnect = $state<string>(start.host?.own.reconnect ?? '');
  let scheme = $state(start.host?.own.scheme ?? '');
  let busy = $state(false);
  let error = $state('');

  // Serielle Leitung: der Port steht im Feld „Adresse“, dazu Geschwindigkeit und Rahmen.
  let ports = $state<SerialPortInfo[]>([]);
  let otherPort = $state(false);
  let baud = $state(String(start.line.baud));
  let otherBaud = $state(!BAUDS.includes(start.line.baud));
  let dataBits = $state(String(start.line.dataBits));
  let parity = $state<SerialSettings['parity']>(start.line.parity);
  let stopBits = $state(String(start.line.stopBits));
  let flow = $state<SerialSettings['flow']>(start.line.flow);

  const looksLikePort = (text: string) => /^(com\d+|\/dev\/\S+)$/i.test(text.trim());

  /** Sieht nach, welche Ports es gerade gibt. Ist noch keiner eingetragen, wird der erste gefundene gewählt. */
  async function findPorts() {
    try {
      ports = await serialPorts();
    } catch (e) {
      ports = [];
      toast(errorText(e), 'err');
    }
    if (protocol === 'serial' && !address && ports.length) address = ports[0].name;
  }

  /** Wechselt das Protokoll. Eine Adresse, die zum neuen nicht passt (IP statt COM-Port und umgekehrt), wird geleert. */
  function setProtocol(next: Protocol) {
    if (next === protocol) return;
    if ((next === 'serial') !== looksLikePort(address)) address = '';
    // Der Port eines Hosts meint sein Protokoll: 22 passt nicht zu Telnet.
    port = '';
    protocol = next;
    error = '';
    if (next === 'serial') void findPorts();
  }

  const portChoice = $derived(otherPort || (address && !ports.some((p) => p.name === address) && !start.host) ? OTHER : address);
  /** Der gespeicherte Port eines Hosts steht in der Auswahl, auch wenn sein Adapter gerade nicht steckt. */
  const portOptions = $derived([
    ...ports.map((p) => ({ value: p.name, label: p.label ? `${p.name} · ${p.label}` : p.name })),
    ...(start.host && address && protocolOf(start.host) === 'serial' && address === start.host.address && !ports.some((p) => p.name === address) ? [{ value: address, label: `${address} · ${t('edit.serial.absent')}` }] : []),
  ]);

  function choosePort(value: string) {
    otherPort = value === OTHER;
    if (!otherPort) address = value;
  }

  function chooseBaud(value: string) {
    otherBaud = value === OTHER;
    if (!otherBaud) baud = value;
  }

  // Wechselt die Gruppe, ändern sich die geerbten Vorgaben sofort mit.
  const defs = $derived(inherited(group || null));
  /** Gilt Mosh für diesen Host, eigener Schalter oder geerbt? Nur dann zeigen sich seine Felder. */
  const moshOn = $derived(mosh ? mosh === 'on' : (defs.mosh?.value ?? false));
  const predictLabel = (p: MoshPredict) => t(`edit.mosh.predict.${p}`);
  const reconnectLabel = (r: Reconnect) => (r === 'auto' ? t('edit.reconnect.auto') : t('edit.reconnect.notice'));
  const inheritedJump = $derived(defs.jump && { value: defs.jump.value ? (hostById(defs.jump.value)?.name ?? '?') : t('detail.none'), source: defs.jump.source.name });
  // Springen lässt sich nur über SSH.
  const jumpOptions = $derived([
    ...(defs.jump?.value ? [{ value: NONE, label: t('detail.none') }] : []),
    ...sshHosts()
      .filter((h) => reachable(home, h))
      .filter((h) => h.id !== start.host?.id)
      .map((h) => ({ value: h.id, label: h.name })),
  ]);
  // Was gilt, wenn Benutzer und Schlüssel hier leer bleiben: die Vorgaben der Gruppen und die hier gewählte Identität.
  const auth = $derived(authFor(group || null, identity ? { identity: untri(identity) } : {}));
  const origin = (from: From<unknown>) => (from.identity ? { source: from.identity.name, from: t('auth.from.identity', { name: from.identity.name }) } : { source: from.group?.name ?? null });
  const inheritedIdentity = $derived(defs.identity && { value: identityById(defs.identity.value)?.name ?? t('detail.identity.none'), source: defs.identity.source.name });
  const identityOptions = $derived([
    ...(defs.identity?.value ? [{ value: NONE, label: t('detail.identity.none') }] : []),
    ...vault.identities.filter((i) => reachable(home, i)).map((i) => ({ value: i.id, label: `${i.name} · ${i.user}` })),
  ]);
  const keyOptions = $derived([...(auth.key ? [{ value: NONE, label: t('ident.key.none') }] : []), ...vault.keys.filter((k) => reachable(home, k)).map((k) => ({ value: k.id, label: `${k.name} · ${keyLabel(k)}` }))]);
  const groupTint = $derived(groupById(group) ? groupColor(groupById(group)!) : null);

  async function browseKey() {
    const path = await pickKeyFile();
    if (path) keyFile = path;
  }

  /** Ein Schlüssel aus dem Tresor ersetzt die Schlüsseldatei: Das Feld für die Datei wird dabei geleert. */
  function useVaultKey(id: string) {
    key = id;
    keyFile = '';
  }

  onMount(() => {
    if (protocol === 'serial') void findPorts();
    // Ein Schlüssel, der ins Fenster gezogen wird, während dieser Editor offen ist, ist gleich ausgewählt.
    return takeKeys((id) => (key = id));
  });

  /** Liest eine ganze Zahl aus einem Feld; null, wenn sie fehlt oder nicht im Bereich liegt. */
  const whole = (text: string, min: number, max: number) => {
    const n = Number(text.trim());
    return text.trim() && Number.isInteger(n) && n >= min && n <= max ? n : null;
  };

  async function save(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    const own: Fields = {};
    let serial: SerialSettings | undefined;
    if (protocol !== 'serial' && port.trim()) {
      const n = whole(port, 1, 65535);
      if (n === null) return void (error = t('err.invalid.port_invalid'));
      own.port = n;
    }
    const ftpOwn = protocol === 'ftp' && !ftpAnonymous && !ftpIdentity;
    if (protocol !== 'serial' && user.trim() && (protocol !== 'ftp' || ftpOwn)) own.user = user.trim();
    if (protocol === 'ftp' && ftpIdentity && !ftpAnonymous) own.identity = ftpIdentity;
    if (protocol === 'ssh') {
      if (jump) own.jump = untri(jump);
      if (identity) own.identity = untri(identity);
      if (key) own.key = untri(key);
      if (startcmd.trim()) own.startcmd = startcmd.trim();
      if (env.trim()) own.env = env.trim();
      if (agent) own.agent = agent === 'on';
      if (agentForward) own.agentForward = agentForward === 'on';
      // Beim Proxy heißt „Keiner“ ausdrücklich keiner; ein eingetippter Wert wird gespeichert, wie er ist.
      if (proxy) own.proxy = untri(proxy).trim();
      if (keepalive.trim()) {
        const n = whole(keepalive, 0, 65535);
        if (n === null) return void (error = t('err.invalid.number_invalid'));
        own.keepalive = n;
      }
      if (legacy) own.legacy = legacy === 'on';
      if (keyFile.trim()) own.keyFile = keyFile.trim();
      if (mosh) own.mosh = mosh === 'on';
      if (moshPredict) own.moshPredict = moshPredict as MoshPredict;
      if (moshPort.trim()) {
        if (!MOSH_PORT.test(moshPort.trim())) return void (error = t('err.invalid.mosh_port_invalid'));
        own.moshPort = moshPort.trim();
      }
      if (moshServer.trim()) own.moshServer = moshServer.trim();
    }
    if (protocol === 'ftp') {
      // Zeitlimit, Terminal-Typ, Zeichensatz und Farbschema gehören zu einem Terminal; ein FTP-Host hat keines.
    } else if (protocol !== 'serial') {
      if (timeout.trim()) {
        const n = whole(timeout, 0, 65535);
        if (n === null) return void (error = t('err.invalid.number_invalid'));
        own.timeout = n;
      }
      if (term.trim()) own.term = term.trim();
    } else {
      const speed = whole(baud, 50, 4_000_000);
      if (speed === null) return void (error = t('err.invalid.baud_invalid'));
      serial = { baud: speed, dataBits: Number(dataBits) as SerialSettings['dataBits'], parity, stopBits: Number(stopBits) as SerialSettings['stopBits'], flow };
    }
    if (protocol !== 'ftp') {
      if (charset) own.charset = charset;
      if (reconnect) own.reconnect = reconnect as Reconnect;
      if (scheme) own.scheme = scheme;
    }

    const input: HostInput = { id: start.host?.id, name, address, protocol, group: group || null, color: color || null, os: os || null, own };
    if (!start.host) input.vault = targetVault();
    if (serial) input.serial = serial;
    if (protocol === 'ftp') {
      // Die abbestellte Rückfrage gilt nur, solange der Host unverschlüsselt bleibt.
      const plainOk = ftpSecurity === 'none' && ftpStart.security === 'none' && ftpStart.plainOk;
      input.ftp = { security: ftpSecurity, anonymous: ftpAnonymous, ...(ftpDir.trim() ? { dir: ftpDir.trim() } : {}), ...(plainOk ? { plainOk: true } : {}) };
      if (!ftpOwn) input.password = null;
      else if (password) input.password = password;
      else if (removePassword) input.password = null;
    }
    if (protocol === 'ssh') {
      if (password) input.password = password;
      else if (removePassword) input.password = null;
      if (proxyPassword) input.proxyPassword = proxyPassword;
      else if (removeProxyPassword) input.proxyPassword = null;
    }

    busy = true;
    try {
      const changed = await hostSave(input);
      applySnapshot(changed.data);
      toast(t('common.saved'), 'ok');
      onsaved(changed.id!);
    } catch (e) {
      error = errorText(e);
    } finally {
      password = '';
      proxyPassword = '';
      busy = false;
    }
  }
</script>

<!-- Was bei jedem Protokoll gleich ist: Verhalten bei einem Abriss und das Farbschema des Terminals. -->
{#snippet lookFields()}
  <InheritField
    label={t('detail.reconnect')}
    bind:value={reconnect}
    inherited={defs.reconnect && { value: reconnectLabel(defs.reconnect.value), source: defs.reconnect.source.name }}
    options={[
      { value: 'notice', label: t('edit.reconnect.notice') },
      { value: 'auto', label: t('edit.reconnect.auto') },
    ]}
  />
  <InheritField
    label={t('detail.scheme')}
    bind:value={scheme}
    inherited={defs.scheme ? { value: schemeName(defs.scheme.value) ?? t('set.scheme.auto'), source: defs.scheme.source.name } : { value: schemeName(settings.termScheme) ?? t('set.scheme.auto'), source: null }}
    options={allSchemes().map((s) => ({ value: s.id, label: s.name }))}
    actions={schemeActions((id) => (scheme = id))}
  />
  <span class="fld-h">{t('edit.scheme.hint')}</span>
{/snippet}

{#snippet charsetField()}
  <InheritField
    label={t(protocol === 'serial' ? 'edit.serial.charset' : 'detail.charset')}
    bind:value={charset}
    inherited={defs.charset ? { value: defs.charset.value.toUpperCase(), source: defs.charset.source.name } : { value: 'UTF-8', source: null }}
    options={CHARSETS.map((value) => ({ value, label: value.toUpperCase() }))}
  />
{/snippet}

{#snippet timeoutAndTerm()}
  <InheritField label={t('detail.timeout')} bind:value={timeout} inherited={defs.timeout ? { value: String(defs.timeout.value), source: defs.timeout.source.name } : { value: '15', source: null }} mono />
  <InheritField label={t('detail.term')} bind:value={term} inherited={defs.term ? { value: defs.term.value, source: defs.term.source.name } : { value: 'xterm-256color', source: null }} mono />
{/snippet}

<form class="editor isl" onsubmit={save}>
  <header class="ed-h">
    <OsIcon os={os || null} {protocol} size="lg" />
    <div style="min-width:0">
      <div class="d-name">{name || t('edit.title.new')}</div>
      <div class="d-sub">{start.host ? t('edit.title.edit') : t('edit.title.new')}</div>
    </div>
    <span class="grow"></span>
    <Button variant="ghost" size="sm" icon="x" title={t('common.close')} onclick={onclose} />
  </header>

  <div class="ed-b">
    <div class="ed-sec">{t('edit.sec.general')}</div>
    <div class="fld">
      <span class="fld-l">{t('detail.protocol')}</span>
      <Segmented
        label={t('detail.protocol')}
        bind:value={() => protocol, setProtocol}
        options={[
          { value: 'ssh', label: 'SSH' },
          { value: 'telnet', label: 'Telnet' },
          { value: 'serial', label: t('proto.serial') },
          { value: 'ftp', label: 'FTP' },
        ]}
      />
      {#if protocol === 'telnet'}<span class="fld-h">{t('edit.telnet.hint')}</span>{/if}
      {#if protocol === 'ftp'}<span class="fld-h">{t('edit.ftp.hint')}</span>{/if}
    </div>
    <TextField label={t('edit.name')} bind:value={name} placeholder={protocol === 'serial' ? 'router-konsole' : protocol === 'telnet' ? 'switch-01' : protocol === 'ftp' ? 'webspace' : 'web-01'} autofocus={!start.host} />
    {#if protocol === 'serial'}
      <div class="fld">
        <span class="fld-l">{t('edit.serial.port')}</span>
        <span class="inh-row">
          <select class="dropdown" aria-label={t('edit.serial.port')} value={portChoice} onchange={(e) => choosePort(e.currentTarget.value)}>
            {#if !address && !otherPort}<option value="">{ports.length ? t('edit.serial.choose') : t('edit.serial.noports')}</option>{/if}
            {#each portOptions as option (option.value)}<option value={option.value}>{option.label}</option>{/each}
            <option value={OTHER}>{t('edit.serial.other')}</option>
          </select>
          <button type="button" class="mini" title={t('edit.serial.rescan')} aria-label={t('edit.serial.rescan')} onclick={findPorts}><Icon name="refresh" size={14} /></button>
        </span>
        {#if portChoice === OTHER}
          <input class="mono" type="text" placeholder="COM7" aria-label={t('edit.serial.port')} bind:value={address} spellcheck="false" autocomplete="off" style="margin-top:6px" />
        {/if}
        <span class="fld-h">{t('edit.serial.port.hint')}</span>
      </div>
    {:else}
      <TextField label={t('edit.address')} bind:value={address} placeholder={protocol === 'telnet' ? '192.168.1.250' : protocol === 'ftp' ? 'ftp.example.org' : '203.0.113.10'} hint={t('edit.address.hint')} mono />
    {/if}
    <label class="fld">
      <span class="fld-l">{t('edit.group')}</span>
      <ActionSelect bind:value={group} options={[{ value: '', label: t('detail.nogroup') }, ...vault.groups.filter((g) => !fixed || sameVault(home, g)).map((g) => ({ value: g.id, label: pathLabel(g.id) }))]} actions={groupActions(() => group || null, (id) => (group = id))} />
    </label>
    <label class="fld">
      <span class="fld-l">{t('edit.os')}</span>
      <select class="dropdown" bind:value={os}>
        <option value="">{t('edit.os.unknown')}</option>
        {#each OS_CHOICES as choice (choice.id)}<option value={choice.id}>{choice.name}</option>{/each}
      </select>
      <span class="fld-h">{t(protocol === 'ssh' ? 'edit.os.hint' : 'edit.os.hint.manual')}</span>
    </label>
    <div class="fld">
      <span class="fld-l">{t('edit.color')}</span>
      <div class="sws">
        {#each COLORS as c (c)}
          <button
            type="button"
            class:on={color.toUpperCase() === c}
            style="background:{c || groupTint || 'var(--text-3)'}"
            title={c || t('edit.color.inherit')}
            aria-label={c || t('edit.color.inherit')}
            onclick={() => (color = c)}
          ></button>
        {/each}
      </div>
      <span class="fld-h">{t('edit.color.hint')}</span>
    </div>

    {#if protocol === 'ssh'}
      <div class="ed-sec">{t('edit.sec.auth')}</div>
      <InheritField label={t('detail.identity')} bind:value={identity} inherited={inheritedIdentity || { value: t('detail.identity.none'), source: null }} options={identityOptions} actions={identityActions((id) => (identity = id))} />
      <InheritField label={t('detail.user')} bind:value={user} inherited={auth.user ? { value: auth.user.value, ...origin(auth.user) } : { value: DEFAULT_USER, source: null }} mono />
      <InheritField
        label={t('detail.port')}
        bind:value={port}
        inherited={defs.port ? { value: String(defs.port.value), source: defs.port.source.name } : { value: String(DEFAULT_PORT), source: null }}
        mono
      />
      <InheritField label={t('detail.key')} bind:value={key} inherited={auth.key ? { value: auth.key.value.name, ...origin(auth.key) } : { value: t('ident.key.none'), source: null }} options={keyOptions} actions={keyActions((id) => (key = id))} />
      <InheritField label={t('edit.keyfile')} bind:value={keyFile} inherited={defs.keyFile && { value: defs.keyFile.value, source: defs.keyFile.source.name }} mono />
      <div style="display:flex;gap:8px;align-items:center">
        <Button size="sm" icon="folder" onclick={browseKey}>{t('edit.keyfile.browse')}</Button>
        <Button size="sm" icon="download" title={t('edit.keyfile.import.hint')} onclick={() => importKeyFile(keyFile, useVaultKey)}>{t('edit.keyfile.import')}</Button>
      </div>
      <span class="fld-h">{t('edit.keyfile.hint')}</span>
      {#if !removePassword}
        <TextField label={t('detail.password')} bind:value={password} hint={start.host?.hasPassword ? t('edit.password.keep') : auth.identityPassword ? t('edit.password.identity') : t('edit.password.hint')} password />
      {/if}
      {#if start.host?.hasPassword}
        <label class="check"><input type="checkbox" bind:checked={removePassword} />{t('edit.password.remove')}</label>
      {/if}

      <InheritField
        label={t('detail.agent')}
        bind:value={agent}
        inherited={defs.agent ? { value: onOff(defs.agent.value), source: defs.agent.source.name } : { value: t('edit.off'), source: null }}
        options={[
          { value: 'on', label: t('edit.on') },
          { value: 'off', label: t('edit.off') },
        ]}
      />
      <span class="fld-h">{t('edit.agent.hint')}</span>
      <InheritField
        label={t('detail.agentForward')}
        bind:value={agentForward}
        inherited={defs.agentForward ? { value: onOff(defs.agentForward.value), source: defs.agentForward.source.name } : { value: t('edit.off'), source: null }}
        options={[
          { value: 'on', label: t('edit.on') },
          { value: 'off', label: t('edit.off') },
        ]}
      />
      <span class="fld-h">{t('edit.agentForward.hint')}</span>

      <div class="ed-sec">{t('edit.sec.route')}</div>
      <InheritField label={t('detail.jump')} bind:value={jump} inherited={inheritedJump || { value: t('detail.none'), source: null }} options={jumpOptions} actions={hostActions((id) => (jump = id))} />
      <InheritField label={t('detail.proxy')} bind:value={proxy} inherited={defs.proxy ? { value: defs.proxy.value || t('detail.none'), source: defs.proxy.source.name } : { value: t('detail.none'), source: null }} mono />
      <span class="fld-h">{t('edit.proxy.hint')}</span>
      {#if proxy && proxy !== NONE}
        {#if !removeProxyPassword}
          <TextField label={t('edit.proxyPassword')} bind:value={proxyPassword} hint={start.host?.hasProxyPassword ? t('edit.password.keep') : t('edit.proxyPassword.hint')} password />
        {/if}
        {#if start.host?.hasProxyPassword}
          <label class="check"><input type="checkbox" bind:checked={removeProxyPassword} />{t('edit.password.remove')}</label>
        {/if}
      {/if}

      <div class="ed-sec">Mosh</div>
      <InheritField
        label={t('edit.mosh')}
        bind:value={mosh}
        inherited={defs.mosh ? { value: onOff(defs.mosh.value), source: defs.mosh.source.name } : { value: t('edit.off'), source: null }}
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
          inherited={defs.moshPredict ? { value: predictLabel(defs.moshPredict.value), source: defs.moshPredict.source.name } : { value: predictLabel('adaptive'), source: null }}
          options={(['adaptive', 'always', 'never'] as const).map((p) => ({ value: p, label: predictLabel(p) }))}
        />
        <span class="fld-h">{t('edit.mosh.predict.hint')}</span>
        <InheritField label={t('edit.mosh.port')} bind:value={moshPort} inherited={defs.moshPort ? { value: defs.moshPort.value, source: defs.moshPort.source.name } : { value: '60000:61000', source: null }} mono />
        <span class="fld-h">{t('edit.mosh.port.hint')}</span>
        <InheritField label={t('edit.mosh.server')} bind:value={moshServer} inherited={defs.moshServer ? { value: defs.moshServer.value, source: defs.moshServer.source.name } : { value: 'mosh-server', source: null }} mono />
        <span class="fld-h">{t('edit.mosh.server.hint')}</span>
      {/if}

      <div class="ed-sec">{t('edit.sec.terminal')}</div>
      <InheritField label={t('detail.startcmd')} bind:value={startcmd} inherited={defs.startcmd && { value: defs.startcmd.value, source: defs.startcmd.source.name }} mono />
      <InheritField label={t('detail.env')} bind:value={env} inherited={defs.env && { value: defs.env.value, source: defs.env.source.name }} mono />
      <span class="fld-h">{t('edit.env.hint')}</span>
      {@render lookFields()}
      <div class="ed-sec">{t('edit.sec.advanced')}</div>
      <InheritField label={t('detail.keepalive')} bind:value={keepalive} inherited={defs.keepalive ? { value: String(defs.keepalive.value), source: defs.keepalive.source.name } : { value: '30', source: null }} mono />
      <span class="fld-h">{t('edit.keepalive.hint')}</span>
      {@render timeoutAndTerm()}
      {@render charsetField()}
      <InheritField
        label={t('detail.legacy')}
        bind:value={legacy}
        inherited={defs.legacy ? { value: onOff(defs.legacy.value), source: defs.legacy.source.name } : { value: t('edit.off'), source: null }}
        options={[
          { value: 'on', label: t('edit.on') },
          { value: 'off', label: t('edit.off') },
        ]}
      />
      <span class="fld-h">{t('edit.legacy.hint')}</span>
    {:else if protocol === 'ftp'}
      <div class="ed-sec">{t('edit.sec.connection')}</div>
      <label class="fld">
        <span class="fld-l">{t('ftp.security')}</span>
        <select class="dropdown" bind:value={ftpSecurity}>
          <option value="explicit">{t('ftp.security.explicit')}</option>
          <option value="implicit">{t('ftp.security.implicit')}</option>
          <option value="none">{t('ftp.security.none')}</option>
        </select>
        <span class="fld-h">{t(`ftp.security.${ftpSecurity}.hint`)}</span>
      </label>
      {#if ftpSecurity === 'none'}
        <div class="warnbox danger"><Icon name="unlock" size={16} /><span>{t('ftp.plain.warning')}</span></div>
      {/if}
      <TextField label={t('detail.port')} bind:value={port} placeholder={String(ftpPort({ security: ftpSecurity, anonymous: false }))} mono />

      <div class="ed-sec">{t('edit.sec.auth')}</div>
      <label class="check"><input type="checkbox" bind:checked={ftpAnonymous} />{t('ftp.anonymous')}</label>
      <span class="fld-h">{t('ftp.anonymous.hint')}</span>
      {#if !ftpAnonymous}
        <label class="fld">
          <span class="fld-l">{t('detail.identity')}</span>
          <select class="dropdown" bind:value={ftpIdentity}>
            <option value="">{t('detail.identity.none')}</option>
            {#each vault.identities.filter((i) => sameVault(home, i)) as i (i.id)}<option value={i.id}>{i.name}</option>{/each}
          </select>
          <span class="fld-h">{t('ftp.identity.hint')}</span>
        </label>
        {#if !ftpIdentity}
          <TextField label={t('detail.user')} bind:value={user} placeholder="web123" mono />
          {#if !removePassword}
            <TextField label={t('detail.password')} bind:value={password} hint={start.host?.hasPassword ? t('edit.password.keep') : t('edit.password.hint')} password />
          {/if}
          {#if start.host?.hasPassword}
            <label class="check"><input type="checkbox" bind:checked={removePassword} />{t('edit.password.remove')}</label>
          {/if}
        {/if}
      {/if}

      <div class="ed-sec">{t('edit.sec.advanced')}</div>
      <TextField label={t('ftp.dir')} bind:value={ftpDir} placeholder="/htdocs" hint={t('ftp.dir.hint')} mono />
    {:else if protocol === 'telnet'}
      <div class="ed-sec">{t('edit.sec.connection')}</div>
      <TextField label={t('detail.port')} bind:value={port} placeholder={String(DEFAULT_TELNET_PORT)} mono />
      <TextField label={t('detail.user')} bind:value={user} placeholder={t('edit.telnet.user.none')} hint={t('edit.telnet.user.hint')} mono />

      <div class="ed-sec">{t('edit.sec.terminal')}</div>
      {@render lookFields()}
      <div class="ed-sec">{t('edit.sec.advanced')}</div>
      {@render timeoutAndTerm()}
      {@render charsetField()}
    {:else}
      <div class="ed-sec">{t('edit.sec.line')}</div>
      <div class="fld-2">
        <label class="fld">
          <span class="fld-l">{t('serial.baud')}</span>
          <select class="dropdown" value={otherBaud ? OTHER : baud} onchange={(e) => chooseBaud(e.currentTarget.value)}>
            {#each BAUDS as rate (rate)}<option value={String(rate)}>{rate}</option>{/each}
            <option value={OTHER}>{t('serial.baud.other')}</option>
          </select>
        </label>
        <label class="fld">
          <span class="fld-l">{t('serial.dataBits')}</span>
          <select class="dropdown" bind:value={dataBits}>
            {#each ['8', '7', '6', '5'] as bits (bits)}<option value={bits}>{bits}</option>{/each}
          </select>
        </label>
      </div>
      {#if otherBaud}
        <TextField label={t('serial.baud.custom')} bind:value={baud} placeholder="250000" mono />
      {/if}
      <div class="fld-2">
        <label class="fld">
          <span class="fld-l">{t('serial.parity')}</span>
          <select class="dropdown" bind:value={parity}>
            <option value="none">{t('serial.parity.none')}</option>
            <option value="even">{t('serial.parity.even')}</option>
            <option value="odd">{t('serial.parity.odd')}</option>
          </select>
        </label>
        <label class="fld">
          <span class="fld-l">{t('serial.stopBits')}</span>
          <select class="dropdown" bind:value={stopBits}>
            <option value="1">1</option>
            <option value="2">2</option>
          </select>
        </label>
      </div>
      <label class="fld">
        <span class="fld-l">{t('serial.flow')}</span>
        <select class="dropdown" bind:value={flow}>
          <option value="none">{t('serial.flow.none')}</option>
          <option value="hardware">{t('serial.flow.hardware')}</option>
          <option value="software">{t('serial.flow.software')}</option>
        </select>
      </label>
      <span class="fld-h">{t('edit.serial.line.hint')}</span>

      <div class="ed-sec">{t('edit.sec.terminal')}</div>
      {@render lookFields()}
      {@render charsetField()}
    {/if}
    {#if error}<p class="errline" role="alert">{error}</p>{/if}
  </div>

  <footer class="ed-f">
    {#if start.host}<Button variant="danger" icon="trash" onclick={() => ondelete(start.host!)}>{t('common.delete')}</Button>{/if}
    <span class="grow"></span>
    <Button onclick={onclose}>{t('common.cancel')}</Button>
    <button type="submit" class="btn primary" disabled={busy}>{t('common.save')}</button>
  </footer>
</form>
