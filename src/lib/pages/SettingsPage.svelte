<script lang="ts">
  import { onMount } from 'svelte';
  import { aboutOpen, appInfo, inApp, logReveal, pickBackground, pickFolder, pickProgram, vaultBackup, vaultChangePassword, vaultSetStartUnlock, type AppInfo } from '../backend';
  import { applyStatus, errorText, vault } from '../data.svelte';
  import ExportDialog from '../ExportDialog.svelte';
  import { openImport } from '../import.svelte';
  import { t } from '../i18n.svelte';
  import { defaultShell, local, shellById, shellName } from '../local.svelte';
  import ShellIcon from '../ui/ShellIcon.svelte';
  import { FONT_CHOICES, allSchemes, fontInstalled, fontStack, look, paneBackground, schemeById } from '../look.svelte';
  import { importSchemes as readSchemes } from '../quick.svelte';
  import { AUTO, type Scheme } from '../schemes';
  import { ACCENTS, settings, toast, ui } from '../state.svelte';
  import { sync } from '../sync.svelte';
  import { checkForUpdate, updates } from '../updates.svelte';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import Switch from '../ui/Switch.svelte';
  import TextField from '../ui/TextField.svelte';
  import WipeDialog from '../WipeDialog.svelte';

  let info = $state<AppInfo | null>(null);
  /** Schriften aus der Auswahl, die auf diesem Rechner installiert sind. */
  let fonts = $state<string[]>([]);
  onMount(() => {
    void appInfo().then((i) => (info = i));
    fonts = FONT_CHOICES.filter(fontInstalled);
  });

  const OTHER = '\u0000other';
  let otherFont = $state(false);
  const fontChoice = $derived(otherFont || (settings.termFont && !fonts.includes(settings.termFont)) ? OTHER : settings.termFont);
  const sample = $derived(schemeById(settings.termScheme));
  const custom = (scheme: Scheme) => settings.customSchemes.some((s) => s.id === scheme.id);

  function chooseFont(value: string) {
    otherFont = value === OTHER;
    if (!otherFont) settings.termFont = value;
  }

  /** Ein einzelnes eingelesenes Schema wird gleich zur Vorgabe; bei mehreren wählt man selbst. */
  async function importSchemes() {
    const found = await readSchemes();
    if (found.length === 1) settings.termScheme = found[0].id;
  }

  function removeScheme(scheme: Scheme) {
    settings.customSchemes = settings.customSchemes.filter((s) => s.id !== scheme.id);
    if (settings.termScheme === scheme.id) settings.termScheme = AUTO;
  }

  async function chooseBackground() {
    try {
      const url = await pickBackground();
      if (url) settings.termBackground = url;
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }

  const step = (value: number, by: number, min: number, max: number) => Math.round(Math.min(max, Math.max(min, value + by)) * 100) / 100;

  const isPreset = $derived(ACCENTS.some((c) => c.toLowerCase() === settings.accent.toLowerCase()));

  let changing = $state(false);
  let oldPassword = $state('');
  let newPassword = $state('');
  let repeatPassword = $state('');
  let passwordError = $state('');
  let logoutOthers = $state(false);
  let busy = $state(false);
  const canChange = $derived(!busy && oldPassword !== '' && [...newPassword].length >= 8 && newPassword === repeatPassword);

  function closeChange() {
    changing = false;
    oldPassword = newPassword = repeatPassword = passwordError = '';
  }

  async function changePassword(event: SubmitEvent) {
    event.preventDefault();
    if (!canChange) return;
    busy = true;
    passwordError = '';
    try {
      await vaultChangePassword(oldPassword, newPassword, sync.linked && logoutOthers);
      closeChange();
      toast(t('set.password.done'), 'ok');
    } catch (e) {
      passwordError = errorText(e);
    } finally {
      busy = false;
    }
  }

  let confirmStart = $state(false);
  let exporting = $state(false);
  let wiping = $state(false);

  /** Das Passwort beim Start wieder zu verlangen ist immer unbedenklich; es abzuschalten braucht eine Rückfrage. */
  async function setStartUnlock(enabled: boolean) {
    confirmStart = false;
    try {
      applyStatus(await vaultSetStartUnlock(enabled));
      toast(t(enabled ? 'set.startpw.off.done' : 'set.startpw.on.done'), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }

  async function backup() {
    try {
      const path = await vaultBackup(t('set.backup.file', { date: new Date().toISOString().slice(0, 10) }));
      if (path) toast(t('set.backup.done', { path }), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }
</script>

<section class="pg isl">
  <div class="crumbs"></div>
  <div class="ph"><h1>{t('set.title')}</h1></div>

  <div class="sec">{t('set.look')}</div>
  <div class="rows">
    <div class="row">
      <div class="rt"><b>{t('set.mode')}</b><span>{t('set.mode.sub')}</span></div>
      <Segmented
        label={t('set.mode')}
        bind:value={settings.mode}
        options={[
          { value: 'dark', label: t('set.mode.dark'), icon: 'moon' },
          { value: 'light', label: t('set.mode.light'), icon: 'sun' },
          { value: 'system', label: t('set.mode.system'), icon: 'monitor' },
        ]}
      />
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.accent')}</b><span>{t('set.accent.sub')}</span></div>
      <div class="sws">
        {#each ACCENTS as c (c)}
          <button class:on={settings.accent.toLowerCase() === c.toLowerCase()} style="background:{c}" title={c} aria-label={c} onclick={() => (settings.accent = c)}></button>
        {/each}
        <label class:on={!isPreset} title={t('set.accent.custom')}>
          <input type="color" aria-label={t('set.accent.custom')} value={settings.accent} oninput={(e) => (settings.accent = e.currentTarget.value)} />
        </label>
      </div>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.effect')}</b><span>{t('set.effect.sub')}{#if inApp && info && info.effect !== (settings.windowEffect === 'none' ? '' : settings.windowEffect)}&nbsp;<b class="note">{t('set.effect.restart')}</b>{/if}</span></div>
      <Segmented
        label={t('set.effect')}
        bind:value={settings.windowEffect}
        options={[
          { value: 'none', label: t('set.effect.none') },
          { value: 'mica', label: 'Mica' },
          { value: 'acrylic', label: t('set.effect.acrylic') },
        ]}
      />
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.lang')}</b><span>{t('set.lang.sub')}</span></div>
      <Segmented
        label={t('set.lang')}
        bind:value={settings.lang}
        options={[
          { value: 'de', label: 'Deutsch' },
          { value: 'en', label: 'English' },
        ]}
      />
    </div>
  </div>

  <div class="sec">{t('set.terminal')}</div>
  <div class="rows">
    <div class="row block">
      <div class="rt"><b>{t('set.scheme')}</b><span>{t('set.scheme.sub')}</span></div>
      <Button size="sm" icon="download" onclick={importSchemes}>{t('set.scheme.import')}</Button>
      {#snippet tile(id: string, name: string, scheme: Scheme, removable: boolean)}
        <div class="scheme" class:on={settings.termScheme === id}>
          <button type="button" style="background:{scheme.background};color:{scheme.foreground}" aria-pressed={settings.termScheme === id} onclick={() => (settings.termScheme = id)}>
            <span><i style="color:{scheme.ansi[2]}">root@web</i>:<i style="color:{scheme.ansi[4]}">~</i>$ ls</span>
            <span><i style="color:{scheme.ansi[12]}">app</i> <i style="color:{scheme.ansi[3]}">log</i> <i style="color:{scheme.ansi[1]}">err</i> <i style="color:{scheme.ansi[5]}">tmp</i> <i style="color:{scheme.ansi[6]}">ln</i></span>
          </button>
          <span class="sn">{name}</span>
          {#if removable}
            <button type="button" class="mini" title={t('set.scheme.remove')} aria-label={t('set.scheme.remove')} onclick={() => removeScheme(scheme)}><Icon name="trash" size={12} /></button>
          {/if}
        </div>
      {/snippet}
      <div class="schemes">
        {@render tile(AUTO, t('set.scheme.auto'), schemeById(AUTO), false)}
        {#each allSchemes() as scheme (scheme.id)}{@render tile(scheme.id, scheme.name, scheme, custom(scheme))}{/each}
      </div>
    </div>
    <div class="row block">
      <div class="rt"><b>{t('set.sample')}</b><span>{t('set.sample.sub')}</span></div>
      <div class="term-sample" class:image={!!look.background} style={look.background ? `--term-image:url("${look.background}");--term-blur:${settings.termBlur}px` : ''}>
        <pre
          class="cur-{settings.termCursor}"
          class:blink={settings.termCursorBlink}
          style="background:{paneBackground(sample)};color:{sample.foreground};font-family:{fontStack(settings.termFont)};font-size:{settings.termFontSize}px;line-height:{settings.termLineHeight * 1.2};--cur:{sample.cursor ??
            settings.accent};font-variant-ligatures:{settings.termLigatures ? 'normal' : 'none'}"><i style="color:{sample.ansi[2]}">deploy@web-01</i>:<i style="color:{sample.ansi[4]}">~/app</i>$ git status --short
 <i style="color:{sample.ansi[1]}">M</i> src/cart.php   <i style="color:{sample.ansi[8]}"># != === => -> &lt;= 0O1lI</i>
<i style="color:{sample.ansi[2]}">??</i> notes.md
<i style="color:{sample.ansi[2]}">deploy@web-01</i>:<i style="color:{sample.ansi[4]}">~/app</i>$ <b></b></pre>
      </div>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.font')}</b><span>{t('set.font.sub')}</span></div>
      {#if fontChoice === OTHER}
        <input class="dropdown" style="width:190px" type="text" aria-label={t('set.font.other')} placeholder={t('set.font.other')} spellcheck="false" bind:value={settings.termFont} />
      {/if}
      <select class="dropdown" aria-label={t('set.font')} value={fontChoice} onchange={(e) => chooseFont(e.currentTarget.value)}>
        <option value="">{t('set.font.bundled')}</option>
        {#each fonts as font (font)}<option value={font}>{font}</option>{/each}
        <option value={OTHER}>{t('set.font.other')}</option>
      </select>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.fontsize')}</b><span>{t('set.fontsize.sub')}</span></div>
      <div class="seg">
        <button type="button" aria-label="−" onclick={() => (settings.termFontSize = step(settings.termFontSize, -1, 8, 32))}>−</button>
        <button type="button" class="on" disabled style="opacity:1;min-width:52px;justify-content:center">{settings.termFontSize} px</button>
        <button type="button" aria-label="+" onclick={() => (settings.termFontSize = step(settings.termFontSize, 1, 8, 32))}>+</button>
      </div>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.lineheight')}</b><span>{t('set.lineheight.sub')}</span></div>
      <div class="seg">
        <button type="button" aria-label="−" onclick={() => (settings.termLineHeight = step(settings.termLineHeight, -0.05, 1, 1.6))}>−</button>
        <button type="button" class="on" disabled style="opacity:1;min-width:52px;justify-content:center">{settings.termLineHeight.toFixed(2)}</button>
        <button type="button" aria-label="+" onclick={() => (settings.termLineHeight = step(settings.termLineHeight, 0.05, 1, 1.6))}>+</button>
      </div>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.ligatures')}</b><span>{t('set.ligatures.sub')}</span></div>
      <Switch bind:checked={settings.termLigatures} label={t('set.ligatures')} />
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.cursor')}</b><span>{t('set.cursor.sub')}</span></div>
      <label class="check"><input type="checkbox" bind:checked={settings.termCursorBlink} />{t('set.cursor.blink')}</label>
      <Segmented
        label={t('set.cursor')}
        bind:value={settings.termCursor}
        options={[
          { value: 'block', label: t('set.cursor.block') },
          { value: 'bar', label: t('set.cursor.bar') },
          { value: 'underline', label: t('set.cursor.underline') },
        ]}
      />
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.opacity')}</b><span>{t('set.opacity.sub')}</span></div>
      <input class="range" type="range" min="30" max="100" step="5" aria-label={t('set.opacity')} bind:value={settings.termOpacity} />
      <span class="rm val">{settings.termOpacity} %</span>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.background')}</b><span>{t('set.background.sub')}</span></div>
      {#if settings.termBackground}
        <input class="range" type="range" min="0" max="24" step="2" aria-label={t('set.background.blur')} title={t('set.background.blur')} bind:value={settings.termBlur} />
        <span class="rm val">{t('set.background.blur')} {settings.termBlur} px</span>
        <Button size="sm" variant="danger" icon="trash" title={t('set.background.remove')} onclick={() => (settings.termBackground = null)} />
      {/if}
      <Button size="sm" icon="image" onclick={chooseBackground}>{t('set.background.choose')}</Button>
    </div>
  </div>

  <div class="sec">{t('set.sessions')}</div>
  <div class="rows">
    <div class="row">
      <div class="rt"><b>{t('set.reconnect')}</b><span>{t('set.reconnect.sub')}</span></div>
      <Segmented
        label={t('set.reconnect')}
        bind:value={settings.reconnect}
        options={[
          { value: 'notice', label: t('edit.reconnect.notice') },
          { value: 'auto', label: t('edit.reconnect.auto') },
        ]}
      />
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.suggest')}</b><span>{t('set.suggest.sub')}</span></div>
      <Switch bind:checked={settings.termSuggest} label={t('set.suggest')} />
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.localShell')}</b><span>{t('set.localShell.sub')}</span></div>
      <ShellIcon shell={defaultShell()} size="sm" />
      <select class="dropdown" style="width:auto;min-width:210px" aria-label={t('set.localShell')} bind:value={settings.localShell} disabled={!local.shells.length}>
        <option value="">{local.shells.length ? t('set.localShell.first', { name: shellName(local.shells[0]) }) : t('local.none')}</option>
        {#each local.shells as shell (shell.id)}<option value={shell.id}>{shellName(shell)}</option>{/each}
        {#if settings.localShell && !shellById(settings.localShell)}<option value={settings.localShell}>{settings.localShell}</option>{/if}
      </select>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.closePrompt')}</b><span>{t('set.closePrompt.sub')}</span></div>
      <Switch bind:checked={settings.closePrompt} label={t('set.closePrompt')} />
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.restore')}</b><span>{t('set.restore.sub')}</span></div>
      <Switch bind:checked={settings.restorePrompt} label={t('set.restore')} />
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.record')}</b><span>{t('set.record.sub')}</span></div>
      <Button size="sm" icon="folder" onclick={() => logReveal()}>{t('logs.folder')}</Button>
      <Switch bind:checked={settings.recordAuto} label={t('set.record')} />
    </div>
  </div>

  <div class="sec">{t('set.files')}</div>
  <div class="rows">
    <div class="row">
      <div class="rt"><b>{t('set.files.follow')}</b><span>{t('set.files.follow.sub')}</span></div>
      <Switch bind:checked={settings.fileFollow} label={t('set.files.follow')} />
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.files.hidden')}</b><span>{t('set.files.hidden.sub')}</span></div>
      <Switch bind:checked={settings.fileHidden} label={t('set.files.hidden')} />
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.files.editor')}</b><span>{t('set.files.editor.sub')}</span></div>
      <Switch bind:checked={settings.fileEditor} label={t('set.files.editor')} />
    </div>
    {#if !settings.fileEditor}
      <div class="row">
        <div class="rt"><b>{t('set.files.program')}</b><span class="mono">{settings.fileEditorPath || t('set.files.program.default')}</span></div>
        {#if settings.fileEditorPath}<Button size="sm" icon="undo" title={t('set.files.program.reset')} onclick={() => (settings.fileEditorPath = '')} />{/if}
        <Button size="sm" icon="folder" onclick={() => pickProgram().then((path) => path && (settings.fileEditorPath = path))}>{t('set.files.program.pick')}</Button>
      </div>
    {/if}
    <div class="row">
      <div class="rt"><b>{t('set.files.downloads')}</b><span class="mono">{settings.downloadDir || t('set.files.downloads.default')}</span></div>
      {#if settings.downloadDir}<Button size="sm" icon="undo" title={t('set.files.program.reset')} onclick={() => (settings.downloadDir = '')} />{/if}
      <Button size="sm" icon="folder" onclick={() => pickFolder().then((path) => path && (settings.downloadDir = path))}>{t('set.files.downloads.pick')}</Button>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.files.parallel')}</b><span>{t('set.files.parallel.sub')}</span></div>
      <select class="dropdown" aria-label={t('set.files.parallel')} bind:value={settings.transferParallel}>
        {#each [1, 2, 3, 4, 6, 8] as n (n)}<option value={n}>{n}</option>{/each}
      </select>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.files.conflict')}</b><span>{t('set.files.conflict.sub')}</span></div>
      <Segmented
        label={t('set.files.conflict')}
        bind:value={settings.transferConflict}
        options={[
          { value: 'ask', label: t('set.files.conflict.ask') },
          { value: 'overwrite', label: t('set.files.conflict.overwrite') },
          { value: 'skip', label: t('set.files.conflict.skip') },
          { value: 'rename', label: t('set.files.conflict.rename') },
        ]}
      />
    </div>
  </div>

  <div class="sec">{t('set.vault')}</div>
  <div class="rows">
    <div class="row">
      <div class="rt"><b>{t('set.startpw')}</b><span>{t('set.startpw.sub')}</span></div>
      <button
        type="button"
        class="swt"
        class:on={!vault.startUnlock}
        role="switch"
        aria-checked={!vault.startUnlock}
        aria-label={t('set.startpw')}
        onclick={() => (vault.startUnlock ? setStartUnlock(false) : (confirmStart = true))}
      ></button>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.autolock')}</b><span>{t('set.autolock.sub')}</span></div>
      <select class="dropdown" aria-label={t('set.autolock')} bind:value={settings.autoLockMinutes}>
        <option value={0}>{t('set.autolock.off')}</option>
        {#each [5, 15, 60] as n (n)}<option value={n}>{t('set.autolock.min', { n })}</option>{/each}
      </select>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.password')}</b><span>{t('set.password.sub')}</span></div>
      <Button size="sm" icon="key" onclick={() => (changing = true)}>{t('set.password.change')}</Button>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.backup')}</b><span>{t('set.backup.sub')}</span></div>
      <Button size="sm" icon="save" onclick={backup}>{t('set.backup.create')}</Button>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.wipe')}</b><span>{t('set.wipe.sub')}</span></div>
      <Button size="sm" variant="danger" icon="trash" onclick={() => (wiping = true)}>{t('set.wipe.open')}</Button>
    </div>
  </div>

  <div class="sec">{t('set.sync')}</div>
  <div class="rows">
    <div class="row">
      <div class="rt"><b>{t('set.sync')}</b><span>{sync.linked ? t('set.sync.sub.on', { username: sync.username, server: sync.server }) : t('set.sync.sub.off')}</span></div>
      <Button size="sm" icon="cloud" onclick={() => (ui.page = 'sync')}>{sync.linked ? t('set.sync.open') : t('sync.setup.create')}</Button>
    </div>
  </div>

  <div class="sec">{t('set.transfer')}</div>
  <div class="rows">
    <div class="row">
      <div class="rt"><b>{t('set.import')}</b><span>{t('set.import.sub')}</span></div>
      <Button size="sm" icon="down" onclick={() => openImport()}>{t('set.import.open')}</Button>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.export')}</b><span>{t('set.export.sub')}</span></div>
      <Button size="sm" icon="upload" onclick={() => (exporting = true)}>{t('set.export.open')}</Button>
    </div>
  </div>

  <!-- Hilfen für den Bau zeigt nur die Entwicklungsversion (und die Vorschau im Browser), nie die Fassung für Nutzer. -->
  {#if !inApp || info?.name.endsWith('Dev')}
    <div class="sec">{t('set.dev')}</div>
    <div class="rows">
      <div class="row">
        <div class="rt"><b>{t('set.kit')}</b><span>{t('set.kit.sub')}</span></div>
        <Button size="sm" icon="blocks" onclick={() => (ui.page = 'kit')}>{t('set.kit.open')}</Button>
      </div>
    </div>
  {/if}

  <div class="sec">{t('set.about')}</div>
  <div class="rows">
    <div class="row">
      <div class="rt"><b>{t('set.version')}</b><span>{info?.name ?? t('app.name')} {info?.version ?? __APP_VERSION__}{#if updates.available}&nbsp;· <b class="note">{t('upd.available', { version: updates.available.version })}</b>{/if}</span></div>
      {#if updates.enabled}
        {#if updates.available}
          <Button size="sm" variant="primary" icon="download" onclick={() => (updates.open = true)}>{t('upd.show')}</Button>
        {:else}
          <Button size="sm" icon="refresh" disabled={updates.checking} onclick={() => checkForUpdate(true)}>{updates.checking ? t('upd.checking') : t('upd.check')}</Button>
        {/if}
      {/if}
    </div>
    {#if updates.enabled}
      <div class="row">
        <div class="rt"><b>{t('set.updates')}</b><span>{t('set.updates.sub')}</span></div>
        <Switch bind:checked={settings.updateCheck} label={t('set.updates')} />
      </div>
    {/if}
    <div class="row">
      <div class="rt">
        <b>{t('set.data')}</b>
        <span class="mono selectable">{inApp ? (info?.dataDir ?? '…') : t('set.browser')}</span>
      </div>
    </div>
    <div class="row">
      <div class="rt"><b>{t('set.source')}</b><span>{t('set.source.sub')}</span></div>
      <Button size="sm" icon="external" onclick={() => aboutOpen().catch((e) => toast(errorText(e), 'err'))}>{t('set.source.open')}</Button>
    </div>
  </div>
</section>

{#if exporting}<ExportDialog onclose={() => (exporting = false)} />{/if}
<WipeDialog bind:open={wiping} />

<Dialog bind:open={confirmStart} title={t('set.startpw.off.title')}>
  <p>{t('set.startpw.off.text1')}</p>
  <div class="warnbox"><span>{t('set.startpw.off.text2')}</span></div>
  {#snippet actions()}
    <!-- Der hervorgehobene Knopf war hier „Abbrechen“; wer ausschalten wollte, griff leicht daneben. -->
    <Button onclick={() => (confirmStart = false)}>{t('common.cancel')}</Button>
    <Button variant="danger" onclick={() => setStartUnlock(true)}>{t('set.startpw.off.confirm')}</Button>
  {/snippet}
</Dialog>

{#if changing}
  <div class="ov" role="presentation" onclick={(e) => e.target === e.currentTarget && closeChange()}>
    <form class="dlg" aria-label={t('set.password')} onsubmit={changePassword}>
      <h2>{t('set.password')}</h2>
      <div class="dlg-b">
        <TextField label={t('set.password.old')} bind:value={oldPassword} password autofocus />
        <TextField label={t('set.password.new')} bind:value={newPassword} hint={t('lock.rule.length')} password />
        <TextField label={t('set.password.repeat')} bind:value={repeatPassword} password />
        <div class="warnbox"><span>{t('lock.warn')}</span></div>
        {#if sync.linked}
          <p class="fld-h">{t('set.password.sync')}</p>
          <label class="check"><input type="checkbox" bind:checked={logoutOthers} />{t('set.password.logout')}</label>
        {/if}
        {#if passwordError}<p class="errline" role="alert">{passwordError}</p>{/if}
      </div>
      <div class="dlg-a">
        <Button onclick={closeChange}>{t('common.cancel')}</Button>
        <button type="submit" class="btn primary" disabled={!canChange}>{t('set.password.change')}</button>
      </div>
    </form>
  </div>
{/if}
