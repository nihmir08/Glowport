<script lang="ts">
  import { onMount } from 'svelte';
  import { appInfo, syncConnect, syncLogin, syncProbe, syncRegister } from '../backend';
  import { applyStatus, errorText } from '../data.svelte';
  import { t } from '../i18n.svelte';
  import { toast } from '../state.svelte';
  import { applySync } from '../sync.svelte';
  import type { BackendError, SyncServerInfo } from '../types';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import TextField from '../ui/TextField.svelte';

  /**
   * `fresh`: Auf diesem Gerät gibt es noch keinen Tresor (erster Start). Dann bleibt nur das Anmelden an einem
   * bestehenden Konto; der Tresor entsteht daraus.
   */
  let { fresh = false, oncancel }: { fresh?: boolean; oncancel?: () => void } = $props();

  let mode = $state<'new' | 'existing'>('new');
  let server = $state('');
  let username = $state('');
  let code = $state('');
  let password = $state('');
  let device = $state('');
  /** Was mit den Einträgen dieses Geräts geschieht, wenn es sich mit einem bestehenden Konto verbindet. */
  let local = $state<'keep' | 'discard'>('keep');
  let askLocal = $state(false);

  let info = $state<SyncServerInfo | null>(null);
  let probing = $state(false);
  let busy = $state(false);
  let error = $state('');
  /** Was an der Adresse nicht stimmt. Steht direkt bei ihr, nicht am Ende des Formulars. */
  let serverError = $state('');

  // Der Name des Rechners ist ein brauchbarer erster Vorschlag.
  onMount(() => void appInfo().then((info) => info?.device && !device && (device = info.device)));

  const existing = $derived(fresh || mode === 'existing');
  const ready = $derived(!busy && server.trim() !== '' && /^[a-z0-9._-]{3,32}$/.test(username.trim()) && password !== '' && (existing || code.trim() !== ''));

  // Eine andere Adresse ist ein anderer Server: Was über den alten bekannt war, gilt nicht mehr.
  $effect(() => {
    void server;
    info = null;
    serverError = '';
  });

  async function probe(): Promise<SyncServerInfo | null> {
    if (info) return info;
    if (probing || !server.trim()) return null;
    probing = true;
    error = '';
    serverError = '';
    try {
      info = await syncProbe(server);
      return info;
    } catch (e) {
      serverError = errorText(e);
      return null;
    } finally {
      probing = false;
    }
  }

  /** Eingabetaste im Feld der Adresse: prüfen, solange der Rest des Formulars noch nicht ausgefüllt ist. */
  function serverKey(event: KeyboardEvent) {
    if (event.key !== 'Enter' || ready) return;
    event.preventDefault();
    void probe();
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!ready) return;
    busy = true;
    error = '';
    try {
      const found = await probe();
      if (!found) return;
      const account = { server: found.server, username: username.trim(), password, device: device.trim() };
      if (fresh) {
        applyStatus(await syncLogin(account));
      } else if (mode === 'new') {
        applySync(await syncRegister({ ...account, code: code.trim() }));
      } else {
        applySync(await syncConnect({ ...account, local: askLocal ? local : undefined }));
      }
      // Das Passwort bleibt keinen Augenblick länger in der Oberfläche als nötig.
      password = '';
      toast(t('sync.setup.done'), 'ok');
    } catch (e) {
      // Der Tresor dieses Geräts gehört nicht zu diesem Konto: erst entscheiden, was mit seinen Einträgen geschieht.
      const reason = (e as Partial<BackendError>)?.code;
      if (reason === 'other_account' && !askLocal) askLocal = true;
      // Beim Anlegen eines Kontos ist das Passwort des Tresors auf diesem Gerät gemeint, kein frei gewähltes.
      else if (reason === 'wrong_password' && !existing) error = t('sync.setup.password.wrong');
      else error = errorText(e);
    } finally {
      busy = false;
    }
  }
</script>

<form class="setup" onsubmit={submit}>
  {#if !fresh}
    <Segmented
      label={t('sync.setup.mode')}
      bind:value={mode}
      options={[
        { value: 'new', label: t('sync.setup.new') },
        { value: 'existing', label: t('sync.setup.existing') },
      ]}
    />
  {/if}

  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="setup-server" onkeydown={serverKey}>
    <TextField label={t('sync.setup.server')} bind:value={server} placeholder="sync.example.com" mono autofocus />
    <Button icon={info ? 'check' : 'refresh'} disabled={probing || !server.trim()} onclick={() => void probe()}>{probing ? t('sync.setup.probing') : t('sync.setup.probe')}</Button>
  </div>
  {#if serverError}<p class="errline" role="alert">{serverError}</p>{/if}
  {#if info}
    <div class="okline"><Icon name="check" size={14} />{t('sync.setup.found', { server: info.server })}</div>
    {#if info.fresh && !existing}<div class="infobox"><Icon name="badge" size={16} /><span>{t('sync.setup.first')}</span></div>{/if}
  {/if}

  <TextField label={t('sync.setup.username')} bind:value={username} hint={existing ? undefined : t('sync.setup.username.hint')} />
  {#if !existing}
    <TextField label={info?.fresh ? t('sync.setup.code.first') : t('sync.setup.code')} bind:value={code} placeholder="XXXX-XXXX-XXXX" mono />
  {/if}
  <TextField label={existing ? t('lock.password') : t('sync.setup.password.own')} bind:value={password} hint={existing ? t('sync.setup.password.account') : t('sync.setup.password.confirm')} password />
  <TextField label={t('sync.setup.device')} bind:value={device} placeholder={t('sync.setup.device.example')} hint={t('sync.setup.device.hint')} />

  {#if askLocal}
    <div class="warnbox"><Icon name="alert" size={16} /><span>{t('sync.setup.other')}</span></div>
    <label class="check"><input type="radio" bind:group={local} value="keep" />{t('sync.setup.other.keep')}</label>
    <label class="check"><input type="radio" bind:group={local} value="discard" />{t('sync.setup.other.discard')}</label>
  {/if}

  {#if error}<p class="errline" role="alert">{error}</p>{/if}
  <div class="setup-a">
    {#if oncancel}<Button onclick={oncancel}>{t('common.cancel')}</Button>{/if}
    <button type="submit" class="btn primary" disabled={!ready}>
      {#if busy}{t('sync.setup.busy')}{:else if fresh}{t('sync.setup.login')}{:else if mode === 'new'}{t('sync.setup.create')}{:else}{t('sync.setup.connect')}{/if}
    </button>
  </div>
</form>
