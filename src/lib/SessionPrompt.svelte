<script lang="ts">
  import { t } from './i18n.svelte';
  import type { Answer, Prompt } from './types';
  import Button from './ui/Button.svelte';
  import TextField from './ui/TextField.svelte';

  /**
   * Die Rückfrage einer Verbindung: Host-Schlüssel, Passwort, Passphrase oder Fragen des Servers.
   * `name` nennt, wohin verbunden wird; `onanswer` bekommt die Antwort. Terminals und die Seite „Dateien“ benutzen sie.
   */
  let { prompt, name, onanswer }: { prompt: Prompt | null; name: string; onanswer: (reply: Answer) => void } = $props();

  let secret = $state('');
  let save = $state(false);
  let values = $state<string[]>([]);
  let remember = $state(false);

  // Jede neue Rückfrage beginnt leer, auch die Wiederholung nach einem falschen Passwort.
  $effect(() => {
    void prompt;
    secret = '';
    // Das Kästchen gilt je Frage: Ein Haken für „Passwort speichern“ soll nicht ungefragt eine Schlüsseldatei übernehmen.
    save = false;
    remember = false;
    values = prompt?.type === 'interactive' ? prompt.prompts.map(() => '') : [];
  });

  function cancel() {
    if (!prompt) return;
    if (prompt.type === 'hostKey') onanswer({ kind: 'hostKey', accept: false });
    else if (prompt.type === 'certificate') onanswer({ kind: 'certificate', accept: false });
    else if (prompt.type === 'plain') onanswer({ kind: 'plain', accept: false });
    else if (prompt.type === 'secret') onanswer({ kind: 'secret' });
    else onanswer({ kind: 'interactive' });
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (prompt?.type === 'secret' && secret) onanswer({ kind: 'secret', value: secret, save });
    if (prompt?.type === 'interactive') onanswer({ kind: 'interactive', values });
    secret = '';
  }
</script>

<svelte:window onkeydown={(e) => prompt && e.key === 'Escape' && cancel()} />

{#if prompt}
  <div class="ov" role="presentation">
    {#if prompt.type === 'hostKey'}
      {@const address = prompt.port === 22 ? prompt.host : `${prompt.host}:${prompt.port}`}
      <div class="dlg" role="dialog" aria-modal="true" aria-label={t(prompt.changed ? 'prompt.hostkey.changed.title' : 'prompt.hostkey.title')}>
        <h2>{t(prompt.changed ? 'prompt.hostkey.changed.title' : 'prompt.hostkey.title')}</h2>
        <div class="dlg-b">
          {#if prompt.changed}
            <div class="warnbox danger"><span>{t('prompt.hostkey.changed.text', { host: address })}</span></div>
          {:else}
            <p>{t('prompt.hostkey.text', { host: address })}</p>
          {/if}
          <dl class="kv">
            <div>
              <dt>{t('prompt.hostkey.fingerprint')} · {prompt.algorithm}</dt>
              <dd><span class="mono selectable" style="word-break:break-all">{prompt.fingerprint}</span></dd>
            </div>
            {#if prompt.known.length}
              <div>
                <dt>{t('prompt.hostkey.before')}</dt>
                {#each prompt.known as print (print)}<dd><span class="mono selectable" style="word-break:break-all">{print}</span></dd>{/each}
              </div>
            {/if}
          </dl>
        </div>
        <div class="dlg-a">
          {#if prompt.changed}
            <!-- Hier ist Abbrechen die sichere und deshalb hervorgehobene Wahl. -->
            <Button variant="danger" onclick={() => onanswer({ kind: 'hostKey', accept: true })}>{t('prompt.hostkey.replace')}</Button>
            <Button variant="primary" onclick={cancel}>{t('common.cancel')}</Button>
          {:else}
            <Button onclick={cancel}>{t('common.cancel')}</Button>
            <Button variant="primary" onclick={() => onanswer({ kind: 'hostKey', accept: true })}>{t('prompt.hostkey.trust')}</Button>
          {/if}
        </div>
      </div>
    {:else if prompt.type === 'certificate'}
      {@const address = prompt.port === 21 || prompt.port === 990 ? prompt.host : `${prompt.host}:${prompt.port}`}
      <div class="dlg" role="dialog" aria-modal="true" aria-label={t(prompt.changed ? 'prompt.cert.changed.title' : 'prompt.cert.title')}>
        <h2>{t(prompt.changed ? 'prompt.cert.changed.title' : 'prompt.cert.title')}</h2>
        <div class="dlg-b">
          {#if prompt.changed}
            <div class="warnbox danger"><span>{t('prompt.cert.changed.text', { host: address })}</span></div>
          {:else}
            <p>{t('prompt.cert.text', { host: address })}</p>
          {/if}
          <dl class="kv">
            <div>
              <dt>{t('prompt.cert.fingerprint')}</dt>
              <dd><span class="mono selectable" style="word-break:break-all">{prompt.fingerprint}</span></dd>
            </div>
          </dl>
        </div>
        <div class="dlg-a">
          {#if prompt.changed}
            <!-- Hier ist Abbrechen die sichere und deshalb hervorgehobene Wahl. -->
            <Button variant="danger" onclick={() => onanswer({ kind: 'certificate', accept: true })}>{t('prompt.cert.replace')}</Button>
            <Button variant="primary" onclick={cancel}>{t('common.cancel')}</Button>
          {:else}
            <Button onclick={cancel}>{t('common.cancel')}</Button>
            <Button variant="primary" onclick={() => onanswer({ kind: 'certificate', accept: true })}>{t('prompt.cert.trust')}</Button>
          {/if}
        </div>
      </div>
    {:else if prompt.type === 'plain'}
      <div class="dlg" role="dialog" aria-modal="true" aria-label={t('prompt.plain.title')}>
        <h2>{t('prompt.plain.title')}</h2>
        <div class="dlg-b">
          <div class="warnbox danger"><span>{t('prompt.plain.text', { host: prompt.host })}</span></div>
          {#if prompt.offersTls}<p>{t('prompt.plain.offers')}</p>{/if}
          {#if prompt.canRemember}<label class="check"><input type="checkbox" bind:checked={remember} />{t('prompt.plain.remember')}</label>{/if}
        </div>
        <div class="dlg-a">
          <!-- Unverschlüsselt weiterzumachen ist nie die hervorgehobene Wahl. -->
          <Button variant="danger" onclick={() => onanswer({ kind: 'plain', accept: true, remember })}>{t('prompt.plain.go')}</Button>
          <span class="grow"></span>
          <Button onclick={cancel}>{t('common.cancel')}</Button>
          {#if prompt.offersTls}<Button variant="primary" onclick={() => onanswer({ kind: 'plain', accept: true, secure: true })}>{t('prompt.plain.secure')}</Button>{/if}
        </div>
      </div>
    {:else if prompt.type === 'secret'}
      {@const passphrase = prompt.kind === 'passphrase'}
      {@const title = passphrase ? t('prompt.passphrase.title') : t('prompt.password.title', { name: prompt.station ?? name })}
      <form class="dlg" aria-label={title} onsubmit={submit}>
        <h2>{title}</h2>
        <div class="dlg-b">
          {#if prompt.station}<p>{t('prompt.station', { station: prompt.station, name: name })}</p>{/if}
          {#if prompt.file}<p class="mono selectable" style="word-break:break-all">{prompt.file}</p>{/if}
          {#if prompt.attempt > 1}<p class="errline" role="alert">{t(passphrase ? 'prompt.passphrase.retry' : 'prompt.password.retry', { n: prompt.attempt })}</p>{/if}
          {#key prompt}
            <TextField label={passphrase ? t('prompt.passphrase.title') : t('detail.password')} bind:value={secret} password autofocus />
          {/key}
          {#if prompt.canSave}
            <label class="check"><input type="checkbox" bind:checked={save} />{t(passphrase ? 'prompt.passphrase.adopt' : 'prompt.password.save')}</label>
            {#if passphrase}<span class="fld-h">{t('prompt.passphrase.adopt.hint')}</span>{/if}
          {/if}
        </div>
        <div class="dlg-a">
          <Button onclick={cancel}>{t('common.cancel')}</Button>
          <button type="submit" class="btn primary" disabled={!secret}>{t('prompt.submit')}</button>
        </div>
      </form>
    {:else}
      <form class="dlg" aria-label={t('prompt.interactive.title')} onsubmit={submit}>
        <h2>{prompt.name || t('prompt.interactive.title')}</h2>
        <div class="dlg-b">
          {#if prompt.station}<p>{t('prompt.station', { station: prompt.station, name: name })}</p>{/if}
          {#if prompt.instructions}<p>{prompt.instructions}</p>{/if}
          {#each prompt.prompts as field, i (i)}
            <TextField label={field.text} bind:value={values[i]} password={!field.echo} autofocus={i === 0} />
          {/each}
        </div>
        <div class="dlg-a">
          <Button onclick={cancel}>{t('common.cancel')}</Button>
          <button type="submit" class="btn primary">{t('prompt.submit')}</button>
        </div>
      </form>
    {/if}
  </div>
{/if}
