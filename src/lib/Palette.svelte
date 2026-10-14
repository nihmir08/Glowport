<script lang="ts">
  import { DEFAULT_TELNET_PORT, addressOf, pathLabel, vault } from './data.svelte';
  import { ftpPlaceName, openPlaceInFiles } from './files.svelte';
  import { t } from './i18n.svelte';
  import { local, shellName } from './local.svelte';
  import { activeTab, openTab } from './sessions.svelte';
  import { firstLine } from './snippets';
  import { useSnippet } from './snippets.svelte';
  import { ui } from './state.svelte';
  import type { FtpPlace, LocalShell, Snippet, Target } from './types';
  import Icon from './ui/Icon.svelte';
  import OsIcon from './ui/OsIcon.svelte';
  import ShellIcon from './ui/ShellIcon.svelte';

  /**
   * Suche über alle Hosts und die Shells dieses PCs, dazu die Schnellverbindung mit `ssh user@host`,
   * `user@host:port`, `user@host -p port`, `telnet host [port]` oder `ftps://user@host` (öffnet den Dateimanager).
   * Ist ein Terminal vorn, findet sie auch Snippets und führt sie dort aus.
   */
  let query = $state('');
  let index = $state(0);
  let input = $state<HTMLInputElement>();

  $effect(() => input?.focus());

  interface Entry {
    key: string;
    label: string;
    detail: string;
    os: string | null;
    protocol?: string;
    /** Ein Eintrag verbindet zu einem Ziel oder führt ein Snippet im Terminal aus. */
    target?: Target;
    /** Ein FTP-Server aus der Schnellverbindung: Er öffnet sich im Dateimanager, wahlweise in einem Ordner. */
    place?: FtpPlace;
    path?: string;
    snippet?: Snippet;
    shell?: LocalShell;
  }

  const validPort = (port: number) => Number.isInteger(port) && port >= 1 && port <= 65535;

  /** Erkennt eine eingetippte Adresse. Geprüft wird sie beim Verbinden noch einmal im Kern. */
  function direct(text: string): Target | null {
    // Eine Adresse mit Schema (`ftp://…`) ist keine SSH-Adresse, auch wenn ein `@` darin steht.
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text.trim())) return null;
    const telnet = /^telnet\s+([^\s:@]+)(?:[\s:]+(\d+))?$/i.exec(text.trim());
    if (telnet) {
      const port = Number(telnet[2] ?? DEFAULT_TELNET_PORT);
      return validPort(port) ? { kind: 'telnet', host: telnet[1], port } : null;
    }
    // `mosh benutzer@host` meldet sich per SSH an und führt das Terminal danach über Mosh.
    const match = /^(?:(ssh|mosh)\s+)?(?:-p\s+(\d+)\s+)?([^@\s]+)@([^\s:]+)(?::(\d+))?(?:\s+-p\s+(\d+))?$/i.exec(text.trim());
    if (!match) return null;
    const port = Number(match[2] ?? match[5] ?? match[6] ?? 22);
    const mosh = match[1]?.toLowerCase() === 'mosh';
    return validPort(port) ? { kind: 'direct', user: match[3], host: match[4], port, ...(mosh ? { mosh } : {}) } : null;
  }

  /**
   * Erkennt `ftp://`, `ftps://` und `ftpes://`, mit Benutzer, Port und Ordner: `ftps://web1@ftp.example.org:2121/htdocs`.
   * `ftp` ist unverschlüsselt (davor warnt der Dateimanager), `ftps` verschlüsselt und auf Port 990 von Anfang an.
   * Ein Passwort in der Adresse wird nicht angenommen: Es stünde lesbar im Suchfeld.
   */
  function directFtp(text: string): { place: FtpPlace; path?: string } | null {
    const match = /^(ftp|ftps|ftpes):\/\/(?:([^@\/\s:]+)@)?([^\s:\/@]+)(?::(\d+))?(\/\S*)?$/i.exec(text.trim());
    if (!match) return null;
    const scheme = match[1].toLowerCase();
    const port = Number(match[4] ?? 21);
    if (!validPort(port)) return null;
    const security = scheme === 'ftp' ? 'none' : scheme === 'ftps' && port === 990 ? 'implicit' : 'explicit';
    return { place: { kind: 'ftp', host: match[3], port, user: match[2] ?? '', security }, path: match[5] && match[5] !== '/' ? match[5] : undefined };
  }

  /** Wörter, bei denen alle Shells erscheinen, auch wenn keine so heißt. */
  const LOCAL_WORDS = ['lokal', 'local', 'terminal', 'shell'];

  const entries = $derived.by((): Entry[] => {
    const needle = query.trim().toLowerCase();
    const found: Entry[] = [];
    const quick = direct(query);
    if (quick?.kind === 'direct') {
      found.push({ key: 'direct', label: `${quick.mosh ? 'mosh' : 'ssh'} ${quick.user}@${quick.host}${quick.port === 22 ? '' : ` -p ${quick.port}`}`, detail: t(quick.mosh ? 'palette.direct.mosh' : 'palette.direct'), os: null, target: quick });
    } else if (quick?.kind === 'telnet') {
      found.push({ key: 'direct', label: `telnet ${quick.host}${quick.port === DEFAULT_TELNET_PORT ? '' : ` ${quick.port}`}`, detail: t('palette.direct'), os: null, target: quick });
    }
    const files = directFtp(query);
    if (files) found.push({ key: 'direct', label: `${files.place.security === 'none' ? 'ftp' : 'ftps'}://${ftpPlaceName(files.place)}${files.path ?? ''}`, detail: t(files.place.security === 'none' ? 'palette.direct.ftp.open' : 'palette.direct.ftp'), os: null, place: files.place, path: files.path });
    // Ohne Tresor gibt es nur die Schnellverbindung und das lokale Terminal.
    const open = vault.state === 'open';
    // Snippets nur, wenn es ein Terminal gibt, in dem sie laufen können, und erst ab einem Suchwort.
    const snippets = open && needle && activeTab() ? vault.snippets.filter((s) => [s.name, s.package].some((text) => text.toLowerCase().includes(needle))).slice(0, 4) : [];
    // Shells erst ab einem Suchwort: Ohne stehen dort die Hosts.
    const every = needle.length >= 3 && LOCAL_WORDS.some((word) => word.startsWith(needle) || needle.startsWith(word));
    const shells = needle ? local.shells.filter((s) => every || [shellName(s), s.name, s.id, s.kind].some((text) => text.toLowerCase().includes(needle))).slice(0, every ? 6 : 3) : [];
    const room = 9 - snippets.length - shells.length;
    for (const host of open ? vault.hosts : []) {
      if (found.length >= room) break;
      if (needle && ![host.name, host.address, host.protocol, pathLabel(host.group)].some((text) => text.toLowerCase().includes(needle))) continue;
      found.push({ key: host.id, label: host.name, detail: addressOf(host), os: host.os, protocol: host.protocol, target: { kind: 'host', id: host.id } });
    }
    for (const shell of shells) found.push({ key: `shell:${shell.id}`, label: shellName(shell), detail: t('local.title'), os: null, shell, target: { kind: 'local', shell: shell.id } });
    for (const snippet of snippets) found.push({ key: snippet.id, label: snippet.name, detail: snippet.kind === 'macro' ? t('macro.label') : firstLine(snippet.command), os: null, snippet });
    return found;
  });

  $effect(() => {
    void entries;
    index = 0;
  });

  function choose(entry: Entry | undefined) {
    if (!entry) return;
    ui.palette = false;
    const tab = activeTab();
    if (entry.snippet && tab) useSnippet(entry.snippet, tab.focus, 'run');
    else if (entry.place) openPlaceInFiles(entry.place, entry.path);
    else if (entry.target) openTab(entry.target);
  }

  function keydown(event: KeyboardEvent) {
    if (event.key === 'Escape') ui.palette = false;
    else if (event.key === 'Enter') choose(entries[index]);
    else if (event.key === 'ArrowDown') index = Math.min(index + 1, entries.length - 1);
    else if (event.key === 'ArrowUp') index = Math.max(index - 1, 0);
    else return;
    event.preventDefault();
  }
</script>

<div class="ov top" role="presentation" onclick={(e) => e.target === e.currentTarget && (ui.palette = false)}>
  <div class="pal" role="dialog" aria-modal="true" aria-label={t('search.placeholder')}>
    <input bind:this={input} bind:value={query} placeholder={t('palette.placeholder')} aria-label={t('palette.placeholder')} spellcheck="false" autocomplete="off" onkeydown={keydown} />
    <div class="pl">
      {#each entries as entry, i (entry.key)}
        <button class="pi" class:on={i === index} onmouseenter={() => (index = i)} onclick={() => choose(entry)}>
          {#if entry.snippet}
            <span class="os sm" style="--c:var(--accent)"><Icon name={entry.snippet.kind === 'macro' ? 'rec' : 'snippet'} size={13} /></span>
          {:else if entry.shell}
            <ShellIcon shell={entry.shell} size="sm" />
          {:else if entry.key === 'direct'}
            <span class="os sm" style="--c:var(--accent)"><Icon name="play" size={12} /></span>
          {:else}
            <OsIcon os={entry.os} protocol={entry.protocol} size="sm" />
          {/if}
          <span class="pn">{entry.label}</span><small>{entry.detail}</small>
        </button>
      {:else}
        <div class="ps">{t('palette.none')}</div>
      {/each}
    </div>
  </div>
</div>
