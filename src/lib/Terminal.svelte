<script lang="ts">
  import { onMount } from 'svelte';
  import { FitAddon } from '@xterm/addon-fit';
  import { SearchAddon } from '@xterm/addon-search';
  import { SerializeAddon } from '@xterm/addon-serialize';
  import { WebglAddon } from '@xterm/addon-webgl';
  import { Terminal } from '@xterm/xterm';
  import '@xterm/xterm/css/xterm.css';
  import { clipboardRead, clipboardWrite, sessionResize } from './backend';
  import { t } from './i18n.svelte';
  import { vault } from './data.svelte';
  import { fontStack, schemeFor, xtermTheme } from './look.svelte';
  import { answerQuery, connect, input, registerTerminal, type Pane } from './sessions.svelte';
  import { hotkeyOf } from './snippets';
  import { snippetForHotkey, useSnippet } from './snippets.svelte';
  import { DEFAULT_FONT_SIZE, settings, ui } from './state.svelte';
  import { suggest, type Suggestion } from './suggest';
  import Icon from './ui/Icon.svelte';

  /** `visible`: Der Tab des Bereichs ist vorn. `focused`: Der Bereich hat in seinem Tab die Tastatur. */
  let { pane, visible, focused }: { pane: Pane; visible: boolean; focused: boolean } = $props();

  const MIN_FONT = 8;
  const MAX_FONT = 32;

  /**
   * Antworten des Terminals auf Anfragen des Programms darin: wo die Schreibmarke steht, was für ein Terminal es ist,
   * ob das Fenster die Tastatur hat. Windows stellt die erste Frage beim Start jedes lokalen Terminals und wartet
   * auf die Antwort. (Umschalt+F3 sieht aus wie eine Antwort zur Schreibmarke und zählt deshalb mit.)
   */
  const REPLIES = [/^\x1b\[[?>]?[\d;]*[cRn]$/, /^\x1b\[[IO]$/, /^\x1b[\]P]/];
  const isReply = (text: string) => REPLIES.some((reply) => reply.test(text));

  let host = $state<HTMLDivElement>();
  let wrap = $state<HTMLDivElement>();
  let terminal: Terminal | undefined;
  let fit: FitAddon | undefined;
  let search: SearchAddon | undefined;
  let finding = $state(false);
  let query = $state('');
  let findInput = $state<HTMLInputElement>();

  const scheme = $derived(schemeFor(pane.target));

  /** Zusatz, der Zeichenfolgen wie `!=` und `=>` als ein Zeichen der Schrift zeichnen lässt. Geladen wird er erst bei Bedarf. */
  let ligatures: { dispose(): void } | undefined;
  async function setLigatures(on: boolean) {
    if (!on) {
      ligatures?.dispose();
      ligatures = undefined;
      return;
    }
    if (ligatures || !terminal) return;
    try {
      const { LigaturesAddon } = await import('@xterm/addon-ligatures');
      // Inzwischen kann das Terminal geschlossen oder der Schalter wieder aus sein.
      if (!terminal || ligatures || !settings.termLigatures) return;
      const addon = new LigaturesAddon();
      terminal.loadAddon(addon);
      ligatures = addon;
    } catch (e) {
      console.warn('Ligaturen lassen sich nicht einschalten', e);
    }
  }

  function setFont(size: number) {
    settings.termFontSize = Math.min(MAX_FONT, Math.max(MIN_FONT, size));
  }

  /**
   * Tasten, die Glowport selbst behandelt. `false` heißt: Das Terminal schickt die Taste nicht an den Server.
   * Strg+Buchstabe bleibt der Shell, außer Strg+C mit Markierung (kopieren) und Strg+V (einfügen).
   */
  function keys(event: KeyboardEvent): boolean {
    if (event.type !== 'keydown') return true;
    // Ein Tastenkürzel, das einem Snippet gehört, behandelt das Fenster; die Shell bekommt die Taste nicht.
    const hotkey = hotkeyOf(event);
    if (hotkey && snippetForHotkey(hotkey)) return false;
    if (hints.length && !event.ctrlKey && !event.altKey && !event.metaKey && hintKey(event)) return false;
    if (!event.ctrlKey) return true;
    const key = event.key.toLowerCase();
    // Strg+Alt+Pfeil wechselt den Bereich; das erledigt die Oberfläche.
    if (event.altKey) return !key.startsWith('arrow');
    // Tab-Wechsel (Strg+Tab) und Tab schließen (Strg+Umschalt+W) gehören der Oberfläche.
    if (key === 'tab') return false;
    if (event.shiftKey) {
      // Teilen (D rechts, E unten), Tab schließen, Multi-Exec, lokales Terminal (T).
      // Strg+Umschalt+K öffnet im Terminal die Suche; Strg+K allein gehört der Sitzung (nano: Zeile ausschneiden).
      if (key === 'w' || key === 'd' || key === 'e' || key === 'm' || key === 't' || key === 'k') return false;
      if (key === 'f') return (openFind(), false);
      if (key === 'c') return (copy(), false);
      if (key === 'v') return (paste(), false);
      return true;
    }
    if (key === 'c' && terminal?.hasSelection()) return (copy(), false);
    if (key === 'v') return (paste(), false);
    if (key === '+' || key === '=') return (setFont(settings.termFontSize + 1), false);
    if (key === '-') return (setFont(settings.termFontSize - 1), false);
    if (key === '0') return (setFont(DEFAULT_FONT_SIZE), false);
    return true;
  }

  function copy() {
    const text = terminal?.getSelection();
    if (text) void clipboardWrite(text).then(() => terminal?.clearSelection());
  }

  function paste() {
    void clipboardRead()
      .then((text) => text && terminal?.paste(text))
      .catch(() => {});
  }

  /**
   * Rechtsklick wie bei Termius: nie ein Kontextmenü. Mit Markierung wird kopiert, ohne Markierung eingefügt.
   * Hat das Programm im Terminal die Maus angefordert (htop, mc, tmux), gehört der Rechtsklick ihm; Umschalt fügt trotzdem ein.
   */
  function rightClick(event: MouseEvent) {
    // Die Suchleiste ist ein gewöhnliches Eingabefeld: Ein Rechtsklick dort fügt nichts ins Terminal ein.
    if ((event.target as Element).closest('.findbar')) return;
    event.preventDefault();
    // xterm.js bereitet sonst sein Eingabefeld auf das Menü vor und füllt es mit der Markierung.
    event.stopPropagation();
    if (!terminal) return;
    if (terminal.hasSelection()) copy();
    else if (terminal.modes.mouseTrackingMode === 'none' || event.shiftKey) paste();
  }

  // ---------- Vorschläge beim Tippen ----------

  let hints = $state<Suggestion[]>([]);
  let hintIndex = $state(0);
  let hintStyle = $state('');
  /** Wo die Zeile begann, an der getippt wird: Zeile im Verlauf und Spalte hinter der Eingabeaufforderung. */
  let anchor: { row: number; column: number } | null = null;
  /** Mit Esc weggeklickt: bis zur nächsten Zeile kommen keine Vorschläge. */
  let dismissed = false;
  let hintTicket = 0;
  let hintTimer: ReturnType<typeof setTimeout> | undefined;

  function hideHints() {
    hintTicket += 1;
    if (hints.length) hints = [];
  }

  /**
   * Liest mit, was getippt wird, aber nur um zu wissen, wann eine neue Zeile beginnt. Was in der Zeile steht,
   * kommt später aus dem Terminal selbst: So stimmt es auch nach Tab, Pfeiltasten und dem Verlauf der Shell,
   * und wo nichts angezeigt wird (Passwort), gibt es auch nichts vorzuschlagen.
   */
  function track(text: string) {
    // Eingabetaste, Strg+C, Strg+D: Die Zeile ist zu Ende. Strg+L zeichnet neu, danach stimmt die Stelle nicht mehr.
    if (/[\r\n\x03\x04\x0c]/.test(text)) {
      anchor = null;
      dismissed = false;
      return hideHints();
    }
    const buffer = terminal?.buffer.active;
    if (!anchor && buffer) anchor = { row: buffer.baseY + buffer.cursorY, column: buffer.cursorX };
  }

  /** Die Zeile zwischen Eingabeaufforderung und Schreibmarke, oder null, wenn sie sich nicht sicher bestimmen lässt. */
  function typedLine(): string | null {
    const term = terminal;
    const buffer = term?.buffer.active;
    if (!term || !buffer || !anchor || buffer.type !== 'normal' || buffer.viewportY !== buffer.baseY) return null;
    const row = buffer.baseY + buffer.cursorY;
    if (row < anchor.row || row - anchor.row > 4 || (row === anchor.row && buffer.cursorX < anchor.column)) return null;
    let line = '';
    for (let r = anchor.row; r <= row; r++) {
      const cells = buffer.getLine(r);
      // Zwischen Anfang und Schreibmarke darf nur umbrochener Text liegen, keine Ausgabe eines Programms.
      if (!cells || (r > anchor.row && !cells.isWrapped)) return null;
      line += cells.translateToString(false, r === anchor.row ? anchor.column : 0, r === row ? buffer.cursorX : term.cols);
    }
    // Steht rechts der Schreibmarke noch etwas, wird mitten in der Zeile bearbeitet.
    if (buffer.getLine(row)?.translateToString(true, buffer.cursorX).trim()) return null;
    return line;
  }

  async function refreshHints() {
    const ticket = ++hintTicket;
    // Vorgeschlagen werden Befehle und Pfade eines Linux-Servers; die Pfade kommen über SSH. Anderswo passten sie nicht.
    const line = settings.termSuggest && pane.kind === 'ssh' && visible && focused && !pane.prompt && pane.phase === 'connected' ? typedLine() : null;
    // Ist die Zeile wieder leer (Strg+U, alles gelöscht), gilt ein früheres Esc nicht mehr.
    if (line === '') dismissed = false;
    if (dismissed || !line?.trim()) return void (hints.length && (hints = []));
    const found = await suggest({ line, place: pane.sessionId === null ? null : { kind: 'session', id: pane.sessionId }, cwd: pane.cwd, lang: settings.lang, snippets: vault.snippets });
    if (ticket !== hintTicket) return;
    // Inzwischen kann weitergetippt worden sein; dann kommt gleich die nächste Runde.
    if (typedLine() !== line) return;
    hints = found;
    hintIndex = 0;
    if (found.length) placeHints(found[0].replace);
  }

  /** Setzt die Liste unter den Anfang des Wortes, das ergänzt wird; weit unten im Terminal darüber. */
  function placeHints(replace: number) {
    const term = terminal;
    const screen = host?.querySelector<HTMLElement>('.xterm-screen');
    if (!term || !screen || !wrap) return;
    const buffer = term.buffer.active;
    const cell = { w: screen.clientWidth / term.cols, h: screen.clientHeight / term.rows };
    const origin = screen.getBoundingClientRect();
    const frame = wrap.getBoundingClientRect();
    const left = Math.max(0, Math.min(origin.left - frame.left + Math.max(0, buffer.cursorX - replace) * cell.w, frame.width - 330));
    const top = origin.top - frame.top + buffer.cursorY * cell.h;
    hintStyle = top + cell.h + 230 > frame.height ? `left:${left}px;bottom:${frame.height - top + 4}px` : `left:${left}px;top:${top + cell.h + 4}px`;
  }

  /** Übernimmt einen Vorschlag: Was vom Wort schon dasteht, bleibt; nur der Rest wird getippt. */
  function acceptHint(hint: Suggestion | undefined) {
    if (!hint) return;
    const line = typedLine();
    hideHints();
    if (line === null) return;
    const old = line.slice(line.length - hint.replace);
    if (hint.snippet) {
      if (hint.replace) input(pane.key, '\x7f'.repeat(hint.replace));
      return useSnippet(hint.snippet, pane.key, 'paste');
    }
    input(pane.key, hint.insert.startsWith(old) ? hint.insert.slice(old.length) : '\x7f'.repeat(hint.replace) + hint.insert);
    terminal?.focus();
  }

  /** Tasten, die der Liste der Vorschläge gehören. Liefert true, wenn die Taste verbraucht ist. */
  function hintKey(event: KeyboardEvent): boolean {
    if (event.key === 'Tab' && !event.shiftKey) acceptHint(hints[hintIndex]);
    else if (event.key === 'ArrowDown') hintIndex = (hintIndex + 1) % hints.length;
    // Am Anfang der Liste gehört der Pfeil nach oben wieder der Shell (ihr Verlauf).
    else if (event.key === 'ArrowUp' && hintIndex > 0) hintIndex -= 1;
    else if (event.key === 'Escape') (dismissed = true), hideHints();
    else return false;
    event.preventDefault();
    return true;
  }

  function openFind() {
    finding = true;
    queueMicrotask(() => findInput?.select());
  }

  function closeFind() {
    finding = false;
    search?.clearDecorations();
    terminal?.focus();
  }

  function find(forward: boolean) {
    if (!query) return;
    const options = { decorations: { matchOverviewRuler: '#fe980380', activeMatchColorOverviewRuler: '#fe9803', matchBackground: '#fe980340', activeMatchBackground: '#fe9803aa' } };
    if (forward) search?.findNext(query, options);
    else search?.findPrevious(query, options);
  }

  onMount(() => {
    const term = new Terminal({
      fontFamily: fontStack(),
      fontSize: settings.termFontSize,
      lineHeight: settings.termLineHeight,
      cursorBlink: settings.termCursorBlink,
      cursorStyle: settings.termCursor,
      scrollback: 10_000,
      rightClickSelectsWord: false,
      allowProposedApi: true,
      // Der Hintergrund kommt vom Bereich hinter dem Terminal (Deckkraft, Bild); lässt sich nach dem Öffnen nicht mehr umstellen.
      allowTransparency: true,
      theme: xtermTheme(scheme),
    });
    terminal = term;
    fit = new FitAddon();
    search = new SearchAddon();
    const serialize = new SerializeAddon();
    term.loadAddon(fit);
    term.loadAddon(search);
    term.loadAddon(serialize);
    term.open(host!);
    // Ohne Grafikkarte (oder wenn der Treiber streikt) zeichnet xterm.js von selbst langsamer, aber richtig.
    try {
      const webgl = new WebglAddon();
      webgl.onContextLoss(() => webgl.dispose());
      term.loadAddon(webgl);
    } catch {
      /* DOM-Darstellung bleibt aktiv */
    }
    fit.fit();

    term.attachCustomKeyEventHandler(keys);
    term.onData((text) => {
      // Was das Terminal von sich aus antwortet, ist keine Eingabe des Nutzers.
      if (isReply(text)) return answerQuery(pane.key, text);
      track(text);
      input(pane.key, text);
    });
    // Vorschläge richten sich nach dem, was im Terminal steht: also erst, wenn die Antwort des Servers gezeichnet ist.
    term.onWriteParsed(() => {
      if (!anchor || !settings.termSuggest) return;
      clearTimeout(hintTimer);
      hintTimer = setTimeout(() => void refreshHints(), 45);
    });
    term.onScroll(() => hints.length && hideHints());
    term.onResize(({ cols, rows }) => pane.sessionId !== null && void sessionResize(pane.sessionId, cols, rows));

    const unregister = registerTerminal(pane.key, {
      write: (bytes, done) => term.write(bytes, done),
      note: (text) => term.write(`\r\n\x1b[2m— ${text.replace(/\r?\n/g, '\r\n— ')}\x1b[0m\r\n`),
      size: () => ({ columns: term.cols, rows: term.rows }),
      focus: () => term.focus(),
      // Erst wenn alles Geschriebene verarbeitet ist, steht der Inhalt fest; ein leerer Schreibauftrag meldet das.
      snapshot: () => new Promise((resolve) => term.write('', () => resolve(serialize.serialize()))),
      paste: (text) => term.paste(text),
    });
    // Unsichtbare Terminals haben keine Größe; angepasst wird, sobald der Tab wieder vorn ist.
    const observer = new ResizeObserver(() => host?.offsetParent && fit?.fit());
    observer.observe(host!);

    // Erst jetzt verbinden: Das Terminal kennt seine Größe, die Zeilenbreite stimmt ab dem ersten Byte.
    void connect(pane.key);
    if (focused) term.focus();

    return () => {
      clearTimeout(hintTimer);
      observer.disconnect();
      unregister();
      terminal = undefined;
      term.dispose();
    };
  });

  $effect(() => {
    if (visible && terminal) {
      const mine = focused && !pane.prompt && !ui.palette;
      requestAnimationFrame(() => {
        fit?.fit();
        if (mine) terminal?.focus();
      });
    }
  });

  $effect(() => {
    const options = { fontSize: settings.termFontSize, fontFamily: fontStack(settings.termFont), lineHeight: settings.termLineHeight, cursorStyle: settings.termCursor, cursorBlink: settings.termCursorBlink };
    if (!terminal) return;
    Object.assign(terminal.options, options);
    fit?.fit();
  });

  $effect(() => void setLigatures(settings.termLigatures));

  // Vorschläge gehören zum Bereich mit der Tastatur; verliert er sie oder endet die Verbindung, verschwinden sie.
  $effect(() => {
    if (!visible || !focused || pane.phase !== 'connected' || pane.prompt || !settings.termSuggest) hideHints();
  });

  $effect(() => {
    const theme = xtermTheme(scheme);
    if (terminal) terminal.options.theme = theme;
  });
</script>

<div class="term-wrap" role="presentation" bind:this={wrap} oncontextmenucapture={rightClick}>
  <div class="term-host" bind:this={host}></div>
  {#if hints.length}
    <div class="hints" style={hintStyle} role="listbox" aria-label={t('suggest.title')}>
      {#each hints as hint, i (hint.kind + hint.label)}
        <!-- pointerdown statt click: Das Terminal behält die Tastatur. pointermove statt pointerenter: Geht die Liste
             unter einem ruhenden Mauszeiger auf, bleibt der erste Vorschlag markiert, und die Eingabetaste nimmt ihn. -->
        <button type="button" role="option" aria-selected={i === hintIndex} class="hint" class:on={i === hintIndex} onpointerdown={(e) => (e.preventDefault(), acceptHint(hint))} onpointermove={() => (hintIndex = i)}>
          <Icon name={hint.kind === 'dir' ? 'folder' : hint.kind === 'file' ? 'file' : hint.kind === 'snippet' ? 'snippet' : hint.kind === 'option' ? 'equal' : 'terminal'} size={13} />
          <b>{hint.label}</b>
          <span>{hint.kind === 'snippet' && !hint.detail ? t('macro.label') : hint.detail}</span>
          {#if i === hintIndex}<kbd>Tab</kbd>{/if}
        </button>
      {/each}
    </div>
  {/if}
  {#if finding}
    <div class="findbar">
      <Icon name="search" size={14} />
      <input
        bind:this={findInput}
        bind:value={query}
        placeholder={t('session.search')}
        aria-label={t('session.search')}
        spellcheck="false"
        onkeydown={(e) => {
          if (e.key === 'Enter') find(!e.shiftKey);
          if (e.key === 'Escape') closeFind();
        }}
      />
      <button type="button" class="mini" title={t('common.close')} aria-label={t('common.close')} onclick={closeFind}><Icon name="x" size={13} /></button>
    </div>
  {/if}
</div>
