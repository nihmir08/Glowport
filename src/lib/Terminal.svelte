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

  /** `visible`: the pane's tab is in front. `focused`: the pane has the keyboard in its tab. */
  let { pane, visible, focused }: { pane: Pane; visible: boolean; focused: boolean } = $props();

  const MIN_FONT = 8;
  const MAX_FONT = 32;

  /**
   * The terminal's answers to requests from the program inside it: where the cursor is, what kind of terminal it is,
   * whether the window has the keyboard. Windows asks the first question when every local terminal starts and waits
   * for the answer. (Shift+F3 looks like a cursor answer and therefore counts too.)
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

  /** Add-on that draws character sequences like `!=` and `=>` as one glyph of the font. It is only loaded when needed. */
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
      // In the meantime the terminal may have been closed or the switch turned off again.
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
   * Keys Glowport handles itself. `false` means: the terminal does not send the key to the server.
   * Ctrl+letter stays with the shell, except Ctrl+C with a selection (copy) and Ctrl+V (paste).
   */
  function keys(event: KeyboardEvent): boolean {
    if (event.type !== 'keydown') return true;
    // A shortcut that belongs to a snippet is handled by the window; the shell does not get the key.
    const hotkey = hotkeyOf(event);
    if (hotkey && snippetForHotkey(hotkey)) return false;
    if (hints.length && !event.ctrlKey && !event.altKey && !event.metaKey && hintKey(event)) return false;
    if (!event.ctrlKey) return true;
    const key = event.key.toLowerCase();
    // Ctrl+Alt+arrow switches the pane; the interface does that.
    if (event.altKey) return !key.startsWith('arrow');
    // Switching tabs (Ctrl+Tab) and closing a tab (Ctrl+Shift+W) belong to the interface.
    if (key === 'tab') return false;
    if (event.shiftKey) {
      // Split (D right, E down), close tab, multi-exec, local terminal (T).
      // Ctrl+Shift+K opens search in the terminal; Ctrl+K alone belongs to the session (nano: cut line).
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
   * Right-click as in Termius: never a context menu. With a selection it copies, without one it pastes.
   * If the program in the terminal requested the mouse (htop, mc, tmux), the right-click belongs to it; Shift pastes anyway.
   */
  function rightClick(event: MouseEvent) {
    // The search bar is an ordinary input field: a right-click there pastes nothing into the terminal.
    if ((event.target as Element).closest('.findbar')) return;
    event.preventDefault();
    // Otherwise xterm.js prepares its input field for the menu and fills it with the selection.
    event.stopPropagation();
    if (!terminal) return;
    if (terminal.hasSelection()) copy();
    else if (terminal.modes.mouseTrackingMode === 'none' || event.shiftKey) paste();
  }

  // ---------- Suggestions while typing ----------

  let hints = $state<Suggestion[]>([]);
  let hintIndex = $state(0);
  let hintStyle = $state('');
  /** Where the line being typed began: line in the scrollback and column after the prompt. */
  let anchor: { row: number; column: number } | null = null;
  /** Dismissed with Esc: no suggestions until the next line. */
  let dismissed = false;
  let hintTicket = 0;
  let hintTimer: ReturnType<typeof setTimeout> | undefined;

  function hideHints() {
    hintTicket += 1;
    if (hints.length) hints = [];
  }

  /**
   * Reads along with what is typed, but only to know when a new line begins. What is in the line
   * comes later from the terminal itself: that way it is right even after Tab, arrow keys and the shell's history,
   * and where nothing is displayed (password), there is nothing to suggest either.
   */
  function track(text: string) {
    // Enter, Ctrl+C, Ctrl+D: the line is over. Ctrl+L redraws, after that the position is no longer right.
    if (/[\r\n\x03\x04\x0c]/.test(text)) {
      anchor = null;
      dismissed = false;
      return hideHints();
    }
    const buffer = terminal?.buffer.active;
    if (!anchor && buffer) anchor = { row: buffer.baseY + buffer.cursorY, column: buffer.cursorX };
  }

  /** The line between prompt and cursor, or null if it cannot be determined reliably. */
  function typedLine(): string | null {
    const term = terminal;
    const buffer = term?.buffer.active;
    if (!term || !buffer || !anchor || buffer.type !== 'normal' || buffer.viewportY !== buffer.baseY) return null;
    const row = buffer.baseY + buffer.cursorY;
    if (row < anchor.row || row - anchor.row > 4 || (row === anchor.row && buffer.cursorX < anchor.column)) return null;
    let line = '';
    for (let r = anchor.row; r <= row; r++) {
      const cells = buffer.getLine(r);
      // Between start and cursor only wrapped text may lie, no output of a program.
      if (!cells || (r > anchor.row && !cells.isWrapped)) return null;
      line += cells.translateToString(false, r === anchor.row ? anchor.column : 0, r === row ? buffer.cursorX : term.cols);
    }
    // If there is still something right of the cursor, editing happens mid-line.
    if (buffer.getLine(row)?.translateToString(true, buffer.cursorX).trim()) return null;
    return line;
  }

  async function refreshHints() {
    const ticket = ++hintTicket;
    // Commands and paths of a Linux server are suggested; the paths come over SSH. Elsewhere they would not fit.
    const line = settings.termSuggest && pane.kind === 'ssh' && visible && focused && !pane.prompt && pane.phase === 'connected' ? typedLine() : null;
    // If the line is empty again (Ctrl+U, everything deleted), an earlier Esc no longer applies.
    if (line === '') dismissed = false;
    if (dismissed || !line?.trim()) return void (hints.length && (hints = []));
    const found = await suggest({ line, place: pane.sessionId === null ? null : { kind: 'session', id: pane.sessionId }, cwd: pane.cwd, lang: settings.lang, snippets: vault.snippets });
    if (ticket !== hintTicket) return;
    // Typing may have continued in the meantime; then the next round comes right away.
    if (typedLine() !== line) return;
    hints = found;
    hintIndex = 0;
    if (found.length) placeHints(found[0].replace);
  }

  /** Places the list below the start of the word being completed; far down in the terminal above it. */
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

  /** Takes a suggestion: what is already there of the word stays; only the rest is typed. */
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

  /** Keys that belong to the suggestion list. Returns true if the key was consumed. */
  function hintKey(event: KeyboardEvent): boolean {
    if (event.key === 'Tab' && !event.shiftKey) acceptHint(hints[hintIndex]);
    else if (event.key === 'ArrowDown') hintIndex = (hintIndex + 1) % hints.length;
    // At the top of the list the up arrow belongs to the shell again (its history).
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
      // The background comes from the pane behind the terminal (opacity, image); it cannot be changed after opening.
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
    // Without a graphics card (or if the driver fails) xterm.js draws on its own, slower but correctly.
    try {
      const webgl = new WebglAddon();
      webgl.onContextLoss(() => webgl.dispose());
      term.loadAddon(webgl);
    } catch {
      /* DOM rendering stays active */
    }
    fit.fit();

    term.attachCustomKeyEventHandler(keys);
    term.onData((text) => {
      // What the terminal answers on its own is not user input.
      if (isReply(text)) return answerQuery(pane.key, text);
      track(text);
      input(pane.key, text);
    });
    // Suggestions depend on what is in the terminal: so only once the server's answer is drawn.
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
      // Only once everything written is processed is the content settled; an empty write reports that.
      snapshot: () => new Promise((resolve) => term.write('', () => resolve(serialize.serialize()))),
      paste: (text) => term.paste(text),
    });
    // Invisible terminals have no size; it is adjusted as soon as the tab is in front again.
    const observer = new ResizeObserver(() => host?.offsetParent && fit?.fit());
    observer.observe(host!);

    // Only connect now: the terminal knows its size, the line width is right from the first byte.
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

  // Suggestions belong to the pane with the keyboard; if it loses it or the connection ends, they disappear.
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
        <!-- pointerdown instead of click: the terminal keeps the keyboard. pointermove instead of pointerenter: if the list
             opens under a resting mouse pointer, the first suggestion stays highlighted and Enter takes it. -->
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
