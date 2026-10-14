// The built-in editor: CodeMirror 6, in the interface's colors. Only loaded when a file is opened.
import type { Extension } from '@codemirror/state';

export interface EditorHandle {
  text(): string;
  /** Replaces the content, e.g. after “Reload”. */
  load(text: string): void;
  focus(): void;
  destroy(): void;
}

export interface EditorOptions {
  text: string;
  /** File name; the language depends on it. */
  name: string;
  /** Path of the file, in case the name alone reveals nothing (e.g. `.conf` under `/etc/nginx`). */
  path: string;
  readOnly: boolean;
  onChange: () => void;
  onSave: () => void;
  onCursor: (line: number, column: number) => void;
}

/** A file's language for display in the footer; `null` = plain text. */
export function languageName(name: string, path: string): string | null {
  return pick(name, path)?.[0] ?? null;
}

type Loader = () => Promise<Extension>;

function pick(name: string, path: string): [string, Loader] | null {
  const lower = name.toLowerCase();
  const ext = lower.includes('.') ? lower.slice(lower.lastIndexOf('.') + 1) : '';
  const legacy = (load: () => Promise<unknown>, key: string): Loader => async () => {
    const [{ StreamLanguage }, mode] = await Promise.all([import('@codemirror/language'), load()]);
    return StreamLanguage.define((mode as Record<string, never>)[key]);
  };
  const shell = legacy(() => import('@codemirror/legacy-modes/mode/shell'), 'shell');
  const properties = legacy(() => import('@codemirror/legacy-modes/mode/properties'), 'properties');
  const nginx = legacy(() => import('@codemirror/legacy-modes/mode/nginx'), 'nginx');

  if (/^(dockerfile|containerfile)$/.test(lower)) return ['Dockerfile', legacy(() => import('@codemirror/legacy-modes/mode/dockerfile'), 'dockerFile')];
  if (/^\.(bashrc|bash_profile|bash_aliases|profile|zshrc|env)$/.test(lower) || lower.startsWith('.env.')) return ['Shell', shell];
  if (/nginx/.test(path.toLowerCase()) && (ext === 'conf' || !ext)) return ['nginx', nginx];
  switch (ext) {
    case 'json':
      return ['JSON', async () => (await import('@codemirror/lang-json')).json()];
    case 'yaml':
    case 'yml':
      return ['YAML', async () => (await import('@codemirror/lang-yaml')).yaml()];
    case 'js':
    case 'mjs':
    case 'cjs':
    case 'jsx':
      return ['JavaScript', async () => (await import('@codemirror/lang-javascript')).javascript({ jsx: ext === 'jsx' })];
    case 'ts':
    case 'tsx':
      return ['TypeScript', async () => (await import('@codemirror/lang-javascript')).javascript({ typescript: true, jsx: ext === 'tsx' })];
    case 'py':
      return ['Python', async () => (await import('@codemirror/lang-python')).python()];
    case 'html':
    case 'htm':
      return ['HTML', async () => (await import('@codemirror/lang-html')).html()];
    case 'css':
      return ['CSS', async () => (await import('@codemirror/lang-css')).css()];
    case 'md':
      return ['Markdown', async () => (await import('@codemirror/lang-markdown')).markdown()];
    case 'xml':
    case 'svg':
      return ['XML', async () => (await import('@codemirror/lang-xml')).xml()];
    case 'sql':
      return ['SQL', async () => (await import('@codemirror/lang-sql')).sql()];
    case 'php':
      return ['PHP', async () => (await import('@codemirror/lang-php')).php()];
    case 'sh':
    case 'bash':
    case 'zsh':
      return ['Shell', shell];
    case 'toml':
      return ['TOML', legacy(() => import('@codemirror/legacy-modes/mode/toml'), 'toml')];
    case 'ini':
    case 'cfg':
    case 'conf':
    case 'service':
    case 'timer':
    case 'properties':
      return ['INI', properties];
    default:
      return null;
  }
}

export async function createEditor(parent: HTMLElement, options: EditorOptions): Promise<EditorHandle> {
  const [{ EditorState, Compartment }, view, commands, language, search, { tags }] = await Promise.all([
    import('@codemirror/state'),
    import('@codemirror/view'),
    import('@codemirror/commands'),
    import('@codemirror/language'),
    import('@codemirror/search'),
    import('@lezer/highlight'),
  ]);
  const { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter, drawSelection } = view;

  // The colors are variables in app.css, so they follow dark and light.
  const colors = language.HighlightStyle.define([
    { tag: [tags.comment, tags.meta], color: 'var(--code-comment)', fontStyle: 'italic' },
    { tag: [tags.keyword, tags.operatorKeyword, tags.modifier, tags.controlKeyword], color: 'var(--code-keyword)' },
    { tag: [tags.string, tags.special(tags.string), tags.regexp], color: 'var(--code-string)' },
    { tag: [tags.number, tags.bool, tags.null, tags.atom], color: 'var(--code-number)' },
    { tag: [tags.propertyName, tags.attributeName, tags.definition(tags.variableName)], color: 'var(--code-name)' },
    { tag: [tags.typeName, tags.className, tags.tagName, tags.namespace], color: 'var(--code-type)' },
    { tag: [tags.function(tags.variableName), tags.function(tags.propertyName), tags.labelName], color: 'var(--code-function)' },
    { tag: [tags.heading, tags.strong], fontWeight: '700' },
    { tag: tags.emphasis, fontStyle: 'italic' },
    { tag: tags.link, color: 'var(--code-string)', textDecoration: 'underline' },
    { tag: tags.invalid, color: 'var(--err)' },
  ]);

  const syntax = new Compartment();
  const editor = new EditorView({
    parent,
    state: EditorState.create({
      doc: options.text,
      extensions: [
        // Line ends stay as the file has them: a Windows file is not silently rewritten to Unix line ends.
        EditorState.lineSeparator.of(options.text.includes('\r\n') ? '\r\n' : '\n'),
        lineNumbers(),
        highlightActiveLineGutter(),
        highlightActiveLine(),
        drawSelection(),
        commands.history(),
        language.indentOnInput(),
        language.bracketMatching(),
        language.syntaxHighlighting(colors),
        search.highlightSelectionMatches(),
        syntax.of([]),
        EditorState.readOnly.of(options.readOnly),
        EditorView.editable.of(!options.readOnly),
        keymap.of([{ key: 'Mod-s', preventDefault: true, run: () => (options.onSave(), true) }, commands.indentWithTab, ...commands.defaultKeymap, ...commands.historyKeymap, ...search.searchKeymap]),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) options.onChange();
          if (update.selectionSet || update.docChanged) {
            const head = update.state.selection.main.head;
            const line = update.state.doc.lineAt(head);
            options.onCursor(line.number, head - line.from + 1);
          }
        }),
      ],
    }),
  });

  // The language comes later; until then the text is already there.
  const found = pick(options.name, options.path);
  if (found)
    void found[1]()
      .then((extension) => editor.dispatch({ effects: syntax.reconfigure(extension) }))
      .catch((e) => console.error('Language not loaded', e));

  return {
    text: () => editor.state.doc.toString(),
    load: (text) => editor.dispatch({ changes: { from: 0, to: editor.state.doc.length, insert: text } }),
    focus: () => editor.focus(),
    destroy: () => editor.destroy(),
  };
}
