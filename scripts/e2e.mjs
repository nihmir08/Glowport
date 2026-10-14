// End-to-end test of the real executable via WebView2's debug interface.
// Runs in a portable copy with its own data folder; the user's real vault is not touched.
// Needs `sh` and `ssh-keygen` on the path (on Windows e.g. from Git): the test server uses `sh` to install
// keys, `ssh-keygen` plays the certificate authority.
// Run in the project folder after `npm run tauri build -- --no-bundle` and `cargo build -p glowport-testserver`:
// node scripts/e2e.mjs
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, rmSync, mkdirSync, copyFileSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const [exeSource = resolve('target/release/glowport.exe'), workDir = join(tmpdir(), 'glowport-e2e')] = process.argv.slice(2);
const PORT = 9223;
const PW1 = 'e2e-pruefung-eins';
const PW2 = 'e2e-pruefung-zwei';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
// Print every result at once: if a step hangs, it is visible how far the test got.
const ok = (name, cond, extra = '') => {
  results.push(`${cond ? 'ok    ' : 'FEHLER'} ${name}${extra ? ` (${extra})` : ''}`);
  console.log(results.at(-1));
};
// Cases that do not work on this machine (e.g. without mosh in WSL). They count neither as passed nor as failed.
const skipped = [];
const skip = (name) => {
  skipped.push(name);
  console.log(`skipped ${name}`);
};

rmSync(workDir, { recursive: true, force: true });
mkdirSync(workDir, { recursive: true });
const exe = join(workDir, 'glowport.exe');
copyFileSync(exeSource, exe);
writeFileSync(join(workDir, 'portable'), '');
const vaultFile = join(workDir, 'data', 'vault.db');
// The user's home directory on the test server. It runs commands in it and reads `.ssh/authorized_keys`
// on every sign-in, like a real server.
const serverHome = join(workDir, 'home');
mkdirSync(serverHome, { recursive: true });
const authorizedKeys = join(serverHome, '.ssh', 'authorized_keys');
// The test server's file system for SFTP and a folder of this machine as counterpart, both with known content.
const serverFiles = join(workDir, 'server-dateien');
const lokal = join(workDir, 'lokal');
/** The folder the test server's FTP servers show: a small web space. */
const ftpFiles = join(workDir, 'ftp-dateien');
const put = (root, path, content) => {
  const file = join(root, ...path.split('/'));
  mkdirSync(join(file, '..'), { recursive: true });
  writeFileSync(file, content);
  return file;
};
put(serverFiles, 'etc/passwd', 'root:x:0:0:root:/root:/bin/sh\ntester:x:1000:1000::/home/tester:/bin/sh\n');
put(serverFiles, 'etc/group', 'root:x:0:\ntester:x:1000:\n');
put(serverFiles, 'etc/hosts', '127.0.0.1 localhost\n');
// The FTP servers' web space; it must exist before the test server starts.
put(ftpFiles, 'htdocs/index.html', '<h1>Es funktioniert</h1>\n');
put(ftpFiles, 'htdocs/mit leerzeichen und ä.txt', 'äöü');
put(ftpFiles, 'logs/access.log', 'GET / 200\n');
put(serverFiles, 'srv/app/config.yaml', 'port: 3000\n');
put(serverFiles, 'srv/app/notes.txt', 'notiz\n');
put(serverFiles, 'srv/app/bild.png', Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13]));
put(serverFiles, 'srv/app/roh.bin', Buffer.from([1, 2, 0, 3, 0, 4]));
// Large enough to pause the transfer in the middle.
put(serverFiles, 'srv/gross.bin', Buffer.alloc(96 * 1024 * 1024, 'glowport-e2e '));
for (let i = 0; i < 40; i++) put(lokal, `viele/${i % 2 ? 'unter/' : ''}datei-${String(i).padStart(2, '0')}.txt`, `Inhalt ${String(i).padStart(2, '0')}\n`);
put(lokal, 'einzeln.txt', 'einzeln\n');
// For folder sync: one identical file, one only left, one only right, one newer on the left.
const then = new Date('2026-01-15T10:00:00Z');
for (const file of [put(lokal, 'abgleich/gleich.txt', 'gleich\n'), put(serverFiles, 'srv/abgleich/gleich.txt', 'gleich\n'), put(serverFiles, 'srv/abgleich/unter/geaendert.txt', 'alt\n')]) utimesSync(file, then, then);
put(lokal, 'abgleich/neu-links.txt', 'links\n');
put(lokal, 'abgleich/unter/geaendert.txt', 'neuer stand\n');
put(serverFiles, 'srv/abgleich/nur-rechts.txt', 'rechts\n');
// Certificate authority. The test server accepts its user certificates (like a real one via `TrustedUserCAKeys`)
// and itself shows a certificate from it for its key.
const caKey = join(workDir, 'ca');
execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'glowport-e2e-ca', '-f', caKey]);
const shots = join(tmpdir(), 'glowport-e2e-bilder');
mkdirSync(shots, { recursive: true });

/**
 * Starts the test server. Its first line names the SSH server's address, the second the simulated
 * Proxmox server: `pve <address> <fingerprint of its certificate>`. Then the two FTP servers follow.
 */
function startServer() {
  // Input open: through it the test pauses the forwarder for Mosh (`mosh pause`, `mosh resume`).
  const child = spawn(resolve('target/debug/glowport-testserver.exe'), [serverHome, caKey], { stdio: ['pipe', 'pipe', 'ignore'], env: { ...process.env, GLOWPORT_TEST_FILES: serverFiles, GLOWPORT_TEST_FTP: ftpFiles, GLOWPORT_TEST_MOSH: 'Ubuntu' } });
  const lines = new Promise((ok, no) => {
    let text = '';
    child.stdout.on('data', (chunk) => {
      text += chunk;
      const found = text.split(/\r?\n/).filter(Boolean);
      if (found.length >= 5) ok(found);
    });
    child.once('error', no);
    // WSL needs a few seconds on the first call (looking for mosh).
    setTimeout(() => no(new Error('Test server does not report its addresses')), 40_000);
  });
  const port = lines.then(([ssh]) => Number(ssh.trim().split(':').pop()));
  const pve = lines.then(([, line]) => {
    const [, address, fingerprint] = line.trim().split(' ');
    return { address, fingerprint };
  });
  // Third and fourth line: the FTP servers, plain (`ftp <address>`) and over TLS (`ftps <address> <fingerprint>`).
  const ftp = lines.then(([, , plain, tls]) => {
    const [, address, fingerprint] = tls.trim().split(' ');
    return { plain: Number(plain.trim().split(':').pop()), tls: Number(address.split(':').pop()), fingerprint };
  });
  // Fifth line: `mosh <address in WSL>` or `mosh -` if there is no mosh there.
  const mosh = lines.then(([, , , , line]) => { const address = line.trim().split(' ')[1]; return address && address !== '-' ? address : null; });
  return { child, port, pve, ftp, mosh };
}

/** Picture of the window content, as WebView2 is drawing it right now. */
async function shot(page, name) {
  const { data } = await page.send('Page.captureScreenshot', { format: 'png' });
  const file = join(shots, `${name}.png`);
  writeFileSync(file, Buffer.from(data, 'base64'));
  console.log(`Bild: ${file}`);
}

async function pressEnter(page) {
  for (const type of ['keyDown', 'keyUp']) await page.send('Input.dispatchKeyEvent', { type, key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: type === 'keyDown' ? '\r' : undefined });
}

/** Real keyboard input into the focused element. */
async function typeLine(page, text) {
  await page.send('Input.insertText', { text });
  await pressEnter(page);
}

/** Real mouse events at a spot in the window. */
async function mouse(page, type, x, y, button = 'none', buttons = 0) {
  await page.send('Input.dispatchMouseEvent', { type, x, y, button, buttons, clickCount: type === 'mouseMoved' ? 0 : 1 });
}

async function rightClick(page, x, y) {
  await mouse(page, 'mousePressed', x, y, 'right', 2);
  await mouse(page, 'mouseReleased', x, y, 'right');
  await sleep(400);
}

/** Selects in the terminal by dragging with the left mouse button. */
async function drag(page, x1, y1, x2, y2) {
  await mouse(page, 'mousePressed', x1, y1, 'left', 1);
  for (const part of [0.3, 0.7, 1]) await mouse(page, 'mouseMoved', x1 + (x2 - x1) * part, y1 + (y2 - y1) * part, 'left', 1);
  await mouse(page, 'mouseReleased', x2, y2, 'left');
  await sleep(200);
}

/**
 * Reads the first lines of a visible terminal (without argument: the first one): select, copy via right-click,
 * read the clipboard. The text that was on the clipboard before is put back afterwards. With `whole` the
 * selection covers the terminal's whole height and width.
 */
async function terminalText(page, index = 0, whole = false) {
  const before = await run(page, `return await invoke('plugin:clipboard-manager|read_text').catch(()=>null)`);
  const area = await run(page, `const r = qa('.pane:not(.off) .xterm-screen')[${index}].getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height };`);
  await drag(page, area.x + 3, area.y + 3, area.x + (whole ? area.w - 6 : Math.min(500, area.w - 6)), area.y + (whole ? area.h - 6 : Math.min(330, area.h - 6)));
  await rightClick(page, area.x + area.w / 2, area.y + area.h / 2);
  const text = await run(page, `return await invoke('plugin:clipboard-manager|read_text').catch(()=>null)`);
  if (typeof before === 'string') await run(page, `await invoke('plugin:clipboard-manager|write_text',{text:${JSON.stringify(before)}})`);
  return text ?? '';
}

function launch() {
  // WebView2 folder of its own: a Glowport the user has open would otherwise share the browser process with the test,
  // which then runs without a debug interface.
  const env = { ...process.env, WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${PORT}`, WEBVIEW2_USER_DATA_FOLDER: join(workDir, 'webview') };
  return spawn(exe, [], { env, stdio: 'ignore', detached: false });
}

/** The program's windows, as the debug interface names them. */
async function listPages() {
  const pages = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
  return pages.filter((p) => p.type === 'page' && p.webSocketDebuggerUrl && /tauri.localhost|^tauri:/.test(p.url));
}

/** Connects to a window; without argument to the first, otherwise to the first whose ID is not in `except`. */
async function connect(except = []) {
  for (let i = 0; i < 80; i++) {
    try {
      const page = (await listPages()).find((p) => !except.includes(p.id));
      if (page) {
        const ws = new WebSocket(page.webSocketDebuggerUrl);
        await new Promise((res, rej) => ((ws.onopen = res), (ws.onerror = rej)));
        let id = 0;
        const pending = new Map();
        ws.onmessage = (e) => {
          const m = JSON.parse(e.data);
          const p = pending.get(m.id);
          if (p) (pending.delete(m.id), m.error ? p.no(new Error(m.error.message)) : p.ok(m.result));
        };
        const send = (method, params = {}) => new Promise((ok, no) => (pending.set(++id, { ok, no }), ws.send(JSON.stringify({ id, method, params }))));
        const client = { send, close: () => ws.close(), target: page.id };
        await ready(client);
        return client;
      }
    } catch {}
    await sleep(250);
  }
  throw new Error('Debug interface not reachable');
}

/** Waits until the interface stands. Before that the window is still loading and every evaluation would go nowhere. */
async function ready(page) {
  for (let i = 0; i < 80; i++) {
    try {
      const r = await page.send('Runtime.evaluate', { expression: "document.readyState === 'complete' && !!window.__TAURI_INTERNALS__ && !!document.querySelector('.win')", returnByValue: true });
      if (r.result?.value === true) return;
    } catch {}
    await sleep(150);
  }
  throw new Error('Interface did not finish loading');
}

const HELPERS = `
const wait=(ms=300)=>new Promise(r=>setTimeout(r,ms));
const q=s=>document.querySelector(s), qa=s=>[...document.querySelectorAll(s)];
const byText=(sel,txt)=>qa(sel).find(e=>e.textContent.trim().includes(txt));
const type=(el,v)=>{el.value=v;el.dispatchEvent(new Event('input',{bubbles:true}))};
const until=async(fn,ms=8000)=>{const end=Date.now()+ms;while(Date.now()<end){const v=fn();if(v)return v;await wait(100)}return null};
const invoke=(cmd,args)=>window.__TAURI_INTERNALS__.invoke(cmd,args);
const fails=async(p)=>{try{await p;return null}catch(e){return e}};
`;

async function run(page, body) {
  // A step that never answers should fail the test instead of stopping it.
  const timeout = new Promise((_, no) => setTimeout(() => no(new Error('Step does not answer (40 s)')), 40_000));
  const r = await Promise.race([page.send('Runtime.evaluate', { expression: `(async()=>{${HELPERS}${body}})()`, awaitPromise: true, returnByValue: true }), timeout]);
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
  return r.result.value;
}

/** Remembers the window's next context menu event; `menuPrevented` then says whether the menu was suppressed. */
const watchMenu = (page) => run(page, `if (!window.__watching) { window.__watching = true; window.addEventListener('contextmenu', e => (window.__menu = e), true); }`);
const menuPrevented = (page) => run(page, `const e = window.__menu; window.__menu = null; return e ? e.defaultPrevented : null`);

/**
 * How Windows keeps a process's main window: “True True 0” means present, visible and not cloaked.
 * Glowport opens its windows cloaked and removes the cloak as soon as the interface stands.
 */
function windowState(pid) {
  const type = `using System; using System.Runtime.InteropServices; public static class Fenster { [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h, int a, out int v, int s); [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h); }`;
  const script = `Add-Type -TypeDefinition '${type}'; $h = (Get-Process -Id ${pid}).MainWindowHandle; $v = 0; [void][Fenster]::DwmGetWindowAttribute($h, 14, [ref]$v, 4); "$($h -ne 0) $([Fenster]::IsWindowVisible($h)) $v"`;
  try {
    return execFileSync('powershell', ['-NoProfile', '-Command', script], { encoding: 'utf8' }).trim();
  } catch (e) {
    return `not readable: ${e.message.slice(0, 80)}`;
  }
}

let app = launch();
const server = startServer();
try {
  let page = await connect();

  // 0a. Very first start, still without settings: the language follows Windows (the portable version has
  // no installer whose choice would take precedence), and the window is visible as soon as the interface stands.
  const systemLang = execFileSync('powershell', ['-NoProfile', '-Command', '(Get-UICulture).TwoLetterISOLanguageName'], { encoding: 'utf8' }).trim() === 'de' ? 'de' : 'en';
  const settingsFile = join(workDir, 'data', 'settings.json');
  const fresh = await run(page, `
    await until(()=>q('.lock-card')); await wait(900);
    return { lang: (await invoke('settings_load'))?.lang, html: document.documentElement.lang, title: q('.lock-card h1').textContent, visible: await invoke('plugin:window|is_visible', { label: 'main' }).catch(e => String(e)) };
  `);
  ok('First start: the language follows Windows as long as nothing is set', fresh.lang === systemLang && fresh.html === systemLang && (systemLang === 'de' ? /anlegen/ : /Create/).test(fresh.title), `Windows ${systemLang}, Glowport ${fresh.lang}: „${fresh.title}“`);
  const shown = windowState(app.pid);
  ok('The window is visible as soon as the interface is ready', shown === 'True True 0' && fresh.visible === true, shown);
  // The test itself runs in German: set the language and restart.
  page.close();
  app.kill();
  await sleep(1200);
  writeFileSync(settingsFile, JSON.stringify({ ...JSON.parse(readFileSync(settingsFile, 'utf8')), lang: 'de' }));
  app = launch();
  page = await connect();

  // 0. Without a vault the start offers, next to creating one, to restore a backup.
  const offer = await run(page, `await until(()=>q('.lock-card')); return !!byText('.lock-card .linkbtn','Sicherung');`);
  ok('without a vault the start offers to restore a backup', offer);

  // 1. First start: no vault, create one through the interface.
  const first = await run(page, `
    await until(()=>q('.lock-card'));
    const before = await invoke('vault_status');
    const title = q('.lock-card h1').textContent;
    const inputs = qa('.lock-card input[type=password]');
    type(inputs[0],'${PW1}'); type(inputs[1],'${PW1}'); q('.lock-card input[type=checkbox]').click(); await wait(100);
    q('.lock-card button[type=submit]').click();
    const nav = await until(()=>q('.nav'));
    return { before: before.state, title, opened: !!nav, after: (await invoke('vault_status')).state, font: getComputedStyle(document.body).fontFamily };
  `);
  ok('first start reports “no vault”', first.before === 'missing' && /anlegen|Create/.test(first.title));
  ok('vault created through the interface', first.opened && first.after === 'open');
  ok('vault file is in the data folder', existsSync(vaultFile));
  ok('interface font loaded', /Inter Variable/.test(first.font), first.font.slice(0, 30));

  // 2. Create group and host through the editors, check inheritance.
  const made = await run(page, `
    byText('.acts .btn','Neue Gruppe').click(); await until(()=>q('.editor'));
    type(q('.editor .fld input'),'Produktiv'); type(qa('.editor .inh-row input')[0],'deploy'); await wait(80);
    q('.editor button[type=submit]').click(); await until(()=>byText('.group','Produktiv'));
    byText('.group','Produktiv').click(); await wait(150);
    byText('.acts .btn','Neuer Host').click(); await until(()=>q('.editor'));
    const f = qa('.editor .fld input'); type(f[0],'web-01'); type(f[1],'10.0.10.11');
    type(q('.editor input[type=password]'),'server-passwort-geheim'); await wait(80);
    q('.editor button[type=submit]').click();
    const card = await until(()=>byText('.host','web-01'));
    const st = await invoke('vault_status');
    return { card: card?.textContent, detail: q('.detail')?.textContent, status: st };
  `);
  const host = made.status.data.hosts[0];
  ok('host saved and shown', made.card?.includes('deploy@10.0.10.11'), made.card?.replace(/\s+/g, ' ').slice(0, 60));
  ok('details show the inherited user with its origin', made.detail?.includes('deploy') && made.detail.includes('Produktiv'));
  ok('the core delivers the host without password, only hasPassword', host?.name === 'web-01' && host.hasPassword === true && !JSON.stringify(made.status).includes('server-passwort-geheim'));
  ok('the group carries the default', made.status.data.groups[0]?.defs.user === 'deploy');

  // 2b. In the editor only “Save” saves: Cancel discards, and no other button submits the form.
  const cancelled = await run(page, `
    q('.detail button[title="Bearbeiten"]').click(); await until(()=>q('.editor'));
    type(q('.editor .fld input'),'umbenannt'); await wait(80);
    const submitters = qa('.editor button').filter(b=>b.type !== 'button').map(b=>b.textContent.trim());
    const browse = byText('.editor .btn','Durchsuchen');
    byText('.editor .btn','Abbrechen').click(); await wait(500);
    return { submitters, browseType: browse?.type, names: (await invoke('vault_status')).data.hosts.map(h=>h.name), editorOpen: !!q('.editor'), toasts: qa('.toast').map(e=>e.textContent.trim()) };
  `);
  ok('only “Save” submits the form', cancelled.submitters.join() === 'Speichern' && cancelled.browseType === 'button', cancelled.submitters.join());
  ok('Abbrechen im Editor speichert nichts', cancelled.names.join() === 'web-01' && !cancelled.editorOpen, cancelled.names.join());

  // 2c. WebView2's context menu exists nowhere, not even in input fields.
  await watchMenu(page);
  const spots = await run(page, `
    q('.detail button[title="Bearbeiten"]').click(); await until(()=>q('.editor'));
    const mid = el => { const r = el.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; };
    return { card: mid(byText('.host','web-01')), field: mid(q('.editor .fld input')) };
  `);
  const menus = [];
  for (const at of [spots.card, spots.field]) {
    await rightClick(page, at.x, at.y);
    menus.push(await menuPrevented(page));
  }
  await run(page, `byText('.editor .btn','Abbrechen').click(); await wait(300);`);
  ok('no context menu on the hosts page and in input fields', menus.join() === 'true,true', menus.join());

  // 3. Core errors arrive as codes; commands with several arguments work.
  const errs = await run(page, `
    const st = await invoke('vault_status'); const g = st.data.groups[0].id, h = st.data.hosts[0].id;
    const e1 = await fails(invoke('host_save',{host:{name:'',address:'x',group:null,color:null,os:null,own:{}}}));
    const e2 = await fails(invoke('host_save',{host:{name:'a',address:'-oProxyCommand=x',group:null,color:null,os:null,own:{}}}));
    const e3 = await fails(invoke('group_save',{group:{id:g,name:'Produktiv',parent:g,color:null,defs:{}}}));
    const dup = await invoke('host_duplicate',{id:h,name:'web-01 (Kopie)'});
    const del = await invoke('host_delete',{id:dup.id});
    const sub = await invoke('group_save',{group:{name:'Web',parent:g,color:null,defs:{port:2200}}});
    const moved = await invoke('host_save',{host:{id:h,name:'web-01',address:'10.0.10.11',group:sub.id,color:'#22c3a6',os:'Ub',own:{}}});
    const dissolved = await invoke('group_delete',{id:sub.id,withContents:false});
    await invoke('vault_set_auto_lock',{minutes:15}); await invoke('vault_touch');
    return { e1, e2, e3, dupHosts: dup.data.hosts.length, afterDelete: del.data.hosts.length, movedHost: moved.data.hosts[0], afterDissolve: dissolved.data };
  `);
  ok('leerer Name → invalid/name_required', errs.e1?.code === 'invalid' && errs.e1.reason === 'name_required');
  ok('address with a leading “-” rejected', errs.e2?.reason === 'address_invalid');
  ok('group inside itself rejected', errs.e3?.reason === 'group_cycle');
  ok('duplicate and delete', errs.dupHosts === 2 && errs.afterDelete === 1);
  ok('moving keeps the password, the color is unified', errs.movedHost.hasPassword === true && errs.movedHost.color === '#22C3A6' && errs.movedHost.os === 'Ub');
  ok('dissolving the group moves the host up', errs.afterDissolve.groups.length === 1 && errs.afterDissolve.hosts[0].group === errs.afterDissolve.groups[0].id);

  // 4. Change password, lock, wrong and right password.
  const lock = await run(page, `
    const weak = await fails(invoke('vault_change_password',{old:'${PW1}',new:'kurz'}));
    const wrong = await fails(invoke('vault_change_password',{old:'falsch',new:'${PW2}'}));
    await invoke('vault_change_password',{old:'${PW1}',new:'${PW2}'});
    q('.tb-ic').click(); await until(()=>q('.lock-card'));
    const hidden = !q('.host') && !q('.nav');
    type(q('.lock-card input'),'${PW1}'); await wait(80); q('.lock-card button[type=submit]').click();
    const msg = await until(()=>q('.lock-card .errline')?.textContent);
    type(q('.lock-card input'),'${PW2}'); await wait(80);
    const t0 = performance.now(); q('.lock-card button[type=submit]').click(); await until(()=>q('.nav')); const ms = Math.round(performance.now()-t0);
    return { weak: weak?.code, wrong: wrong?.code, hidden, msg, ms, open: (await invoke('vault_status')).state };
  `);
  ok('changing the password checks length and old password', lock.weak === 'weak_password' && lock.wrong === 'wrong_password');
  ok('Sperren verbirgt alles', lock.hidden);
  ok('old password is rejected', /Falsches|Wrong/.test(lock.msg ?? ''), lock.msg);
  ok('new password unlocks', lock.open === 'open', `${lock.ms} ms until the interface is back`);
  // 4b. Real connection to the test server: create host, connect, answer prompts, type, sign out.
  const port = await server.port;
  const opened = await run(page, `
    // Host über den Editor anlegen, danach über die Suche (Strg+K) öffnen.
    qa('.nv')[0].click(); await wait(200);
    byText('.acts .btn','Neuer Host').click(); await until(()=>q('.editor'));
    const f = qa('.editor .fld input'); type(f[0],'testserver'); type(f[1],'127.0.0.1');
    const inherit = qa('.editor .inh-row input'); type(inherit[0],'tester'); type(inherit[1],'${port}'); await wait(80);
    q('.editor button[type=submit]').click();
    await until(()=>q('.detail'));
    const saved = (await invoke('vault_status')).data.hosts.find(h=>h.name==='testserver');
    window.dispatchEvent(new KeyboardEvent('keydown',{key:'k',ctrlKey:true,bubbles:true}));
    const pal = await until(()=>q('.pal input')); type(pal,'testserver'); await until(()=>byText('.pi','testserver'));
    pal.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
    const key = await until(()=>q('.dlg'));
    const keyText = key?.textContent ?? '';
    qa('.dlg .btn').find(b=>b.textContent.includes('Vertrauen')).click();
    const field = await until(()=>q('.dlg input[type=password]'));
    const passwordText = q('.dlg')?.textContent ?? '';
    type(field,'falsch'); await wait(80); q('.dlg button[type=submit]').click();
    const retry = await until(()=>q('.dlg .errline')?.textContent);
    type(q('.dlg input[type=password]'),'richtig'); q('.dlg input[type=checkbox]').click(); await wait(80);
    q('.dlg button[type=submit]').click();
    const connected = await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    await wait(1200);
    const st = await invoke('vault_status');
    return { id: saved.id, keyText, passwordText, retry, connected: !!connected, tab: q('.tabs .tab.on .nm')?.textContent, canvas: !!q('.pane:not(.off) canvas'),
      known: st.data.knownHosts.map(k=>k.host+':'+k.port+' '+k.algorithm), host: st.data.hosts.find(h=>h.id===saved.id) };
  `);
  ok('prompt about the unknown server shows address and fingerprint', opened.keyText.includes(`127.0.0.1:${port}`) && opened.keyText.includes('SHA256:'));
  ok('a wrong password leads to a second prompt', opened.passwordText.includes('testserver') && /Versuch 2/.test(opened.retry ?? ''), opened.retry);
  ok('connection is up', opened.connected && opened.tab === 'testserver', opened.canvas ? 'terminal with WebGL' : 'terminal without WebGL');
  ok('server key stored in the vault', opened.known.join() === `127.0.0.1:${port} ssh-ed25519`, opened.known.join());
  ok('typed password saved, system detected', opened.host?.hasPassword === true && opened.host.os === 'Ub', `os=${opened.host?.os}`);
  const logo = await run(page, `const tile = q('.sview:not(.off) .tbar .os.logo'); return { drawn: !!tile?.querySelector('svg path'), text: tile?.textContent.trim(), name: tile?.title };`);
  ok('the detected system shows its logo instead of a code', logo.drawn && logo.text === '' && logo.name === 'Ubuntu', logo.name);
  await typeLine(page, 'size');
  await sleep(600);
  await shot(page, 'terminal');

  // Right-click like in Termius: with a selection copy, without a selection paste, never a menu.
  // The clipboard belongs to the user; its text is remembered and put back at the end.
  const clipRead = () => run(page, `return await invoke('plugin:clipboard-manager|read_text').catch(()=>null)`);
  const clipWrite = (text) => run(page, `await invoke('plugin:clipboard-manager|write_text',{text:${JSON.stringify(text)}})`);
  const clipBefore = await clipRead();
  const area = await run(page, `
    const r = q('.pane:not(.off) .xterm-screen').getBoundingClientRect();
    return { x: r.left, y: r.top, w: r.width, h: r.height };
  `);
  await clipWrite('glowport-e2e-platzhalter');
  // Select the terminal's first lines: greeting, input “size” and the reported size.
  await drag(page, area.x + 3, area.y + 3, area.x + 400, area.y + 140);
  await rightClick(page, area.x + area.w / 2, area.y + area.h / 2);
  const copied = await clipRead();
  ok('right-click with a selection copies', !!copied?.includes('Welcome to the test server') && copied.includes('$ size'), JSON.stringify(copied?.slice(0, 60)));
  ok('right-click in the terminal opens no menu', (await menuPrevented(page)) === true);
  await clipWrite('exit');
  await rightClick(page, area.x + area.w / 2, area.y + area.h / 2);
  // If the selection were still there, the second right-click would have copied again instead of pasting.
  ok('copying clears the selection', (await clipRead()) === 'exit' && (await menuPrevented(page)) === true);
  await pressEnter(page);
  const left = await run(page, `
    const bar = await until(()=>q('.pane:not(.off) .endbar')?.textContent);
    qa('.pane:not(.off) .endbar .btn').find(b=>b.textContent.includes('Neu verbinden')).click();
    const again = await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    const asked = !!q('.dlg');
    return { bar, again: !!again, asked };
  `);
  // “exit” only came via the clipboard; if something from copying were in the input line, the session would stay open.
  ok('right-click without a selection pastes: exit ends the session', /Server hat die Sitzung beendet/.test(left.bar ?? ''), left.bar?.trim().slice(0, 50));
  if (typeof clipBefore === 'string') await clipWrite(clipBefore);
  ok('reconnecting needs no prompts', left.again && !left.asked);
  await typeLine(page, 'drop');
  const dropped = await run(page, `
    const bar = await until(()=>q('.pane:not(.off) .endbar')?.textContent);
    const again = await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    q('.tabs .tab.on .x').click(); await wait(300);
    return { bar, again: !!again, tabs: qa('.tabs .tab').length, live: await invoke('session_count') };
  `);
  ok('a dropped connection is reported and reconnected on its own', /abgerissen/.test(dropped.bar ?? '') && /Neuer Versuch/.test(dropped.bar ?? '') && dropped.again, dropped.bar?.trim().slice(0, 60));
  ok('closing the tab disconnects the session', dropped.tabs === 1 && dropped.live === 0, `${dropped.live} sessions`);

  // 4c. Quick connect via search, warning when closing with a running session, then save as a host.
  const quick = await run(page, `
    window.dispatchEvent(new KeyboardEvent('keydown',{key:'k',ctrlKey:true,bubbles:true}));
    const pal = await until(()=>q('.pal input')); type(pal,'ssh tester@127.0.0.1 -p ${port}'); await until(()=>byText('.pi','Direkt verbinden'));
    pal.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
    const field = await until(()=>q('.dlg input[type=password]'));
    const dialog = q('.dlg')?.textContent ?? ''; const canSave = !!q('.dlg input[type=checkbox]');
    type(field,'richtig'); await wait(80); q('.dlg button[type=submit]').click();
    const connected = await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    q('.wc .cl').click(); const warn = await until(()=>q('.dlg')); const warnText = warn?.textContent ?? '';
    byText('.dlg .btn','Abbrechen').click(); await wait(300);
    const still = !!q('.sview:not(.off) .live.connected');
    byText('.sview:not(.off) .tbar .btn','Als Host speichern').click();
    const renamed = await until(()=>q('.tabs .tab.on .nm')?.textContent === '127.0.0.1');
    const made = (await invoke('vault_status')).data.hosts.find(h=>h.name==='127.0.0.1');
    q('.tabs .tab.on .x').click(); await wait(300);
    if (made) await invoke('host_delete',{id:made.id});
    return { dialog, canSave, connected: !!connected, warnText, still, renamed: !!renamed, made };
  `);
  ok('quick connect recognises the known server and only asks for the password', quick.dialog.includes('tester@127.0.0.1') && !quick.canSave && quick.connected);
  ok('closing with a running session asks first', quick.warnText.includes('beenden') && quick.still, quick.warnText.trim().slice(0, 40));
  ok('Schnellverbindung als Host gespeichert', quick.renamed && quick.made?.own.user === 'tester' && quick.made.own.port === port);

  // 4d. Keys and identities: generate, give to an identity and sign in with it without a password.
  const keyMade = await run(page, `
    qa('.nv')[1].click(); await until(()=>byText('.acts .btn','Schlüssel erzeugen'));
    byText('.acts .btn','Schlüssel erzeugen').click(); await until(()=>q('.editor .seg'));
    type(q('.editor .fld input'),'e2e-schluessel'); await wait(80);
    q('.editor button[type=submit]').click();
    const shown = (await until(()=>q('.editor .pubkey')))?.textContent ?? '';
    return { shown, key: (await invoke('vault_status')).data.keys[0], card: !!byText('.host','e2e-schluessel') };
  `);
  const madeKey = keyMade.key;
  ok('key generated through the interface', madeKey?.kind === 'ed25519' && madeKey.origin === 'generated' && /^ssh-ed25519 \S+ e2e-schluessel$/.test(madeKey.publicKey) && keyMade.card);
  ok('details show the public key, the core does not hand out the private one', keyMade.shown === madeKey?.publicKey && !JSON.stringify(madeKey).includes('PRIVATE') && madeKey.fingerprint.startsWith('SHA256:'));

  const identity = await run(page, `
    byText('.acts .btn','Neue Identität').click(); await until(()=>byText('.editor .d-sub','Neue Identität'));
    const f = qa('.editor .fld input'); type(f[0],'E2E'); type(f[1],'tester');
    const select = q('.editor select'); select.value = '${madeKey.id}'; select.dispatchEvent(new Event('change',{bubbles:true})); await wait(80);
    q('.editor button[type=submit]').click();
    await until(()=>byText('.host','E2E'));
    return (await invoke('vault_status')).data.identities[0];
  `);
  ok('identity with key created', identity?.user === 'tester' && identity.key === madeKey.id && identity.hasPassword === false);

  // In place: generate a new key in an identity's editor; it is selected right away afterwards.
  const inPlace = await run(page, `
    byText('.acts .btn','Neue Identität').click(); await until(()=>byText('.editor .d-sub','Neue Identität'));
    const select = q('.editor select');
    const offers = [...select.querySelectorAll('optgroup option')];
    const create = offers.find(o => o.textContent.includes('erzeugen'));
    select.value = create.value; select.dispatchEvent(new Event('change',{bubbles:true}));
    const dialog = await until(()=>q('.ov.quick .editor'));
    const stayed = select.value;
    type(dialog.querySelector('.fld input'),'zz-an-ort-und-stelle'); await wait(80);
    dialog.querySelector('button[type=submit]').click();
    await until(()=>!q('.ov.quick'));
    const made = (await invoke('vault_status')).data.keys.find(k => k.name === 'zz-an-ort-und-stelle');
    const chosen = select.value;
    byText('.editor .btn','Abbrechen').click(); await wait(200);
    if (made) await invoke('key_delete', { id: made.id });
    return { offers: offers.map(o => o.textContent.trim()), stayed, made: made?.id, chosen };
  `);
  ok('a key can be created in the identity editor and is selected afterwards', inPlace.offers.length === 2 && inPlace.stayed === '' && !!inPlace.made && inPlace.chosen === inPlace.made, inPlace.offers.join(' | '));
  await shot(page, 'schluessel');

  // Certificate: a certificate authority of our own certifies the key. The test server only trusts it; it does not
  // know the key itself yet.
  const publicFile = join(workDir, 'e2e-schluessel.pub');
  writeFileSync(publicFile, `${madeKey.publicKey}\n`);
  execFileSync('ssh-keygen', ['-q', '-s', caKey, '-I', 'e2e-zertifikat', '-n', 'tester', '-V', '+1h', publicFile]);
  const certificateText = readFileSync(join(workDir, 'e2e-schluessel-cert.pub'), 'utf8');
  const certified = await run(page, `
    byText('.host','e2e-schluessel').click(); await until(()=>byText('.editor .btn','Zertifikat hinzufügen'));
    byText('.editor .btn','Zertifikat hinzufügen').click(); const area = await until(()=>q('.dlg textarea'));
    type(area,'ssh-ed25519-cert-v01@openssh.com Unsinn'); await wait(80);
    byText('.dlg .btn','Hinzufügen').click();
    const refused = await until(()=>q('.dlg .errline')?.textContent);
    type(area, ${JSON.stringify(certificateText)}); await wait(80);
    byText('.dlg .btn','Hinzufügen').click();
    await until(()=>byText('.editor .chip','e2e-zertifikat'));
    return { refused, panel: q('.editor').textContent, certificate: (await invoke('vault_status')).data.keys[0].certificate };
  `);
  ok('certificate stored with the key, nonsense is rejected', certified.certificate?.keyId === 'e2e-zertifikat' && certified.certificate.principals.join() === 'tester' && certified.panel.includes('Gilt für: tester') && /kein Zertifikat/.test(certified.refused ?? ''), certified.refused);

  // The new host has no password, and the server does not know the key: only the certificate gets in.
  const viaKey = await run(page, `
    qa('.nv')[0].click(); await until(()=>byText('.acts .btn','Neuer Host'));
    byText('.acts .btn','Neuer Host').click(); await until(()=>q('.editor'));
    const f = qa('.editor .fld input'); type(f[0],'schluessel-host'); type(f[1],'127.0.0.1');
    const pick = qa('.editor .inh-row select')[0]; pick.value = '${identity.id}'; pick.dispatchEvent(new Event('change',{bubbles:true}));
    type(qa('.editor .inh-row input')[1],'${port}'); await wait(120);
    const userHint = qa('.editor .inh-row input')[0].placeholder;
    q('.editor button[type=submit]').click();
    const detail = (await until(()=>q('.detail'))).textContent;
    byText('.detail .btn','Verbinden').click();
    const connected = await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    return { userHint, detail, connected: !!connected, asked: !!q('.dlg') };
  `);
  ok('host takes user and key from the identity', viaKey.userHint === 'tester' && viaKey.detail.includes('aus Identität „E2E“') && viaKey.detail.includes('e2e-schluessel'), viaKey.userHint);
  ok('sign-in with key and certificate, without the server knowing the key', viaKey.connected && !viaKey.asked && !existsSync(authorizedKeys));

  // Continue without certificate: from now on the server should know the key itself.
  const plain = await run(page, `
    q('.tabs .tab.on .x').click(); await wait(300);
    qa('.nv')[1].click(); await until(()=>byText('.host','e2e-schluessel'));
    byText('.host','e2e-schluessel').click(); await until(()=>byText('.editor .btn','Zertifikat entfernen'));
    byText('.editor .btn','Zertifikat entfernen').click(); await until(()=>byText('.editor .btn','Zertifikat hinzufügen'));
    return (await invoke('vault_status')).data.keys[0].certificate ?? null;
  `);
  ok('Zertifikat entfernt', plain === null);


  // Copy the public key to the test server through the dialog. Signing in uses the saved password.
  const deploy = async () =>
    run(page, `
      byText('.host','e2e-schluessel').click(); await until(()=>byText('.editor .btn','Auf Hosts kopieren'));
      byText('.editor .btn','Auf Hosts kopieren').click(); await until(()=>q('.picklist'));
      const adopt = q('.dlg .check input').checked;
      byText('.pick','testserver').querySelector('input').click(); await wait(100);
      byText('.dlg .btn','Auf 1 Hosts kopieren').click();
      await until(()=>byText('.dlg .btn','Schließen'), 30000);
      const result = byText('.pick','testserver').querySelector('.chip')?.textContent.trim();
      const summary = qa('.dlg .fld-h').at(-1)?.textContent.trim();
      byText('.dlg .btn','Schließen').click(); await wait(200);
      return { adopt, result, summary, own: (await invoke('vault_status')).data.hosts.find(h => h.name === 'testserver').own };
    `);
  const deployed = await deploy();
  const onServer = existsSync(authorizedKeys) ? readFileSync(authorizedKeys, 'utf8') : '';
  ok('key copied to the host through the dialog', deployed.result === 'Eingetragen' && onServer.trim() === madeKey.publicKey, `${deployed.result}: ${deployed.summary}`);
  ok('afterwards the host signs in with this key (checkbox preset)', deployed.adopt === true && deployed.own.key === madeKey.id);
  const repeated = await deploy();
  ok('a second copy adds nothing twice', repeated.result === 'War schon dort' && readFileSync(authorizedKeys, 'utf8') === onServer, repeated.result);

  // Key file with passphrase: at the prompt, tick that the key should go into the vault. Afterwards the host
  // signs in without a passphrase. The server knows the key because it is in authorized_keys.
  const fileKey = join(workDir, 'datei-schluessel');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', 'datei-passphrase', '-C', 'datei', '-f', fileKey]);
  writeFileSync(authorizedKeys, onServer + readFileSync(`${fileKey}.pub`, 'utf8'));
  const adopted = await run(page, `
    const read = await invoke('key_read_file', { path: ${JSON.stringify(fileKey)} });
    const made = await invoke('host_save', { host: { name: 'datei-host', address: '127.0.0.1', group: null, color: null, os: null, own: { user: 'tester', port: ${port}, keyFile: ${JSON.stringify(fileKey)} } } });
    qa('.nv')[0].click(); const card = await until(()=>byText('.host','datei-host'));
    card.dispatchEvent(new MouseEvent('dblclick',{bubbles:true}));
    const field = await until(()=>q('.dlg input[type=password]'), 15000);
    const dialog = q('.dlg')?.textContent ?? '';
    const box = q('.dlg input[type=checkbox]'); const preset = box?.checked;
    type(field,'falsch'); await wait(80); q('.dlg button[type=submit]').click();
    const retry = await until(()=>q('.dlg .errline')?.textContent);
    type(q('.dlg input[type=password]'),'datei-passphrase'); q('.dlg input[type=checkbox]').click(); await wait(80);
    q('.dlg button[type=submit]').click();
    const connected = await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    await wait(600);
    const after = (await invoke('vault_status')).data;
    const host = after.hosts.find(h => h.id === made.id); const key = after.keys.find(k => k.name === 'datei-schluessel');
    // Neu verbinden: Der Schlüssel kommt jetzt aus dem Tresor, niemand fragt mehr.
    q('.tabs .tab.on .x').click(); await wait(300);
    byText('.host','datei-host').dispatchEvent(new MouseEvent('dblclick',{bubbles:true}));
    const again = await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    const asked = !!q('.dlg');
    q('.tabs .tab.on .x').click(); await wait(300);
    if (key) await invoke('key_delete', { id: key.id });
    await invoke('host_delete', { id: made.id });
    return { read: read.text.includes('OPENSSH PRIVATE KEY'), dialog, preset, retry, connected: !!connected, own: host?.own, key: key?.id, origin: key?.origin, again: !!again, asked, leak: JSON.stringify(after).includes('PRIVATE KEY') };
  `);
  writeFileSync(authorizedKeys, onServer);
  ok('the passphrase prompt offers to take the key into the vault', adopted.read && adopted.dialog.includes('Schlüssel in den Tresor übernehmen') && adopted.preset === false && /Versuch 2/.test(adopted.retry ?? ''), adopted.retry);
  ok('after signing in the key file is in the vault and the host uses it', adopted.connected && !!adopted.key && adopted.own?.key === adopted.key && adopted.origin === 'imported' && !adopted.leak);
  ok('afterwards the host connects without a passphrase', adopted.again && !adopted.asked);

  // Through a jump host: the test server forwards to itself. No password is stored for the jump host,
  // so Glowport asks for exactly that hop. Plus startup command and environment variable on the destination.
  const viaJump = await run(page, `
    qa('.nv')[0].click(); await until(()=>byText('.host','schluessel-host'));
    byText('.host','schluessel-host').click(); await until(()=>q('.detail'));
    const target = (await invoke('vault_status')).data.hosts.find(h => h.name === 'schluessel-host');
    const hop = await invoke('host_save', { host: { name: 'sprung', address: '127.0.0.1', group: null, color: null, os: null, own: { user: 'tester', port: ${port} } } });
    const broken = await fails(invoke('host_save', { host: { ...target, own: { ...target.own, env: 'kaputt' } } }));
    // Der Agent ist eingeschaltet: Läuft auf diesem Rechner keiner, geht es still mit dem Schlüssel aus dem Tresor weiter.
    const badProxy = await fails(invoke('host_save', { host: { ...target, own: { ...target.own, proxy: 'ich:geheim@proxy' } } }));
    const proxied = await invoke('host_save', { host: { ...target, own: { ...target.own, proxy: 'socks5://ich@127.0.0.1:9' }, proxyPassword: 'proxy-geheim' } });
    const proxyKept = proxied.data.hosts.find(h => h.id === target.id).hasProxyPassword === true && !JSON.stringify(proxied).includes('proxy-geheim');
    const fine = { term: 'vt100', keepalive: 0, timeout: 20, charset: 'iso-8859-1', legacy: true };
    await invoke('host_save', { host: { ...target, own: { ...target.own, ...fine, jump: hop.id, startcmd: 'env', env: 'STUFE=e2e', agent: true, agentForward: true } } });
    const agents = await invoke('agent_list');
    byText('.detail .btn','Verbinden').click();
    const field = await until(()=>q('.dlg input[type=password]'), 15000);
    const dialog = q('.dlg')?.textContent ?? '';
    type(field,'richtig'); q('.dlg input[type=checkbox]').click(); await wait(80);
    q('.dlg button[type=submit]').click();
    const connected = await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    await wait(1200);
    const hosts = (await invoke('vault_status')).data.hosts;
    return { broken: broken?.reason, badProxy: badProxy?.reason, proxyKept, dialog, connected: !!connected, agents, hop: hosts.find(h => h.id === hop.id), target: hosts.find(h => h.id === target.id) };
  `);
  ok('the jump host asks for its own password', viaJump.dialog.includes(`Passwort für tester@127.0.0.1:${port}`) && viaJump.dialog.includes('Sprung-Server'), viaJump.dialog.trim().slice(0, 70));
  ok('connection through the jump host is up (now with the copied key), its password is stored with it and not with the destination', viaJump.connected && viaJump.hop?.hasPassword === true && viaJump.target?.hasPassword === false);
  ok('this computer\'s agents are queried', viaJump.agents.map(a => a.kind).join() === 'openssh,pageant' && viaJump.agents.every(a => typeof a.running === 'boolean' && Array.isArray(a.keys)) && viaJump.target?.own.agent === true, viaJump.agents.map(a => `${a.kind}: ${a.running ? a.keys.length + ' keys' : 'not running'}`).join(', '));
  const shell = await terminalText(page);
  ok('startup command and environment variable arrive in the shell', shell.includes('$ env') && shell.includes('STUFE=e2e') && viaJump.broken === 'env_invalid', JSON.stringify(shell.slice(0, 90)));
  // The host speaks ISO-8859-1: “ä” goes out as one byte. The test server takes that for broken UTF-8 and answers
  // with the replacement character in UTF-8, whose three bytes arrive here as three characters.
  await typeLine(page, 'term');
  await typeLine(page, 'ä');
  await sleep(600);
  const fineShell = await terminalText(page);
  ok('the host\'s terminal type and character set apply', fineShell.includes('vt100') && fineShell.includes('unknown: ï¿½'), JSON.stringify(fineShell.slice(-60)));
  ok('proxy: a password in the address is rejected, its own field stays in the core', viaJump.badProxy === 'proxy_invalid' && viaJump.proxyKept === true);

  // Importing runs through the commands: the test cannot operate the file dialog.
  const encryptedKey = readFileSync(resolve('crates/net/tests/keys/openssh_ed25519_enc'), 'utf8');
  const imported = await run(page, `
    q('.tabs .tab.on .x').click(); await wait(300);
    const text = ${JSON.stringify(encryptedKey)};
    const info = await invoke('key_inspect', { text });
    const garbage = await fails(invoke('key_inspect', { text: 'Hallo' }));
    const none = await fails(invoke('key_import', { key: { name: 'e2e-import', text } }));
    const wrong = await fails(invoke('key_import', { key: { name: 'e2e-import', text, passphrase: 'falsch' } }));
    const done = await invoke('key_import', { key: { name: 'e2e-import', text, passphrase: 'geheim' } });
    return { info, garbage: garbage?.code, none: none?.code, wrong: wrong?.code, key: done.data.keys.find(k => k.id === done.id) };
  `);
  ok('the key file is recognised before the import', imported.info.format === 'openssh' && imported.info.encrypted && imported.info.kind === 'ed25519' && imported.garbage === 'key_unreadable');
  ok('import requires and checks the passphrase', imported.none === 'passphrase_required' && imported.wrong === 'wrong_passphrase' && imported.key?.fingerprint === 'SHA256:+mcbLMkgoIlEAnnSBVbTyfVSZUNm5w/PZWj1l+QQtwg' && imported.key.origin === 'imported');

  const cleaned = await run(page, `
    const afterKey = await invoke('key_delete', { id: '${madeKey.id}' });
    const hostId = afterKey.data.hosts.find(h => h.name === 'schluessel-host').id;
    const afterIdentity = await invoke('identity_delete', { id: '${identity.id}' });
    const own = afterIdentity.data.hosts.find(h => h.id === hostId).own;
    await invoke('host_delete', { id: hostId });
    const end = await invoke('host_delete', { id: afterKey.data.hosts.find(h => h.name === 'sprung').id });
    const adopted = afterKey.data.hosts.find(h => h.name === 'testserver').own.key;
    return { loose: afterKey.data.identities[0].key, adopted, own, keys: end.data.keys.map(k => k.name), identities: end.data.identities.length };
  `);
  ok('deleting clears the references in identity and host', cleaned.loose === null && cleaned.adopted === undefined && cleaned.own.identity === undefined && cleaned.keys.join() === 'e2e-import' && cleaned.identities === 0, JSON.stringify(cleaned.own));

  // 4e. Certificate authority for servers: the known entry for the test server is removed. Still no
  // prompt comes, because it shows a valid certificate from the trusted authority for its address.
  const caPublic = readFileSync(`${caKey}.pub`, 'utf8');
  const certifiedHost = await run(page, `
    qa('.nv')[5].click(); await until(()=>byText('.acts .btn','Zertifizierungsstelle'));
    byText('.acts .btn','Zertifizierungsstelle').click(); await until(()=>q('.dlg textarea'));
    const f = qa('.dlg .fld input'); type(f[0],'E2E-Stelle'); type(f[1],'127.0.0.1');
    type(q('.dlg textarea'),'kein Schlüssel'); await wait(80);
    q('.dlg button[type=submit]').click();
    const refused = await until(()=>q('.dlg .errline')?.textContent);
    type(q('.dlg textarea'), ${JSON.stringify(caPublic)}); await wait(80);
    q('.dlg button[type=submit]').click();
    const row = await until(()=>byText('.row','E2E-Stelle'));
    const rowText = row.textContent;
    for (const known of (await invoke('vault_status')).data.knownHosts) await invoke('known_host_delete', { id: known.id });
    qa('.nv')[0].click(); await until(()=>byText('.host','testserver'));
    byText('.host','testserver').click(); await until(()=>q('.detail'));
    byText('.detail .btn','Verbinden').click();
    const connected = await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    const asked = !!q('.dlg');
    const after = (await invoke('vault_status')).data;
    q('.tabs .tab.on .x').click(); await wait(300);
    await invoke('authority_delete', { id: after.authorities[0].id });
    return { refused, rowText, connected: !!connected, asked, known: after.knownHosts.length, authority: after.authorities[0] };
  `);
  ok('certificate authority added through the interface', certifiedHost.authority?.pattern === '127.0.0.1' && certifiedHost.authority.kind === 'Ed25519' && certifiedHost.rowText.includes('für 127.0.0.1') && !!certifiedHost.refused, certifiedHost.refused);
  ok('server with a certificate from the trusted authority: connection without a key prompt', certifiedHost.connected && !certifiedHost.asked && certifiedHost.known === 0);


  // 4f. Meilenstein 4 – geteilte Terminals, Multi-Exec, Umordnen, Tab umbenennen.
  const mid = `const mid = el => { const r = el.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2, l: r.left, t: r.top, w: r.width, h: r.height }; };`;
  // Move a host into a group by dragging and back out through the breadcrumbs.
  const carry = async (from, to) => {
    await mouse(page, 'mousePressed', from.x, from.y, 'left', 1);
    for (const part of [0.2, 0.5, 0.8, 1]) await mouse(page, 'mouseMoved', from.x + (to.x - from.x) * part, from.y + (to.y - from.y) * part, 'left', 1);
    await sleep(250);
    const hint = await run(page, `return { chip: q('.dragchip')?.textContent.trim() ?? '', marked: qa('.drop').length };`);
    await mouse(page, 'mouseReleased', to.x, to.y, 'left');
    await sleep(600);
    return hint;
  };
  const cards = await run(page, `${mid} return { host: mid(byText('.host','testserver')), group: mid(byText('.group:not(.ws)','Produktiv')) };`);
  const intoHint = await carry(cards.host, cards.group);
  const inGroup = await run(page, `
    const data = (await invoke('vault_status')).data; const host = data.hosts.find(h => h.name === 'testserver');
    byText('.group:not(.ws)','Produktiv').click(); await until(()=>byText('.host','testserver'));
    ${mid} return { group: host.group, expected: data.groups[0].id, password: host.hasPassword, user: host.own.user, from: mid(byText('.host','testserver')), to: mid(q('.crumbs button[data-group=""]')) };
  `);
  ok('host moved into a group by dragging, its values stay', intoHint.chip.includes('nach „Produktiv“') && intoHint.marked === 1 && inGroup.group === inGroup.expected && inGroup.password === true && inGroup.user === 'tester', intoHint.chip);
  const outHint = await carry(inGroup.from, inGroup.to);
  const outside = await run(page, `
    const host = (await invoke('vault_status')).data.hosts.find(h => h.name === 'testserver');
    q('.crumbs button[data-group=""]').click(); await until(()=>byText('.host','testserver'));
    return host.group;
  `);
  ok('through the breadcrumbs the host comes out of the group again', outHint.chip.includes('ohne Gruppe') && outside === null, outHint.chip);

  const split = await run(page, `
    byText('.host','testserver').click(); await until(()=>q('.detail'));
    byText('.detail .btn','Verbinden').click();
    // Der bekannte Eintrag wurde eben gelöscht, die Zertifizierungsstelle auch: Glowport fragt wieder nach dem Schlüssel.
    const key = await until(()=>q('.dlg'), 15000);
    qa('.dlg .btn').find(b=>b.textContent.includes('Vertrauen'))?.click();
    await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    q('.sview:not(.off) .tbar .btn[title^="Rechts teilen"]').click();
    await until(()=>qa('.pane:not(.off)').length === 2);
    const both = await until(()=>qa('.pane:not(.off) .pane-h .dot.connected').length === 2, 15000);
    await wait(800);
    return { asked: !!key, both: !!both, live: await invoke('session_count'), tab: q('.tabs .tab.on .nm')?.textContent, widths: qa('.pane:not(.off)').map(p=>Math.round(p.getBoundingClientRect().width)) };
  `);
  ok('split right opens a second pane to the same host', split.both && split.live === 2 && split.tab === 'testserver +1' && Math.abs(split.widths[0] - split.widths[1]) < 4, `widths ${split.widths.join(' / ')}`);

  // Without multi-exec only the pane with the keyboard gets the input, with multi-exec both.
  await typeLine(page, 'echo allein');
  await sleep(500);
  const alone = [await terminalText(page, 0), await terminalText(page, 1)];
  ok('without multi-exec, input only goes to the pane with the keyboard', !alone[0].includes('echo allein') && alone[1].includes('echo allein'));
  const multiOn = await run(page, `
    byText('.sview:not(.off) .tbar .btn','Multi-Exec').click();
    const banner = await until(()=>q('.mx')?.textContent);
    qa('.pane:not(.off) .xterm-helper-textarea')[1].focus();
    return { banner, marked: q('.tabs .tab.on').classList.contains('multi') };
  `);
  await typeLine(page, 'size');
  await sleep(700);
  const together = [await terminalText(page, 0), await terminalText(page, 1)];
  ok('multi-exec sends input to all panes of the tab', /alle 2 Terminals/.test(multiOn.banner ?? '') && multiOn.marked && together.every((text) => text.includes('$ size')), JSON.stringify(together[0].slice(-40)));

  // Grab the right pane by its header and put it to the left of the other one.
  const grab = await run(page, `${mid} const panes = qa('.pane:not(.off)'); return { names: panes.map(p=>p.dataset.pane), from: mid(panes[1].querySelector('.pane-h b')), to: mid(panes[0]) };`);
  await mouse(page, 'mousePressed', grab.from.x, grab.from.y, 'left', 1);
  for (const part of [0.2, 0.5, 0.8, 1]) await mouse(page, 'mouseMoved', grab.from.x + (grab.to.l + grab.to.w * 0.1 - grab.from.x) * part, grab.from.y + (grab.to.y - grab.from.y) * part, 'left', 1);
  await sleep(250);
  const preview = await run(page, `return { area: !!q('.droparea'), chip: q('.dragchip')?.textContent.trim() };`);
  await mouse(page, 'mouseReleased', grab.to.l + grab.to.w * 0.1, grab.to.y, 'left');
  await sleep(500);
  const moved = await run(page, `return { order: qa('.pane:not(.off)').sort((a,b)=>a.getBoundingClientRect().left-b.getBoundingClientRect().left).map(p=>p.dataset.pane), live: await invoke('session_count'), still: qa('.pane:not(.off) .pane-h .dot.connected').length };`);
  ok('Bereich per Ziehen umgeordnet, beide Sitzungen laufen weiter', preview.area && preview.chip === 'testserver' && moved.order.join() === [grab.names[1], grab.names[0]].join() && moved.live === 2 && moved.still === 2, moved.order.join(' | '));
  const kept = [await terminalText(page, 0), await terminalText(page, 1)];
  const stillMulti = await run(page, `return !!q('.mx') && q('.tabs .tab.on').classList.contains('multi')`);
  ok('the terminals keep their content when rearranged, multi-exec stays on', kept[0].includes('$ size') && !kept[0].includes('echo allein') && kept[1].includes('echo allein') && stillMulti, JSON.stringify(kept[1].slice(0, 50)));

  // Rename the tab (double-click) and save it as a workspace through the menu.
  const named = await run(page, `
    q('.tabs .tab.on').dispatchEvent(new MouseEvent('dblclick',{bubbles:true}));
    const field = await until(()=>q('.tab-name')); type(field,'Zwei Server');
    field.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true})); await wait(200);
    ${mid} return { name: q('.tabs .tab.on .nm')?.textContent, at: mid(q('.tabs .tab.on .nm')) };
  `);
  await rightClick(page, named.at.x, named.at.y);
  const stored = await run(page, `
    const menu = await until(()=>q('.menu')); const items = qa('.menu .mi').map(e=>e.textContent.trim());
    qa('.menu .sws button')[2].click(); await wait(150);
    const tint = getComputedStyle(q('.tabs .tab.on')).getPropertyValue('--c').trim();
    byText('.menu .mi','Als Arbeitsbereich speichern').click();
    const field = await until(()=>q('.dlg input[type=text]'));
    const prefilled = field.value; const boxes = qa('.dlg .lprev > div').length; const multi = q('.dlg .check input')?.checked;
    q('.dlg button[type=submit]').click(); await until(()=>!q('.dlg'));
    return { menu: !!menu, items, tint, prefilled, boxes, multi, workspaces: (await invoke('vault_status')).data.workspaces };
  `);
  ok('tab renamed and colored', named.name === 'Zwei Server' && stored.tint.toUpperCase() === '#F59E0B' && stored.items.includes('In eigenes Fenster'), stored.tint);
  const workspace = stored.workspaces[0];
  ok('tab stored in the vault as a workspace', stored.prefilled === 'Zwei Server' && stored.boxes === 2 && stored.multi === true && workspace?.name === 'Zwei Server' && workspace.multi === true && workspace.layout.dir === 'row' && workspace.layout.a.pane.kind === 'host' && workspace.layout.a.pane.id === workspace.layout.b.pane.id, JSON.stringify(workspace?.layout).slice(0, 70));

  // 4g. Recording: switch on, have something printed, switch off; the file is readable text without control characters.
  const logDir = join(workDir, 'data', 'logs');
  await run(page, `byText('.sview:not(.off) .tbar .btn','Multi-Exec').click(); await until(()=>!q('.mx')); byText('.sview:not(.off) .tbar .btn','Mitschnitt').click(); await until(()=>q('.pane:not(.off) .recdot'));`);
  await typeLine(page, 'echo mitgeschnitten');
  await sleep(700);
  const recording = await run(page, `
    const running = await invoke('log_list');
    const busy = await fails(invoke('log_delete', { id: running[0]?.id }));
    byText('.sview:not(.off) .tbar .btn','Mitschnitt').click(); await until(()=>!q('.pane:not(.off) .recdot'));
    const done = await invoke('log_list');
    const text = await invoke('log_read', { id: done[0].id });
    const outside = await fails(invoke('log_read', { id: '..\\\\vault.db' }));
    return { running, busy: busy?.code, done, text, outside: outside?.code };
  `);
  const logFile = recording.done[0]?.file ?? '';
  const onDisk = existsSync(logFile) ? readFileSync(logFile, 'utf8') : '';
  ok('recording runs per pane and cannot be deleted meanwhile', recording.running.length === 1 && recording.running[0].endedAt === null && recording.running[0].name === 'testserver' && recording.busy === 'log_running');
  ok('recording is stored as text without control characters in a file in the data folder', logFile.startsWith(logDir) && recording.text.includes('echo mitgeschnitten') && !recording.text.includes('\x1b') && onDisk.startsWith('# Glowport-Mitschnitt') && onDisk.includes(`tester@127.0.0.1:${port}`) && recording.done[0].endedAt >= recording.done[0].startedAt && recording.outside === 'not_found', JSON.stringify(recording.text.slice(0, 60)));
  const logPage = await run(page, `
    q('.tabs .tab.home').click(); await wait(200);
    qa('.nv')[6].click(); const row = await until(()=>byText('.pick-row','testserver'));
    row.click(); const shown = await until(()=>qa('.log-text div').some(d=>d.textContent.includes('mitgeschnitten')));
    // Umbenennen an Ort und Stelle: Stift, Namen tippen, Eingabetaste.
    q('.logview .btn[title="Umbenennen"]').click();
    const field = await until(()=>q('.logview .tab-name')); type(field,'Deploy: Probe'); await wait(80);
    field.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
    const listed = await until(()=>byText('.pick-row','Deploy: Probe'));
    const renamed = (await invoke('log_list'))[0];
    const still = qa('.log-text div').some(d=>d.textContent.includes('mitgeschnitten')) && q('.logview .d-name')?.textContent;
    const left = await invoke('log_delete', { id: renamed.id });
    return { shown: !!shown, listed: listed?.textContent ?? '', renamed, still, left: left.length };
  `);
  ok('Recordings page shows the text', logPage.shown);
  ok('recording renamed: name in the list, the file is called that afterwards, content and times stay', logPage.listed.includes('testserver') && logPage.renamed.title === 'Deploy: Probe' && logPage.renamed.name === 'testserver' && logPage.renamed.file.endsWith('_Deploy__Probe.log') && logPage.renamed.endedAt === recording.done[0].endedAt && logPage.still === 'Deploy: Probe' && !existsSync(logFile), logPage.renamed.file.split(/[\\/]/).pop());
  ok('deleting removes the recording\'s file', logPage.left === 0 && !existsSync(logPage.renamed.file));

  // 4h. Color scheme on the host: the pane gets the scheme's background. Plus a second tab from the workspace.
  const themed = await run(page, `
    const host = (await invoke('vault_status')).data.hosts.find(h => h.name === 'testserver');
    const bad = await fails(invoke('host_save', { host: { ...host, own: { ...host.own, scheme: 'Kein Schema!' } } }));
    await invoke('host_save', { host: { ...host, own: { ...host.own, scheme: 'dracula' } } });
    qa('.nv')[0].click(); const card = await until(()=>byText('.group.ws','Zwei Server'));
    card.dispatchEvent(new MouseEvent('dblclick',{bubbles:true}));
    await until(()=>qa('.pane:not(.off) .pane-h .dot.connected').length === 2, 15000);
    return { bad: bad?.reason, tabs: qa('.tabs .tab:not(.home)').map(t=>t.textContent.trim()), multi: !!q('.mx'), backgrounds: qa('.pane:not(.off)').map(p=>p.style.getPropertyValue('--pane-bg')), live: await invoke('session_count') };
  `);
  ok('the workspace opens its hosts in their layout, multi-exec is on', themed.tabs.length === 2 && themed.tabs[1].startsWith('Zwei Server') && themed.multi && themed.live === 4, themed.tabs.join(' | '));
  ok('the host\'s color scheme applies in its terminals', themed.bad === 'scheme_invalid' && themed.backgrounds.every((bg) => bg.toLowerCase().startsWith('#282a36')), themed.backgrounds.join());

  // 4i. Tab into a window of its own and back: the sessions keep running, the content moves along.
  await run(page, `q('.tabs .tab.on .x').click(); await wait(400); qa('.tabs .tab:not(.home)')[0].click(); await wait(300);`);
  await typeLine(page, 'echo before-the-move');
  await sleep(500);
  const before = await run(page, `${mid} return { live: await invoke('session_count'), at: mid(q('.tabs .tab.on .nm')) };`);
  await rightClick(page, before.at.x, before.at.y);
  await run(page, `await until(()=>q('.menu')); byText('.menu .mi','In eigenes Fenster').click(); await until(()=>qa('.tabs .tab:not(.home)').length === 0);`);
  const second = await connect([page.target]);
  const inWindow = await run(second, `
    const both = await until(()=>qa('.pane:not(.off) .pane-h .dot.connected').length === 2, 15000);
    await wait(900);
    return { both: !!both, label: window.__TAURI_INTERNALS__.metadata.currentWindow.label, home: !!q('.tabs .tab.home'), nav: !!q('.nav'), tab: q('.tabs .tab.on .nm')?.textContent, live: await invoke('session_count'), vault: (await invoke('vault_status')).state };
  `);
  ok('the tab opens as a window of its own without a start tab, the vault is open there', inWindow.both && inWindow.label.startsWith('tab-') && !inWindow.home && !inWindow.nav && inWindow.tab === 'Zwei Server' && inWindow.vault === 'open', inWindow.label);
  ok('the sessions were not reconnected in the process', before.live === 2 && inWindow.live === 2 && (await run(page, `return await invoke('session_count')`)) === 2);
  // Reading goes through the Windows clipboard. If copying fails in one of the two panes, its text contains
  // what was on the clipboard before; that is why the output names the start of both texts.
  const carriedPanes = [await terminalText(second, 0), await terminalText(second, 1)];
  const carried = carriedPanes.join('');
  ok('the terminal\'s content moved along', carried.includes('echo before-the-move') && carried.includes('Welcome to the test server'), JSON.stringify(carriedPanes.map((text) => `${text.length}: ${text.slice(0, 40)}`)));
  await run(second, `qa('.pane:not(.off) .xterm-helper-textarea')[0].focus();`);
  await typeLine(second, 'echo im-neuen-fenster');
  await sleep(600);
  const typed = (await terminalText(second, 0)) + (await terminalText(second, 1));
  ok('work continues in the new window', typed.includes('echo im-neuen-fenster'));
  // A host renamed by the main window is called that in the other window at once too.
  const synced = await run(page, `
    const host = (await invoke('vault_status')).data.hosts.find(h => h.name === 'testserver');
    await invoke('host_save', { host: { ...host, name: 'testserver-neu' } });
    return host.id;
  `);
  const seen = await run(second, `return !!(await until(()=>qa('.pane:not(.off) .pane-h b').every(b=>b.textContent === 'testserver-neu'), 5000));`);
  await run(page, `const host = (await invoke('vault_status')).data.hosts.find(h => h.id === '${synced}'); await invoke('host_save', { host: { ...host, name: 'testserver' } });`);
  ok('changes to the vault arrive in all windows', seen);
  const tabAt = await run(second, `${mid} return mid(q('.tabs .tab.on .nm'));`);
  await rightClick(second, tabAt.x, tabAt.y);
  await run(second, `await until(()=>q('.menu')); byText('.menu .mi','Zurück ins Hauptfenster').click();`).catch(() => {});
  second.close();
  const back = await run(page, `
    const both = await until(()=>qa('.pane:not(.off) .pane-h .dot.connected').length === 2, 15000);
    await wait(900);
    return { both: !!both, tab: q('.tabs .tab.on .nm')?.textContent, live: await invoke('session_count') };
  `);
  const windows = (await listPages()).length;
  ok('Back to main window: tab and sessions are back, the second window is closed', back.both && back.tab === 'Zwei Server' && back.live === 2 && windows === 1, `${windows} windows`);
  const returned = (await terminalText(page, 0)) + (await terminalText(page, 1));
  ok('the content is kept on the way back too', returned.includes('echo im-neuen-fenster'));
  await run(page, `q('.tabs .tab.on .x').click(); await wait(400); const ws = (await invoke('vault_status')).data.workspaces[0]; await invoke('workspace_delete', { id: ws.id });`);
  ok('closing the tab disconnects all its sessions', (await run(page, `await wait(300); return await invoke('session_count')`)) === 0);

  // 4j. Files: the test server shows a folder of this machine over SFTP as its file system.
  const hostId = await run(page, `return (await invoke('vault_status')).data.hosts.find(h => h.name === 'testserver').id`);
  const place = JSON.stringify({ kind: 'host', id: hostId });
  const DONE = `const done = async (ids, ms = 90000) => { const end = Date.now() + ms; while (Date.now() < end) { const list = (await invoke('transfer_list')).filter(x => ids.includes(x.id)); if (list.length === ids.length && list.every(x => ['done','failed','cancelled'].includes(x.state))) return list; await wait(150); } return null };`;
  const filesPage = await run(page, `
    q('.tabs .tab.home')?.click(); qa('.nv')[4].click();
    await until(()=>qa('.fcol').length === 2 && qa('.fcol')[0].querySelectorAll('.frow').length > 0, 10000);
    const label = i => qa('.fcol')[i].querySelector('.flist')?.getAttribute('aria-label');
    const select = qa('.fcol')[1].querySelector('select'); select.value = '${hostId}'; select.dispatchEvent(new Event('change',{bubbles:true}));
    await until(()=>label(1) === '/home/tester', 15000);
    return { left: label(0), right: label(1), note: qa('.fcol')[1].querySelector('.fnote')?.textContent.trim(), home: await invoke('fs_home', { place: ${place} }), page: !!q('.fmid') };
  `);
  ok('Files page: this PC on the left, on the right the host connects without a prompt in its home directory', filesPage.page && !!filesPage.left && filesPage.right === '/home/tester' && filesPage.home === '/home/tester', filesPage.note ?? '');

  const ops = await run(page, `
    const place = ${place};
    const names = async (path) => (await invoke('fs_list', { place, path })).entries.map(e => e.name).sort().join();
    const before = await names('/srv/app');
    await invoke('fs_mkdir', { place, dir: '/srv/app', name: 'neu' });
    const twice = await fails(invoke('fs_mkdir', { place, dir: '/srv/app', name: 'neu' }));
    const badName = await fails(invoke('fs_mkdir', { place, dir: '/srv/app', name: 'a/b' }));
    await invoke('fs_rename', { place, path: '/srv/app/neu', name: 'archiv' });
    const taken = await fails(invoke('fs_rename', { place, path: '/srv/app/notes.txt', name: 'archiv' }));
    await invoke('fs_write', { place, path: '/srv/app/archiv/drin.txt', text: 'inhalt' });
    await invoke('fs_chmod', { place, request: { paths: ['/srv/app/archiv'], mode: 0o700, owner: null, group: null, recursive: true } });
    const listed = await invoke('fs_list', { place, path: '/srv/app/archiv/../archiv' });
    const read = await invoke('fs_read', { place, path: '/srv/app/config.yaml' });
    await invoke('fs_write', { place, path: '/srv/app/config.yaml', text: read.text + 'neu: ja\\n' });
    const image = await invoke('fs_read', { place, path: '/srv/app/bild.png' });
    const bytes = new Uint8Array(await invoke('fs_read_bytes', { place, path: '/srv/app/bild.png' }));
    const binary = await invoke('fs_read', { place, path: '/srv/app/roh.bin' });
    const locked = await fails(invoke('fs_write', { place, path: '/etc/hosts', text: 'x' }));
    const missing = await fails(invoke('fs_list', { place, path: '/gibt/es/nicht' }));
    const notDir = await fails(invoke('fs_list', { place, path: '/srv/app/notes.txt' }));
    const after = await names('/srv/app');
    await invoke('fs_remove', { place, paths: ['/srv/app/archiv'] });
    return { before, twice: twice?.code, badName: badName?.code, taken: taken?.code, entry: listed.entries[0], path: listed.path, crumbs: listed.crumbs.map(c=>c.path).join(' '), parent: listed.parent, read, image, bytes: [...bytes.slice(0, 4)], binary: binary.kind, locked: locked?.code, missing: missing?.code, notDir: notDir?.code, after, end: await names('/srv/app') };
  `);
  ok('list, create, rename folders on the server; existing and invalid names are rejected', ops.before === 'bild.png,config.yaml,notes.txt,roh.bin' && ops.twice === 'file_exists' && ops.badName === 'name_required' && ops.taken === 'file_exists' && ops.after === 'archiv,bild.png,config.yaml,notes.txt,roh.bin', ops.after);
  ok('the core normalises paths: path from the root and the folder above', ops.path === '/srv/app/archiv' && ops.crumbs === '/ /srv /srv/app /srv/app/archiv' && ops.parent === '/srv/app', ops.crumbs);
  ok('changing permissions also affects the folder\'s content', ops.entry?.name === 'drin.txt' && ops.entry.mode === 0o700 && ops.entry.owner === 'tester', `${ops.entry?.mode?.toString(8)} ${ops.entry?.owner}`);
  ok('read a file and write it back changed', ops.read.kind === 'text' && ops.read.editable && ops.read.text === 'port: 3000\n' && readFileSync(join(serverFiles, 'srv', 'app', 'config.yaml'), 'utf8') === 'port: 3000\nneu: ja\n');
  ok('images come as bytes, other binary data is not shown as text', ops.image.kind === 'image' && ops.image.mime === 'image/png' && ops.bytes.join() === '137,80,78,71' && ops.binary === 'binary', ops.bytes.join());
  ok('errors come as codes: locked folder, missing path, file instead of folder', ops.locked === 'permission_denied' && ops.missing === 'no_such_file' && ops.notDir === 'not_a_directory' && readFileSync(join(serverFiles, 'etc', 'hosts'), 'utf8') === '127.0.0.1 localhost\n', `${ops.locked} ${ops.missing} ${ops.notDir}`);
  ok('deleting takes the folder with its content', ops.end === 'bild.png,config.yaml,notes.txt,roh.bin' && !existsSync(join(serverFiles, 'srv', 'app', 'archiv')));

  // Uploading: a folder with many small files and a single file; afterwards everything is on the server.
  const uploaded = await run(page, `
    ${DONE}
    const ids = await invoke('transfer_start', { request: { from: { kind: 'local' }, paths: [${JSON.stringify(join(lokal, 'viele'))}, ${JSON.stringify(join(lokal, 'einzeln.txt'))}], to: ${place}, dest: '/srv/app', policy: 'overwrite', parallel: 4 } });
    const list = await done(ids);
    const same = await fails(invoke('transfer_start', { request: { from: ${place}, paths: ['/srv/app/notes.txt'], to: ${place}, dest: '/srv/app', policy: 'overwrite', parallel: 4 } }));
    return { list, same: same?.code };
  `);
  const arrived = Array.from({ length: 40 }, (_, i) => join(serverFiles, 'srv', 'app', 'viele', i % 2 ? 'unter' : '.', `datei-${String(i).padStart(2, '0')}.txt`)).filter((file) => existsSync(file) && readFileSync(file, 'utf8') === `Inhalt ${file.slice(-6, -4)}\n`).length;
  ok('upload a folder with many files and a single file', uploaded.list?.length === 2 && uploaded.list.every((x) => x.state === 'done' && x.direction === 'upload') && uploaded.list[0].files === 40 && uploaded.list[0].filesDone === 40 && arrived === 40 && readFileSync(join(serverFiles, 'srv', 'app', 'einzeln.txt'), 'utf8') === 'einzeln\n', `${arrived} of 40, ${uploaded.list?.map((x) => x.state).join()}`);
  ok('source and destination in the same folder are rejected', uploaded.same === 'same_place');

  // Existing names: skip leaves the old one in place, “keep both” puts the new one next to it.
  writeFileSync(join(lokal, 'einzeln.txt'), 'neuer inhalt\n');
  const policies = await run(page, `
    ${DONE}
    const start = (policy) => invoke('transfer_start', { request: { from: { kind: 'local' }, paths: [${JSON.stringify(join(lokal, 'einzeln.txt'))}], to: ${place}, dest: '/srv/app', policy, parallel: 4 } });
    const skipped = await done(await start('skip'));
    const kept = await done(await start('rename'));
    return { skipped: skipped?.[0].state, kept: kept?.[0].state };
  `);
  ok('existing names: skip or put beside', policies.skipped === 'done' && policies.kept === 'done' && readFileSync(join(serverFiles, 'srv', 'app', 'einzeln.txt'), 'utf8') === 'einzeln\n' && readFileSync(join(serverFiles, 'srv', 'app', 'einzeln (2).txt'), 'utf8') === 'neuer inhalt\n');

  // Download a large file, pause in the middle: exactly what was transferred is at the destination.
  const big = join(serverFiles, 'srv', 'gross.bin');
  const total = statSync(big).size;
  const paused = await run(page, `
    await invoke('transfer_clear');
    const [id] = await invoke('transfer_start', { request: { from: ${place}, paths: ['/srv/gross.bin'], to: { kind: 'local' }, dest: ${JSON.stringify(lokal)}, policy: 'overwrite', parallel: 4 } });
    const find = async () => (await invoke('transfer_list')).find(t => t.id === id);
    const end = Date.now() + 20000;
    while (Date.now() < end && !((await find()).done > 0)) await wait(15);
    await invoke('transfer_control', { ids: [id], action: 'pause' });
    await wait(900);
    return await find();
  `);
  const partial = existsSync(join(lokal, 'gross.bin')) ? statSync(join(lokal, 'gross.bin')).size : -1;
  ok('pausing a transfer midway: exactly as much as reported is at the destination', paused.state === 'paused' && paused.direction === 'download' && paused.done > 0 && paused.done < total && partial === paused.done, `${paused.done} of ${total}, at the destination ${partial}`);
  ok('the paused transfer is noted for the restart', existsSync(join(workDir, 'data', 'transfers.json')) && readFileSync(join(workDir, 'data', 'transfers.json'), 'utf8').includes('gross.bin'));

  // Kill and restart the program: the transfer is offered again as paused and finishes from the old position.
  page.close();
  app.kill();
  await sleep(1200);
  app = launch();
  page = await connect();
  const resumed = await run(page, `
    ${DONE}
    await until(()=>q('.lock-card'));
    const offered = await invoke('transfer_list');
    type(q('.lock-card input'),'${PW2}'); await wait(80); q('.lock-card button[type=submit]').click(); await until(()=>q('.nav'));
    const shownList = !!(await until(()=>q('.xfers'), 3000));
    await invoke('transfer_control', { ids: null, action: 'resume' });
    const list = await done(offered.map(x => x.id));
    await wait(700);
    return { offered, list, shownList, chip: !!(await until(()=>q('.st-x'), 3000)) };
  `);
  const hash = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
  ok('after the restart the transfer is in the list, paused, with its progress', resumed.offered.length === 1 && resumed.offered[0].state === 'paused' && resumed.offered[0].resumed && resumed.offered[0].done === paused.done, `${resumed.offered[0]?.done}`);
  ok('resumed it runs to the end, the file is complete and unchanged', resumed.list?.[0].state === 'done' && resumed.list[0].done === total && hash(join(lokal, 'gross.bin')) === hash(big) && !existsSync(join(workDir, 'data', 'transfers.json')), `${resumed.list?.[0].state}`);
  ok('after unlocking the list opens on its own, the status bar shows the transfers', resumed.shownList && resumed.chip);

  // Compare folders: detect differences, transfer only those, afterwards both sides are equal.
  const synced2 = await run(page, `
    ${DONE}
    const args = { left: { kind: 'local' }, leftPath: ${JSON.stringify(join(lokal, 'abgleich'))}, right: ${place}, rightPath: '/srv/abgleich' };
    const before = await invoke('fs_compare', args);
    const plan = before.filter(d => d.state !== 'same').map(d => ({ rel: d.rel, toRight: d.state === 'left' || d.state === 'newerLeft' }));
    const list = await done(await invoke('sync_start', { ...args, items: plan }));
    const after = await invoke('fs_compare', args);
    return { before: before.map(d => d.rel + '=' + d.state).join(' '), moved: list?.map(x => x.state + ':' + x.direction).sort().join(' '), after: after.map(d => d.state).join(' ') };
  `);
  ok('folder sync recognises what is missing and what is newer', synced2.before === 'gleich.txt=same neu-links.txt=left nur-rechts.txt=right unter/geaendert.txt=newerLeft', synced2.before);
  ok('syncing transfers only the differences in both directions; afterwards everything is the same', synced2.moved === 'done:download done:upload done:upload' && synced2.after === 'same same same same' && readFileSync(join(lokal, 'abgleich', 'nur-rechts.txt'), 'utf8') === 'rechts\n' && readFileSync(join(serverFiles, 'srv', 'abgleich', 'unter', 'geaendert.txt'), 'utf8') === 'neuer stand\n', `${synced2.moved} | ${synced2.after}`);

  // Edit in your own program: the working copy is watched; every save uploads it again.
  const watching = await run(page, `
    await invoke('watch_open', { place: ${place}, path: '/srv/app/notes.txt', program: 'C:\\\\Windows\\\\System32\\\\where.exe' });
    return await invoke('watch_list');
  `);
  const copy = join(workDir, 'data', 'edit', String(watching[0]?.id), 'notes.txt');
  const fetched = existsSync(copy) && readFileSync(copy, 'utf8');
  await sleep(1200);
  writeFileSync(copy, 'im eigenen Programm geändert\n');
  const uploadedBack = await run(page, `
    const end = Date.now() + 15000; let list;
    while (Date.now() < end) { list = await invoke('watch_list'); if (list[0]?.uploads > 0 || list[0]?.error) break; await wait(200); }
    await invoke('watch_stop', { id: list[0].id });
    return { watch: list[0], left: (await invoke('watch_list')).length };
  `);
  ok('editing in your own program: fetch a working copy, upload after saving, clean up when done', fetched === 'notiz\n' && watching[0]?.origin === 'testserver:/srv/app/notes.txt' && uploadedBack.watch?.uploads === 1 && !uploadedBack.watch.error && readFileSync(join(serverFiles, 'srv', 'app', 'notes.txt'), 'utf8') === 'im eigenen Programm geändert\n' && uploadedBack.left === 0 && !existsSync(copy), JSON.stringify(uploadedBack.watch));

  // File panel next to the terminal: it uses the session's connection and shows the server's home directory.
  const bar = await run(page, `
    qa('.nv')[0].click(); await until(()=>byText('.host','testserver'));
    byText('.host','testserver').click(); await until(()=>q('.detail'));
    byText('.detail .btn','Verbinden').click(); await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    const shown = await until(()=>q('.sview:not(.off) .fbar .flist')?.getAttribute('aria-label') === '/home/tester', 15000);
    const before = await invoke('session_count');
    // Über das Feld für den Pfad in einen anderen Ordner.
    q('.fbar .fpath .mini').click(); const field = await until(()=>q('.fbar .fpath input'));
    type(field, '/srv/app'); field.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
    const rows = await until(()=>q('.fbar .flist')?.getAttribute('aria-label') === '/srv/app' && qa('.fbar .frow').length >= 5 && qa('.fbar .frow .fn').map(n=>n.textContent).join(), 10000);
    // Die Leiste ausblenden und wieder zeigen.
    byText('.tbar .btn','Dateien').click(); await wait(200); const hidden = !q('.sview:not(.off) .fbar');
    byText('.tbar .btn','Dateien').click(); await until(()=>q('.sview:not(.off) .fbar .frow'));
    const result = { shown: !!shown, rows, hidden, sessions: [before, await invoke('session_count')], note: q('.fbar .fnote')?.textContent.trim() };
    q('.tabs .tab.on .x').click(); await wait(500);
    return result;
  `);
  ok('the file bar at the terminal shows the server\'s files over the session\'s connection', bar.shown && /config\.yaml/.test(bar.rows || '') && /viele/.test(bar.rows || '') && bar.hidden && bar.sessions.join() === '1,1', bar.note ?? String(bar.rows));

  // A host without saved credentials: the Files page asks for the password like the terminal does.
  const asked = await run(page, `
    const base = (await invoke('vault_status')).data.hosts.find(h => h.name === 'testserver');
    const { id, hasPassword, ...rest } = base;
    const made = await invoke('host_save', { host: { ...rest, name: 'ohne-passwort', group: null, own: { user: 'tester', port: base.own.port } } });
    qa('.nv')[4].click(); await until(()=>qa('.fcol').length === 2);
    // Der neue Host steht erst in der Auswahl, wenn die Oberfläche den geänderten Tresor nachgeladen hat.
    const select = qa('.fcol')[1].querySelector('select');
    const pick = async (id) => { await until(()=>[...select.options].some(o => o.value === id)); select.value = id; select.dispatchEvent(new Event('change',{bubbles:true})); };
    await pick(made.id);
    const field = await until(()=>q('.dlg input[type=password]'), 15000);
    const title = q('.dlg h2')?.textContent;
    type(field,'falsch'); await wait(80); q('.dlg button[type=submit]').click();
    const retry = await until(()=>q('.dlg .errline')?.textContent, 8000);
    type(q('.dlg input[type=password]'),'richtig'); q('.dlg input[type=checkbox]').click(); await wait(80); q('.dlg button[type=submit]').click();
    const label = await until(()=>qa('.fcol')[1].querySelector('.flist')?.getAttribute('aria-label') === '/home/tester', 15000);
    await wait(500);
    const saved = (await invoke('vault_status')).data.hosts.find(h => h.id === made.id).hasPassword;
    const listed = (await invoke('fs_list', { place: { kind: 'host', id: made.id }, path: '/srv/app' })).entries.length;
    // Abbrechen der Rückfrage: Die Spalte sagt, dass nicht verbunden wurde, und es bleibt keine Verbindung hängen.
    const other = await invoke('host_save', { host: { ...rest, name: 'abgebrochen', group: null, own: { user: 'tester', port: base.own.port } } });
    await pick(other.id);
    await until(()=>q('.dlg input[type=password]'), 15000);
    byText('.dlg .btn','Abbrechen').click();
    // Bis das Ende gemeldet ist, steht in der Spalte noch „Wird geladen“.
    const note = (await until(()=>/abgebrochen/.test(qa('.fcol')[1].querySelector('.fnote p')?.textContent ?? ''), 8000)) ? qa('.fcol')[1].querySelector('.fnote p').textContent : qa('.fcol')[1].querySelector('.fnote p')?.textContent;
    await wait(300);
    const result = { title, retry, label: !!label, saved, listed, note, dialog: !!q('.dlg'), sessions: await invoke('session_count') };
    await invoke('host_delete', { id: made.id }); await invoke('host_delete', { id: other.id });
    return result;
  `);
  ok('the Files page asks for the password for a host without credentials, repeats after a wrong one and saves it on request', /ohne-passwort/.test(asked.title ?? '') && /Versuch 2/.test(asked.retry ?? '') && asked.label && asked.saved && asked.listed >= 5, `${asked.title} | ${asked.retry}`);
  ok('cancelled prompt: the column says so, and no connection is left hanging', /abgebrochen/.test(asked.note ?? '') && !asked.dialog && asked.sessions === 0, asked.note ?? '');

  // Dragging into Explorer: a server's files are fetched into a working folder for it. The test does not start the
  // drag itself; without a pressed mouse button Windows would drop wherever the pointer happens to be.
  const staged = await run(page, `
    ${DONE}
    const got = await invoke('drag_stage', { place: ${place}, paths: ['/srv/app/config.yaml', '/srv/app/viele'] });
    const list = await done(got.ids);
    const local = await fails(invoke('drag_stage', { place: { kind: 'local' }, paths: ['C:\\\\Windows'] }));
    const missing = await fails(invoke('drag_out', { paths: ['C:\\\\gibt\\\\es\\\\nicht.txt'] }));
    return { paths: got.paths, list, local: local?.code, missing: missing?.code };
  `);
  ok('preparing for Explorer fetches files and folders into the working folder', staged.list?.every((x) => x.state === 'done' && x.dest.startsWith('Explorer')) && staged.paths.length === 2 && staged.paths.every((path) => path.startsWith(join(workDir, 'data', 'drag')) && existsSync(path)) && readFileSync(staged.paths[0], 'utf8') === 'port: 3000\nneu: ja\n' && existsSync(join(staged.paths[1], 'unter', 'datei-01.txt')) && staged.local === 'not_supported' && staged.missing === 'no_such_file', staged.paths.map((path) => path.split(/[\\/]/).slice(-2).join('/')).join(' '));

  // 4k. Port rules: a destination on this machine that is only addressed through the test server.
  const echo = net.createServer((socket) => socket.on('data', (data) => socket.write(Buffer.concat([Buffer.from('echo:'), data]))).on('error', () => {}));
  await new Promise((done) => echo.listen(0, '127.0.0.1', done));
  const echoPort = echo.address().port;
  const freePort = () =>
    new Promise((done) => {
      const probe = net.createServer();
      probe.listen(0, '127.0.0.1', () => {
        const found = probe.address().port;
        probe.close(() => done(found));
      });
    });
  /** Talks to a port on this machine: sends `steps` in order and waits for that many bytes each. Returns the answers or null. */
  const talk = (to, steps) =>
    new Promise((done) => {
      const socket = net.connect(to, '127.0.0.1');
      const replies = [];
      let got = Buffer.alloc(0);
      const finish = (value) => (socket.destroy(), done(value));
      const next = () => (steps.length > replies.length ? socket.write(steps[replies.length].send) : finish(replies));
      socket.setTimeout(6000, () => finish(null));
      socket.on('error', () => finish(null));
      socket.on('connect', next);
      socket.on('data', (data) => {
        got = Buffer.concat([got, data]);
        if (got.length < steps[replies.length].expect) return;
        replies.push(got);
        got = Buffer.alloc(0);
        next();
      });
    });
  const say = async (to, text) => (await talk(to, [{ send: text, expect: text.length + 5 }]))?.[0].toString() ?? null;
  const [pLocal, pSocks, pRemote, pAsk, pLoss] = [await freePort(), await freePort(), await freePort(), await freePort(), await freePort()];
  const RULES = `
    const saveRule = (rule) => invoke('forward_save', { rule });
    const rule = (name, kind, bindPort, extra = {}) => ({ name, kind, host: '${hostId}', bindAddress: '', bindPort, destHost: '127.0.0.1', destPort: ${echoPort}, ...extra });
    const row = name => qa('.rows .row').find(r => r.querySelector('.rt b')?.textContent === name);
    const states = () => invoke('forward_list');
    const phase = async (id, wanted, ms = 20000) => { const end = Date.now() + ms; while (Date.now() < end) { const state = (await states()).find(s => s.id === id); if ((state?.phase ?? 'off') === wanted) return state ?? true; await wait(150); } return null; };
  `;
  const rules = await run(page, `
    ${RULES}
    const bad = { port: (await fails(saveRule(rule('x', 'local', 70000))))?.reason, host: (await fails(saveRule(rule('x', 'local', 3000, { host: '0'.repeat(32) }))))?.reason, dest: (await fails(saveRule(rule('x', 'local', 3000, { destHost: ' ' }))))?.reason };
    const local = (await saveRule(rule('E2E lokal', 'local', ${pLocal}))).id;
    const dynamic = (await saveRule(rule('E2E dynamisch', 'dynamic', ${pSocks}))).id;
    const remote = (await saveRule(rule('E2E remote', 'remote', ${pRemote}))).id;
    q('.tabs .tab.home')?.click(); qa('.nv')[2].click();
    await until(()=>row('E2E lokal') && row('E2E dynamisch') && row('E2E remote'));
    const shown = qa('.rows .row .rt').map(r => r.textContent.replace(/\\s+/g, ' ').trim());
    const before = (await states()).length;
    for (const name of ['E2E lokal', 'E2E dynamisch', 'E2E remote']) row(name).querySelector('.swt').click();
    const running = await until(()=>qa('.rows .chip.ok').length === 3, 20000);
    return { bad, ids: { local, dynamic, remote }, shown, before, running: !!running, status: q('.st')?.textContent.replace(/\\s+/g, ' '), dynamicDest: (await invoke('vault_status')).data.forwards.find(f => f.id === dynamic) };
  `);
  ok('port rules: impossible values are rejected', rules.bad.port === 'port_invalid' && rules.bad.host === 'host_missing' && rules.bad.dest === 'dest_required', JSON.stringify(rules.bad));
  ok('Ports page shows the rules with their route; all are off at first', rules.before === 0 && rules.shown.some((t) => t.includes(`lokal ${pLocal} → testserver → 127.0.0.1:${echoPort}`)) && rules.shown.some((t) => t.includes(`dynamisch ${pSocks} → testserver`)) && rules.shown.some((t) => t.includes(`testserver:${pRemote} → Dieser PC`)), rules.shown.join(' | '));
  ok('three rules switched on with their switches; the status bar counts them', rules.running && /3 Port-Regeln aktiv/.test(rules.status ?? '') && rules.dynamicDest?.destHost === '' && rules.dynamicDest.destPort === 0, rules.status);

  const viaLocal = await say(pLocal, 'hallo');
  ok('local rule: this computer\'s port leads through the server to the destination', viaLocal === 'echo:hallo', String(viaLocal));
  const socks = await talk(pSocks, [
    { send: Buffer.from([5, 1, 0]), expect: 2 },
    { send: Buffer.concat([Buffer.from([5, 1, 0, 1, 127, 0, 0, 1]), Buffer.from([echoPort >> 8, echoPort & 255])]), expect: 10 },
    { send: 'socks', expect: 10 },
  ]);
  ok('dynamic rule: SOCKS 5 connects through the server to the named destination', socks?.[0].equals(Buffer.from([5, 0])) && socks[1][1] === 0 && socks[2].toString() === 'echo:socks', socks ? socks.map((b) => b.toString('hex')).join(' ') : 'no answer');
  const viaRemote = await say(pRemote, 'von aussen');
  ok('remote rule: the server\'s port leads back to the destination on this computer', viaRemote === 'echo:von aussen', String(viaRemote));

  const ruleCount = await run(page, `
    ${RULES}
    await wait(1300);
    const local = (await states()).find(s => s.id === '${rules.ids.local}');
    const second = (await saveRule(rule('E2E belegt', 'local', ${pLocal}))).id;
    const taken = await fails(invoke('forward_start', { id: second }));
    const stillOff = !(await states()).some(s => s.id === second);
    await invoke('forward_delete', { id: second });
    // Der Editor einer laufenden Regel zeigt ihren Stand.
    await until(()=>row('E2E lokal'));
    row('E2E lokal').click(); await until(()=>q('.editor .fwd-live.on'));
    const live = q('.editor .fwd-live').textContent.replace(/\\s+/g, ' ');
    q('.editor .ed-h .btn.ghost').click(); await wait(200);
    return { local, taken: taken?.code, stillOff, live };
  `);
  ok('the rule counts connections and bytes', ruleCount.local?.phase === 'running' && ruleCount.local.total === 1 && ruleCount.local.sent === 5 && ruleCount.local.received === 10 && ruleCount.local.open === 0 && ruleCount.local.since > 0, JSON.stringify(ruleCount.local));
  ok('a port in use is reported at once, the second rule stays off', ruleCount.taken === 'port_in_use' && ruleCount.stillOff, ruleCount.taken);
  ok('the editor shows the running rule\'s state and its address', /Läuft/.test(ruleCount.live) && ruleCount.live.includes(`127.0.0.1:${pLocal}`) && /Bisher insgesamt\s*1/.test(ruleCount.live), ruleCount.live.slice(0, 90));

  // A host without a saved password: switching on brings the same prompt as for a terminal.
  const asking = await run(page, `
    ${RULES}
    const base = (await invoke('vault_status')).data.hosts.find(h => h.name === 'testserver');
    const { id, hasPassword, ...rest } = base;
    const made = await invoke('host_save', { host: { ...rest, name: 'regel-ohne-passwort', group: null, own: { user: 'tester', port: base.own.port } } });
    const id2 = (await saveRule(rule('E2E Rückfrage', 'local', ${pAsk}, { host: made.id }))).id;
    await until(()=>row('E2E Rückfrage'));
    row('E2E Rückfrage').querySelector('.swt').click();
    const first = await until(()=>q('.dlg input[type=password]'), 15000);
    const title = q('.dlg h2')?.textContent;
    const during = (await states()).find(s => s.id === id2)?.phase;
    byText('.dlg .btn', 'Abbrechen').click();
    const off = await phase(id2, 'off');
    const switchOff = !row('E2E Rückfrage').querySelector('.swt').classList.contains('on');
    const sessions = await invoke('session_count');
    // Zweiter Anlauf, diesmal mit Passwort.
    row('E2E Rückfrage').querySelector('.swt').click();
    await until(()=>q('.dlg input[type=password]'), 15000);
    type(q('.dlg input[type=password]'), 'richtig'); await wait(80); q('.dlg button[type=submit]').click();
    const on = await phase(id2, 'running');
    return { asked: !!first, title, during, off: !!off, switchOff, sessions, on: !!on, host: made.id, id: id2, after: await invoke('session_count') };
  `);
  const viaAsked = asking.on ? await say(pAsk, 'gefragt') : null;
  ok('switching on asks for the password like a terminal; cancelling leaves the rule off', asking.asked && /regel-ohne-passwort/.test(asking.title ?? '') && asking.during === 'starting' && asking.off && asking.switchOff && asking.sessions === 0, `${asking.title} | ${asking.during}`);
  ok('with the password the forwarding is up, without a session staying open', asking.on && viaAsked === 'echo:gefragt' && asking.after === 0, String(viaAsked));

  // Drop: this destination makes the test server cut the connection. The rule reconnects by itself.
  const lossId = await run(page, `${RULES} const id = (await saveRule(rule('E2E Abriss', 'local', ${pLoss}, { destHost: 'disconnect.test', destPort: 1 }))).id; await invoke('forward_start', { id }); await phase(id, 'running'); return id;`);
  net.connect(pLoss, '127.0.0.1').on('error', () => {});
  const loss = await run(page, `
    ${RULES}
    const retrying = await phase('${lossId}', 'retrying', 15000);
    const again = await phase('${lossId}', 'running', 25000);
    return { error: retrying?.error, countdown: retrying?.retryIn, again: !!again, since: again?.since };
  `);
  ok('after a dropped connection the rule reconnects on its own', loss.error === 'connection_lost' && loss.again && loss.since > 0, JSON.stringify(loss));

  // Switching off frees the port; a changed rule does not keep running with old values.
  const stopped = await run(page, `
    ${RULES}
    row('E2E lokal').querySelector('.swt').click();
    const off = await phase('${rules.ids.local}', 'off');
    await saveRule({ ...rule('E2E dynamisch', 'dynamic', ${pSocks}), id: '${rules.ids.dynamic}' });
    const edited = await phase('${rules.ids.dynamic}', 'off', 3000);
    await invoke('forward_stop', { id: '${lossId}' });
    await invoke('forward_stop', { id: '${rules.ids.remote}' });
    return { off: !!off, edited: !!edited, left: (await states()).map(s => s.id) };
  `);
  const afterStop = await say(pLocal, 'weg');
  ok('switching off frees the port; saving switches a running rule off', stopped.off && stopped.edited && afterStop === null && stopped.left.join() === asking.id, `${stopped.left.length} left`);

  // 4l. Snippets: check, create, run on hosts.
  const snips = await run(page, `
    const save = (snippet) => invoke('snippet_save', { snippet });
    const base = { name: 'E2E Größe', package: 'E2E', kind: 'command', command: 'size', steps: [], hotkey: 'Alt+1' };
    const bad = { empty: (await fails(save({ ...base, command: ' ' })))?.reason, key: (await fails(save({ ...base, hotkey: 'Ctrl+C' })))?.reason, macro: (await fails(save({ ...base, kind: 'macro' })))?.reason };
    await save(base);
    const taken = (await fails(save({ ...base, name: 'Zweites', hotkey: 'Alt+1' })))?.reason;
    await save({ name: 'E2E Variable', package: 'E2E', kind: 'command', command: '{{befehl:term}}', steps: [], hotkey: null });
    q('.tabs .tab.home')?.click(); qa('.nv')[3].click();
    await until(()=>byText('.ph .btn', 'Neues Snippet'));
    byText('.ph .btn', 'Neues Snippet').click(); await until(()=>q('.editor textarea'));
    const field = label => [...q('.editor').querySelectorAll('.fld')].find(f => f.querySelector('.fld-l')?.textContent.trim().startsWith(label))?.querySelector('input,textarea');
    type(field('Name'), 'E2E Ausgabe'); type(field('Paket'), 'E2E');
    type(field('Befehl'), 'echo glowport-$((6*7)) {{wort:hallo}}; echo fehler >&2; exit 3');
    await wait(200);
    const vars = qa('.editor .chip.a').map(c => c.textContent.replace(/\\s+/g, ' ').trim());
    q('.editor button[type=submit]').click();
    const row = name => qa('.rows .row').find(r => r.querySelector('.rt b')?.textContent === name);
    await until(()=>row('E2E Ausgabe') && !q('.editor'));
    const sections = qa('.pg .sec').map(s => s.textContent.trim());
    // Auf Hosts ausführen: einer mit hinterlegtem Passwort, einer ohne.
    row('E2E Ausgabe').querySelector('.btn').click(); await until(()=>q('.dlg .picklist'));
    const preview = q('.dlg .run-cmd').textContent;
    type(q('.dlg .run-vars input'), 'welt'); await wait(100);
    const pick = name => qa('.dlg .pick').find(p => p.querySelector('b').textContent === name);
    pick('testserver').querySelector('input').click(); pick('regel-ohne-passwort').querySelector('input').click(); await wait(100);
    const button = q('.dlg .dlg-a .btn.primary').textContent.trim();
    q('.dlg .dlg-a .btn.primary').click();
    const finished = await until(()=>byText('.dlg .fld-h', 'Fertig'), 40000);
    const chip = name => pick(name)?.querySelector('.chip')?.textContent.trim();
    const chips = { good: chip('testserver'), locked: chip('regel-ohne-passwort') };
    pick('testserver').querySelector('input').click(); await wait(200);
    const output = q('.dlg .run-out').textContent;
    const summary = finished?.textContent;
    byText('.dlg .btn', 'Schließen').click(); await wait(200);
    return { bad, taken, vars, sections, preview, button, chips, output, summary };
  `);
  ok('snippets: empty command, impossible and duplicate shortcut are rejected', snips.bad.empty === 'command_required' && snips.bad.key === 'hotkey_invalid' && snips.bad.macro === 'macro_empty' && snips.taken === 'hotkey_taken', JSON.stringify(snips.bad));
  ok('snippet created through the editor; the variable is recognised, the package forms a section', snips.vars.join() === 'wort = hallo' && snips.sections.some((s) => /Paket · E2E/i.test(s)), `${snips.vars.join()} | ${snips.sections.join(', ')}`);
  ok('Run on hosts: output with error output and exit code per host; without credentials nothing is asked', snips.preview.includes('glowport-$((6*7)) hallo') && /Auf 2 Hosts/.test(snips.button) && /Fehler 3/.test(snips.chips.good ?? '') && /Anmeldung abgelehnt/.test(snips.chips.locked ?? '') && snips.output.includes('glowport-42 welt') && snips.output.includes('fehler') && /0 ohne Fehler, 2 mit Fehler/.test(snips.summary ?? ''), `${snips.chips.good} | ${snips.chips.locked} | ${JSON.stringify(snips.output.slice(0, 40))}`);

  // 4m. In the terminal: sidebar with server info and snippets, hotkeys, macro, suggestions while typing.
  const side = await run(page, `
    qa('.nv')[0].click(); await until(()=>byText('.host', 'testserver'));
    byText('.host', 'testserver').click(); await until(()=>q('.detail'));
    byText('.detail .btn', 'Verbinden').click(); await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    await wait(900);
    byText('.sview:not(.off) .tbar .btn', 'Seitenleiste').click(); await until(()=>q('.side'));
    // Der Testserver führt die Messung in sh auf diesem Rechner aus. Die Shell von Git bildet /proc nach; dann
    // kommen echte Zahlen. Ohne /proc sagt die Anzeige, dass sie Linux braucht, statt leer zu bleiben.
    const info = await until(()=>(q('.side .facts') || /Linux/.test(q('.side .fnote')?.textContent ?? '')) && q('.side .side-b').textContent.replace(/\\s+/g, ' ').trim(), 20000);
    const meters = qa('.side .meter-l span').map(s => s.textContent.trim());
    await wait(2600);
    const cpu = q('.side .meter-l b')?.textContent.trim();
    qa('.side .stab').find(b=>b.title==='Snippets').click(); await until(()=>q('.side .snip'));
    const snip = name => qa('.side .snip').find(s => s.querySelector('.snip-h b').textContent === name);
    const press = (name, label) => [...snip(name).querySelectorAll('.btn')].find(b => b.textContent.trim() === label).click();
    const listed = qa('.side .snip .snip-h b').map(b => b.textContent);
    press('E2E Größe', 'Ausführen'); await wait(700);
    press('E2E Variable', 'Ausführen'); await until(()=>q('.dlg .run-vars'));
    const preview = q('.dlg .run-cmd').textContent;
    q('.dlg button[type=submit]').click(); await wait(700);
    // Einfügen tippt nur, ohne abzuschicken.
    press('E2E Größe', 'Einfügen'); await wait(500);
    return { info, meters, cpu, listed, preview, focus: document.activeElement?.className };
  `);
  const afterSnippets = await terminalText(page);
  await run(page, `qa('.side .stab').find(b=>b.title==='Info').click(); await until(()=>q('.side .facts') || q('.side .fnote')); await wait(4500);`);
  await shot(page, 'server-info');
  await run(page, `qa('.side .stab').find(b=>b.title==='Snippets').click(); await until(()=>q('.side .snip')); q('.pane:not(.off) .xterm-helper-textarea').focus();`);
  await pressEnter(page);
  await sleep(400);
  // Docker, services and processes in the sidebar. The test server simulates a Linux for it
  // (crates/testserver/src/admin.rs): the user may control containers, not services, and sudo wants a password.
  const SIDE = `
    const tab = name => qa('.side .stab').find(b=>b.title===name);
    const row = name => qa('.side .mg-row').find(r=>r.querySelector('.mg-main b')?.textContent.trim()===name);
    const sub = name => row(name)?.querySelector('.mg-sub').textContent.trim() ?? '';
    const button = (text, scope) => [...scope.querySelectorAll('button')].find(b=>b.textContent.trim()===text);
  `;
  const dock = await run(page, SIDE + `
    const tabs = (await until(()=>qa('.side .stab').length === 5 && qa('.side .stab'), 15000))?.map(b=>b.title);
    tab('Docker').click(); await until(()=>row('e2e-web'), 15000);
    const containers = qa('.side .mg-row').map(r=>[r.querySelector('.mg-main b').textContent.trim(), r.querySelector('.mg-sub').textContent.trim()]);
    const sum = q('.side .mg-sum').textContent.trim();
    row('e2e-web').querySelector('.mg-head').click(); await wait(200);
    const facts = row('e2e-web').querySelector('.mg-facts').textContent.replace(/\\s+/g,' ').trim();
    button('Stoppen', row('e2e-web')).click();
    const asked = (await until(()=>q('.dlg')))?.querySelector('h2').textContent;
    button('Stoppen', q('.dlg')).click();
    const stopped = await until(()=>/^beendet/.test(sub('e2e-web')) && sub('e2e-web'), 12000);
    const order = qa('.side .mg-row .mg-main b').map(b=>b.textContent.trim());
    button('Starten', row('e2e-web')).click();
    const started = await until(()=>/^läuft/.test(sub('e2e-web')) && sub('e2e-web'), 12000);
    return { tabs, containers, sum, facts, asked, stopped, order, started };
  `);
  ok('m10 The sidebar shows Docker, services and processes where the server provides them', JSON.stringify(dock.tabs) === JSON.stringify(['Info', 'Snippets', 'Docker', 'Dienste', 'Prozesse']), JSON.stringify(dock.tabs));
  ok('m10 Docker: running ones first, with state; an exited one names its error', JSON.stringify(dock.containers) === JSON.stringify([['e2e-db', 'läuft seit 1 Std'], ['e2e-web', 'läuft seit 1 Std'], ['e2e-job', 'vor 1 Std mit Fehler 1 beendet']]) && dock.sum === '2 von 3 laufen', JSON.stringify([dock.containers, dock.sum]));
  ok('m10 Docker: expanded, image, published ports and memory are shown', /nginx:1\.27/.test(dock.facts) && /8080 → 80\/tcp/.test(dock.facts) && /64,0 MB \/ 2,0 GB/.test(dock.facts), dock.facts);
  ok('m10 Docker: stopping asks and stops; the container moves down and can be started again', dock.asked === 'Container „e2e-web“ stoppen?' && /^beendet vor \d+ s$/.test(dock.stopped) && dock.order.indexOf('e2e-web') > dock.order.indexOf('e2e-db') && /^läuft seit \d+ s$/.test(dock.started), JSON.stringify([dock.asked, dock.stopped, dock.order, dock.started]));

  const logTab = await run(page, SIDE + `
    const before = qa('.tabs .tab').length;
    button('Logs', row('e2e-web')).click();
    await until(()=>qa('.tabs .tab').length === before + 1);
    const connected = !!(await until(()=>q('.sview:not(.off) .live.connected'), 15000));
    await wait(2200);
    return { opened: qa('.tabs .tab').length - before, connected, title: q('.tabs .tab.on').textContent.trim() };
  `);
  const logText = await terminalText(page);
  ok('m10 Docker: “Logs” opens a tab on the same server and types the command there', logTab.opened === 1 && logTab.connected && logTab.title.includes('testserver') && /\$ docker logs --tail 200 -f 111111111111\r?\n/.test(logText), JSON.stringify([logTab, logText.slice(-160)]));
  await run(page, `q('.tabs .tab.on .x').click(); await wait(500); await until(()=>q('.side'));`);

  const svc = await run(page, SIDE + `
    // Einen Dienst abwarten, den es bei Docker nicht gibt: Dort heißt ein Container genauso wie hier ein Dienst.
    tab('Dienste').click(); await until(()=>q('.side .mg-filter') && row('ssh'), 15000);
    const units = qa('.side .mg-row').map(r=>[r.querySelector('.mg-main b').textContent.trim(), r.querySelector('.mg-num b').textContent.trim(), r.querySelector('.mg-num span')?.textContent.trim() ?? '']);
    const filters = () => [...q('.side .mg-filter').querySelectorAll('button')];
    const label = filters()[2].textContent.trim();
    filters()[2].click(); await wait(200);
    const failedOnly = qa('.side .mg-row .mg-main b').map(b=>b.textContent.trim());
    filters()[0].click(); await wait(200);
    type(q('.side .mg-search input'), 'switched'); await wait(200);
    const found = qa('.side .mg-row .mg-main b').map(b=>b.textContent.trim());
    type(q('.side .mg-search input'), ''); await wait(200);
    row('e2e-idle').querySelector('.mg-head').click();
    const status = await until(()=>/Active:/.test(q('.side .mg-log')?.textContent ?? '') && q('.side .mg-log').textContent, 10000);
    button('Starten', row('e2e-idle')).click();
    const said = await until(()=>byText('.toast', 'sudo will ein Passwort')?.textContent.trim(), 10000);
    await wait(400);
    return { units, label, failedOnly, found, status, said, still: row('e2e-idle').querySelector('.mg-num b').textContent.trim() };
  `);
  const typedSudo = await terminalText(page);
  ok('m10 Services: failed ones first, with state and whether it starts on boot', JSON.stringify(svc.units) === JSON.stringify([['e2e-backup', 'Fehler', ''], ['e2e-web', 'läuft', 'startet mit'], ['ssh', 'läuft', 'startet mit'], ['e2e-idle', 'aus', '']]), JSON.stringify(svc.units));
  ok('m10 Services: the “Failed” filter and the search (also in the description) narrow down', svc.label === 'Fehler 1' && svc.failedOnly.join() === 'e2e-backup' && svc.found.join() === 'e2e-idle', JSON.stringify([svc.label, svc.failedOnly, svc.found]));
  ok('m10 Services: expanded, state and latest messages are shown', /Active: inactive \(dead\)/.test(svc.status) && /Stopped e2e-idle\.service/.test(svc.status), svc.status);
  ok('m10 Without root: sudo wants a password, so the command is in the terminal and not sent', !!svc.said && svc.still === 'aus' && /\$ sudo systemctl start 'e2e-idle\.service'$/.test(typedSudo.trimEnd()), JSON.stringify([svc.said, svc.still, typedSudo.slice(-120)]));
  // Send the line so the terminal is empty again for what follows. The test server does not know sudo.
  await run(page, `q('.pane:not(.off) .xterm-helper-textarea').focus();`);
  await pressEnter(page);
  await sleep(400);

  const procs = await run(page, SIDE + `
    const load = name => row(name)?.querySelector('.mg-num b').textContent.trim() ?? '';
    tab('Prozesse').click(); await until(()=>row('python3'), 15000);
    const first = load('python3');
    const cpu = await until(()=>/^\\d+ %$/.test(load('python3')) && load('python3'), 15000);
    const names = qa('.side .mg-row .mg-main b').map(b=>b.textContent.trim());
    const who = row('python3').querySelector('.mg-sub').textContent.trim();
    row('sleep').querySelector('.mg-head').click(); await wait(200);
    const command = row('sleep').querySelector('.mg-facts dd').textContent.trim();
    button('Beenden', row('sleep')).click();
    const asked = (await until(()=>q('.dlg')))?.querySelector('h2').textContent;
    const named = q('.dlg .mg-cmd')?.textContent.trim();
    button('Beenden', q('.dlg')).click();
    const gone = !!(await until(()=>!row('sleep'), 12000));
    row('sshd').querySelector('.mg-head').click(); await wait(200);
    button('Beenden', row('sshd')).click(); await until(()=>q('.dlg'));
    button('Beenden', q('.dlg')).click();
    const said = await until(()=>qa('.toast').map(t=>t.textContent.trim()).filter(t=>t.includes('sudo will ein Passwort')).length, 10000);
    await wait(400);
    return { first, cpu, names, who, command, asked, named, gone, said, still: !!row('sshd') };
  `);
  const typedKill = await terminalText(page);
  ok('m10 Processes: the load comes from two measurements; the one with the highest load is on top, kernel threads are missing', (procs.first === '…' || /^\d+ %$/.test(procs.first)) && Number.parseInt(procs.cpu) >= 30 && Number.parseInt(procs.cpu) <= 70 && procs.names[0] === 'python3' && !procs.names.includes('kthreadd') && procs.who === 'e2e · 4711', JSON.stringify([procs.first, procs.cpu, procs.names, procs.who]));
  ok('m10 Processes: ending asks, names the command and ends our own process', procs.command === 'sleep 600' && procs.asked === '„sleep“ (4712) beenden?' && procs.named === 'sleep 600' && procs.gone, JSON.stringify([procs.command, procs.asked, procs.named, procs.gone]));
  ok('m10 Processes: only root ends someone else\'s process; the command for it is in the terminal', !!procs.said && procs.still && /\$ sudo kill -TERM 300$/.test(typedKill.trimEnd()), JSON.stringify([procs.said, procs.still, typedKill.slice(-80)]));
  await run(page, `q('.pane:not(.off) .xterm-helper-textarea').focus();`);
  await pressEnter(page);
  await sleep(400);
  await shot(page, 'seitenleiste-prozesse');
  await run(page, `qa('.side .stab').find(b=>b.title==='Snippets').click(); await until(()=>q('.side .snip')); q('.pane:not(.off) .xterm-helper-textarea').focus();`);

  ok('server info shows load and key facts, or says for a server without /proc that it needs Linux', side.meters.length ? side.meters.includes('Prozessor') && side.meters.includes('Arbeitsspeicher') && /\d+ % · \d+ Kern/.test(side.cpu ?? '') && /Laufzeit/.test(side.info) : /Linux/.test(side.info ?? ''), `${side.cpu} | ${(side.info ?? '').slice(0, 110)}`);
  ok('snippets at the terminal: run sends, variables are asked first, paste only types', side.listed.includes('E2E Größe') && side.preview === 'term' && /\$ size\r?\n\d+x\d+/.test(afterSnippets) && /\$ term\r?\nxterm-256color/.test(afterSnippets) && /\$ size\s*$/.test(afterSnippets.trimEnd()) && side.focus === 'xterm-helper-textarea', JSON.stringify(afterSnippets.slice(-70)));

  // Hotkey Alt+1 runs “E2E Größe” in the terminal.
  const sizes = (text) => (text.match(/\d+x\d+/g) ?? []).length;
  const beforeKey = sizes(await terminalText(page, 0, true));
  for (const type of ['rawKeyDown', 'keyUp']) await page.send('Input.dispatchKeyEvent', { type, key: '1', code: 'Digit1', windowsVirtualKeyCode: 49, modifiers: 1 });
  await sleep(700);
  const sizesAfterKey = sizes(await terminalText(page, 0, true));
  ok('a snippet\'s shortcut runs it in the terminal', sizesAfterKey === beforeKey + 1, `${beforeKey} → ${sizesAfterKey}`);

  // In the terminal Ctrl+K belongs to the session (nano: cut line, bash: delete to end of line); search
  // opens there with Ctrl+Shift+K. The test server echoes every character; Ctrl+K is a line feed without
  // carriage return: if it arrives, the Q typed afterwards is one line below the prompt.
  await run(page, `q('.pane:not(.off) .xterm-helper-textarea').focus();`);
  for (const type of ['rawKeyDown', 'keyUp']) await page.send('Input.dispatchKeyEvent', { type, key: 'k', code: 'KeyK', windowsVirtualKeyCode: 75, modifiers: 2 });
  await sleep(400);
  const paletteAfterK = await run(page, `return !!q('.pal')`);
  await page.send('Input.insertText', { text: 'Q' });
  await sleep(500);
  const afterK = (await terminalText(page, 0, true)).split(/\r?\n/).map((line) => line.trimEnd()).filter(Boolean);
  await run(page, `q('.pane:not(.off) .xterm-helper-textarea').focus();`);
  for (const type of ['rawKeyDown', 'keyUp']) await page.send('Input.dispatchKeyEvent', { type, key: 'K', code: 'KeyK', windowsVirtualKeyCode: 75, modifiers: 10 });
  await sleep(400);
  const paletteAfterShiftK = await run(page, `const open = !!q('.pal'); if (open) q('.pal input').dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true})); await wait(200); q('.pane:not(.off) .xterm-helper-textarea').focus(); return open;`);
  // Finish the line; the test server does not know it and stays silent.
  await pressEnter(page);
  await sleep(400);
  ok('Ctrl+K goes to the session in the terminal without opening search; Ctrl+Shift+K opens search there', !paletteAfterK && afterK.at(-1)?.trim() === 'Q' && /\$$/.test(afterK.at(-2) ?? '') && paletteAfterShiftK, JSON.stringify([paletteAfterK, afterK.slice(-3), paletteAfterShiftK]));

  // Makro: aufzeichnen, benennen, abspielen.
  await run(page, `q('.side .side-f .btn').click(); await until(()=>q('.side .macrobox.rec')); q('.pane:not(.off) .xterm-helper-textarea').focus();`);
  await typeLine(page, 'size');
  await sleep(500);
  await typeLine(page, 'term');
  await sleep(500);
  const macro = await run(page, `
    const recorded = q('.side .macrobox.rec').textContent.replace(/\\s+/g, ' ').trim();
    byText('.side .macrobox .btn', 'Fertig').click(); await until(()=>byText('.dlg h2', 'Makro speichern'));
    const warned = q('.dlg .warnbox')?.textContent.includes('Passwort');
    type(q('.dlg input[type=text]'), 'E2E Makro'); await wait(100); q('.dlg button[type=submit]').click();
    const snip = () => qa('.side .snip').find(s => s.querySelector('.snip-h b').textContent === 'E2E Makro');
    await until(snip);
    const saved = (await invoke('vault_status')).data.snippets.find(s => s.name === 'E2E Makro');
    [...snip().querySelectorAll('.btn')].find(b => b.textContent.trim() === 'Abspielen').click();
    await wait(2600);
    return { counted: recorded, warned, kind: saved?.kind, keys: saved?.steps.map(s => s.keys).join('|'), steps: saved?.steps.length, playing: !!q('.side .macrobox:not(.rec)') };
  `);
  const afterMacro = sizes(await terminalText(page, 0, true));
  ok('macro: what is typed is recorded, saved with a name and typed again when played', /2 Schritte/.test(macro.counted) && macro.warned && macro.kind === 'macro' && macro.keys === 'size\r|term\r' && afterMacro === sizesAfterKey + 2 && !macro.playing, `${macro.counted} | ${JSON.stringify(macro.keys)} | ${sizesAfterKey} → ${afterMacro}`);

  // Suggestions while typing: commands, subcommands, paths on the server. Tab accepts.
  const hints = () => run(page, `return qa('.hints .hint').map(h => (h.classList.contains('on') ? '*' : '') + h.querySelector('b').textContent)`);
  const tab = async () => {
    for (const type of ['rawKeyDown', 'keyUp']) await page.send('Input.dispatchKeyEvent', { type, key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
    await sleep(700);
  };
  await run(page, `q('.pane:not(.off) .xterm-helper-textarea').focus();`);
  await page.send('Input.insertText', { text: 'sys' });
  await sleep(700);
  const commandHints = await hints();
  await tab();
  const subHints = await hints();
  await page.send('Input.insertText', { text: 're' });
  await sleep(700);
  const narrowed = await hints();
  await pressEnter(page);
  await sleep(500);
  const hintsGone = await hints();
  await page.send('Input.insertText', { text: 'cat /srv/ap' });
  await sleep(1200);
  const pathHints = await hints();
  await tab();
  await sleep(500);
  const inside = await hints();
  const typedPath = await terminalText(page, 0, true);
  await pressEnter(page);
  await sleep(400);
  ok('suggestions: command, after Tab its subcommands, narrowed while typing on; Enter clears them', commandHints.join() === '*systemctl' && subHints[0] === '*status' && subHints.includes('restart') && narrowed.join() === '*restart,reload' && hintsGone.length === 0, `${commandHints.join()} | ${subHints.slice(0, 3).join()} | ${narrowed.join()}`);
  ok('suggestions: paths come from the server, Tab completes the folder and shows its content', pathHints.join() === '*app/' && inside.map((name) => name.replace(/^\*/, '')).includes('config.yaml') && /cat \/srv\/app\/\s*$/.test(typedPath.trimEnd()), `${pathHints.join()} | ${inside.slice(0, 4).join()}`);

  // Clean up: panel closed, tab closed; with the host its rule disappears, also from operation.
  const tidied = await run(page, `
    q('.side .side-h .btn.ghost').click(); await wait(200);
    q('.tabs .tab.on .x').click(); await wait(400);
    const before = (await invoke('forward_list')).map(s => s.id);
    await invoke('host_delete', { id: '${asking.host}' });
    const end = Date.now() + 6000;
    let left = before;
    while (Date.now() < end && left.length) { await wait(200); left = (await invoke('forward_list')).map(s => s.id); }
    const data = (await invoke('vault_status')).data;
    return { before, left, rules: data.forwards.map(f => f.name), sessions: await invoke('session_count'), side: !!q('.side') };
  `);
  ok('with the host its rule disappears from vault and operation', tidied.before.join() === asking.id && tidied.left.length === 0 && !tidied.rules.includes('E2E Rückfrage') && tidied.rules.includes('E2E lokal') && tidied.sessions === 0 && !tidied.side, tidied.rules.join(', '));
  echo.close();

  // 4n. Import. An OpenSSH configuration with a jump host, three key files (plain, with
  // passphrase, missing), two port rules and a host that already exists in the vault.
  const importDir = join(workDir, 'import');
  mkdirSync(importDir, { recursive: true });
  const freeKey = join(importDir, 'id_e2e');
  const lockedKey = join(importDir, 'id_e2e_zu');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'e2e-frei', '-f', freeKey]);
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', 'geheim', '-C', 'e2e-zu', '-f', lockedKey]);
  const configFile = put(
    importDir,
    'config',
    [
      'Host e2e-bastion',
      '  HostName 198.51.100.10',
      '  User deploy',
      `  IdentityFile ${freeKey}`,
      '  DynamicForward 11080',
      'Host e2e-web',
      '  HostName 198.51.100.11',
      '  User deploy',
      '  Port 2200',
      '  ProxyJump e2e-bastion',
      '  LocalForward 18080 127.0.0.1:80',
      `  IdentityFile ${lockedKey}`,
      'Host e2e-alt',
      '  HostName 198.51.100.12',
      `  IdentityFile ${join(importDir, 'gibt-es-nicht')}`,
      '  ProxyCommand nc %h %p',
      'Host schon-da',
      '  HostName 127.0.0.1',
      `  Port ${port}`,
      'Host *',
      '  ServerAliveInterval 40',
      '',
    ].join('\n'),
  );

  // The dialog opens from the Hosts page and shows all sources; the search on this PC answers.
  const impDialog = await run(page, `
    q('.tabs .tab.home')?.click(); await wait(150); qa('.nv')[0].click(); await wait(300);
    byText('.ph .acts .btn','Importieren').click();
    await until(()=>q('.dlg.imp'));
    const scanned = await until(()=>q('.imp-found') || (q('.imp-none') && !q('.imp-none').textContent.includes('Sieht nach')), 20000);
    const tiles = qa('.imp-src').length;
    q('.imp-head .btn.ghost').click(); await wait(250);
    return { tiles, scanned: !!scanned, closed: !q('.dlg.imp') };
  `);
  ok('Import opens the dialog with all sources, the search on this PC answers', impDialog.tiles === 13 && impDialog.scanned && impDialog.closed, `${impDialog.tiles} tiles`);

  // Drag a file into the window: Tauri reports that as an event, which can be simulated here.
  const impPreview = await run(page, `
    await invoke('plugin:event|emit', { event: 'tauri://drag-drop', payload: { paths: [${JSON.stringify(configFile)}], position: { x: 500, y: 400 } } }).catch(()=>null);
    const list = await until(()=>q('.imp-list'), 8000);
    if (!list) return { opened: false };
    const row = name => qa('.imp-list .pick').find(r => r.querySelector('b')?.textContent === name);
    const chips = name => [...(row(name)?.querySelectorAll('.chip') ?? [])].map(c => c.textContent.trim());
    const part = async text => { qa('.imp .seg button').find(b => b.textContent.trim().startsWith(text)).click(); await wait(250); };
    const hosts = qa('.imp-list .pick b').map(b => b.textContent);
    const web = chips('e2e-web'), old = chips('e2e-alt'), known = chips('schon-da');
    const origin = q('.imp-origin').textContent;
    const into = q('.imp-opt select').selectedOptions[0].textContent.trim(), group = q('.imp-name')?.value;
    const button = q('.imp .dlg-a .btn.primary').textContent.trim();
    await part('Schlüssel');
    const keys = qa('.imp-list .pick').map(r => r.querySelector('b').textContent + '|' + [...r.querySelectorAll('.chip')].at(-1).textContent.trim() + '|' + r.querySelector('input').disabled);
    await part('Port-Regeln');
    const rules = qa('.imp-list .pick span.mono').map(s => s.textContent);
    await part('Hosts');
    return { opened: true, hosts, web, old, known, origin, into, group, button, keys, rules };
  `);
  ok('file dragged into the window: the preview shows the configuration\'s hosts', impPreview.opened && impPreview.hosts.join() === 'e2e-bastion,e2e-web,e2e-alt,schon-da' && impPreview.origin.includes('OpenSSH') && impPreview.origin.includes('config'), impPreview.opened ? impPreview.hosts.join() : 'preview did not open');
  if (impPreview.opened) {
    ok('the preview names jump host, keys, notes and what already exists', impPreview.web.some((c) => c.includes('über e2e-bastion')) && impPreview.web.includes('id_e2e_zu') && impPreview.old.some((c) => c.includes('ProxyCommand')) && impPreview.known.some((c) => c.includes('Schon vorhanden')), [impPreview.web, impPreview.old, impPreview.known].map((c) => c.join('/')).join(' | '));
    ok('keys: a free one goes into the vault, one with a passphrase stays a file, a missing one is locked', impPreview.keys.join(';') === 'id_e2e|Kommt in den Tresor|false;id_e2e_zu|Mit Passphrase · bleibt Schlüsseldatei|false;gibt-es-nicht|Datei fehlt|true', impPreview.keys.join(';'));
    ok('port rules from LocalForward and DynamicForward', impPreview.rules.length === 2 && impPreview.rules.some((r) => r.startsWith('SOCKS 127.0.0.1:11080')) && impPreview.rules.some((r) => r.includes('18080') && r.includes('127.0.0.1:80')), impPreview.rules.join(' | '));
    ok('default: a new group named after the source, an existing host is skipped', impPreview.into === 'Neue Gruppe' && impPreview.group === 'OpenSSH' && impPreview.button === '3 Hosts importieren', `${impPreview.into} „${impPreview.group}“, ${impPreview.button}`);
    const impDone = await run(page, `
      q('.imp .dlg-a .btn.primary').click();
      await until(()=>q('.imp-done'), 15000);
      const sum = qa('.imp-sum div').map(d => d.querySelector('b').textContent + ' ' + d.querySelector('span').textContent);
      byText('.imp .dlg-a .btn','Zu den Hosts').click(); await wait(400);
      const shown = await until(()=>byText('.group','OpenSSH'));
      return { sum, closed: !q('.dlg.imp'), shown: !!shown };
    `);
    ok('import through the interface: the report names hosts, group, keys and rules', impDone.sum.join(', ') === '3 neue Hosts, 1 neue Gruppe, 1 Schlüssel im Tresor, 1 Schlüsseldatei, 2 Port-Regeln, 1 ausgelassen' && impDone.closed && impDone.shown, impDone.sum.join(', '));
  } else {
    // Without the simulated drop the same import runs through the commands, so the rest stays tested.
    await run(page, `
      const d = await invoke('import_file', { path: ${JSON.stringify(configFile)} });
      await invoke('import_apply', { token: d.token, options: { hosts: d.hosts.map(h=>h.ref), keys: d.keys.filter(k=>k.state!=='missing').map(k=>k.ref), forwards: d.forwards.map(f=>f.ref), snippets: [], knownHosts: [], into: { name: 'OpenSSH' }, existing: 'skip', keysToVault: true, passwords: true } });
    `);
  }
  const impVault = await run(page, `
    const s = (await invoke('vault_status')).data;
    const host = name => s.hosts.find(h => h.name === name);
    const group = s.groups.find(g => g.name === 'OpenSSH');
    const key = s.keys.find(k => k.name === 'id_e2e');
    const web = host('e2e-web'), bastion = host('e2e-bastion'), old = host('e2e-alt');
    return {
      inGroup: [web, bastion, old].every(h => h && h.group === group?.id), doubled: !!host('schon-da'), total: s.hosts.length,
      web: web && [web.address, web.own.user, web.own.port, web.own.keepalive, web.own.jump === bastion?.id, web.own.keyFile === ${JSON.stringify(lockedKey)}, web.own.key ?? null].join('|'),
      bastion: bastion && [bastion.own.key === key?.id, key?.origin, bastion.own.jump ?? null].join('|'),
      old: old && [old.own.key ?? null, old.own.keyFile ?? null, old.own.jump ?? null].join('|'),
      rules: s.forwards.filter(f => [web?.id, bastion?.id].includes(f.host)).map(f => f.kind + ':' + f.bindPort + '>' + f.destPort).sort().join(),
    };
  `);
  ok('in the vault: hosts in their group, jump host and the configuration\'s values, no duplicate host', impVault.inGroup && !impVault.doubled && impVault.web === '198.51.100.11|deploy|2200|40|true|true|', `${impVault.web}, ${impVault.total} hosts`);
  ok('in the vault: free key imported and set on the host, the missing one nowhere, rules created', impVault.bastion === 'true|imported|' && impVault.old === '||' && impVault.rules === 'dynamic:11080>0,local:18080>80', `${impVault.bastion} · ${impVault.old} · ${impVault.rules}`);

  // A table with groups and passwords, once with and once without “take over passwords”. Plus known_hosts.
  const csvFile = put(importDir, 'hosts.csv', 'Groups,Label,Hostname/IP,Port,Username,Password\r\nE2E-CSV/Unter,csv-a,198.51.100.21,22,root,pw-a\r\nE2E-CSV/Unter,csv-b,198.51.100.22,2222,root,pw-b\r\n,csv-telnet,198.51.100.23,23,admin,\r\n'.replace('\r\n,csv-telnet,198.51.100.23,23,admin,', '\r\n,csv-leer,,22,admin,'));
  const knownFile = put(importDir, 'known_hosts', `198.51.100.21 ${readFileSync(`${freeKey}.pub`, 'utf8').split(' ').slice(0, 2).join(' ')}\n|1|c2FsdA==|aGFzaA== ${readFileSync(`${lockedKey}.pub`, 'utf8').split(' ').slice(0, 2).join(' ')}\n`);
  const impTable = await run(page, `
    const d = await invoke('import_file', { path: ${JSON.stringify(csvFile)} });
    const text = JSON.stringify(d);
    const all = { hosts: d.hosts.map(h=>h.ref), keys: [], forwards: [], snippets: [], knownHosts: [], into: null, existing: 'skip', keysToVault: true };
    const first = await invoke('import_apply', { token: d.token, options: { ...all, hosts: ['h0'], passwords: true } });
    const gone = await fails(invoke('import_apply', { token: d.token, options: { ...all, passwords: true } }));
    const d2 = await invoke('import_file', { path: ${JSON.stringify(csvFile)} });
    const second = await invoke('import_apply', { token: d2.token, options: { ...all, hosts: ['h1'], passwords: false } });
    const k = await invoke('import_file', { path: ${JSON.stringify(knownFile)} });
    const third = await invoke('import_apply', { token: k.token, options: { ...all, hosts: [], knownHosts: k.knownHosts.map(x=>x.ref), passwords: false } });
    const unknown = await fails(invoke('import_file', { path: ${JSON.stringify(freeKey)} }));
    const s = third.data;
    const host = name => s.hosts.find(h => h.name === name);
    const under = s.groups.find(g => g.name === 'Unter'), top = s.groups.find(g => g.name === 'E2E-CSV');
    return {
      source: d.source, auth: d.hosts.map(h => h.auth + ':' + h.hasPassword).join(), secret: text.includes('pw-a'), skipped: d.skipped.map(x => x.reason).join(),
      first: first.report.hosts + '/' + first.report.groups, gone: gone?.code, second: second.report.hosts + '/' + second.report.groups, d2existing: d2.hosts.map(h => !!h.existing).join(),
      path: under?.parent === top?.id && host('csv-a')?.group === under?.id, passwords: [host('csv-a')?.hasPassword, host('csv-b')?.hasPassword, host('csv-b')?.own.port].join(),
      known: k.source + ':' + k.knownHosts.length + ':' + k.skipped.map(x => x.reason).join() + ':' + third.report.knownHosts, knownHost: s.knownHosts.some(x => x.host === '198.51.100.21' && x.algorithm === 'ssh-ed25519'),
      unknown: unknown?.code,
    };
  `);
  ok('table: format recognised, passwords do not leave the core, a row without an address is skipped', impTable.source === 'csv' && impTable.auth === 'password:true,password:true' && impTable.secret === false && impTable.skipped === 'no_address', `${impTable.source} ${impTable.auth} ${impTable.skipped}`);
  ok('table: groups are created once, a draft applies only once, passwords only on request', impTable.first === '1/2' && impTable.gone === 'not_found' && impTable.second === '1/0' && impTable.d2existing === 'true,false' && impTable.path && impTable.passwords === 'true,false,2222', `${impTable.first} ${impTable.second} ${impTable.passwords}`);
  ok('known_hosts: key taken over, hashed name skipped; a key file is not an import', impTable.known === 'knownhosts:1:hashed:1' && impTable.knownHost && impTable.unknown === 'import_unknown', `${impTable.known} ${impTable.unknown}`);

  // Portable version and updates: the test runs as a portable copy, which never looks for updates.
  const impDelivery = await run(page, `
    const info = await invoke('app_info');
    const refused = await fails(invoke('update_check'));
    // Die Optionen sind der letzte Eintrag der Navigation, wie viele davor auch stehen.
    qa('.nv').at(-1).click(); await until(()=>byText('.sec','Import und Export'));
    const rows = qa('.rows .row .rt b').map(b => b.textContent);
    return { portable: info.portable, updates: info.updates, dataDir: info.dataDir, refused: refused?.code, button: !!byText('.btn','Nach Updates suchen'), rows: ['Importieren','Exportieren'].every(r => rows.includes(r)), switch: rows.includes('Beim Start nach Updates suchen') };
  `);
  ok('portable version: data next to the program, the webview\'s too; no search for updates', impDelivery.portable === true && impDelivery.updates === false && impDelivery.refused === 'update_unavailable' && !impDelivery.button && !impDelivery.switch && impDelivery.rows && existsSync(join(workDir, 'data', 'webview')), `${impDelivery.dataDir} ${impDelivery.refused}`);

  // Clean up: what the import created disappears again; the later steps count the entries.
  const impCleared = await run(page, `
    let s = (await invoke('vault_status')).data;
    for (const g of s.groups.filter(g => ['OpenSSH','E2E-CSV'].includes(g.name))) await invoke('group_delete', { id: g.id, withContents: true });
    s = (await invoke('vault_status')).data;
    for (const k of s.keys.filter(k => k.name === 'id_e2e')) await invoke('key_delete', { id: k.id });
    for (const k of s.knownHosts.filter(k => k.host === '198.51.100.21')) await invoke('known_host_delete', { id: k.id });
    s = (await invoke('vault_status')).data;
    qa('.nv')[0].click(); await wait(200);
    return { hosts: s.hosts.map(h => h.name).sort().join(), groups: s.groups.map(g => g.name).join(), rules: s.forwards.length };
  `);
  ok('after cleaning up the vault is as before the import', !/e2e-|csv-/.test(impCleared.hosts) && !/OpenSSH|E2E-CSV/.test(impCleared.groups), `${impCleared.hosts} · ${impCleared.groups}`);

  // 4o. Local terminal, Telnet, serial line.
  // A counterpart for Telnet: it negotiates like a switch (echo, character mode, terminal type, window size),
  // echoes what is typed and remembers what the client sends. The line “ende” makes it close the connection.
  const telnetSeen = { bytes: Buffer.alloc(0), lines: [] };
  const telnetServer = net.createServer((socket) => {
    let line = '';
    socket.on('error', () => {});
    socket.write(Buffer.from([255, 251, 1, 255, 251, 3, 255, 253, 24, 255, 253, 31, 255, 250, 24, 1, 255, 240]));
    socket.write('\r\nUser Access Verification\r\n\r\nUsername: ');
    socket.on('data', (data) => {
      telnetSeen.bytes = Buffer.concat([telnetSeen.bytes, data]);
      for (let i = 0; i < data.length; ) {
        const byte = data[i];
        if (byte === 255) {
          // Protocol commands are not part of the text.
          const verb = data[i + 1];
          const end = verb === 250 ? data.indexOf(Buffer.from([255, 240]), i) : -1;
          i = verb === 250 ? (end < 0 ? data.length : end + 2) : i + (verb === 255 ? 2 : 3);
          continue;
        }
        i += 1;
        if (byte === 13) continue;
        if (byte !== 10) {
          line += String.fromCharCode(byte);
          socket.write(Buffer.from([byte]));
          continue;
        }
        telnetSeen.lines.push(line);
        if (line === 'ende') return void socket.end('\r\nbye\r\n');
        socket.write(telnetSeen.lines.length === 1 ? '\r\nm8-switch>' : `\r\necho:${line}\r\nm8-switch>`);
        line = '';
      }
    });
  });
  await new Promise((done) => telnetServer.listen(0, '127.0.0.1', done));
  const telnetPort = telnetServer.address().port;
  const m8Tabs = await run(page, `return qa('.tabs .tab:not(.home)').length`);

  // The tab bar's plus offers the shells the core finds on this PC; the command prompt starts.
  const m8Shells = await run(page, `
    const shells = await invoke('local_shells');
    q('.tab-add').click(); await until(()=>q('.menu.newtab'));
    const offered = qa('.menu.newtab .mi[data-shell]').map(b => b.dataset.shell);
    const first = !!q('.menu.newtab .mi[data-shell] kbd');
    q('.menu.newtab .mi[data-shell="cmd"]').click();
    const running = await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    await wait(1000);
    return { ids: shells.map(s => s.id), offered, first, running: !!running, state: q('.sview:not(.off) .live')?.textContent.trim(), tab: q('.tabs .tab.on .nm')?.textContent,
      address: q('.sview:not(.off) .tbar .tt span')?.textContent, bar: !!q('.sview:not(.off) .fbar'), filesButton: !!byText('.sview:not(.off) .tbar .btn','Dateien'), icon: !!q('.sview:not(.off) .tbar .os.logo svg') };
  `);
  ok('the core finds this PC\'s shells, the plus offers exactly them', m8Shells.ids.includes('cmd') && m8Shells.ids.includes('powershell') && m8Shells.offered.join() === m8Shells.ids.join() && m8Shells.first, m8Shells.ids.join(', '));
  ok('local terminal: Command Prompt runs as a tab, without a file bar', m8Shells.running && m8Shells.state === 'Läuft' && m8Shells.tab === 'Eingabeaufforderung' && m8Shells.address === 'Dieser PC' && !m8Shells.bar && !m8Shells.filesButton && m8Shells.icon, `${m8Shells.state} · ${m8Shells.tab}`);
  // The answer contains what only the shell fills in; the echo of the input alone would not contain it.
  await typeLine(page, 'echo m8-%OS%-ok');
  await sleep(1200);
  const m8Echo = await terminalText(page);
  ok('local terminal: input reaches the real shell, its output the terminal', m8Echo.includes('m8-Windows_NT-ok'), m8Echo.trim().split('\n').at(-2)?.trim().slice(0, 50));
  await typeLine(page, 'exit 3');
  const m8Ended = await run(page, `
    const bar = await until(()=>q('.pane:not(.off) .endbar'), 10000);
    const text = bar?.textContent.trim() ?? ''; const state = q('.sview:not(.off) .live')?.textContent.trim();
    byText('.pane:not(.off) .endbar .btn','Neu starten')?.click();
    const again = await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    await wait(600);
    q('.tabs .tab.on .x').click(); await wait(400);
    return { text, state, again: !!again };
  `);
  ok('local terminal: the end names the shell\'s exit code, “Restart” starts it again', m8Ended.text.includes('Die Shell wurde beendet (3).') && m8Ended.state === 'Beendet' && m8Ended.again, m8Ended.text.slice(0, 60));

  // Ctrl+Shift+T opens the default shell (without a setting the first one found).
  const m8Hotkey = await run(page, `
    const first = (await invoke('local_shells'))[0];
    const before = qa('.tabs .tab:not(.home)').length;
    window.dispatchEvent(new KeyboardEvent('keydown',{key:'T',ctrlKey:true,shiftKey:true,bubbles:true}));
    const opened = await until(()=>qa('.tabs .tab:not(.home)').length === before + 1);
    const running = await until(()=>q('.sview:not(.off) .live.connected'), 20000);
    const tab = q('.tabs .tab.on .nm')?.textContent;
    await wait(500);
    q('.tabs .tab.on .x').click(); await wait(400);
    return { opened: !!opened, running: !!running, tab, first: first.kind === 'cmd' ? 'Eingabeaufforderung' : first.name, left: qa('.tabs .tab:not(.home)').length - before };
  `);
  ok('Ctrl+Shift+T opens the default shell; closing ends it', m8Hotkey.opened && m8Hotkey.running && m8Hotkey.tab === m8Hotkey.first && m8Hotkey.left === 0, m8Hotkey.tab);

  // Search finds shells and understands “telnet address port”.
  const m8Search = await run(page, `
    window.dispatchEvent(new KeyboardEvent('keydown',{key:'k',ctrlKey:true,bubbles:true}));
    const pal = await until(()=>q('.pal input')); type(pal,'eingabeauff');
    const shell = await until(()=>byText('.pi','Eingabeaufforderung'));
    const label = shell?.querySelector('small')?.textContent;
    type(pal,'telnet 127.0.0.1 ${telnetPort}'); const entry = await until(()=>byText('.pi','Direkt verbinden'));
    const text = entry?.querySelector('.pn')?.textContent;
    pal.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
    const connected = await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    await wait(800);
    return { shell: !!shell, label, text, connected: !!connected, tab: q('.tabs .tab.on .nm')?.textContent, save: !!byText('.sview:not(.off) .tbar .btn','Als Host speichern'), bar: !!q('.sview:not(.off) .fbar') };
  `);
  ok('search: finds the shell and offers Telnet quick connect', m8Search.shell && m8Search.label === 'Lokales Terminal' && m8Search.text === `telnet 127.0.0.1 ${telnetPort}`, m8Search.text);
  await typeLine(page, 'admin');
  await sleep(500);
  await typeLine(page, 'show m8');
  await sleep(900);
  const m8Telnet = await terminalText(page);
  const sent = [...telnetSeen.bytes];
  const has = (...part) => sent.some((_, i) => part.every((b, j) => sent[i + j] === b));
  ok('Telnet: connected, what is typed comes back as the server\'s echo', m8Search.connected && m8Search.tab === '127.0.0.1' && !m8Search.bar && m8Telnet.includes('Username: admin') && m8Telnet.includes('echo:show m8'), m8Telnet.trim().split('\n').at(-2)?.trim());
  ok('Telnet: terminal type and window size negotiated, Enter is CR LF', has(255, 251, 24) && has(255, 251, 31) && has(255, 250, 31) && has(255, 250, 24, 0, ...Buffer.from('xterm-256color'), 255, 240) && has(13, 10) && !has(13, 0) && telnetSeen.lines.join() === 'admin,show m8', telnetSeen.lines.join());

  // Saved as a host, the connection carries its protocol. The core refuses what only works over SSH for it.
  const m8Saved = await run(page, `
    byText('.sview:not(.off) .tbar .btn','Als Host speichern').click();
    await until(()=>!byText('.sview:not(.off) .tbar .btn','Als Host speichern'));
    const made = (await invoke('vault_status')).data.hosts.find(h=>h.name==='127.0.0.1');
    const forward = await fails(invoke('forward_save',{rule:{name:'m8',kind:'local',host:made.id,bindAddress:'',bindPort:18999,destHost:'127.0.0.1',destPort:80}}));
    const files = await fails(invoke('fs_connect',{id:made.id}));
    const jump = await fails(invoke('host_save',{host:{name:'m8-hinten',address:'198.51.100.77',group:null,color:null,os:null,own:{jump:made.id}}}));
    const bad = await fails(invoke('host_save',{host:{name:'m8-rdp',address:'198.51.100.78',protocol:'rdp',group:null,color:null,os:null,own:{}}}));
    return { protocol: made?.protocol, port: made?.own.port, password: made?.hasPassword, forward: forward?.reason, files: files?.reason, jump: jump?.reason, bad: bad?.reason };
  `);
  ok('Telnet quick connection saved as a host, with protocol and port', m8Saved.protocol === 'telnet' && m8Saved.port === telnetPort && m8Saved.password === false);
  ok('port rules, files and jumping only work over SSH; an unknown protocol is rejected', m8Saved.forward === 'host_not_ssh' && m8Saved.files === 'host_not_ssh' && m8Saved.jump === 'host_not_ssh' && m8Saved.bad === 'protocol_invalid', `${m8Saved.forward}, ${m8Saved.files}, ${m8Saved.jump}, ${m8Saved.bad}`);
  await typeLine(page, 'ende');
  const m8Closed = await run(page, `
    const bar = await until(()=>q('.pane:not(.off) .endbar'), 10000);
    const text = bar?.textContent.trim() ?? '';
    q('.tabs .tab.on .x').click(); await wait(400);
    return { text };
  `);
  ok('Telnet: if the server closes, the session ends with this information', m8Closed.text.includes('Die Gegenstelle hat die Verbindung beendet.'), m8Closed.text.slice(0, 60));

  // A serial host via the editor. There is no device here: the port nobody has cannot be opened.
  const m8Serial = await run(page, `
    q('.tabs .tab.home').click(); qa('.nv')[0].click(); await wait(300);
    byText('.ph .acts .btn','Neuer Host').click(); await until(()=>q('.editor'));
    qa('.editor .seg button').find(b=>b.textContent.trim()==='Seriell').click();
    const select = await until(()=>q('.editor select[aria-label="Port"]'));
    await wait(500);
    const ports = await invoke('serial_ports');
    const offered = [...select.options].map(o=>o.value).filter(v => v && v !== 'other');
    const sshOnly = !!byText('.editor .ed-sec','Anmeldung');
    type(q('.editor .fld input[type=text]'),'m8-konsole');
    select.value = 'other'; select.dispatchEvent(new Event('change',{bubbles:true}));
    const free = await until(()=>q('.editor input[aria-label="Port"]'));
    type(free,'COM254');
    const baud = q('.editor .fld-2 select'); baud.value = '115200'; baud.dispatchEvent(new Event('change',{bubbles:true}));
    await wait(150);
    q('.editor button[type=submit]').click();
    await until(()=>!q('.editor'));
    const made = (await invoke('vault_status')).data.hosts.find(h=>h.name==='m8-konsole');
    const card = byText('.host','m8-konsole')?.textContent ?? '';
    byText('.host','m8-konsole').dispatchEvent(new MouseEvent('dblclick',{bubbles:true}));
    const bar = await until(()=>q('.pane:not(.off) .endbar'), 12000);
    const end = bar?.textContent.trim() ?? ''; const state = q('.sview:not(.off) .live')?.textContent.trim(); const address = q('.sview:not(.off) .tbar .tt span')?.textContent;
    q('.tabs .tab.on .x').click(); await wait(400);
    return { ports: ports.map(p=>p.name).join(), offered: offered.join(), sshOnly, made, card, end, state, address };
  `);
  ok('host editor “Serial”: offers the PC\'s ports and shows no sign-in', m8Serial.offered === m8Serial.ports && !m8Serial.sshOnly, `Ports: ${m8Serial.ports || 'none'}`);
  ok('serial host saved: port and line in the vault, the tile shows both', m8Serial.made?.protocol === 'serial' && m8Serial.made.address === 'COM254' && m8Serial.made.serial?.baud === 115200 && m8Serial.made.serial.dataBits === 8 && m8Serial.card.includes('COM254 · 115200 8N1') && m8Serial.card.includes('SERIAL'), m8Serial.card.trim().slice(0, 50));
  ok('serial line: a port that does not exist is reported with the system\'s reason', m8Serial.end.includes('Der Port lässt sich nicht öffnen:') && m8Serial.state === 'Geschlossen' && m8Serial.address === 'COM254 · 115200 8N1', m8Serial.end.slice(0, 70));

  // Workspaces take in local terminals; the import takes over Telnet and serial lines.
  const m8Csv = put(importDir, 'netz.csv', 'Groups,Label,Hostname/IP,Protocol,Port,Username\r\nM8-Netz,m8-switch,198.51.100.31,telnet,,admin\r\nM8-Netz,m8-com,COM7,serial,115200,\r\n');
  const m8Import = await run(page, `
    const server = (await invoke('vault_status')).data.hosts.find(h=>h.name==='testserver');
    const ws = await invoke('workspace_save',{workspace:{name:'m8-werkbank',multi:true,layout:{dir:'row',ratio:0.5,a:{pane:{kind:'host',id:server.id}},b:{pane:{kind:'local',shell:'cmd'}}}}});
    const saved = ws.data.workspaces.find(w=>w.name==='m8-werkbank');
    await invoke('workspace_delete',{id:saved.id});
    const d = await invoke('import_file', { path: ${JSON.stringify(m8Csv)} });
    const done = await invoke('import_apply', { token: d.token, options: { hosts: d.hosts.map(h=>h.ref), keys: [], forwards: [], snippets: [], knownHosts: [], into: null, existing: 'skip', keysToVault: true, passwords: false } });
    const again = await invoke('import_file', { path: ${JSON.stringify(m8Csv)} });
    await invoke('import_discard', { token: again.token });
    return { workspace: saved?.layout.b?.pane.kind + ':' + saved?.layout.b?.pane.shell + ':' + saved?.multi, draft: d.hosts.map(h => h.name + ':' + h.protocol).join(), report: done.report.hosts + '/' + done.report.groups,
      vault: done.data.hosts.filter(h=>h.name.startsWith('m8-') && h.name !== 'm8-konsole').map(h => h.name + ':' + h.protocol + ':' + (h.serial?.baud ?? h.own.user ?? '')).sort().join(), existing: again.hosts.every(h => !!h.existing) };
  `);
  ok('workspace with a local terminal is saved', m8Import.workspace === 'local:cmd:true', m8Import.workspace);
  ok('import: Telnet and serial line arrive as hosts with their protocol and count as existing afterwards', m8Import.draft === 'm8-switch:telnet,m8-com:serial' && m8Import.report === '2/1' && m8Import.vault === 'm8-com:serial:115200,m8-switch:telnet:admin' && m8Import.existing, m8Import.vault);

  // Clean up: this section's tabs and hosts disappear; the later steps count the entries.
  const m8Cleared = await run(page, `
    while (qa('.tabs .tab:not(.home)').length > ${m8Tabs}) { qa('.tabs .tab:not(.home) .x').at(-1).click(); await wait(250); }
    let s = (await invoke('vault_status')).data;
    for (const g of s.groups.filter(g => g.name === 'M8-Netz')) await invoke('group_delete', { id: g.id, withContents: true });
    s = (await invoke('vault_status')).data;
    for (const h of s.hosts.filter(h => h.protocol !== 'ssh')) await invoke('host_delete', { id: h.id });
    s = (await invoke('vault_status')).data;
    q('.tabs .tab.home').click(); qa('.nv')[0].click(); await wait(200);
    return { hosts: s.hosts.map(h => h.name + ':' + h.protocol).sort().join(), groups: s.groups.map(g => g.name).join(), tabs: qa('.tabs .tab:not(.home)').length, sessions: await invoke('session_count') };
  `);
  telnetServer.close();
  ok('after cleaning up: no hosts of this section, no tabs, no session any more', !/m8-|telnet|serial|M8/.test(m8Cleared.hosts + m8Cleared.groups) && m8Cleared.tabs === m8Tabs, `${m8Cleared.hosts} · ${m8Cleared.sessions} sessions`);

  // FTP and FTPS. The test server brings two FTP servers on the same folder
  // (crates/testserver/src/ftp.rs): a plain one and one with a self-signed certificate.
  {
  const ftp = await server.ftp;
  const ftpLokal = join(workDir, 'ftp-lokal');
  const ftpBig = Buffer.alloc(3 * 1024 * 1024 + 17);
  for (let i = 0; i < ftpBig.length; i++) ftpBig[i] = (i * 31 + 7) % 251;
  put(ftpLokal, 'gross.bin', ftpBig);
  put(ftpLokal, 'ordner/a.txt', 'a');
  put(ftpLokal, 'ordner/tief/b.txt', 'b');
  mkdirSync(join(ftpLokal, 'zurueck'), { recursive: true });
  const FTP_TOOLS = `
    const openFiles = async name => {
      q('.tabs .tab.home')?.click(); await wait(150); qa('.nv')[0].click(); await until(()=>byText('.host', name));
      byText('.host', name).click(); await until(()=>q('.detail'));
      qa('.detail button').find(b=>b.textContent.trim()==='Dateien öffnen').click();
    };
    const right = () => qa('.fcol')[1];
    const need = async (fn, what, ms = 20000) => { const v = await until(fn, ms); if (!v) throw new Error(what+' missing. Dialog:'+(q('.dlg')?.textContent ?? 'none').slice(0,200)+' | right: '+(right()?.textContent ?? 'no column').slice(0,300)+' | page: '+(q('.nv.on')?.textContent ?? '?')); return v; };
    const dialog = () => ({ title: q('.dlg h2')?.textContent.trim(), text: q('.dlg')?.textContent ?? '', buttons: qa('.dlg button').map(b=>b.textContent.trim()) });
    const press = text => { const b = qa('.dlg button').find(b=>b.textContent.trim()===text); if (!b) throw new Error('Button “'+text+'” missing in:'+(q('.dlg')?.textContent ?? 'no dialog').slice(0,300)); b.click(); };
    const code = p => p.then(()=>null, e=>e.code);
    const hostOf = async id => (await invoke('vault_status')).data.hosts.find(h=>h.id===id);
    const finished = async (ids, ms = 90000) => { const end = Date.now() + ms; while (Date.now() < end) { const list = (await invoke('transfer_list')).filter(x => ids.includes(x.id)); if (list.length === ids.length && list.every(x => ['done','failed','cancelled'].includes(x.state))) return list.map(x => x.state); await wait(200); } return ['timeout']; };
  `;

  // FTPS: unknown certificate before signing in, then the start folder.
  const ftps = await run(page, `${FTP_TOOLS}
    await invoke('host_save', { host: { name: 'm11-ftps', address: '127.0.0.1', protocol: 'ftp', group: null, color: null, os: null, own: { user: 'tester', port: ${ftp.tls}, term: 'xterm' }, ftp: { security: 'explicit', anonymous: false, dir: '/htdocs' }, password: 'richtig' } });
    const id = (await invoke('vault_status')).data.hosts.find(h=>h.name==='m11-ftps').id;
    await wait(300);
    const saved = await hostOf(id);
    const chip = byText('.host','m11-ftps')?.querySelector('.chip')?.textContent.trim();
    await openFiles('m11-ftps');
    await need(()=>q('.dlg'), 'prompt');
    const asked = dialog();
    press('Vertrauen und verbinden');
    await need(()=>byText('.fcol .chip','FTPS') && right().textContent.includes('index.html'), 'folder over FTPS');
    const shown = { page: !!q('.fmid'), path: right().querySelector('.fcrumbs')?.textContent.replace(/\\s+/g,''), text: right().textContent };
    const known = (await invoke('vault_status')).data.knownHosts.filter(k=>k.algorithm==='tls').map(k=>k.host+':'+k.port+' '+k.fingerprint);
    return { id, saved, chip, asked, shown, known };
  `);
  ok('m11 FTP host: the core saves encryption and start folder, the password stays in the core, nothing of the terminal remains', ftps.saved.protocol === 'ftp' && JSON.stringify(ftps.saved.ftp) === JSON.stringify({ security: 'explicit', anonymous: false, dir: '/htdocs' }) && ftps.saved.hasPassword === true && JSON.stringify(ftps.saved.own) === JSON.stringify({ user: 'tester', port: ftp.tls }) && !('password' in ftps.saved), JSON.stringify(ftps.saved));
  ok('m11 FTPS: before signing in Glowport shows the fingerprint of the certificate the server really has', ftps.asked.title === 'Unbekanntes Zertifikat' && ftps.asked.text.includes(ftp.fingerprint) && ftps.asked.text.includes(`127.0.0.1:${ftp.tls}`), ftps.asked.text.slice(0, 200));
  ok('m11 FTPS: “Open files” leads into the file manager, into the start folder, with the “FTPS” badge', ftps.shown.page && ftps.shown.path === '/htdocs' && ftps.shown.text.includes('mit leerzeichen und ä.txt'), `${ftps.shown.path} ${ftps.chip}`);
  ok('m11 FTPS: the confirmed certificate is listed with the known hosts', ftps.known.join() === `127.0.0.1:${ftp.tls} ${ftp.fingerprint}`, ftps.known.join());

  // Everything the file manager does, on the real core over FTPS; checked against the server's folder.
  const ftpPlace = `{ kind: 'host', id: '${ftps.id}' }`;
  const ftpWork = await run(page, `${FTP_TOOLS}
    const place = ${ftpPlace};
    const names = async path => (await invoke('fs_list', { place, path })).entries.map(e => e.name).sort().join();
    const root = await invoke('fs_list', { place, path: '/' });
    const tidy = (await invoke('fs_list', { place, path: '/htdocs/../logs//' })).path;
    const read = await invoke('fs_read', { place, path: '/htdocs/mit leerzeichen und ä.txt' });
    await invoke('fs_mkdir', { place, dir: '/htdocs', name: 'neu' });
    await invoke('fs_write', { place, path: '/htdocs/neu/notiz.txt', text: 'erste Fassung' });
    await invoke('fs_rename', { place, path: '/htdocs/neu/notiz.txt', name: 'umbenannt.txt' });
    const taken = await code(invoke('fs_rename', { place, path: '/htdocs/index.html', name: 'neu' }));
    const missing = await code(invoke('fs_list', { place, path: '/gibt/es/nicht' }));
    const before = (await invoke('fs_list', { place, path: '/htdocs' })).ftp;
    const chmod = await code(invoke('fs_chmod', { place, request: { paths: ['/htdocs/index.html'], mode: 0o600, owner: null, group: null, recursive: false } }));
    const after = (await invoke('fs_list', { place, path: '/htdocs' })).ftp;
    const up = await finished(await invoke('transfer_start', { request: { from: { kind: 'local' }, paths: [${JSON.stringify(join(ftpLokal, 'gross.bin'))}, ${JSON.stringify(join(ftpLokal, 'ordner'))}], to: place, dest: '/htdocs/neu', policy: 'overwrite', parallel: 4 } }));
    const listed = await names('/htdocs/neu');
    return { root: root.entries.map(e => e.name + ':' + e.kind).sort().join(), writable: root.writable, tidy, read, taken, missing, before, chmod, after, up, listed };
  `);
  // The simulated server confirms a file shortly before its last piece is on disk. A real
  // server does not do that; here the test waits instead of comparing or fetching half a file.
  for (let i = 0; i < 50 && (!existsSync(join(ftpFiles, 'htdocs/neu/gross.bin')) || statSync(join(ftpFiles, 'htdocs/neu/gross.bin')).size < ftpBig.length); i++) await sleep(100);
  const ftpDown = await run(page, `${FTP_TOOLS}
    const place = ${ftpPlace};
    const down = await finished(await invoke('transfer_start', { request: { from: place, paths: ['/htdocs/neu/gross.bin', '/htdocs/neu/ordner'], to: { kind: 'local' }, dest: ${JSON.stringify(join(ftpLokal, 'zurueck'))}, policy: 'overwrite', parallel: 4 } }));
    return { down };
  `);
  const onFtp = (path) => (existsSync(join(ftpFiles, path)) ? readFileSync(join(ftpFiles, path)) : null);
  const ftpBack = (path) => (existsSync(join(ftpLokal, 'zurueck', path)) ? readFileSync(join(ftpLokal, 'zurueck', path)) : null);
  ok('m11 Files over FTPS: read folders, clean up paths, umlauts and spaces in the name', ftpWork.root === 'htdocs:dir,logs:dir' && ftpWork.tidy === '/logs' && ftpWork.read.text === 'äöü', `${ftpWork.root} ${ftpWork.tidy} ${JSON.stringify(ftpWork.read)}`);
  ok('m11 Files over FTPS: create, write, rename; renaming never overwrites; a missing folder is reported', onFtp('htdocs/neu/umbenannt.txt')?.toString() === 'erste Fassung' && ftpWork.taken === 'file_exists' && onFtp('htdocs/index.html') !== null && ['no_such_file', 'not_a_directory'].includes(ftpWork.missing), `${ftpWork.taken} ${ftpWork.missing}`);
  ok('m11 Permissions: if the server cannot change them, Glowport says so, and the menu item disappears', ftpWork.before?.chmod === true && ftpWork.chmod === 'not_supported' && ftpWork.after?.chmod === false, `${JSON.stringify(ftpWork.before)} ${ftpWork.chmod} ${JSON.stringify(ftpWork.after)}`);
  ok('m11 Transfers over FTPS: a large file and a folder with subfolders up, unchanged', ftpWork.up.every((s) => s === 'done') && ftpWork.up.length === 2 && onFtp('htdocs/neu/gross.bin')?.equals(ftpBig) && onFtp('htdocs/neu/ordner/tief/b.txt')?.toString() === 'b', `${ftpWork.up.join()} ${ftpWork.listed} ${onFtp('htdocs/neu/gross.bin')?.length} of ${ftpBig.length}`);
  ok('m11 Transfers over FTPS: the same back down, unchanged', ftpDown.down.every((s) => s === 'done') && ftpBack('gross.bin')?.equals(ftpBig) && ftpBack('ordner/a.txt')?.toString() === 'a' && ftpBack('ordner/tief/b.txt')?.toString() === 'b', `${ftpDown.down.join()} ${ftpBack('gross.bin')?.length} of ${ftpBig.length}`);

  // Unencrypted and without a saved password: first the warning, then the question for the password.
  const plain = await run(page, `${FTP_TOOLS}
    await invoke('host_save', { host: { name: 'm11-offen', address: '127.0.0.1', protocol: 'ftp', group: null, color: null, os: null, own: { user: 'tester', port: ${ftp.plain} }, ftp: { security: 'none', anonymous: false } } });
    const id = (await invoke('vault_status')).data.hosts.find(h=>h.name==='m11-offen').id;
    await wait(300);
    q('.tabs .tab.home')?.click(); qa('.nv')[0].click();
    const chip = (await need(()=>byText('.host','m11-offen'), 'host card')).querySelector('.chip')?.textContent.trim();
    await openFiles('m11-offen');
    await need(()=>q('.dlg'), 'prompt');
    const warned = dialog();
    press('Abbrechen');
    const again = await need(()=>right().querySelector('.fnote button'), 'notice after cancelling');
    const cancelled = right().querySelector('.fnote p')?.textContent.trim();
    again.click();
    await need(()=>q('.dlg'), 'prompt');
    q('.dlg input[type=checkbox]').click(); await wait(80);
    press('Trotzdem verbinden');
    const field = await need(()=>q('.dlg input[type=password]'), 'password prompt');
    const remembered = (await hostOf(id)).ftp;
    type(field,'falsch'); await wait(80); q('.dlg button[type=submit]').click();
    const retry = await need(()=>q('.dlg .errline')?.textContent, 'second password prompt');
    type(q('.dlg input[type=password]'),'richtig'); q('.dlg input[type=checkbox]').click(); await wait(80);
    q('.dlg button[type=submit]').click();
    await need(()=>byText('.fcol .chip','unverschlüsselt') && right().textContent.includes('htdocs'), 'folder unencrypted');
    await wait(300);
    const host = await hostOf(id);
    const read = await invoke('fs_read', { place: { kind: 'host', id }, path: '/htdocs/index.html' });
    return { id, chip, warned, cancelled, remembered, retry, host, read: read.text, tls: (await invoke('vault_status')).data.knownHosts.filter(k=>k.algorithm==='tls').length };
  `);
  ok('m11 Unencrypted: the card says so, and Glowport warns before connecting; “Connect anyway” is not the highlighted button', /unverschlüsselt/.test(plain.chip) && plain.warned.title === 'Unverschlüsselte Verbindung' && /nicht verschlüsselt/.test(plain.warned.text) && !plain.warned.buttons.includes('Auf FTPS umstellen'), `${plain.chip} ${plain.warned.buttons.join()}`);
  ok('m11 Unencrypted: cancelled, it stays at “not connected”; nothing went to the server', /abgebrochen/i.test(plain.cancelled), plain.cancelled);
  ok('m11 Unencrypted: “Don\'t ask again” is stored on the host afterwards', plain.remembered.plainOk === true && plain.host.ftp.plainOk === true && plain.host.ftp.security === 'none', JSON.stringify(plain.host.ftp));
  ok('m11 Password: a wrong one leads to the second prompt, the right one connects and is stored in the vault on request', /Versuch 2/.test(plain.retry ?? '') && plain.host.hasPassword === true && plain.read === '<h1>Es funktioniert</h1>\n' && plain.tls === 1, `${plain.retry} ${plain.host.hasPassword}`);

    // Search by name, copying between SFTP and FTP, the names in the list of transfers.
    const ftpMore = await run(page, `${FTP_TOOLS}
      const place = ${ftpPlace};
      const shownAs = (await invoke('transfer_list')).filter(x => (x.source + x.dest).includes('/htdocs/neu')).map(x => x.direction + ' ' + x.source + ' -> ' + x.dest);
      const ssh = (await invoke('vault_status')).data.hosts.find(h=>h.name==='testserver');
      const across = ssh ? await finished(await invoke('transfer_start', { request: { from: { kind: 'host', id: ssh.id }, paths: ['/srv/app/config.yaml'], to: place, dest: '/htdocs/neu', policy: 'overwrite', parallel: 4 } })) : ['no SSH host'];
      // Die rechte Spalte zeigt noch den offenen Server aus dem Abschnitt davor; gesucht wird ab seiner Wurzel.
      [...right().querySelectorAll('button')].find(b=>b.title==='Hier suchen').click();
      const field = await need(()=>q('.fsearch-q input'), 'Suchfeld');
      const modes = !!q('.fsearch-q .seg');
      type(field,'B.TXT'); await wait(80); q('.fsearch-q button[type=submit]').click();
      await need(()=>q('.fsearch-r .pick-row'), 'search hits');
      await wait(600);
      const hits = qa('.fsearch-r .pick-row').map(r => r.querySelector('b').textContent.trim() + ' in ' + r.querySelectorAll('.mono')[0].textContent.trim());
      qa('.dlg button, .ov button').find(b=>b.textContent.trim()==='Schließen').click(); await wait(200);
      return { shownAs, across, modes, hits };
    `);
    for (let i = 0; i < 50 && !existsSync(join(ftpFiles, 'htdocs/neu/config.yaml')); i++) await sleep(100);
    await sleep(300);
    ok('m11 The transfer list names the FTP host', ftpMore.shownAs.length >= 2 && ftpMore.shownAs.some((t) => /^upload .* -> m11-ftps:\/htdocs\/neu/.test(t)) && ftpMore.shownAs.some((t) => /^download m11-ftps:\/htdocs\/neu/.test(t)), ftpMore.shownAs.join(' | '));
    ok('m11 Copied from an SSH host (SFTP) directly to the FTP server, unchanged', ftpMore.across.join() === 'done' && onFtp('htdocs/neu/config.yaml')?.equals(readFileSync(join(serverFiles, 'srv/app/config.yaml'))), `${ftpMore.across.join()} ${onFtp('htdocs/neu/config.yaml')?.length}`);
    ok('m11 Search over FTP: by name, case-insensitive, through the subfolders; content search is not offered', !ftpMore.modes && ftpMore.hits.join() === 'b.txt in /htdocs/neu/ordner/tief', ftpMore.hits.join(' | '));

    // Quick connect: `ftp://` is unencrypted and warns without remembering anything; the password is asked for and not saved.
    const quick = await run(page, `${FTP_TOOLS}
      const palette = async text => {
        window.dispatchEvent(new KeyboardEvent('keydown',{key:'k',ctrlKey:true,bubbles:true}));
        const pal = await need(()=>q('.pal input'), 'Suche');
        type(pal, text);
        const entry = await need(()=>qa('.pal .pi').find(e=>e.textContent.includes('://')), 'quick connect entry');
        const shown = entry.textContent.replace(/\\s+/g,' ').trim();
        pal.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
        return shown;
      };
      const password = async () => {
        const field = await need(()=>q('.dlg input[type=password]'), 'password prompt');
        const canSave = !!q('.dlg input[type=checkbox]');
        type(field,'richtig'); await wait(80); q('.dlg button[type=submit]').click();
        return canSave;
      };
      const chosen = () => right().querySelector('select').selectedOptions[0]?.textContent.trim();
      const hostsBefore = (await invoke('vault_status')).data.hosts.length;

      // Ein Passwort in der Adresse wird nicht angenommen.
      window.dispatchEvent(new KeyboardEvent('keydown',{key:'k',ctrlKey:true,bubbles:true}));
      const pal = await need(()=>q('.pal input'), 'Suche');
      type(pal, 'ftp://tester:richtig@127.0.0.1:${ftp.plain}'); await wait(300);
      const withPassword = qa('.pal .pi').length;
      pal.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true})); await wait(200);

      const plainEntry = await palette('ftp://tester@127.0.0.1:${ftp.plain}/htdocs');
      await need(()=>q('.dlg'), 'Warnung');
      const warned = { ...dialog(), remember: !!q('.dlg input[type=checkbox]') };
      press('Trotzdem verbinden');
      const plainSave = await password();
      await need(()=>byText('.fcol .chip','unverschlüsselt') && right().textContent.includes('index.html'), 'quick connect folder');
      const plain = { chosen: chosen(), path: right().querySelector('.fcrumbs')?.textContent.replace(/\\s+/g,'') };

      // Derselbe Weg zu einem Server, der TLS kann: Die Warnung bietet FTPS an und öffnet ihn dann verschlüsselt.
      const tlsEntry = await palette('ftp://tester@127.0.0.1:${ftp.tls}');
      await need(()=>q('.dlg'), 'Warnung');
      const offered = dialog();
      press('Auf FTPS umstellen');
      await password();
      await need(()=>byText('.fcol .chip','FTPS') && right().textContent.includes('htdocs'), 'folder after switching the quick connection');
      const secure = { chosen: chosen(), read: (await invoke('fs_read', { place: { kind: 'ftp', host: '127.0.0.1', port: ${ftp.tls}, user: 'tester', security: 'explicit' }, path: '/htdocs/index.html' })).text };

      // Mit ftps:// verbindet Glowport gleich verschlüsselt. Es ist derselbe Server wie eben, als derselbe Benutzer:
      // Die Verbindung steht schon, also fragt nichts mehr.
      const ftpsEntry = await palette('ftps://tester@127.0.0.1:${ftp.tls}/logs');
      await need(()=>byText('.fcol .chip','FTPS') && right().textContent.includes('access.log'), 'folder over ftps://');
      const direct = { chosen: chosen(), path: right().querySelector('.fcrumbs')?.textContent.replace(/\\s+/g,'') };
      const hostsAfter = (await invoke('vault_status')).data.hosts.length;
      return { withPassword, plainEntry, warned, plainSave, plain, tlsEntry, offered, secure, ftpsEntry, direct, hostsBefore, hostsAfter };
    `);
    ok('m11 Quick connect: `ftp://` appears in the search as unencrypted, `ftps://` as FTPS; a password in the address is not accepted', /ftp:\/\/tester@127\.0\.0\.1:\d+\/htdocs.*unverschlüsselt/.test(quick.plainEntry) && /ftps:\/\/tester@127\.0\.0\.1:\d+\/logs.*FTPS/.test(quick.ftpsEntry) && quick.withPassword === 0, `${quick.plainEntry} | ${quick.ftpsEntry} | ${quick.withPassword}`);
    ok('m11 Quick connect unencrypted: warning without “don\'t ask again”, password without saving, then the named folder', quick.warned.title === 'Unverschlüsselte Verbindung' && !quick.warned.remember && !quick.warned.buttons.includes('Auf FTPS umstellen') && !quick.plainSave && quick.plain.chosen === `tester@127.0.0.1:${ftp.plain}` && quick.plain.path === '/htdocs', JSON.stringify(quick.plain));
    ok('m11 Quick connect: if the server can do FTPS, “Switch to FTPS” opens it encrypted', quick.offered.buttons.includes('Auf FTPS umstellen') && quick.secure.chosen === `tester@127.0.0.1:${ftp.tls}` && quick.secure.read === '<h1>Es funktioniert</h1>\n', JSON.stringify(quick.secure));
    ok('m11 Quick connect over `ftps://`: encrypted, in the named folder, over the connection that is already up; no host is created in the vault', quick.direct.path === '/logs' && quick.hostsAfter === quick.hostsBefore, `${quick.direct.path} ${quick.hostsBefore}/${quick.hostsAfter}`);

    // Changed settings apply to the next connection: the old one is not used any further.
    const changed = await run(page, `${FTP_TOOLS}
      const place = ${ftpPlace};
      const before = await code(invoke('fs_list', { place, path: '/htdocs' }));
      const host = await hostOf('${ftps.id}');
      await invoke('host_save', { host: { ...host, ftp: { ...host.ftp, security: 'none' } } });
      await wait(500);
      const after = await code(invoke('fs_list', { place, path: '/htdocs' }));
      return { before, after };
    `);
    ok('m11 If a connected FTP host is changed, the old connection no longer applies: the next access asks anew', changed.before === null && changed.after === 'files_auth', `${changed.before} ${changed.after}`);

  // A host set up plain although its server can do TLS: the prompt offers to switch it.
  const secure = await run(page, `${FTP_TOOLS}
    await invoke('host_save', { host: { name: 'm11-umstellen', address: '127.0.0.1', protocol: 'ftp', group: null, color: null, os: null, own: { user: 'tester', port: ${ftp.tls} }, ftp: { security: 'none', anonymous: false }, password: 'richtig' } });
    const id = (await invoke('vault_status')).data.hosts.find(h=>h.name==='m11-umstellen').id;
    await wait(300);
    await openFiles('m11-umstellen');
    await need(()=>q('.dlg'), 'prompt');
    const offered = dialog();
    press('Auf FTPS umstellen');
    await need(()=>byText('.fcol .chip','FTPS') && right().textContent.includes('htdocs'), 'folder after switching');
    await wait(300);
    const host = await hostOf(id);
    for (const gone of ['${ftps.id}', '${plain.id}', id]) await invoke('host_delete', { id: gone });
    for (const known of (await invoke('vault_status')).data.knownHosts.filter(k=>k.algorithm==='tls')) await invoke('known_host_delete', { id: known.id });
    await invoke('transfer_clear');
    qa('.nv')[0].click(); await wait(300);
    const left = (await invoke('vault_status')).data;
    return { offered, ftp: host.ftp, asked: !!q('.dlg'), hosts: left.hosts.filter(h=>h.name.startsWith('m11-')).length, known: left.knownHosts.filter(k=>k.algorithm==='tls').length };
  `);
  ok('m11 If the server can do FTPS, the warning offers to switch the host; afterwards it is encrypted and does not ask about the certificate again', secure.offered.buttons.includes('Auf FTPS umstellen') && /kann FTPS/.test(secure.offered.text) && JSON.stringify(secure.ftp) === JSON.stringify({ security: 'explicit', anonymous: false }) && !secure.asked, JSON.stringify(secure.ftp));
  ok('m11 After cleaning up: no hosts and no certificates of this section any more', secure.hosts === 0 && secure.known === 0, `${secure.hosts} ${secure.known}`);
  }

  // Proxmox. The test server brings a simulated Proxmox server (crates/testserver/src/pve.rs):
  // HTTPS with a self-signed certificate, two tokens (one may do everything, one may only look), six machines.
  const pve = await server.pve;
  const PVE_TOKEN = 'glowport@pve!test';
  const PVE_SECRET = '0c6f2c1e-58a1-4c0e-9d3b-7a1f0e2b4c55';
  /** Knobs and counters of the simulated server, bypassing Glowport. */
  const pveTest = (path) =>
    new Promise((done, failed) => {
      const request = https.get(`${pve.address}/test/${path}`, { rejectUnauthorized: false }, (response) => {
        let body = '';
        response.on('data', (chunk) => (body += chunk));
        response.on('end', () => done(JSON.parse(body).data));
      });
      request.on('error', failed);
    });
  const PVE = `
    const go = async label => { q('.tabs .tab.home')?.click(); await wait(150); qa('.nv').find(b=>b.textContent.trim()===label).click(); await wait(400); };
    const field = label => qa('.dlg .fld').find(f=>f.querySelector('.fld-l')?.textContent.trim()===label)?.querySelector('input');
    const button = (text, scope = document) => [...scope.querySelectorAll('button')].find(b=>b.textContent.trim()===text);
    const titled = (text, scope = document) => [...scope.querySelectorAll('button')].find(b=>b.title===text);
    const machine = name => qa('.pve-row').find(r=>r.querySelector('.pve-name b').textContent.trim()===name);
    const state = name => { const s = machine(name)?.querySelector('.pve-state'); return s ? [...s.childNodes].filter(n=>n.nodeType===3).map(n=>n.textContent).join('').trim() : undefined; };
    const parts = el => [...el.children].map(c=>c.textContent.trim()).filter(Boolean).join(' ');
    const hosts = async () => (await invoke('vault_status')).data.hosts;
    const linked = async vmid => (await hosts()).find(h=>h.proxmox?.vmid===vmid);
  `;
  const pveSetup = await run(page, PVE + `
    await go('Proxmox');
    const intro = !!(await until(()=>q('.pve-intro')));
    button('Verbindung hinzufügen').click(); await until(()=>q('.dlg'));
    type(field('Name'),'E2E-PVE'); type(field('Adresse'),'${pve.address}/'); type(field('Kennung des Tokens'),'${PVE_TOKEN}'); type(field('Geheimnis des Tokens'),'${PVE_SECRET}'); await wait(150);
    button('Prüfen', q('.dlg')).click();
    const finger = (await until(()=>q('.pve-finger'), 15000))?.textContent.trim();
    return { intro, finger, proven: !!q('.dlg .okline'), next: qa('.dlg button').map(b=>b.textContent.trim()+(b.disabled?' (disabled)':'')).join('|') };
  `);
  const seenBefore = await pveTest('seen');
  ok('m10 Proxmox: for a self-signed certificate “Check” first only shows the fingerprint; the token has not gone out yet', pveSetup.intro && pveSetup.finger === pve.fingerprint && !pveSetup.proven && pveSetup.next === 'Abbrechen|Mit Token prüfen (disabled)' && seenBefore.tokens === 0, JSON.stringify([pveSetup.next, seenBefore]));
  const pveSaved = await run(page, PVE + `
    q('.dlg .check input').click(); await wait(150);
    button('Mit Token prüfen', q('.dlg')).click();
    const proven = (await until(()=>q('.dlg .okline'), 15000))?.textContent.trim();
    button('Speichern', q('.dlg')).click(); await until(()=>!q('.dlg'));
    await until(()=>machine('shop-01'), 20000); await wait(300);
    const data = (await invoke('vault_status')).data;
    const rows = qa('.pve-row').map(r=>[r.querySelector('.pve-name b').textContent.trim(), r.querySelector('.pve-name span').textContent.trim(), parts(r.querySelector('.pve-addr'))]);
    return { proven, connection: data.proxmox, secretShown: JSON.stringify(data).includes('${PVE_SECRET}'), rows, nodes: qa('.pve-node').map(parts), head: q('.pve-t span').textContent.trim(), states: ['shop-01','spielwiese'].map(state), offer: qa('.pve-h button').map(b=>b.textContent.trim()).filter(Boolean).join() };
  `);
  const pveId = pveSaved.connection?.[0]?.id;
  ok('m10 Proxmox: with a confirmed fingerprint the token applies; the connection is in the vault, its secret does not reach the interface', /Proxmox VE 9\.0\.11 antwortet/.test(pveSaved.proven ?? '') && pveSaved.connection.length === 1 && pveSaved.connection[0].name === 'E2E-PVE' && pveSaved.connection[0].address === pve.address && pveSaved.connection[0].fingerprint === pve.fingerprint && !('secret' in pveSaved.connection[0]) && !pveSaved.secretShown && (await pveTest('seen')).tokens > 0, JSON.stringify(pveSaved.connection));
  ok('m10 Proxmox: the page shows nodes and machines with kind, state and the address with its origin', pveSaved.head.includes('Proxmox VE 9.0.11') && pveSaved.nodes.some((n) => n.startsWith('old') && n.includes('nicht erreichbar')) && pveSaved.nodes.some((n) => /^pve Prozessor 21 % von 32 Kernen/.test(n)) && JSON.stringify(pveSaved.rows) === JSON.stringify([['shop-01', 'VM 101', 'deploy@10.0.10.11 aus Cloud-Init'], ['pihole', 'Container 111', 'root@10.0.0.53 aus den Einstellungen'], ['gitea', 'Container 112', 'root@10.0.10.74 vom Container gemeldet'], ['monitoring', 'VM 120', '10.0.10.90 vom Gastagenten'], ['spielwiese', 'VM 130', 'keine Adresse bekannt'], ['debian-13-vorlage', 'VM 9000 · Vorlage', '']]) && pveSaved.states.join() === 'läuft,aus' && pveSaved.offer === '5 Hosts anlegen', JSON.stringify([pveSaved.head, pveSaved.nodes, pveSaved.rows, pveSaved.states, pveSaved.offer]));

  // Refreshing does not ask every machine for its settings every time; “Reload” does.
  const configsBefore = (await pveTest('seen')).configs;
  await run(page, `await invoke('proxmox_overview', { id: '${pveId}' }); await invoke('proxmox_overview', { id: '${pveId}' });`);
  const configsQuiet = (await pveTest('seen')).configs;
  await run(page, `await invoke('proxmox_overview', { id: '${pveId}', fresh: true });`);
  const configsFresh = (await pveTest('seen')).configs;
  ok('m10 Proxmox: what was read about a machine applies for a while; “Reload” asks every one anew', configsQuiet === configsBefore && configsFresh === configsBefore + 6, `${configsBefore} → ${configsQuiet} → ${configsFresh}`);

  const pveImport = await run(page, PVE + `
    button('5 Hosts anlegen', q('.pve-h')).click(); await until(()=>q('.pve-pick'));
    const picks = qa('.pve-prow').map(r=>r.querySelector('.pve-name b').textContent.trim()+':'+r.querySelector('input').checked).join();
    const run = qa('.dlg button').at(-1).textContent.trim();
    qa('.dlg button').at(-1).click(); await until(()=>!q('.dlg'));
    let made = [];
    for (let i = 0; i < 60 && made.length < 4; i++) { await wait(200); made = (await hosts()).filter(h=>h.proxmox); }
    await until(()=>machine('shop-01')?.querySelector('.pve-tags .chip.on'), 15000);
    const shop = made.find(h=>h.proxmox.vmid===101), dns = made.find(h=>h.proxmox.vmid===111);
    return { picks, run, made: made.map(h=>h.name).sort().join(), shop, dns, offer: qa('.pve-h button').map(b=>b.textContent.trim()).filter(Boolean).join(), linked: !!machine('shop-01').querySelector('.pve-tags .chip.on') };
  `);
  ok('m10 Proxmox: the preview preselects what has an address and is not a template', pveImport.picks === 'shop-01:true,pihole:true,gitea:true,monitoring:true,spielwiese:false,debian-13-vorlage:false' && pveImport.run === '4 Hosts anlegen', `${pveImport.picks} · ${pveImport.run}`);
  ok('m10 Proxmox: the machines become linked hosts with address, user and operating system', pveImport.made === 'gitea,monitoring,pihole,shop-01' && pveImport.shop.address === '10.0.10.11' && pveImport.shop.own.user === 'deploy' && pveImport.shop.os === 'Li' && pveImport.shop.proxmox.connection === pveId && pveImport.shop.proxmox.kind === 'qemu' && pveImport.dns.own.user === 'root' && pveImport.dns.os === 'De' && pveImport.dns.proxmox.kind === 'lxc' && pveImport.offer === '1 Host anlegen' && pveImport.linked, JSON.stringify([pveImport.made, pveImport.shop, pveImport.offer]));

  // Keeping up to date: in Proxmox name and address of VM 101 change. What was changed by hand on the host stays.
  await pveTest('rename/shop-neu');
  await pveTest('address/10.0.10.99');
  const pveFollow = await run(page, PVE + `
    titled('Neu lesen', q('.pve-h')).click();
    let host;
    for (let i = 0; i < 60; i++) { await wait(200); host = await linked(101); if (host.name === 'shop-neu' && host.address === '10.0.10.99') break; }
    const first = [host.name, host.address];
    // Den Namen von Hand ändern; die Adresse bleibt, wie Glowport sie gesetzt hat.
    await invoke('host_save', { host: { ...host, name: 'Von Hand' } });
    return { first, kept: (await linked(101)).proxmox.vmid, card: await (async()=>{ await go('Hosts'); const card = await until(()=>byText('.host','Von Hand')); return card?.querySelector('.pve-chip')?.textContent.trim(); })() };
  `);
  await pveTest('rename/shop-drei');
  await pveTest('address/10.0.10.100');
  const pveByHand = await run(page, PVE + `
    await invoke('proxmox_overview', { id: '${pveId}', fresh: true });
    await wait(300);
    const host = await linked(101);
    await go('Proxmox'); await until(()=>machine('shop-drei'), 15000);
    return { host: [host.name, host.address], row: machine('shop-drei').querySelector('.pve-tags .chip.on')?.title };
  `);
  ok('m10 Proxmox: if name and address change in Proxmox, the host follows; the tile shows the machine\'s state', pveFollow.first.join() === 'shop-neu,10.0.10.99' && pveFollow.kept === 101 && pveFollow.card === 'läuft', JSON.stringify(pveFollow));
  ok('m10 Proxmox: a name set by hand stays, the address keeps following', pveByHand.host.join() === 'Von Hand,10.0.10.100' && pveByHand.row === 'Gehört zum Host „Von Hand“', JSON.stringify(pveByHand));

  // Switching: start without a prompt, shut down with one; from there on to the hard stop. Glowport waits until
  // Proxmox has carried out the task. As with Proxmox, the list of machines still names the old state for eight
  // seconds afterwards; the display must still be right at once, including the button for the next step.
  const staleBefore = (await pveTest('seen')).stale;
  const pvePower = await run(page, PVE + `
    let from = Date.now();
    button('Starten', machine('spielwiese')).click();
    const started = await until(()=>state('spielwiese') === 'läuft', 20000);
    const startTook = Date.now() - from;
    titled('Herunterfahren', machine('monitoring')).click();
    const asked = (await until(()=>q('.dlg')))?.querySelector('h2').textContent;
    const choices = qa('.dlg button').map(b=>b.textContent.trim()).join('|');
    button('Hart stoppen', q('.dlg')).click(); await wait(200);
    const hard = q('.dlg h2').textContent;
    from = Date.now();
    button('Hart stoppen', q('.dlg')).click();
    const stopped = await until(()=>state('monitoring') === 'aus' && button('Starten', machine('monitoring')), 20000);
    const stopTook = Date.now() - from;
    const offered = [...machine('monitoring').querySelectorAll('.pve-acts button')].map(b=>b.textContent.trim()||b.title).join('|');
    // Auch das nächste Nachlesen bleibt dabei, solange die Liste noch den alten Zustand nennt.
    await invoke('proxmox_overview', { id: '${pveId}' }); await wait(300);
    const still = [state('spielwiese'), state('monitoring')].join();
    const refused = await fails(invoke('proxmox_action', { id: '${pveId}', guest: { node: 'pve', vmid: 9000, kind: 'qemu' }, action: 'start' }));
    return { started: !!started, startTook, asked, choices, hard, stopped: !!stopped, stopTook, offered, still, refused };
  `);
  const staleAfter = (await pveTest('seen')).stale;
  ok('m10 Proxmox: after switching the display is right immediately, even while Proxmox\'s list still names the old state', pvePower.started && pvePower.stopped && pvePower.startTook < 5000 && pvePower.stopTook < 5000 && pvePower.still === 'läuft,aus' && staleAfter > staleBefore, JSON.stringify([pvePower.startTook, pvePower.stopTook, pvePower.still, staleAfter - staleBefore]));
  ok('m10 Proxmox: starting switches at once, shutting down asks and leads to “Force stop” with its own prompt', pvePower.started && pvePower.asked === '„monitoring“ herunterfahren?' && pvePower.choices === 'Abbrechen|Hart stoppen|Herunterfahren' && pvePower.hard === '„monitoring“ hart stoppen?' && pvePower.stopped && pvePower.offered === 'Starten', JSON.stringify(pvePower));
  ok('m10 Proxmox: if Proxmox does not carry out a task, its reason is in the message', pvePower.refused?.code === 'proxmox_failed' && /VM is a template/.test(pvePower.refused.message), JSON.stringify(pvePower.refused));

  // On the host: the machine's state and buttons. “Start and connect” waits until the host accepts connections;
  // for that the host of the switched-off VM 120 points to the test server.
  const pveHost = await run(page, PVE + `
    const host = await linked(120);
    await invoke('host_save', { host: { ...host, address: '127.0.0.1', own: { ...host.own, user: 'tester', port: ${port} } } });
    await go('Hosts'); (await until(()=>byText('.host','monitoring'))).click(); await until(()=>q('.d-pve .d-pve-a'), 15000);
    const block = q('.d-pve').innerText.replace(/\\s+/g,' ').trim();
    const before = qa('.tabs .tab:not(.home)').length;
    button('Starten und verbinden', q('.d-pve')).click();
    const opened = await until(()=>qa('.tabs .tab:not(.home)').length > before, 30000);
    const tab = q('.tabs .tab.on .nm')?.textContent;
    await wait(1500);
    while (qa('.tabs .tab:not(.home)').length > before) { qa('.tabs .tab:not(.home) .x').at(-1).click(); await wait(300); if (q('.dlg')) { qa('.dlg button').at(-1).click(); await wait(300); } }
    await go('Hosts'); (await until(()=>byText('.host','monitoring'))).click();
    await until(()=>q('.d-pve') && button('Herunterfahren', q('.d-pve')), 15000);
    const running = q('.d-pve').innerText.replace(/\\s+/g,' ').trim();
    // Verknüpfung lösen: Der Host bleibt, die Maschine gilt wieder als nicht angelegt.
    titled('Verknüpfung lösen', q('.d-pve')).click();
    const asked = (await until(()=>q('.dlg')))?.querySelector('h2').textContent;
    button('Verknüpfung lösen', q('.dlg')).click(); await until(()=>!q('.d-pve'), 8000);
    const after = (await hosts()).find(h=>h.name==='monitoring');
    return { block, opened: !!opened, tab, running, asked, unlinked: !!after && !after.proxmox && after.address === '127.0.0.1', detail: !!q('.detail') };
  `);
  ok('m10 Proxmox: the details of a linked host show its machine and switch it', /^aus VM 120 · E2E-PVE Starten Starten und verbinden$/.test(pveHost.block) && /^läuft .*VM 120 · E2E-PVE Neu starten Herunterfahren$/.test(pveHost.running), JSON.stringify([pveHost.block, pveHost.running]));
  ok('m10 Proxmox: “Start and connect” starts the machine and opens the tab as soon as it accepts connections', pveHost.opened && pveHost.tab === 'monitoring', JSON.stringify([pveHost.opened, pveHost.tab]));
  ok('m10 Proxmox: “Unlink” asks and leaves the host as it is', pveHost.asked === 'Verknüpfung von „monitoring“ lösen?' && pveHost.unlinked && pveHost.detail, JSON.stringify(pveHost));

  // Permissions and certificate: the token that may only look lacks switching; a certificate other than the confirmed one
  // is not accepted, and no token goes out before.
  const tokensBefore = (await pveTest('seen')).tokens;
  const pveRights = await run(page, PVE + `
    const wrong = await invoke('proxmox_probe', { input: { name: 'x', address: '${pve.address}', tokenId: '${PVE_TOKEN}', secret: '${PVE_SECRET}', fingerprint: '${'AB:'.repeat(31)}AB' } });
    await go('Proxmox'); await until(()=>machine('pihole'));
    titled('Bearbeiten', q('.pve-h')).click(); await until(()=>q('.dlg'));
    type(field('Kennung des Tokens'),'leser@pve!test'); type(field('Geheimnis des Tokens'),'${PVE_SECRET}'); await wait(150);
    button('Prüfen', q('.dlg')).click();
    const proven = (await until(()=>q('.dlg .okline'), 15000))?.textContent.trim();
    const missing = q('.dlg .warnbox')?.textContent.replace(/\\s+/g,' ').trim();
    const asksAgain = !!q('.pve-finger');
    button('Abbrechen', q('.dlg')).click(); await wait(200);
    const bad = await fails(invoke('proxmox_probe', { input: { name: 'x', address: '${pve.address}', tokenId: '${PVE_TOKEN}', secret: 'falsch', fingerprint: '${pve.fingerprint}' } }));
    const shape = await fails(invoke('proxmox_save', { input: { name: 'x', address: 'http://pve.example.de', tokenId: '${PVE_TOKEN}', secret: 'x' } }));
    const token = await fails(invoke('proxmox_save', { input: { name: 'x', address: '${pve.address}', tokenId: 'no-shape', secret: 'x' } }));
    return { wrong, proven, missing, asksAgain, bad: bad?.code, shape: shape?.code, token: [token?.code, token?.reason].join(':') };
  `);
  ok('m10 Proxmox: a certificate other than the confirmed one is reported, and the token stays here', pveRights.wrong.version === '' && pveRights.wrong.changed === true && pveRights.wrong.fingerprint === pve.fingerprint, JSON.stringify(pveRights.wrong));
  ok('m10 Proxmox: when editing, the confirmed fingerprint still applies; what the token lacks is shown', /Proxmox VE 9\.0\.11/.test(pveRights.proven ?? '') && !pveRights.asksAgain && pveRights.missing === 'Dem Token fehlt das Recht: ein- und ausschalten, den Gastagenten fragen', JSON.stringify([pveRights.proven, pveRights.missing, pveRights.asksAgain]));
  ok('m10 Proxmox: a wrong secret, an address without https and an ID without shape are rejected', pveRights.bad === 'proxmox_token' && pveRights.shape === 'proxmox_address' && pveRights.token === 'invalid:token_invalid' && (await pveTest('seen')).tokens > tokensBefore, JSON.stringify(pveRights));

  // Signing in to the machines: the connection names an identity. It applies where Cloud-Init names no key from the
  // vault, when connecting as on newly created hosts. Name and identity can be saved without a new check.
  const pveLogin = await run(page, PVE + `
    const admin = (await invoke('identity_save', { identity: { name: 'E2E-Admin', user: 'admin', key: null } })).id;
    await go('Hosts'); await go('Proxmox'); await until(()=>machine('monitoring'));
    const before = parts(machine('monitoring').querySelector('.pve-addr'));
    titled('Bearbeiten', q('.pve-h')).click(); await until(()=>q('.dlg'));
    const select = qa('.dlg .fld').find(f=>f.querySelector('.fld-l')?.textContent.trim()==='Anmeldung an den Maschinen').querySelector('select');
    const offered = [...select.options].map(o=>o.textContent.trim());
    select.value = admin; select.dispatchEvent(new Event('change', { bubbles: true })); await wait(150);
    const buttons = qa('.dlg button').map(b=>b.textContent.trim()).join('|');
    button('Speichern', q('.dlg')).click(); await until(()=>!q('.dlg'));
    const saved = (await invoke('vault_status')).data.proxmox[0];
    const after = await until(()=>{ const text = parts(machine('monitoring').querySelector('.pve-addr')); return text !== before && text; }, 8000);
    const linkedRow = parts(machine('pihole').querySelector('.pve-addr'));
    button('2 Hosts anlegen', q('.pve-h')).click(); await until(()=>q('.pve-pick'));
    const preview = qa('.pve-prow').map(r=>r.querySelector('.pve-name b').textContent.trim()+':'+r.querySelector('.pve-key').textContent.trim()+':'+r.querySelector('input').checked).join();
    qa('.dlg button').at(-1).click(); await until(()=>!q('.dlg'));
    let made; for (let i = 0; i < 60 && !made; i++) { await wait(200); made = (await hosts()).find(h=>h.proxmox?.vmid===120); }
    await invoke('identity_delete', { id: admin });
    const end = (await invoke('vault_status')).data;
    return { offered, buttons, identity: saved.identity === admin, fingerprint: saved.fingerprint, before, after, linkedRow, preview, own: made?.own, wanted: { identity: admin }, cleared: [end.proxmox[0].identity ?? null, end.hosts.find(h=>h.id===made?.id)?.own.identity ?? null] };
  `);
  ok('m10 Proxmox: the connection takes an identity for its machines; that needs no new check, the fingerprint stays', pveLogin.offered[0] === 'Keine Identität' && pveLogin.offered.includes('E2E-Admin (admin)') && pveLogin.buttons === 'Abbrechen|Prüfen|Speichern' && pveLogin.identity && pveLogin.fingerprint === pve.fingerprint, JSON.stringify([pveLogin.offered, pveLogin.buttons, pveLogin.identity]));
  ok('m10 Proxmox: without a key from Cloud-Init the connection\'s identity applies; a created host shows its own sign-in', pveLogin.before === '10.0.10.90 vom Gastagenten' && pveLogin.after === 'admin@10.0.10.90 vom Gastagenten' && pveLogin.linkedRow === 'root@10.0.0.53 aus den Einstellungen', JSON.stringify([pveLogin.before, pveLogin.after, pveLogin.linkedRow]));
  ok('m10 Proxmox: the preview names the sign-in, and the new host carries the identity', pveLogin.preview === 'monitoring:E2E-Admin:true,spielwiese:E2E-Admin:false,debian-13-vorlage:E2E-Admin:false' && JSON.stringify(pveLogin.own) === JSON.stringify(pveLogin.wanted), JSON.stringify([pveLogin.preview, pveLogin.own]));
  ok('m10 Proxmox: a deleted identity disappears from the connection and from the host', pveLogin.cleared.join() === ',', JSON.stringify(pveLogin.cleared));

  // Remove a second connection: its hosts stay and only lose the link. Then clean up; the
  // first connection stays in the vault beyond the restart.
  const pveRemove = await run(page, PVE + `
    const second = (await invoke('proxmox_save', { input: { name: 'Zweite', address: '${pve.address}', tokenId: '${PVE_TOKEN}', secret: '${PVE_SECRET}', fingerprint: '${pve.fingerprint}' } })).id;
    await invoke('proxmox_import', { id: second, picks: [{ node: 'pve', vmid: 130, kind: 'qemu' }], group: null });
    const made = (await hosts()).find(h=>h.proxmox?.connection === second);
    await go('Hosts'); await go('Proxmox');
    const block = await until(()=>qa('.pve').find(p=>p.querySelector('.pve-t b').textContent==='Zweite'));
    titled('Verbindung entfernen', block).click();
    const asked = (await until(()=>q('.dlg')))?.querySelector('h2').textContent;
    button('Verbindung entfernen', q('.dlg')).click(); await until(()=>qa('.pve').length === 1, 8000);
    const data = (await invoke('vault_status')).data;
    const left = data.hosts.find(h=>h.id === made.id);
    for (const h of data.hosts.filter(h=>h.proxmox || ['monitoring','spielwiese'].includes(h.name))) await invoke('host_delete', { id: h.id });
    const end = (await invoke('vault_status')).data;
    await go('Hosts');
    return { made: [made.name, made.address, made.proxmox.vmid], asked, connections: data.proxmox.map(p=>p.name).join(), left: !!left && !left.proxmox, hosts: end.hosts.map(h=>h.name).sort().join(), still: end.proxmox.map(p=>p.name).join() };
  `);
  ok('m10 Proxmox: without a known address the new host shows the machine\'s name for now', pveRemove.made.join() === 'spielwiese,spielwiese,130', JSON.stringify(pveRemove.made));
  ok('m10 Proxmox: with the connection only the link disappears, the host stays', pveRemove.asked === 'Verbindung „Zweite“ entfernen?' && pveRemove.connections === 'E2E-PVE' && pveRemove.left && !/shop|pihole|gitea|monitoring|spielwiese|Von Hand/.test(pveRemove.hosts) && pveRemove.still === 'E2E-PVE', JSON.stringify(pveRemove));

  // 4z. Mosh. Signing in happens over SSH at the test server; mosh-server runs in this machine's WSL, the
  // test server forwards UDP via 127.0.0.1 and can pause the line (dropout).
  const moshHost = await run(page, `return (await invoke('vault_status')).data.hosts.find(h => h.name === 'testserver')`);
  const setMosh = (own) => run(page, `await invoke('host_save', { host: { ...${JSON.stringify(moshHost)}, own: ${JSON.stringify(own)} } })`);
  const openTestserver = () =>
    run(page, `
      q('.tabs .tab.home')?.click(); qa('.nv')[0].click(); await until(()=>byText('.host','testserver'));
      byText('.host','testserver').click(); await until(()=>q('.detail'));
      byText('.detail .btn','Verbinden').click();
      return !!(await until(()=>q('.sview:not(.off) .live.connected'), 30000));
    `);
  const moshAddress = await server.mosh;
  if (!moshAddress) {
    skip('Mosh over the server in WSL (no mosh-server in the WSL Ubuntu)');
  } else {
    await setMosh({ ...moshHost.own, mosh: true });
    const connected = await openTestserver();
    const chip = await run(page, `return !!(await until(()=>q('.sview:not(.off) .tbar .mchip'), 5000))`);
    ok('Mosh: a host with the switch connects over Mosh, the terminal\'s header shows “Mosh”', connected && chip);
    await run(page, `q('.pane:not(.off) .xterm-helper-textarea').focus();`);
    await typeLine(page, 'echo mosh-$((6*7))');
    await sleep(1200);
    ok('Mosh: input and output run over Mosh', (await terminalText(page, 0, true)).includes('mosh-42'));
    const side = await run(page, `
      if (!q('.side')) byText('.tbar .btn','Seitenleiste')?.click();
      const tab = await until(()=>qa('.side .stab').find(b=>b.title==='Info'));
      tab?.click();
      return !!(await until(()=>q('.side .meter'), 15000));
    `);
    ok('Mosh: the server info comes over the SSH connection next to it', side);
    server.child.stdin.write('mosh pause\n');
    const silent = await run(page, `return (await until(()=>q('.sview:not(.off) .moshbar.warn')?.textContent, 20000)) ?? ''`);
    server.child.stdin.write('mosh resume\n');
    const back = await run(page, `return !!(await until(()=>!q('.sview:not(.off) .moshbar.warn'), 20000)) && !!q('.sview:not(.off) .live.connected')`);
    ok('Mosh: on a dropout the bar appears, the tab stays connected and recovers', silent.includes('Keine Verbindung zum Server seit') && back, silent.slice(0, 60));
    await run(page, `q('.tabs .tab.on .x').click(); await wait(600);`);
    ok('Mosh: closing the tab ends the session', (await run(page, `await wait(300); return await invoke('session_count')`)) === 0);
  }
  // If mosh-server is missing, the host connects over SSH and names the install command (the test server counts as Ubuntu).
  await setMosh({ ...moshHost.own, mosh: true, moshServer: 'mosh-missing' });
  const fallbackConnected = await openTestserver();
  const fallback = await run(page, `return (await until(()=>q('.sview:not(.off) .moshbar')?.textContent, 10000)) ?? ''`);
  const fallbackChip = await run(page, `return !!q('.sview:not(.off) .tbar .mchip')`);
  ok('Mosh: if mosh-server is missing, the session runs over SSH with a notice and the install command', fallbackConnected && fallback.includes('nicht installiert') && fallback.includes('sudo apt install mosh') && !fallbackChip, fallback.slice(0, 80));
  await run(page, `q('.tabs .tab.on .x').click(); await wait(500);`);
  await setMosh(moshHost.own);
  ok('Mosh: host without Mosh again', (await run(page, `return (await invoke('vault_status')).data.hosts.find(h => h.name === 'testserver').own.mosh ?? null`)) === null);

  // 5. Switch on starting without the master password: the key is stored as a protected file in the data folder.
  const keyFile = join(workDir, 'data', 'start-unlock.bin');
  // Through the interface, the way the user does it: options, switch, confirm the prompt. Once must be enough.
  const enabled = await run(page, `
    qa('.nv').at(-1).click();
    const startSwitch = () => qa('button.swt[role=switch]').find(b => b.getAttribute('aria-label')?.includes('Master-Passwort'));
    const sw = await until(startSwitch);
    const before = sw.classList.contains('on');
    sw.click(); await until(()=>q('.dlg'));
    const dialog = q('.dlg').textContent;
    qa('.dlg .btn').find(b=>b.textContent.includes('Ohne Passwort')).click();
    const off = await until(()=>!startSwitch().classList.contains('on'));
    return { before, dialog, off: !!off, start: (await invoke('vault_status')).startUnlock };
  `);
  ok('the switch starts at “require” and asks when switched off', enabled.before && enabled.dialog.includes('Windows-Benutzerkonto'));
  ok('starting without a password is on after confirming once', enabled.off && enabled.start === true && existsSync(keyFile));

  // 5b. Crash with an open tab: at the next start Glowport asks whether it should be restored.
  const restoreFile = join(workDir, 'data', 'open-tabs.json');
  await run(page, `
    qa('.nv')[0].click(); await until(()=>byText('.host','testserver'));
    byText('.host','testserver').click(); await until(()=>q('.detail'));
    byText('.detail .btn','Verbinden').click(); await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    await wait(1200);
  `);
  ok('open tabs are recorded in case of a crash', existsSync(restoreFile) && readFileSync(restoreFile, 'utf8').includes('"kind":"host"'));
  page.close();
  app.kill();
  await sleep(1200);
  app = launch();
  page = await connect();
  const offered = await run(page, `
    const list = await until(()=>q('.rlist'), 15000);
    const text = q('.dlg')?.textContent ?? ''; const before = qa('.tabs .tab:not(.home)').length;
    byText('.dlg .btn','Wiederherstellen').click();
    const connected = await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    return { list: !!list, text, before, connected: !!connected, tab: q('.tabs .tab.on .nm')?.textContent };
  `);
  ok('after a crash Glowport asks and only restores after consent', offered.list && offered.text.includes('nicht ordentlich beendet') && offered.text.includes('testserver') && offered.before === 0 && offered.connected && offered.tab === 'testserver', offered.text.trim().slice(0, 50));
  // End properly: confirm the warning, the program ends itself, nothing is left to restore.
  // Tick “Don't ask again with open sessions” on the way; it must be saved before the window disappears.
  const exited = new Promise((done) => app.once('exit', () => done(true)));
  await run(page, `q('.wc .cl').click(); await until(()=>q('.dlg')); q('.dlg input[type=checkbox]').click(); await wait(100); qa('.dlg .btn').find(b=>b.textContent.trim() === 'Beenden').click();`).catch(() => {});
  const gone = await Promise.race([exited, sleep(8000).then(() => false)]);
  ok('quitting properly: the program ends and remembers no open tabs', gone && !existsSync(restoreFile));
  ok('closing: “Don\'t ask again” is saved', JSON.parse(readFileSync(settingsFile, 'utf8')).closePrompt === false);
  page.close();

  // 6. Restart: open without a password, data complete, no plaintext in the file.
  app.kill();
  await sleep(1200);
  const bytes = readFileSync(vaultFile);
  ok('the vault file contains no plaintext', !['web-01', 'Produktiv', 'deploy', 'server-passwort-geheim', '10.0.10.11', 'testserver', 'richtig', 'ssh-ed25519', 'e2e-import', 'PRIVATE KEY', 'E2E-PVE', PVE_TOKEN, PVE_SECRET, pve.fingerprint].some((t) => bytes.includes(t)), `${bytes.length} bytes`);
  app = launch();
  page = await connect();
  const auto = await run(page, `
    await until(()=>q('.nav') || q('.lock-card'));
    const st = await invoke('vault_status');
    const shown = !!q('.nav') && !q('.lock-card');
    q('.tb-ic').click(); await until(()=>q('.lock-card'));
    const afterLock = (await invoke('vault_status')).state;
    const refused = await fails(invoke('host_delete',{id:'00000000000000000000000000000000'}));
    type(q('.lock-card input'),'falsch'); await wait(80); q('.lock-card button[type=submit]').click();
    const msg = await until(()=>q('.lock-card .errline')?.textContent);
    type(q('.lock-card input'),'${PW2}'); await wait(80); q('.lock-card button[type=submit]').click(); await until(()=>q('.nav'));
    const off = await invoke('vault_set_start_unlock',{enabled:false});
    // Die Verbindung zu Proxmox hat den Neustart überstanden, samt dem Geheimnis ihres Tokens.
    const kept = (await invoke('vault_status')).data.proxmox;
    const pveVersion = (await invoke('proxmox_overview', { id: kept[0]?.id }).catch(e => e))?.version;
    await invoke('proxmox_delete', { id: kept[0]?.id });
    return { pve: kept.map(p=>p.name).join(), pveVersion, pveLeft: (await invoke('vault_status')).data.proxmox.length, state: st.state, start: st.startUnlock, shown, hosts: st.data?.hosts.map(h=>h.name+'|'+h.hasPassword), groups: st.data?.groups.map(g=>g.name), keys: st.data?.keys.map(k=>k.name+'|'+k.origin), damaged: st.data?.damaged, afterLock, refused: refused?.code, msg, off: off.startUnlock };
  `);
  ok('restart opens without a password', auto.state === 'open' && auto.start === true && auto.shown);
  ok('m10 Proxmox: the connection is still in the vault after the restart and still applies; afterwards it can be removed', auto.pve === 'E2E-PVE' && auto.pveVersion === '9.0.11' && auto.pveLeft === 0, JSON.stringify([auto.pve, auto.pveVersion, auto.pveLeft]));
  ok('data complete after restart', auto.hosts?.join() === 'testserver|true,web-01|true' && auto.groups?.join() === 'Produktiv' && auto.keys?.join() === 'e2e-import|imported' && auto.damaged === 0);
  ok('locking still requires the master password', auto.afterLock === 'locked' && auto.refused === 'locked' && /Falsches|Wrong/.test(auto.msg ?? ''));
  ok('switching off removes the stored key', auto.off === false && !existsSync(keyFile));
  page.close();

  // 7. Restart after switching off: locked again.
  app.kill();
  await sleep(1200);
  app = launch();
  page = await connect();
  const again = await run(page, `
    await until(()=>q('.lock-card'));
    const state = (await invoke('vault_status')).state;
    type(q('.lock-card input'),'${PW2}'); await wait(80); q('.lock-card button[type=submit]').click();
    await until(()=>q('.nav'));
    return { state, open: (await invoke('vault_status')).state };
  `);
  ok('after switching off Glowport starts locked again', again.state === 'locked' && again.open === 'open');

  // 7b. After “Don't ask again” Glowport ends with an open session without a prompt.
  const quietExit = new Promise((done) => app.once('exit', () => done(true)));
  const quiet = await run(page, `
    qa('.nv')[0].click(); await until(()=>byText('.host','testserver'));
    byText('.host','testserver').click(); await until(()=>q('.detail'));
    byText('.detail .btn','Verbinden').click(); await until(()=>q('.sview:not(.off) .live.connected'), 15000);
    setTimeout(()=>q('.wc .cl').click(), 50);
    return true;
  `).catch(() => false);
  const quietGone = await Promise.race([quietExit, sleep(8000).then(() => false)]);
  const quietDialog = quietGone ? '' : await run(page, `return q('.dlg')?.textContent ?? 'no dialog'`).catch((e) => e.message);
  ok('closing: with an open session Glowport ends without a prompt when set up that way', quiet && quietGone, quietDialog);
  page.close();
  if (!quietGone) {
    app.kill();
    await sleep(1200);
  }

  // 8. Sign out and delete data, from the lock screen: afterwards Glowport restarts without a vault.
  app = launch();
  page = await connect();
  const wipeExit = new Promise((done) => app.once('exit', () => done(true)));
  const wipeText = await run(page, `
    await until(()=>q('.lock-card'));
    byText('.lock-card .linkbtn','Daten auf diesem PC').click(); await until(()=>q('.dlg'));
    const text = q('.dlg').textContent;
    const confirm = qa('.dlg .btn').find(b=>b.textContent.includes('Abmelden und löschen'));
    const blocked = confirm.disabled;
    q('.dlg input[type=checkbox]').click(); await wait(100);
    setTimeout(()=>confirm.click(), 50);
    return blocked ? text : '';
  `);
  ok('delete from the lock screen: checkbox required; the prompt says that without the master password there is no sign-out at the server', wipeText.includes('Ohne Master-Passwort') && wipeText.includes('kein Zurück'), wipeText.slice(0, 60));
  const wipeRestarted = await Promise.race([wipeExit, sleep(10000).then(() => false)]);
  page.close();
  page = await connect();
  const afterWipe = await run(page, `await until(()=>q('.lock-card')); return [(await invoke('vault_status')).state, q('.lock-card h1')?.textContent]`);
  ok('delete: Glowport restarts, vault and key store are gone, the settings stay', wipeRestarted && JSON.stringify(afterWipe) === JSON.stringify(['missing', 'Tresor anlegen']) && !existsSync(vaultFile) && !existsSync(keyFile) && existsSync(settingsFile), JSON.stringify(afterWipe));
  // The restarted program is not a child of the test: end it through its window.
  await run(page, `setTimeout(()=>q('.wc .cl').click(), 50); return true`).catch(() => {});
  await sleep(1500);
  page.close();
} catch (e) {
  results.push(`ABBRUCH ${e.message}`);
  console.log(results.at(-1));
} finally {
  app.kill();
  server.child.kill();
  await sleep(800);
  // The WebView2 processes only release their folder shortly after the program ends.
  try {
    rmSync(workDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 400 });
  } catch (e) {
    console.log(`Note: ${workDir} could not be cleaned up (${e.code})`);
  }
}
if (skipped.length) console.log(`
${skipped.length} skipped: ${skipped.join('; ')}`);
process.exit(results.some((r) => !r.startsWith('ok')) ? 1 : 0);
