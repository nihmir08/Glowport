// Pictures of new screens from the browser preview, for showing them before building them out.
// Runs against the stand-in core (backend-fake.ts) in an invisible Edge with its own profile.
// Run in the project folder while the preview is running (`npm run dev`, port 1420):
// node scripts/mockups.mjs [target folder]
// Current shots: the Mosh screens. Earlier versions for other features are in the Git history.
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const out = resolve(process.argv[2] ?? 'entwuerfe/meilenstein-12');
const URL = 'http://localhost:1420/';
const PORT = 9224;
const SIZE = { width: 1360, height: 860 };
const EDGE = ['C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Microsoft/Edge/Application/msedge.exe'].find(existsSync);
const profile = join(tmpdir(), 'glowport-bilder');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PASSWORD = 'vorschau-bilder';

if (!EDGE) throw new Error('Microsoft Edge nicht gefunden');
rmSync(profile, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

const HELPERS = `
const wait=(ms=300)=>new Promise(r=>setTimeout(r,ms));
const q=s=>document.querySelector(s), qa=s=>[...document.querySelectorAll(s)];
const byText=(sel,txt)=>qa(sel).find(e=>e.textContent.trim().includes(txt));
const type=(el,v)=>{el.value=v;el.dispatchEvent(new Event('input',{bubbles:true}))};
const until=async(fn,ms=8000)=>{const end=Date.now()+ms;while(Date.now()<end){const v=fn();if(v)return v;await wait(100)}throw new Error('Wartezeit abgelaufen: '+fn)};
const mid=el=>{const b=el.getBoundingClientRect();return {x:b.left+b.width/2,y:b.top+b.height/2,w:b.width,h:b.height,l:b.left,t:b.top}};
const pane=name=>qa('.pane:not(.off)').find(p=>p.getAttribute('aria-label')===name);
`;

async function connect() {
  for (let i = 0; i < 80; i++) {
    try {
      const pages = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
      const page = pages.find((p) => p.type === 'page' && p.url.startsWith(URL));
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
        return { send: (method, params = {}) => new Promise((ok, no) => (pending.set(++id, { ok, no }), ws.send(JSON.stringify({ id, method, params })))), close: () => ws.close() };
      }
    } catch {}
    await sleep(250);
  }
  throw new Error('Edge nicht erreichbar. Läuft die Vorschau auf Port 1420?');
}

// The scaling comes from the browser itself and not from an emulation afterwards: only then does xterm.js (WebGL) draw sharply.
// `--guest`: without signing in to a Microsoft account. Otherwise Edge puts its own sync dialog over the
// page in a fresh profile, and the script does not find the preview.
const edge = spawn(EDGE, ['--headless=new', '--guest', `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`, `--window-size=${SIZE.width},${SIZE.height}`, '--force-device-scale-factor=1.5', '--hide-scrollbars', URL], { stdio: 'ignore' });
try {
  const page = await connect();
  await page.send('Emulation.setDeviceMetricsOverride', { ...SIZE, deviceScaleFactor: 0, mobile: false });

  /** Waits until the page has loaded and shows `selector`. Vite sometimes loads a second time on the first call. */
  const settled = async (selector) => {
    const end = Date.now() + 30_000;
    for (let calm = 0; calm < 3; ) {
      if (Date.now() > end) throw new Error(`Seite zeigt ${selector} nicht`);
      await sleep(500);
      const r = await page.send('Runtime.evaluate', { expression: `document.readyState === 'complete' && !!document.querySelector(${JSON.stringify(selector)})`, returnByValue: true }).catch(() => null);
      calm = r?.result?.value === true ? calm + 1 : 0;
    }
  };
  const run = async (body) => {
    const r = await page.send('Runtime.evaluate', { expression: `(async()=>{${HELPERS}${body}})()`, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
    return r.result.value;
  };
  const shot = async (name) => {
    await sleep(450); // Let fade-ins and shadows settle
    const { data } = await page.send('Page.captureScreenshot', { format: 'png' });
    writeFileSync(join(out, `${name}.png`), Buffer.from(data, 'base64'));
    console.log(`${name}.png`);
  };
  const mouse = (type, x, y, button = 'left', extra = {}) => page.send('Input.dispatchMouseEvent', { type, x, y, button, buttons: type === 'mouseReleased' ? 0 : button === 'right' ? 2 : 1, clickCount: 1, ...extra });
  const click = async (x, y, button = 'left') => {
    await mouse('mouseMoved', x, y, 'none', { buttons: 0 });
    await mouse('mousePressed', x, y, button);
    await mouse('mouseReleased', x, y, button);
    await sleep(120);
  };
  /** Drags from one point to another with the mouse button pressed and keeps the button pressed. */
  const dragTo = async (from, to) => {
    await mouse('mouseMoved', from.x, from.y, 'none', { buttons: 0 });
    await mouse('mousePressed', from.x, from.y);
    for (let i = 1; i <= 8; i++) await mouse('mouseMoved', from.x + ((to.x - from.x) * i) / 8, from.y + ((to.y - from.y) * i) / 8);
    await sleep(250);
  };
  const key = async (name, code, vk, modifiers = 0, text) => {
    await page.send('Input.dispatchKeyEvent', { type: text ? 'keyDown' : 'rawKeyDown', key: name, code, windowsVirtualKeyCode: vk, modifiers, text });
    await page.send('Input.dispatchKeyEvent', { type: 'keyUp', key: name, code, windowsVirtualKeyCode: vk, modifiers });
  };
  const enter = () => key('Enter', 'Enter', 13, 0, '\r');
  /** Types into a pane's terminal and sends the line. */
  const command = async (name, text) => {
    const at = await run(`return mid(pane(${JSON.stringify(name)}).querySelector('.term-host'))`);
    await click(at.x, at.y);
    await page.send('Input.insertText', { text });
    await enter();
    await sleep(250);
  };
  /** Opens a host via search (Ctrl+K). */
  const openHost = async (name) => {
    // If the cursor is in an input field, Ctrl+K belongs to it.
    await run(`document.activeElement?.blur()`);
    await key('k', 'KeyK', 75, 2);
    await run(`await until(()=>q('.pal input'))`);
    await page.send('Input.insertText', { text: name });
    await sleep(200);
    await enter();
    await run(`await until(()=>pane(${JSON.stringify(name)})?.querySelector('.xterm-screen')); await wait(900)`);
  };
  const unlock = async () => {
    await settled('.lock-card');
    await run(`
      const field = await until(()=>q('.lock-card input[type=password]'));
      type(field,'${PASSWORD}'); await wait(100);
      q('.lock-card button[type=submit]').click(); await until(()=>q('.nav'));
    `);
  };

  // Helpers: `go(name)` switches the page, `field(label)` is the input field with this label.
  const TOOLS = `
    const go=async label=>{q('.tabs .tab.home')?.click(); await wait(150); qa('.nv').find(b=>b.textContent.trim()===label).click(); await wait(400)};
    const field=label=>qa('.fld').find(f=>f.querySelector('.fld-l')?.textContent.trim()===label)?.querySelector('input');
    const fill=(label,value)=>type(field(label),value);
    const button=(text,scope=document)=>[...scope.querySelectorAll('button')].find(b=>b.textContent.trim()===text);
    const titled=(title,scope=document)=>[...scope.querySelectorAll('button')].find(b=>b.title===title);
    const card=name=>qa('.host, .group').find(c=>c.querySelector('.h-name')?.textContent.trim()===name);
    const top=()=>{q('.pg').scrollTop=0};
    // Reiter der Seitenleiste und eine Zeile darin.
    const side=async label=>{(await until(()=>titled(label, q('.side')))).click(); await wait(500)};
    const row=name=>qa('.side .mg-row').find(r=>r.querySelector('.mg-main b')?.textContent.trim()===name);
  `;
  const tools = (body) => run(TOOLS + body);

  // A stand-in vault with sample data: this is what a device looks like that is already in use.
  await settled('.lock-card');
  await tools(`
    await until(()=>qa('.lock-card input[type=password]').length === 2);
    const inputs = qa('.lock-card input[type=password]');
    type(inputs[0],'${PASSWORD}'); type(inputs[1],'${PASSWORD}'); q('.lock-card input[type=checkbox]').click(); await wait(100);
    q('.lock-card button[type=submit]').click(); await until(()=>q('.nav'));
  `);

  // 1 · Hosts: an SSH host with Mosh carries the “Mosh” badge next to “SSH”.
  await tools(`
    await go('Hosts');
    type(q('input[placeholder="Hosts durchsuchen"]'),'Homelab'); await until(()=>card('nas') && card('pihole')); await wait(300);
  `);
  await shot('01-hosts-mosh-zeichen');

  // 2 · Details: Mosh with local echo.
  await tools(`card('nas').click(); await until(()=>titled('Bearbeiten')); await wait(300);`);
  await shot('02-host-einzelheiten-mosh');

  // 3 · Host editor: the switch and the advanced fields.
  await tools(`
    titled('Bearbeiten').click(); await until(()=>q('.editor'));
    const sec = qa('.editor .ed-sec').find(e=>e.textContent.trim()==='Mosh'); sec.scrollIntoView({block:'start'}); await wait(300);
  `);
  await shot('03-host-editor-mosh');
  await tools(`button('Abbrechen', q('.editor')).click(); await wait(300); type(q('input[placeholder="Hosts durchsuchen"]'),''); await wait(200);`);

  // 4 · Connected over Mosh: the badge is in the terminal's header.
  await openHost('nas');
  await command('nas', 'uptime');
  await shot('04-tab-ueber-mosh');

  // 5 · Dropout: the bar counts, the terminal stays open.
  await command('nas', 'drop');
  await sleep(3300);
  await shot('05-mosh-keine-verbindung');
  await sleep(4500);

  // 6 · mosh-server is missing on “pihole”: connected over SSH, hint with the install command.
  await openHost('pihole');
  await tools(`await until(()=>q('.moshbar')); await wait(300);`);
  await shot('06-rueckfall-auf-ssh-mosh-fehlt');

  // 7 · Quick connect: “mosh user@host”.
  await key('k', 'KeyK', 75, 10);
  await run(`await until(()=>q('.pal input'))`);
  await page.send('Input.insertText', { text: 'mosh deploy@203.0.113.50' });
  await sleep(400);
  await shot('07-schnellverbindung-mosh');
  await key('Escape', 'Escape', 27);
  await sleep(200);

  // 8 · The same in light.
  await tools(`await go('Optionen'); byText('.seg button','Hell').click(); await wait(300); q('.tabs .tab:not(.home)')?.click(); await wait(600);`);
  await shot('08-rueckfall-hell');
  page.close();
} finally {
  edge.kill();
  await sleep(800);
  try {
    rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  } catch {}
}
