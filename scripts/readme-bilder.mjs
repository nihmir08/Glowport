// Pictures for the README: the interface in English with the stand-in core's sample data (backend-fake.ts),
// captured in an invisible Edge with its own profile. Run in the project folder while the preview is running
// (`npm run dev`, port 1420): node scripts/readme-images.mjs [target folder]
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { de } from '../src/lib/i18n/de.ts';
import { en } from '../src/lib/i18n/en.ts';

const out = resolve(process.argv[2] ?? 'docs/images');
const URL = 'http://localhost:1420/';
const PORT = 9225;
const SIZE = { width: 1360, height: 860 };
const EDGE = ['C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Microsoft/Edge/Application/msedge.exe'].find(existsSync);
const profile = join(tmpdir(), 'glowport-readme-bilder');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PASSWORD = 'vorschau-bilder';

/** The English text for a German one: that way buttons can be named the same way as in the other scripts. */
const tr = (text) => {
  const key = Object.keys(de).find((k) => de[k] === text);
  if (!key) throw new Error(`Kein Text „${text}“ in de.ts`);
  return en[key];
};
const s = (text) => JSON.stringify(tr(text));

if (!EDGE) throw new Error('Microsoft Edge not found');
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
const nav=async i=>{q('.tabs .tab.home')?.click(); await wait(150); qa('.nv')[i].click(); await wait(400)};
const field=label=>qa('.fld').find(f=>f.querySelector('.fld-l')?.textContent.trim()===label)?.querySelector('input');
const fill=(label,value)=>type(field(label),value);
const button=(text,scope=document)=>[...scope.querySelectorAll('button')].find(b=>b.textContent.trim()===text);
const titled=(title,scope=document)=>[...scope.querySelectorAll('button')].find(b=>b.title===title);
const card=name=>qa('.host, .group').find(c=>c.querySelector('.h-name')?.textContent.trim()===name);
const rule=name=>qa('.rows .row').find(r=>r.querySelector('.rt b')?.textContent===name);
const side=async label=>{(await until(()=>titled(label, q('.side')))).click(); await wait(500)};
const srow=name=>qa('.side .mg-row').find(r=>r.querySelector('.mg-main b')?.textContent.trim()===name);
const top=()=>{const p=q('.pg'); if(p) p.scrollTop=0};
const bar=()=>q('.fbar'), col=i=>qa('.fcol')[i];
const rowIn=(scope,name)=>[...scope.querySelectorAll('.frow')].find(r=>r.querySelector('.fn').firstChild.textContent===name);
const rows=scope=>[...scope.querySelectorAll('.frow')].length;
const pathOf=scope=>scope.querySelector('.flist').getAttribute('aria-label');
const goto=async(scope,path)=>{
  scope.querySelector('.fpath .mini').click();
  const f=await until(()=>scope.querySelector('.fpath input'));
  type(f,path); f.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
  await until(()=>pathOf(scope)===path && !scope.querySelector('.flist.busy')); await wait(150);
};
const pick=(scope,name,ctrl=false)=>{
  const r=rowIn(scope,name); r.scrollIntoView({block:'nearest'});
  r.dispatchEvent(new PointerEvent('pointerdown',{bubbles:true,button:0,ctrlKey:ctrl}));
  window.dispatchEvent(new PointerEvent('pointerup',{bubbles:true}));
};
const choose=(scope,value)=>{const sel=scope.querySelector('select'); sel.value=value; sel.dispatchEvent(new Event('change',{bubbles:true}))};
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
  throw new Error('Edge not reachable. Is the preview running on port 1420?');
}

// See scripts/mockups.mjs: scaling by the browser itself so xterm.js draws sharply; `--guest` without a Microsoft account.
const edge = spawn(EDGE, ['--headless=new', '--guest', `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`, `--window-size=${SIZE.width},${SIZE.height}`, '--force-device-scale-factor=1.5', '--hide-scrollbars', URL], { stdio: 'ignore' });
try {
  const page = await connect();
  await page.send('Emulation.setDeviceMetricsOverride', { ...SIZE, deviceScaleFactor: 0, mobile: false });

  const settled = async (selector) => {
    const end = Date.now() + 30_000;
    for (let calm = 0; calm < 3; ) {
      if (Date.now() > end) throw new Error(`Page does not show ${selector}`);
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
    await sleep(450);
    const { data } = await page.send('Page.captureScreenshot', { format: 'png' });
    writeFileSync(join(out, `${name}.png`), Buffer.from(data, 'base64'));
    console.log(`${name}.png`);
  };
  const mouse = (type, x, y, button = 'left', extra = {}) => page.send('Input.dispatchMouseEvent', { type, x, y, button, buttons: type === 'mouseReleased' ? 0 : 1, clickCount: 1, ...extra });
  const click = async (x, y) => {
    await mouse('mouseMoved', x, y, 'none', { buttons: 0 });
    await mouse('mousePressed', x, y);
    await mouse('mouseReleased', x, y);
    await sleep(120);
  };
  const key = async (name, code, vk, modifiers = 0, text) => {
    await page.send('Input.dispatchKeyEvent', { type: text ? 'keyDown' : 'rawKeyDown', key: name, code, windowsVirtualKeyCode: vk, modifiers, text });
    await page.send('Input.dispatchKeyEvent', { type: 'keyUp', key: name, code, windowsVirtualKeyCode: vk, modifiers });
  };
  const enter = () => key('Enter', 'Enter', 13, 0, '\r');
  const command = async (name, text) => {
    const at = await run(`return mid(pane(${JSON.stringify(name)}).querySelector('.term-host'))`);
    await click(at.x, at.y);
    await page.send('Input.insertText', { text });
    await enter();
    await sleep(300);
  };
  const openHost = async (name) => {
    await run(`document.activeElement?.blur()`);
    await key('k', 'KeyK', 75, 2);
    await run(`await until(()=>q('.pal input'))`);
    await page.send('Input.insertText', { text: name });
    await sleep(200);
    await enter();
    await run(`await until(()=>pane(${JSON.stringify(name)})?.querySelector('.xterm-screen')); await wait(900)`);
  };

  // English interface before the sample vault is created: then groups and snippets get English names too.
  await settled('.lock-card');
  await run(`localStorage.setItem('glowport.settings', JSON.stringify({ lang: 'en' })); location.reload();`).catch(() => {});
  await sleep(1000);
  await settled('.lock-card');
  await run(`
    await until(()=>qa('.lock-card input[type=password]').length === 2);
    const inputs = qa('.lock-card input[type=password]');
    type(inputs[0],'${PASSWORD}'); type(inputs[1],'${PASSWORD}'); q('.lock-card input[type=checkbox]').click(); await wait(100);
    q('.lock-card button[type=submit]').click(); await until(()=>q('.nav'));
    await until(()=>card('Production'));
  `);

  // 1 · Hosts: the root with workspaces and groups, then a group with its defaults and hosts.
  await shot('hosts-overview');
  await run(`card('Production').click(); await until(()=>card('Web')); card('Web').click(); await until(()=>card('web-01')); card('web-01').click(); await wait(500);`);
  await shot('hosts');

  // 2 · A workspace: three split terminals with one click.
  await run(`q('.crumbs button[data-group=""]').click(); await until(()=>byText('.group.ws','Deploy round')); byText('.group.ws','Deploy round').click(); await until(()=>q('.detail .lprev'));
    byText('.detail .btn',${s('Öffnen')}).click(); await until(()=>qa('.pane:not(.off) .xterm-screen').length === 3); await wait(1200);`);
  await command('web-01', 'uptime');
  await command('web-01', 'df -h /');
  await command('web-02', 'systemctl is-active nginx');
  await command('db-01', 'whoami');
  await shot('terminals');

  // 3 · A terminal with sidebar: the server's load.
  await openHost('pve-01');
  await command('pve-01', 'uptime');
  // Without the file panel: root's home directory is empty.
  await run(`if(bar()) byText('.tbar .btn','Files').click(); titled(${s('Server-Info und Snippets neben dem Terminal zeigen')}).click(); await until(()=>q('.side .meter')); await wait(15000);`);
  await shot('server-info');

  // 4 · Docker in the sidebar.
  await openHost('web-01');
  await run(`if(!q('.side')) titled(${s('Server-Info und Snippets neben dem Terminal zeigen')}).click(); await until(()=>q('.side')); await side('Docker'); await until(()=>srow('shop-web'));`);
  await shot('docker');

  // 5 · File bar at the terminal.
  await run(`qa('.tabs .tab').at(-1).querySelector('button.x').click(); await wait(500);`);
  await openHost('web-01');
  await run(`if(q('.side')) titled(${s('Server-Info und Snippets neben dem Terminal zeigen')})?.click(); if(!bar()) byText('.tbar .btn','Files').click(); await until(()=>bar() && rows(bar())>5);`);
  await command('web-01', 'ls');
  await shot('file-sidebar');

  // 6 · Files page: server to server.
  const hosts = await run(`return JSON.parse(localStorage.getItem('glowport.fakevault')).hosts.map(h=>({id:h.id,name:h.name}))`);
  const id = (name) => hosts.find((h) => h.name === name).id;
  await run(`await nav(4); await until(()=>qa('.fcol').length===2);
    choose(col(0),'${id('db-01')}'); await until(()=>pathOf(col(0))==='/home/deploy'); await goto(col(0),'/srv/backup');
    choose(col(1),'${id('web-01')}'); await until(()=>rows(col(1))>1); await goto(col(1),'/var/www/app'); pick(col(0),'db.sql.gz');`);
  await shot('files');

  // 7 · Port rules, two running.
  await run(`await nav(2); await until(()=>rule('Grafana')); rule('Grafana').querySelector('.swt').click(); rule('SOCKS via bastion').querySelector('.swt').click(); await until(()=>qa('.rows .chip.ok').length===2); await wait(3200);`);
  await shot('port-forwarding');

  // 8 · A snippet on all hosts, with a result per host.
  await run(`await nav(3); await until(()=>rule('Disk usage')); rule('Disk usage').querySelector('.btn').click(); await until(()=>q('.dlg .picklist'));
    byText('.dlg .pickbar .btn',${s('Alle')}).click(); await wait(150);
    q('.dlg .dlg-a .btn.primary').click(); await until(()=>q('.dlg .fld-h') && byText('.dlg .fld-h',${JSON.stringify(tr('Fertig: {ok} ohne Fehler, {failed} mit Fehler.').split(':')[0])}),30000); await wait(300);`);
  await shot('snippets');
  await run(`byText('.dlg .btn',${s('Schließen')}).click(); await wait(250);`);

  // 9 · Keys.
  await run(`await nav(1); await wait(500);`);
  await shot('keys');

  // 10 · Proxmox.
  await run(`await nav(7); await until(()=>q('.pve-row')); await wait(1500);`);
  await shot('proxmox');

  // 11 · Sync and sharing: own server, a shared vault with members.
  await run(`await nav(8); await until(()=>q('.setup-wrap'));
    fill(${s('Adresse des Sync-Servers')},'sync.example.com'); await wait(100);
    button(${s('Prüfen')}).click(); await until(()=>q('.okline'));
    const fields = qa('.setup-wrap .fld input'); type(fields[1],'alex'); type(fields[2],'K7QF-2MXA-9RTD'); type(fields[3],'${PASSWORD}'); type(fields[4],'Office PC'); await wait(200);
    button(${s('Sync einrichten')}).click(); await until(()=>q('.sync-line')); await wait(500);
    top(); card('Team Infra').click(); await until(()=>q('.vault-detail')); await wait(400);`);
  await shot('sync');

  // 12 · Import from other programs.
  // First let the message from setting up sync fade out.
  await run(`await until(()=>!q('.toasts .toast'),15000); await nav(0); byText('.ph .acts .btn',${s('Importieren')}).click(); await until(()=>q('.imp-found')); await wait(400);`);
  await shot('import');
  await key('Escape', 'Escape', 27);
  await sleep(300);

  // 13 · Quick connect via search.
  await run(`document.activeElement?.blur()`);
  await key('k', 'KeyK', 75, 2);
  await run(`await until(()=>q('.pal input'))`);
  await page.send('Input.insertText', { text: 'ssh deploy@203.0.113.50' });
  await sleep(500);
  await shot('quick-connect');
  await key('Escape', 'Escape', 27);
  await sleep(200);

  // 14 · Settings: color schemes.
  await run(`await nav(9); await until(()=>q('.schemes')); byText('.sec','Terminal').scrollIntoView({ block: 'start' }); await wait(300);`);
  await shot('themes');

  // 15 · Light: the split terminals.
  await run(`top(); byText('.seg button',${s('Hell')}).click(); await wait(300); byText('.tabs .tab','Deploy round').click(); await wait(800);`);
  await shot('light');

  // 16 · Banner from scripts/readme-banner.html; it shows the picture of the split terminals from docs/images.
  await page.send('Emulation.setDeviceMetricsOverride', { width: 1600, height: 560, deviceScaleFactor: 0, mobile: false });
  await page.send('Page.navigate', { url: pathToFileURL(resolve('scripts/readme-banner.html')).href });
  await sleep(1500);
  await shot('banner');
  page.close();
} finally {
  edge.kill();
  await sleep(800);
  try {
    rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  } catch {}
}
