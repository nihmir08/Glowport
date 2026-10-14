// End-to-end test of syncing on the real executable: three running programs (two devices of one
// account and a second account) against a sync server on this PC. Every program runs as a portable copy
// with its own data folder; the user's real vault and server are not touched.
// Run in the project folder after `npm run build:dev` and `cargo build -p glowport-sync-server`:
// node scripts/e2e-sync.mjs [executable]
import { spawn } from 'node:child_process';
import { copyFileSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const exeSource = resolve(process.argv[2] ?? 'target/release/glowport-dev.exe');
const serverExe = resolve('target/debug/glowport-sync.exe');
const workDir = join(tmpdir(), 'glowport-e2e-sync');
const SERVER_PORT = 18787;
// Instead of a server of its own, an already running fresh one (e.g. the Linux program in WSL):
// GLOWPORT_E2E_SERVER=http://127.0.0.1:8787 GLOWPORT_E2E_SETUP=<setup code> node scripts/e2e-sync.mjs
const EXTERNAL = process.env.GLOWPORT_E2E_SERVER;
const SERVER = EXTERNAL ?? `http://127.0.0.1:${SERVER_PORT}`;
const PW_ANNA = 'e2e-abgleich-anna';
const PW_ANNA_NEU = 'e2e-sync-anna-new';
const PW_BERT = 'e2e-abgleich-bert';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
const ok = (name, cond, extra = '') => {
  results.push(`${cond ? 'ok    ' : 'FEHLER'} ${name}${extra ? ` (${extra})` : ''}`);
  console.log(results.at(-1));
};

rmSync(workDir, { recursive: true, force: true });
mkdirSync(workDir, { recursive: true });

/** Starts the sync server and returns the setup code for the first account. */
function startServer() {
  if (EXTERNAL) return { child: null, code: Promise.resolve(process.env.GLOWPORT_E2E_SETUP ?? '') };
  const child = spawn(serverExe, ['--listen', `127.0.0.1:${SERVER_PORT}`, '--data', join(workDir, 'server')], { stdio: ['ignore', 'pipe', 'inherit'] });
  const code = new Promise((ok, no) => {
    let text = '';
    child.stdout.on('data', (chunk) => {
      text += String(chunk);
      const found = /administrator\): (\S+)/.exec(text);
      if (found && text.includes('listening on')) ok(found[1]);
    });
    child.once('error', no);
    setTimeout(() => no(new Error('Sync server does not report')), 15_000);
  });
  return { child, code };
}

const HELPERS = `
const wait=(ms=300)=>new Promise(r=>setTimeout(r,ms));
const q=s=>document.querySelector(s), qa=s=>[...document.querySelectorAll(s)];
const until=async(fn,ms=8000)=>{const end=Date.now()+ms;while(Date.now()<end){const v=await fn();if(v)return v;await wait(150)}return null};
const invoke=(cmd,args)=>window.__TAURI_INTERNALS__.invoke(cmd,args);
const fails=async(p)=>{try{await p;return null}catch(e){return e?.code ?? String(e)}};
const snapshot=async()=>(await invoke('vault_status')).data;
const hostNames=async()=>((await snapshot())?.hosts ?? []).map(h=>h.name).sort();
const host=(name,extra={})=>({name,address:'10.0.0.1',group:null,color:null,os:null,own:{},...extra});
const type=(el,text)=>{el.focus();Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el,text);el.dispatchEvent(new Event('input',{bubbles:true}))};
`;

/** A running Glowport: its own copy, its own data folder, its own debug interface. */
class Instance {
  constructor(name, port) {
    this.name = name;
    this.port = port;
    this.dir = join(workDir, name);
    mkdirSync(join(this.dir, 'data'), { recursive: true });
    copyFileSync(exeSource, join(this.dir, 'glowport.exe'));
    writeFileSync(join(this.dir, 'portable'), '');
    // German from the start: the test reads interface texts.
    writeFileSync(join(this.dir, 'data', 'settings.json'), JSON.stringify({ lang: 'de' }));
  }

  async start() {
    const env = { ...process.env, WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${this.port}`, WEBVIEW2_USER_DATA_FOLDER: join(this.dir, 'webview') };
    this.child = spawn(join(this.dir, 'glowport.exe'), [], { env, stdio: 'ignore' });
    return this.attach();
  }

  /** Connects to the window, e.g. after the program restarted itself. */
  async attach() {
    for (let i = 0; i < 120; i++) {
      try {
        const pages = await (await fetch(`http://127.0.0.1:${this.port}/json`)).json();
        const page = pages.find((p) => p.type === 'page' && p.webSocketDebuggerUrl && /tauri.localhost|^tauri:/.test(p.url));
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
          this.send = (method, params = {}) => new Promise((ok, no) => (pending.set(++id, { ok, no }), ws.send(JSON.stringify({ id, method, params }))));
          this.ws = ws;
          for (let j = 0; j < 100; j++) {
            const r = await this.send('Runtime.evaluate', { expression: "document.readyState === 'complete' && !!window.__TAURI_INTERNALS__ && !!document.querySelector('.win')", returnByValue: true }).catch(() => null);
            if (r?.result?.value === true) return this;
            await sleep(150);
          }
        }
      } catch {}
      await sleep(250);
    }
    throw new Error(`${this.name}: debug interface not reachable`);
  }

  /** Runs code in the window; `invoke` calls the core's commands like the interface does. */
  async run(body) {
    const timeout = new Promise((_, no) => setTimeout(() => no(new Error(`${this.name}: step does not answer (60 s)`)), 60_000));
    const r = await Promise.race([this.send('Runtime.evaluate', { expression: `(async()=>{${HELPERS}${body}})()`, awaitPromise: true, returnByValue: true }), timeout]);
    if (r.exceptionDetails) throw new Error(`${this.name}: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
    return r.result.value;
  }

  stop() {
    try {
      this.ws?.close();
    } catch {}
    this.child?.kill();
  }
}

const J = JSON.stringify;
const server = startServer();
const a = new Instance('anna-pc', 9231);
const b = new Instance('anna-laptop', 9232);
const c = new Instance('bert-pc', 9233);
try {
  const setupCode = await server.code;
  await Promise.all([a.start(), b.start(), c.start()]);

  // ── A vault becomes an account ─────────────────────────────────────────────────────────────────────────
  await a.run(`await invoke('vault_create',{password:${J(PW_ANNA)}}); for (const n of ['web-01','db-01']) await invoke('host_save',{host:host(n)});`);
  const probe = await a.run(`return await invoke('sync_probe',{server:${J(SERVER + '/')}})`);
  ok('m9 The server answers and waits for its first account', probe.server === SERVER && probe.fresh === true, J(probe));
  ok('m9 A wrong code creates no account', (await a.run(`return await fails(invoke('sync_register',{request:{server:${J(SERVER)},code:'FALS-CHER-CODE',username:'anna',password:${J(PW_ANNA)},device:'PC'}}))`)) === 'code_invalid');
  ok('m9 Neither does a wrong master password', (await a.run(`return await fails(invoke('sync_register',{request:{server:${J(SERVER)},code:${J(setupCode)},username:'anna',password:'falsch-falsch',device:'PC'}}))`)) === 'wrong_password');
  const registered = await a.run(`return await invoke('sync_register',{request:{server:${J(SERVER)},code:${J(setupCode)},username:'anna',password:${J(PW_ANNA)},device:'PC'}})`);
  ok('m9 Set up sync: linked, the first account administers the server', registered.linked && registered.admin && registered.username === 'anna' && registered.server === SERVER, J({ ...registered, code: '…' }));
  const synced = await a.run(`return await until(async()=>{const s=await invoke('sync_state'); return s.phase==='synced' && s.pending===0 && s.syncedAt ? s : null}, 15000)`);
  ok('m9 The first sync runs through, nothing waits any more', !!synced, J(synced && { phase: synced.phase, pending: synced.pending }));
  ok('m9 Our own safety code has six words', synced?.code.split(' · ').length === 6, synced?.code);
  ok('m9 Die Statusleiste zeigt „Abgeglichen“', await a.run(`return !!(await until(()=>q('.st .st-x .sdot.synced')))`));

  // ── Second device: only user name and master password ─────────────────────────────────────────────────
  ok('m9 Sign in with account: a wrong password is rejected', (await b.run(`return await fails(invoke('sync_login',{request:{server:${J(SERVER)},username:'anna',password:'falsch-falsch',device:'Laptop'}}))`)) === 'unauthorized');
  // From here on through the real start screen, the way a human does it.
  const wrongAddress = await b.run(`
    (await until(()=>qa('.linkbtn').at(-1))).click();
    await until(()=>q('form.setup'));
    type(qa('form.setup input')[0],'does-not-exist.invalid');
    await wait(150);
    qa('form.setup input')[0].dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
    return await until(()=>q('.setup-server + .errline')?.textContent, 15000)`);
  ok('m9 Start screen: an address without a sync server is reported at the address, Enter is enough', wrongAddress === 'Der Sync-Server ist nicht erreichbar.', J(wrongAddress));
  const joined = await b.run(`
    const fields=()=>qa('form.setup input');
    type(fields()[0],${J(SERVER)}); type(fields()[1],'anna'); type(fields()[2],${J(PW_ANNA)}); type(fields()[3],'Laptop');
    await wait(150);
    const gone = !q('.setup-server + .errline');
    q('form.setup button[type=submit]').click();
    const opened = !!(await until(()=>q('.nav'), 20000));
    const arrived = !!(await until(()=>qa('.host').length===2, 15000));
    // Die Liste muss stehen bleiben: Eine verspätete ältere Antwort darf sie nicht wieder leeren.
    let least = 2; const end = Date.now()+3000;
    while (Date.now()<end) { least = Math.min(least, qa('.host').length); await wait(20); }
    return { gone, opened, arrived, least, names: await hostNames() }`);
  ok('m9 Sign in with account: the vault of the second device is created from the account', joined.opened && joined.gone, J(joined));
  ok('m9 The second device shows the hosts of the first one, and they stay', joined.arrived && joined.least === 2 && J(joined.names) === J(['db-01', 'web-01']), J(joined));
  ok('m9 Its interface shows the open vault', await b.run(`return !!(await until(()=>q('.nav')))`));

  // ── Changes arrive by themselves ──────────────────────────────────────────────────────────────────────
  const started = Date.now();
  const added = await a.run(`return (await invoke('host_save',{host:host('new-from-a')})).id`);
  const seen = await b.run(`return await until(async()=>(await hostNames()).includes('new-from-a'), 15000)`);
  ok('m9 A new host appears on the other device without anyone doing anything there', seen === true, `${Date.now() - started} ms`);
  await b.run(`await invoke('host_delete',{id:${J(added)}})`);
  ok('m9 Deletion comes back the same way', (await a.run(`return await until(async()=>!(await hostNames()).includes('new-from-a'), 15000)`)) === true);
  const devices = await a.run(`return (await invoke('sync_devices')).map(d=>[d.name,d.current])`);
  ok('m9 The device list names both devices', J(devices) === J([['PC', true], ['Laptop', false]]), J(devices));

  // ── Second account via an invitation code ─────────────────────────────────────────────────────────────
  await c.run(`await invoke('vault_create',{password:${J(PW_BERT)}}); await invoke('host_save',{host:host('berts-server')});`);
  ok('m9 No second account without a code', (await c.run(`return await fails(invoke('sync_register',{request:{server:${J(SERVER)},code:${J(setupCode)},username:'bert',password:${J(PW_BERT)},device:'Berts PC'}}))`)) === 'code_invalid');
  const invite = await a.run(`return (await invoke('admin_invite_create')).at(-1).code`);
  ok('m9 The administrator creates an invitation code', /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(invite), invite);
  // “New account” in the window: this device's master password is meant, and the form says so.
  const form = await c.run(`
    qa('.nv').at(-2).click();
    await until(()=>q('form.setup'));
    const fields=()=>qa('form.setup input');
    type(fields()[0],${J(SERVER)}); type(fields()[1],'bert'); type(fields()[2],${J(invite)}); type(fields()[3],'a-completely-different-password');
    await wait(150);
    q('form.setup button[type=submit]').click();
    const error = await until(()=>qa('form.setup .errline').at(-1)?.textContent, 15000);
    return { labels: qa('form.setup .fld-l').map(e=>e.textContent), error, linked: (await invoke('sync_state')).linked }`);
  ok('m9 “New account” names the password and explains a wrong one', form.labels.includes('Master-Passwort dieses Geräts') && form.error.startsWith('Das ist nicht das Master-Passwort dieses Geräts') && form.linked === false, J(form));
  const bert = await c.run(`return await invoke('sync_register',{request:{server:${J(SERVER)},code:${J(invite)},username:'bert',password:${J(PW_BERT)},device:'Berts PC'}})`);
  ok('m9 With the code the second account is created, without administration', bert.linked && !bert.admin, J({ linked: bert.linked, admin: bert.admin }));
  ok('m9 It may not create codes', (await c.run(`return await fails(invoke('admin_invite_create'))`)) === 'not_admin');
  const accounts = await a.run(`return (await invoke('admin_accounts')).map(x=>[x.username,x.admin,x.devices])`);
  ok('m9 Der Verwalter sieht beide Konten', J(accounts) === J([['anna', true, 2], ['bert', false, 1]]), J(accounts));

  // ── Shared vault: invite, accept, roles ───────────────────────────────────────────────────────────────
  const team = await a.run(`return await invoke('shared_create',{name:'Team Infra'})`);
  const candidate = await a.run(`return await invoke('shared_lookup',{username:'bert'})`);
  ok('m9 Looking up an account shows the safety code of the other one', candidate.username === 'bert' && candidate.known === 'new' && candidate.code === bert.code, J(candidate));
  await a.run(`await invoke('shared_invite',{vault:${J(team)},account:${J(candidate.account)},role:'read'})`);
  const invited = await a.run(`const v=(await snapshot()).vaults.find(v=>v.id===${J(team)}); return v && [v.name, v.role, v.members.map(m=>[m.name,m.role,m.invited,m.me])]`);
  ok('m9 The vault names its members; the invitee counts as invited', J(invited) === J(['Team Infra', 'owner', [['anna', 'owner', false, true], ['bert', 'read', true, false]]]), J(invited));

  const invitation = await c.run(`return await until(async()=>(await invoke('sync_state')).invitations[0], 15000)`);
  ok('m9 The invitation arrives: name, owner, role and her safety code', invitation && invitation.name === 'Team Infra' && invitation.owner === 'anna' && invitation.role === 'read' && invitation.code === registered.code, J(invitation));
  ok('m9 Die Statusleiste meldet die Einladung', await c.run(`return !!(await until(()=>qa('.st .st-x').find(e=>e.textContent.includes('Einladung'))))`));
  await c.run(`await invoke('invitation_accept',{vault:${J(team)}})`);
  ok('m9 After accepting, the invitee has the vault, with read access', (await c.run(`return await until(async()=>(await snapshot()).vaults.find(v=>v.id===${J(team)})?.role, 15000)`)) === 'read');

  const teamHost = await a.run(`return (await invoke('host_save',{host:host('team-host',{address:'10.9.9.9'}),vault:${J(team)}})).id`);
  ok('m9 A host created in the vault lives there', (await a.run(`return (await snapshot()).homes[${J(teamHost)}]`)) === team);
  ok('m9 The member sees it in the shared vault', (await c.run(`return await until(async()=>(await snapshot()).homes[${J(teamHost)}], 15000)`)) === team);
  ok('m9 With read access it cannot be changed', (await c.run(`return await fails(invoke('host_save',{host:host('renamed',{id:${J(teamHost)}})}))`)) === 'read_only');
  ok('m9 … not deleted', (await c.run(`return await fails(invoke('host_delete',{id:${J(teamHost)}}))`)) === 'read_only');
  ok('m9 … and nothing put into it', (await c.run(`return await fails(invoke('host_save',{host:host('own'),vault:${J(team)}}))`)) === 'read_only');
  const badges = await c.run(`
    qa('.nv')[0].click(); await until(()=>q('.vsw'));
    return { tabs: qa('.vsw button').map(b=>b.textContent.trim()), badge: qa('.host').find(h=>h.querySelector('.h-name')?.textContent.trim()==='team-host')?.querySelector('.chip.vault')?.textContent.trim() };
  `);
  ok('m9 Hosts page: switcher with all vaults, the host carries its vault\'s badge', J(badges) === J({ tabs: ['Alle', 'Persönlich', 'Team Infra'], badge: 'Team Infra' }), J(badges));

  // ── Moving, more permissions, second own device ───────────────────────────────────────────────────────
  const web = await a.run(`return (await snapshot()).hosts.find(h=>h.name==='web-01').id`);
  const moved = await a.run(`return (await invoke('host_move',{id:${J(web)},vault:${J(team)},carry:true})).id`);
  ok('m9 An existing host moves into the shared vault', moved !== web && (await a.run(`return (await snapshot()).homes[${J(moved)}]`)) === team);
  ok('m9 … and arrives at the member', (await c.run(`return await until(async()=>(await hostNames()).includes('web-01'), 15000)`)) === true);
  await a.run(`await invoke('shared_set_role',{vault:${J(team)},account:${J(candidate.account)},role:'write'})`);
  ok('m9 More rights apply at the member without a key rotation', (await c.run(`return await until(async()=>(await snapshot()).vaults.find(v=>v.id===${J(team)})?.role==='write', 15000)`)) === true);
  await c.run(`await invoke('host_save',{host:host('team-host',{id:${J(teamHost)},address:'10.9.9.10'})})`);
  ok('m9 Now the member changes it, and the owner sees it', (await a.run(`return await until(async()=>(await snapshot()).hosts.find(h=>h.id===${J(teamHost)})?.address==='10.9.9.10', 15000)`)) === true);
  const onLaptop = await b.run(`return await until(async()=>{const s=await snapshot(); const v=s.vaults.find(v=>v.id===${J(team)}); return v && s.hosts.some(h=>h.name==='team-host') ? [v.name,v.role] : null}, 15000)`);
  ok('m9 The owner\'s second device has the vault on its own, as owner', J(onLaptop) === J(['Team Infra', 'owner']), J(onLaptop));

  // ── Removing rotates the key ──────────────────────────────────────────────────────────────────────────
  await a.run(`await invoke('shared_remove',{vault:${J(team)},account:${J(candidate.account)}})`);
  ok('m9 After removal the vault disappears at the member', (await c.run(`return await until(async()=>(await snapshot()).vaults.length===1, 15000)`)) === true);
  const leftover = await c.run(`return [await hostNames(), (await invoke('sync_notices')).map(n=>n.kind)]`);
  ok('m9 … with its hosts, with a notice; their own ones stay', J(leftover) === J([['berts-server'], ['vault_removed']]), J(leftover));
  ok('m9 The owner keeps working with the new key', (await a.run(`await invoke('host_save',{host:host('after-the-rotation'),vault:${J(team)}}); return (await snapshot()).vaults.find(v=>v.id===${J(team)}).members.length`)) === 1);
  ok('m9 … and her second device follows', (await b.run(`return await until(async()=>(await hostNames()).includes('after-the-rotation'), 15000)`)) === true);

  // ── Changing the master password ──────────────────────────────────────────────────────────────────────
  await a.run(`await invoke('vault_change_password',{old:${J(PW_ANNA)},new:${J(PW_ANNA_NEU)},logoutOthers:false})`);
  ok('m9 Password changed: the other device learns about it', (await b.run(`return await until(async()=>(await invoke('sync_now')).passwordChanged, 15000)`)) === true);
  const unlocks = await b.run(`
    const tryUnlock=async p=>{await invoke('vault_lock'); return await fails(invoke('vault_unlock',{password:p}))};
    return [await tryUnlock(${J(PW_ANNA)}), await tryUnlock(${J(PW_ANNA_NEU)}), await tryUnlock(${J(PW_ANNA)}), await tryUnlock(${J(PW_ANNA_NEU)})];
  `);
  ok('m9 There the old one opens until the new one was used once; after that only the new one', J(unlocks) === J([null, null, 'wrong_password', null]), J(unlocks));
  ok('m9 After unlocking, syncing runs again', (await b.run(`return await until(async()=>{const s=await invoke('sync_state'); return s.linked && s.phase==='synced'}, 15000)`)) === true);

  // ── Sign out and delete data (open and connected) ──────────────────────────────────────────────────────
  const wipeAsk = await c.run(`
    qa('.nv').at(-1).click();
    const open = await until(()=>qa('.row').find(r=>r.textContent.includes('Abmelden und Daten löschen'))?.querySelector('.btn'));
    open.click(); await until(()=>q('.dlg'));
    const text = q('.dlg').textContent;
    const confirm = qa('.dlg .btn').find(b=>b.textContent.includes('Abmelden und löschen'));
    const blocked = confirm.disabled;
    q('.dlg input[type=checkbox]').click(); await wait(100);
    const freed = !confirm.disabled;
    confirm.click();
    return { linked: text.includes(${J(SERVER)}), blocked, freed };
  `).catch((e) => ({ error: e.message }));
  ok('Delete: the prompt names the sync server and requires the checkbox', wipeAsk.linked && wipeAsk.blocked && wipeAsk.freed, J(wipeAsk));
  // The old program ends with the restart; only afterwards does the debug interface belong to the new one.
  const ended = await Promise.race([new Promise((done) => (c.child.exitCode !== null ? done(true) : c.child.once('exit', () => done(true)))), sleep(20_000).then(() => false)]);
  ok('Delete: the program quits to restart', ended);
  await c.attach();
  const wiped = await c.run(`await until(()=>q('.lock-card')); return [(await invoke('vault_status')).state, q('.lock-card h1')?.textContent, (await invoke('sync_state')).linked]`);
  ok('Delete: Glowport restarts without a vault and without a sign-in', J(wiped) === J(['missing', 'Tresor anlegen', false]), J(wiped));
  const bertDevices = await a.run(`return (await invoke('admin_accounts')).find(x=>x.username==='bert')?.devices`);
  ok('Delete: the device is signed out at the server', bertDevices === 0, J(bertDevices));
  // Without vault and sessions the window closes without asking; the restarted program does not belong to the test.
  await c.run(`q('.wc .cl').click()`).catch(() => {});

  // ── Sign out device, disconnect ───────────────────────────────────────────────────────────────────────
  const laptop = await a.run(`return (await invoke('sync_devices')).find(d=>!d.current).id`);
  await a.run(`await invoke('sync_device_remove',{id:${J(laptop)}})`);
  ok('m9 A signed-out device notices and keeps its vault', (await b.run(`return await until(async()=>(await invoke('sync_now').catch(()=>invoke('sync_state'))).phase==='signedOut', 15000)`)) === true && (await b.run(`return (await hostNames()).length`)) > 0);
  const unlinked = await a.run(`return [(await invoke('sync_unlink')).linked, (await hostNames()).length > 0, (await snapshot()).vaults.length]`);
  ok('m9 Unlink from the server: the vault stays, the shared one too', J(unlinked) === J([false, true, 2]), J(unlinked));
} finally {
  for (const instance of [a, b, c]) instance.stop();
  server.child?.kill();
  await sleep(800);
}

const failed = results.filter((line) => line.startsWith('FEHLER')).length;
console.log(`\n${results.length - failed} of ${results.length} passed`);
process.exit(failed ? 1 : 0);
