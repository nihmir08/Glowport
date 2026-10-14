# Running the sync server

This guide sets up `glowport-sync` on a Linux server of your own. What the server does, and what it never gets to see, is described in [`sync.md`](sync.md).

**Status:** Option A has been run through on Ubuntu (WSL), by hand and with `install.sh`, including the commands, backup and restore; Glowport synced fully against that service. On a Debian server it runs behind NGINX with a Let's Encrypt certificate (service via `install.sh`, the site written by hand with TLS). Not run yet: option B (Docker), `certbot --nginx` with the template, Caddy, the Proxmox example and the service with its own certificate on port 443.

## What it is

- **A single program**, `glowport-sync`. It needs nothing but itself.
- **A single file**, `sync.db`, in the data folder. It holds everything: accounts, devices, the encrypted records.
- By default it listens on `127.0.0.1:8787`, i.e. only for the same machine. It reaches the outside world through a web server that handles HTTPS. Glowport only ever connects via `https://`.

## What you need

- A Linux machine (64-bit, x86) that runs permanently: a dedicated server, or a VM or container on it.
- An address for the server, ideally a subdomain such as `sync.your-domain.com` whose DNS record points to the machine.
- Reachable from outside: port 443 (and port 80, so the certificate can be issued).

The examples use `sync.example.com` throughout. Replace it with your address.

## Option A: as a service (recommended)

**In short:** upload the `dist-server` folder of the project to the server (program, service file, `install.sh`) and run as `root`:

```bash
sh install.sh
```

The script performs steps 1 to 4 below and prints the setup code at the end. Running it again only replaces the program (update). If the web server runs on another machine or container, pass its internal address to the script: `PROXY=10.0.0.10 sh install.sh`.

**By hand, step by step:**

1. **Put the program on the server.** The Linux program is in the project under `dist-server/glowport-sync` (built with `sh scripts/build-server.sh` on Linux, e.g. WSL; it runs on any 64-bit Linux without further packages). Upload it, for example with Glowport's file manager, and place it in `/usr/local/bin`:

   ```bash
   install -m 755 glowport-sync /usr/local/bin/glowport-sync
   ```

2. **Create a dedicated user.** The service does not run as `root`:

   ```bash
   useradd --system --home-dir /var/lib/glowport-sync --shell /usr/sbin/nologin glowport-sync
   ```

3. **Set up the service.** Copy `server/glowport-sync.service` from the project to `/etc/systemd/system/` and start it:

   ```bash
   systemctl daemon-reload
   systemctl enable --now glowport-sync
   ```

4. **Check that it runs:**

   ```bash
   journalctl -u glowport-sync -n 20
   ```

   It shows `glowport-sync listening on 127.0.0.1:8787` and, as long as there is no account yet, the **setup code**.

5. **Put HTTPS in front:** see the section “HTTPS”.

The data lives in `/var/lib/glowport-sync`. Only the service may access this folder.

## Option B: with Docker

1. Copy the project folder to the server. The folders `target`, `node_modules` and `dist` are not needed.
2. In the `server` folder:

   ```bash
   docker compose up -d --build
   ```

   The first build takes a few minutes.
3. Setup code and signs of life:

   ```bash
   docker compose logs glowport-sync
   ```

The container is only reachable via `127.0.0.1:8787`. The data lives in the Docker volume `glowport-sync-data`.

## HTTPS

### With Caddy (easiest)

Caddy obtains and renews the certificate by itself. The whole configuration is in `server/Caddyfile`:

```
sync.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

### With NGINX

1. Copy `server/nginx.conf` to `/etc/nginx/sites-available/glowport-sync`, enter your address, link it into `sites-enabled`.
2. Obtain the certificate and let certbot add it:

   ```bash
   certbot --nginx -d sync.example.com
   ```

The important parts of the template are the WebSocket lines (`Upgrade`, `Connection`) and the long timeouts. Without them, changes reach other devices only after up to a minute instead of right away.

Whether the WebSocket gets through is shown by NGINX's access log as a line for `/v1/live` with the status `101`. NGINX writes that line only when the connection ends, i.e. after Glowport was closed:

```bash
grep "/v1/live" /var/log/nginx/access.log | tail -1
```

### The web server runs on another machine or container

Then `127.0.0.1` is not enough: the sync server has to listen where the web server can reach it, i.e. on its address in the internal network. In the examples the web server has the internal address `10.0.0.10`, the sync server `10.0.0.20`.

- In the service file (or directly with `PROXY=10.0.0.10 sh install.sh`):

  ```
  Environment=GLOWPORT_SYNC_LISTEN=0.0.0.0:8787
  Environment=GLOWPORT_SYNC_TRUST_PROXY=10.0.0.10
  ```

  The second line names the web server's address: only it is trusted to say who the sender is. Anyone who reaches port 8787 directly therefore cannot pretend to have a different address.
- In the web server, use the internal address of the sync server instead of `127.0.0.1:8787`: `proxy_pass http://10.0.0.20:8787;`
- Port 8787 does not belong on the internet. The connection between web server and sync server is unencrypted; it must never leave the machine's internal network.

### Example: a container of its own on Proxmox, NGINX in another one

1. **DNS:** create a record for the address (`sync.example.com`) that points to the public IP under which NGINX is reachable.
2. **Create the container** (Proxmox → “Create CT”): Debian 13 template, keep “Unprivileged container” and “Nesting” ticked, 1 core, 256 MB memory, 4 GB disk, the same bridge as NGINX and a fixed internal address from the same network. Then enable “Start at boot” under Options.
3. **Copy the files in and set up.** Upload the `dist-server` folder to the Proxmox host, change into it and run (with the number of your container instead of `120` and the internal address of NGINX):

   ```bash
   pct push 120 glowport-sync /root/glowport-sync
   pct push 120 glowport-sync.service /root/glowport-sync.service
   pct push 120 install.sh /root/install.sh
   pct exec 120 -- env PROXY=10.0.0.10 sh /root/install.sh
   ```

   The setup code is shown at the end.
4. **NGINX:** add `server/nginx.conf` as a new site, enter the address and, at `proxy_pass`, the container's internal address, run `nginx -t`, reload, then `certbot --nginx -d sync.example.com`.
5. **Check** as described below, then create the first account.

Administration commands are later run from the host like this: `pct exec 120 -- runuser -u glowport-sync -- glowport-sync accounts`

### Without a web server in front

`glowport-sync` can also do HTTPS itself if it is given the certificate and key as files (PEM, as issued by Let's Encrypt). The lines for this are commented out in `server/glowport-sync.service`. Keep in mind:

- The user `glowport-sync` must be able to read both files. It may not read the files under `/etc/letsencrypt`; they have to be copied into its folder after every renewal, e.g. to `/var/lib/glowport-sync/tls/`.
- The server picks up changed files by itself within an hour, without a restart.

To start with, a web server in front is the easier way.

### Check

```bash
curl https://sync.example.com/v1/info
```

The answer is a short line in curly braces. The server is then reachable from outside and the certificate is fine.

## The first account

1. In Glowport click **Sync** on the left, then **Set up sync**, **New account**.
2. Enter the address under “Sync server address” (`sync.example.com`) and click **Check**.
3. Glowport reports that the server has no account yet and asks for the **setup code**. It is in the server's output (`journalctl -u glowport-sync` or `docker compose logs glowport-sync`).

   The server prints a new setup code every time it starts. Only the latest one is valid.
4. Choose a user name, confirm your master password, give the device a name, click **Set up sync**.

This first account administers the server. Once it exists, there is no setup code any more.

## More people and devices

- **Another device of your own:** on a fresh Glowport choose “Sign in with an account” at startup and enter address, user name and master password. If the device already has a vault: Sync → Set up sync → “I already have an account”. No code is needed for this.
- **Another person:** in Glowport go to Sync → **Manage server** → **Create invitation code**. The code is valid once and for seven days. The person chooses “New account” and enters it.

## Administration by command

Everything “Manage server” can do in Glowport also works on the server itself. This is meant for the case that no administrator can get in any more, for example because the master password is lost.

| Command | Effect |
|---|---|
| `glowport-sync accounts` | list accounts: devices, storage, last seen |
| `glowport-sync invite` | create an invitation code |
| `glowport-sync invites` | list open invitation codes |
| `glowport-sync revoke <code>` | revoke an open invitation code |
| `glowport-sync disable <name>` | disable an account: no sign-in, no sync, the data stays |
| `glowport-sync enable <name>` | enable an account again |
| `glowport-sync delete <name>` | delete an account with its devices and personal vault |
| `glowport-sync admin <name>` | make an account an administrator |
| `glowport-sync noadmin <name>` | take administration away from an account |
| `glowport-sync backup <file>` | write a backup |

The commands take effect immediately, even while the server is running. This is how to call them:

- **As a service:** as the service's user, so the files belong to it. The data folder is found automatically:

  ```bash
  runuser -u glowport-sync -- glowport-sync accounts
  ```

- **With Docker**, in the `server` folder:

  ```bash
  docker compose exec glowport-sync glowport-sync accounts
  ```

No command can reset a password or look into a vault. Whoever loses their master password needs a new account; `admin` then makes it an administrator again.

## Backup

```bash
runuser -u glowport-sync -- glowport-sync backup /var/lib/glowport-sync/backup-2026-10-10.db
```

This works while the server is running and writes a complete, consistent copy. Always use this command: while the server runs, part of the data is not yet in `sync.db` itself, so a plain copy of the file would be incomplete. An existing file is never overwritten. The backup contains the same as the server: encrypted records that nobody can read without the master passwords. Still, do not leave it lying around openly, and copy it off the server.

**Restore:** stop the service, put the backup into the data folder as `sync.db`, delete the files `sync.db-wal` and `sync.db-shm` if present, start the service.

```bash
systemctl stop glowport-sync
install -o glowport-sync -g glowport-sync -m 600 backup-2026-10-10.db /var/lib/glowport-sync/sync.db
rm -f /var/lib/glowport-sync/sync.db-wal /var/lib/glowport-sync/sync.db-shm
systemctl start glowport-sync
```

Devices that had moved on beyond the backup notice this. Glowport shows “Server behind” on the affected vault and offers **Upload this device's state**. Nothing is lost: every device has a complete copy of its vaults anyway.

## Updating

- **As a service:** put the new `glowport-sync` into `/usr/local/bin`, then `systemctl restart glowport-sync`.
- **With Docker:** upload the new project folder, then `docker compose up -d --build`.

Server and Glowport tell each other their version. If they ever do not match, Glowport says which side needs an update.

## Log

```bash
journalctl -u glowport-sync -f
```

One line for everything that changes something or fails:

```
2026-10-10 14:03:27 200 POST /v1/vaults/{vault}/records alex
2026-10-10 14:05:02 401 POST /v1/login -
```

That is time (UTC), status, kind of request and account. Contents, tokens, passwords and the senders' addresses never appear in it. Plain reads are not logged.

## Settings

As an argument at startup or via the environment (in the service file as `Environment=`, with Docker under `environment:`):

| Argument | Environment | Default | Meaning |
|---|---|---|---|
| `--listen` | `GLOWPORT_SYNC_LISTEN` | `127.0.0.1:8787` | where the server listens |
| `--data` | `GLOWPORT_SYNC_DATA` | `./data` | data folder |
| `--trust-proxy` | `GLOWPORT_SYNC_TRUST_PROXY=1` | off | behind a web server on the same machine: the sender is in `X-Forwarded-For` |
| `--trust-proxy-from` | `GLOWPORT_SYNC_TRUST_PROXY=10.0.0.10` | – | the same, but only trusted for connections from this address (several separated by commas): the web server on another machine |
| `--tls-cert` | `GLOWPORT_SYNC_TLS_CERT` | – | certificate (PEM) for HTTPS without a web server in front |
| `--tls-key` | `GLOWPORT_SYNC_TLS_KEY` | – | matching private key (PEM) |
| – | `GLOWPORT_SYNC_MAX_RECORD_KIB` | 256 | size of one record in KiB |
| – | `GLOWPORT_SYNC_MAX_RECORDS` | 20000 | records per vault |
| – | `GLOWPORT_SYNC_MAX_VAULTS` | 50 | vaults per account |

Only enable `GLOWPORT_SYNC_TRUST_PROXY=1` if the server listens on `127.0.0.1`, so that only the web server on the same machine can reach it. In every other case name the web server's address. Otherwise anyone who reaches the server directly could claim any sender address and get around the brake on guessing attempts.

## When something does not work

| Glowport says | Usual cause |
|---|---|
| “The sync server cannot be reached.” | The DNS record does not point to the machine, port 443 is closed, or the service is not running. `curl https://sync.example.com/v1/info` shows how far you get. |
| “The sync server's certificate is not accepted …” | The certificate has expired, was issued for another address or is self-made. Glowport trusts the same issuers as Windows. |
| “This code is not valid (any more).” for the setup code | The server has been restarted since. The code from the last start applies. |
| “Too many failed attempts. Please try again in a quarter of an hour.” | After five wrong sign-ins to an account there is a quarter-hour pause. If a web server sits in front and `--trust-proxy` is missing, all senders share one address and slow each other down. |
| The service does not start, the journal says `226/NAMESPACE` | Inside a Proxmox container the service's sandboxing needs the “Nesting” option (Container → Options → Features). Enable it and restart the container. |
| Changes arrive only after about a minute | The web server in front does not pass the WebSocket through. With NGINX, the `Upgrade` and `Connection` lines from the template are missing. |
