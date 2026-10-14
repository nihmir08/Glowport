# Server management: Docker, services, processes, Proxmox

Design document. Built and released with Glowport 0.10.

## Summary

- **The sidebar of an SSH session** gets three tabs: **Docker**, **Services**, **Processes**. They show what runs on the server and control it with one click. Everything goes over the connection that already exists; nothing is installed on the server.
- **A page of its own, “Proxmox”**, connects Glowport to a Proxmox server via an API token. It lists VMs and containers, starts and stops them, connects directly and, if you want, creates hosts that Glowport keeps up to date afterwards.

## Design decisions

| Question | Decision |
|---|---|
| How do VMs and containers become hosts? | **With a selection, then kept up to date.** A preview with checkboxes; whatever is created is kept up to date by Glowport (address, name, state). |
| What may Glowport do in Proxmox? | **View, connect, start/stop/restart.** Stopping and restarting with a confirmation. Nothing that deletes data. No snapshots or backups. |
| What if the session is not root? | **sudo without a password, otherwise in the terminal.** Glowport never touches a sudo password. |
| How much Docker? | **Containers:** list, start, stop, restart, logs, shell. No Compose projects, images, volumes or networks. |

## Sidebar

The tabs only exist for SSH sessions, and each only where it has something to show: when first opened, Glowport checks once whether `docker`, `systemctl` and `ps` exist on the server. If something is missing, the tab is missing too. Measuring and reloading only happens while the tab is open.

Every list comes from a single command on the existing connection (the same way as the server info). Glowport reads the output; nothing is left behind on the server.

### Docker

- **List:** all containers, running ones first. Per container: name, image, state (running, stopped, restarting, unhealthy), uptime, published ports; for running ones also CPU and memory.
- **Actions:** start, stop, restart. Stopping and restarting with a confirmation.
- **Logs:** opens a new tab on the same server in which the logs follow along (the last 200 lines, then continuously).
- **Shell:** opens a new tab on the same server with a shell inside the container (`bash`, otherwise `sh`).
- Commands: `docker ps -a`, `docker inspect` and `docker stats --no-stream` with fixed columns, `docker start|stop|restart`, for the tabs `docker logs -f` and `docker exec -it`.

### Services

- **List:** the server's systemd services. Per service: name, description, state (running, exited, failed, inactive) and whether it starts at boot. Failed ones are at the top. Search by name, filters “running only” and “failed only”.
- **Actions:** start, stop, restart, enable and disable at boot. Stopping, restarting and disabling with a confirmation.
- **Details:** a click expands the service and shows its latest messages. “Follow” opens a tab in which the service's journal follows along.
- Commands: `systemctl list-units` and `list-unit-files`, `systemctl start|stop|restart|enable|disable`, `journalctl -u`.

### Processes

- **List:** the processes with the highest load, at most 200. Per process: ID, user, CPU, memory, run time, command. Sort by CPU or memory, search by name or user.
- **Actions:** terminate (politely, `TERM`) and kill (`KILL`), both with a confirmation that names the process's command.
- Commands: `ps` with fixed columns, the CPU time used from `/proc`, `kill`. The load comes from two measurements in a row; when first opened it therefore only appears after five seconds.

### Permissions

1. Glowport first runs everything as the signed-in user.
2. If that is not enough, it tries `sudo -n`, i.e. sudo without a password prompt.
3. If sudo asks for a password, Glowport writes the command with `sudo` in front into the session's terminal without sending it, and says so. You press Enter and type the password there. That way you see what runs, and Glowport never gets to see the password.

If even the list cannot be read (for example Docker without membership in the `docker` group and without password-less sudo), the tab says so, with the reason.

### Limits

- Linux with the programs named above only. No Podman, no Kubernetes, no Windows servers.
- The tabs do not exist for Telnet, serial lines and local terminals.
- Refreshing happens at a fixed interval (Docker and processes every five seconds, services every ten) while the tab is open.

## Proxmox

### Connection

- **Details:** name, address (`https://pve.example.com:8006`), token ID (`user@pve!glowport`) and its secret. Several connections are possible.
- **You create the token yourself in Proxmox** (Datacenter → Permissions → API Tokens) and enter it in Glowport. It only needs the permission to see VMs and containers and to switch them on and off; how to do that is described below under “Creating the token”. Glowport checks what the token may do when setting up and says what is missing.
- **Signing in to the machines:** an identity can be chosen on the connection (a user with key or password, from the Keys page). Glowport uses it to sign in to the machines of this connection: with “Connect” on the Proxmox page and on hosts created from it. If Cloud-Init names a key for a machine that is in your vault, Cloud-Init applies (user and key). Without either, only the user Proxmox names remains, and Glowport asks for the password if the server accepts one. Name and identity of a connection can be changed without checking it again.
- **Stored** in the personal vault, the secret encrypted like a password. With sync it reaches your other devices. It cannot be shared in this version.
- **Certificate:** Proxmox ships a self-signed certificate that no computer trusts by itself. Glowport connects without asking if the certificate is trusted (e.g. from Let's Encrypt). Otherwise it shows the certificate's fingerprint the first time; you compare it with the one in the Proxmox interface and confirm; Glowport remembers it in the connection. If it changes later, Glowport does not connect and says why. This is the same procedure as for SSH's known hosts.
- **“Check” therefore runs in two steps.** The first only establishes the connection and shows the fingerprint; the token does not go out. Only after your tick (“The fingerprint matches”) does “Check with token” send the token and read version and permissions. With a trusted certificate the first step is skipped. When editing a connection, Glowport does not ask again as long as the server shows the same certificate.

### Creating the token

Easiest in the Proxmox server's shell (node → Shell):

```
pveum role add Glowport --privs "VM.Audit VM.PowerMgmt VM.GuestAgent.Audit Sys.Audit"
pveum user add glowport@pve
pveum acl modify / --users glowport@pve --roles Glowport
pveum user token add glowport@pve glowport --privsep 0
```

The last command shows the token's secret, and only this one time. In Glowport: ID `glowport@pve!glowport`, plus the secret.

- `VM.Audit`: see machines and their settings (this is where address, user and keys from Cloud-Init come from).
- `VM.PowerMgmt`: start, shut down, stop, restart.
- `VM.GuestAgent.Audit`: ask the guest agent for the addresses (before Proxmox 9 this permission was called `VM.Monitor`).
- `Sys.Audit`: load of the nodes. Without this permission Glowport shows the nodes by name only.
- `--privsep 0`: the token may do what its user may do. With separated privileges the token would need the same role again for itself (`--tokens 'glowport@pve!glowport'`).

Proxmox shows the fingerprint for comparison under node → System → Certificates (`pve-ssl.pem`), or in the shell: `openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256`.

### The page

A new entry “Proxmox” in the bar on the left. Per connection its nodes, below them their VMs and containers:

- Name, number, kind (VM or container), state, CPU, memory, uptime, tags. Templates are marked as such.
- **Actions:** start, shut down, stop (hard), restart. Shutting down, stopping and restarting with a confirmation. Glowport shows whether Proxmox carried out the task. Afterwards it asks the machine itself for its state so the display is correct right away: Proxmox only refreshes the list of all machines every few seconds.
- **Connect:** opens an SSH session to the machine's address, even if it is not saved as a host.
- **Create as hosts:** see below.
- Refreshed every ten seconds while the page is open.

### Where Glowport gets address and sign-in from

Glowport combines what Proxmox offers instead of relying on one source:

| Source | Provides |
|---|---|
| Cloud-Init of the VM | fixed address, user, stored public keys |
| Guest agent of the VM (if running) | the addresses the VM really has right now; the operating system |
| Settings of the container | fixed address |
| Running container | the addresses it has right now |

- A fixed address from Cloud-Init or the settings applies before a measured one. Without a fixed address (DHCP), what the guest agent or container reports counts; IPv4 comes before IPv6, and addresses that are only valid inside the machine do not count.
- If Glowport also finds a stored public key in the vault (by its fingerprint), it puts that key on the host. Otherwise it puts the identity chosen on the connection.
- If a server only accepts keys and none is intended for the connection, the sign-in ends at once; Glowport then says that this is the reason.
- Proxmox does not hand out the password from Cloud-Init.
- If Proxmox knows no address (no Cloud-Init, no guest agent, machine off), Glowport says so; the address can then be entered by hand.

### Creating hosts and keeping them up to date

- **Preview:** all VMs and containers of a connection with what Glowport knows about them (address, user, key, operating system). You tick what should become a host and choose the group. Templates and machines without an address are not preselected.
- **In the personal vault:** the hosts live where the connection lives; only groups of the personal vault are offered. If you move such a host into a shared vault, its link is dropped (the other members would not have the connection).
- **Without a known address** the new host gets the machine's name for now. As soon as Proxmox knows an address (the machine runs, the guest agent answers), Glowport fills it in.
- **Link:** a host created this way remembers which machine it belongs to. In the host overview it carries a badge with the machine's state, and in its details the state plus the buttons to start, shut down and restart. If the machine is off, there is “Start and connect”: Glowport starts it and opens the tab as soon as it accepts connections (it waits up to two minutes). “Unlink” separates host and machine again; the host stays.
- **Recognised** by its number. If the machine moves to another node in the cluster, the link stays.
- **Keeping up to date:** if address or name change in Proxmox, the host follows. What you changed on the host yourself stays: a name or address set by hand is not overwritten. If Proxmox currently knows no address (machine off, no Cloud-Init), the last known one stays.
- **How often it asks:** Glowport reads the list of machines every ten seconds. It remembers a machine's settings and address for a minute so the server is not asked for every machine on every refresh; “Reload” asks for everything again right away.
- **New machines** do not become hosts by themselves. The page shows how many have not been created yet.
- **Deleted machines:** the host stays and is marked as “no longer present in Proxmox”. Glowport never deletes a host by itself.
- Syncing happens while the Proxmox page or the host overview is open, not in the background.

## Security

- The token's secret is stored encrypted in the vault and only goes to the Proxmox server it belongs to, over HTTPS.
- Glowport neither asks for nor stores a sudo password.
- Everything that stops or ends something has a confirmation that names the target.
- Names of containers, services and processes come from the server. They never go into a command unchecked: Glowport only inserts IDs it has read itself and checked for their form.
- In a shared vault with read permission the rule still holds: connect yes, change no. The sidebar tabs belong to the session and are open to whoever is connected; what they may do there is decided by their permissions on the server.

## Not in this version

- Docker: Compose projects, images, volumes, networks, Podman.
- Proxmox: console in the window, snapshots, backups, creating and deleting machines, storage, cluster management, signing in with user and password instead of a token, connections in shared vaults.
