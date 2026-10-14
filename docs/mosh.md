# Mosh

Design document. Built and released with Glowport 1.0.

## Summary

- **Mosh is a switch on an SSH host:** “Connect via Mosh”. Signing in works as always over SSH (password, key, agent, jump hosts, all the usual prompts). Glowport then starts `mosh-server` on the server and the terminal runs over Mosh: encrypted over UDP, it survives Wi-Fi changes, sleep and dropouts, and what you type appears right away, even on a slow line.
- **Sidebar, files and snippets** run over an SSH connection next to it. If that one drops, the terminal keeps running; Glowport re-establishes the SSH connection by itself when needed.
- **If `mosh-server` is missing on the server**, Glowport connects over plain SSH and shows a hint in the tab with the command to install it.
- Quick connect: `mosh user@host`.

## Design decisions

| Question | Decision |
|---|---|
| Which library? | **`mosh-client`** (MIT or Apache-2.0), so Glowport stays MIT. With it, Mosh only works over IPv4. The other Rust implementations are GPL-3 and would have turned all of Glowport into GPL. |
| How do you choose Mosh? | **A switch on the SSH host**, plus quick connect `mosh user@host`. No protocol of its own in the selection. |
| Sidebar, files, snippets in a Mosh tab? | **An SSH connection stays open next to it** and re-establishes itself after a drop. |
| `mosh-server` missing on the server? | **Connect over SSH with a hint** including the install command. |

## Result of the trial

`mosh-client` 0.1.4 against `mosh-server` 1.4.0 in Ubuntu on WSL: the session is up 25–40 ms after the server starts. Input and output, non-ASCII characters, a new window size, lots of output (`seq 1 200000` in 30 ms; Mosh only sends the final state of the screen), full-screen programs, a clean end after `exit`. **Six seconds without a line** (UDP dropped in WSL): what the server wrote in the meantime arrived 0.13 s after the line came back. Not tested: a real network change with a new address (tested by the library according to its author), third-party servers.

## Setting up a host

In the host editor for SSH, in the connection section:

- **Switch “Connect via Mosh”** (default off). Like the other SSH settings it can also be set on a group and is inherited.
- Below it, only when the switch is on, under “Advanced”:
  - **Local echo:** Automatic (default, like Mosh itself: shows typed text right away as soon as the line is slow), Always, Off.
  - **UDP port or range** (empty = Mosh chooses, 60000–61000). For servers behind a firewall that only opens one port, e.g. `60001` or `60001:60010`.
  - **Path to `mosh-server`** (empty = as found on the server). For installations outside the search path, e.g. `~/.local/bin/mosh-server`.

The host card and the list show a small “Mosh” next to “SSH”.

## Connecting

1. SSH connection as before, with all prompts (unknown server, password, one-time code).
2. Glowport runs `mosh-server new -s -c 256 -l LANG=…` on the server (language from the host's environment, otherwise `C.UTF-8`; with port and path from the settings). The server answers with a port and a fresh session key.
3. **Address for UDP:** for a direct connection, the IPv4 address the SSH connection actually used; with a proxy or jump host, the host's IPv4 address as this PC resolves it.
4. The terminal switches to Mosh. The SSH connection stays open for the sidebar.

**If Mosh cannot be established, the tab becomes a normal SSH session with a hint** (the SSH connection is already up). Reasons and hints:

| Situation | Hint |
|---|---|
| `mosh-server` missing | “mosh-server is not installed on the server. Connected over SSH.” Plus the matching command for the detected system: `sudo apt install mosh` (Debian, Ubuntu), `sudo dnf install mosh` (Fedora, RHEL), `sudo pacman -S mosh` (Arch), `sudo apk add mosh` (Alpine), otherwise a pointer to mosh.org. Copyable. |
| No IPv4 address | “Mosh needs an IPv4 address; this host only has IPv6. Connected over SSH.” |
| No answer over UDP (10 s) | “The Mosh server does not answer over UDP (port …). Usually a firewall blocks ports 60000–61000. Connected over SSH.” |
| `mosh-server` reports an error | Its first line, shortened, plus “Connected over SSH.” |

The hint appears as a bar at the top of the terminal and can be closed; the tab then carries no “Mosh”.

## The tab

- In the terminal's header a **“Mosh”** badge next to “Connected”.
- **Interrupted line:** if Glowport hears nothing from the server for more than a few seconds, a bar appears at the top, like in the original: “No connection to the server for 12 s. Mosh reconnects by itself.” Typing keeps working; local echo shows it underlined until the server confirms it. When the line comes back, the bar disappears. The tab does not end; the “On disconnect” setting does not apply to Mosh tabs.
- **End:** when the shell ends (`exit`), when the tab is closed, or when the server ends the session. Closing ends `mosh-server` cleanly.
- **Sidebar, files, snippets and port rules of this session** use the SSH connection next to it. While it is disconnected they show “SSH connection lost, the terminal keeps running over Mosh” and try again the next time they are opened or refreshed, with the same credentials as the first time (from the vault or from this session's memory, never from disk). If that would need a new prompt (one-time code), Glowport only asks when you click “Reconnect” in the sidebar.
- **Scrollback:** Mosh only transfers the visible screen, no history. The tab's history contains what Glowport got to see; with a lot of output at once, lines are missing. That is how Mosh works; whoever needs history uses `tmux` or `screen`. A hint says so once, in the first Mosh tab.
- **Recording** records what arrives in the terminal (i.e. without the skipped intermediate states).
- **Splitting, multi-exec, separate windows** work as with SSH.

## Quick connect

`mosh user@host` and `mosh user@host:port` (the port is the SSH port) in search or quick connect. Signing in works as with `ssh user@host`.

## Import and export

- CSV table: the protocol column value “mosh” becomes an SSH host with Mosh switched on.
- Exporting as a table writes “mosh” into the protocol column.
- MobaXterm: Mosh sessions are skipped like other unsupported protocols, because their type and structure in the file are not reliably known.

## Sync

The new settings are ordinary fields on the host and are synced along. Older Glowport versions on other devices simply connect such hosts over SSH. The sync server does not change.

## Security

- The session key arrives over the already verified SSH connection, lives only in memory and is stored nowhere. Every UDP packet is encrypted and authenticated with AES-128-OCB; the library discards foreign packets.
- Mosh only trusts the address that comes from the SSH connection; it only accepts packets from elsewhere once they are validly encrypted (this is how network changes work).
- The output of `mosh-server` is treated as untrusted: read with a limit, only the single `MOSH CONNECT` line is evaluated.
- Agent forwarding and environment variables apply, as with SSH, to the shell that starts `mosh-server`.

## Tests

- Core: tests against `mosh-server` in WSL if present (otherwise skipped, with a message): setup, input, output, size, line failure, end, missing `mosh-server`, fallback to SSH.
- End-to-end: the test server gets a UDP forwarder (`127.0.0.1` → WSL), because WSL does not pass UDP through `127.0.0.1`. This makes it possible to simulate dropouts and a change of the sender port. Without Mosh in WSL these cases are skipped and counted as skipped.

## Not in this version

- IPv6 for Mosh (the library cannot do it).
- Mosh without SSH (e.g. with a `mosh-server` started by hand).
- Port forwarding over Mosh (Mosh has none; port rules run over the SSH connection next to it).

## Notes

- The library is young (one developer, version 0.1.4, only as a Git dependency). It pins `aes` to 0.9.1; russh uses the same version with it (0.9.2 and 0.9.3 only bring performance improvements, no security fixes).
