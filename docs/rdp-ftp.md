# RDP and FTP/FTPS

Design document.

**Status:** FTP and FTPS are fully built (including imports and quick connect) and part of Glowport since 0.11. **RDP is not part of the program yet:** its core (`crates/rdp`, outside the workspace) is built and tested, but the IronRDP library currently pins pre-release versions of `picky`/`sspi` that cannot be combined with the SSH library in the same program. RDP will follow once IronRDP catches up.

## Summary

- **RDP:** a Windows computer (or Linux with xrdp) opens as a tab of its own, like a terminal. Picture, keyboard, mouse; the size follows the tab; text and files go through the clipboard; the remote computer's sound plays through your speakers.
- **FTP and FTPS:** an FTP server opens in the existing file manager: two panes, transfers with a queue, viewing and editing. FTPS is the default; unencrypted FTP works with a clear warning.
- **Proxmox:** Windows machines connect via RDP instead of SSH.

## Design decisions

| Question | Decision |
|---|---|
| What can RDP do besides picture, keyboard, mouse? | **Text clipboard, sound, and files through the clipboard.** |
| Where do the Windows key, Alt+Tab and the like go? | **Only in full screen to the remote computer**, otherwise they stay with your PC. |
| Unencrypted FTP? | **Yes, with a warning.** FTPS is the default. |
| Windows machines on the Proxmox page via RDP? | **Yes.** |

## Result of the RDP trial

The plan was to try the IronRDP library first. Result: **it works.** In a throwaway program the client signed in to a simulated RDP server (over TLS and over NLA), a wrong password was rejected, the picture arrived correctly pixel for pixel, keys, characters and mouse reached the server.

Two things are built differently from what the library ships ready-made:

- **Certificate:** the ready-made client accepts every certificate without showing it. Glowport shows the fingerprint on the first connection and remembers it (see “Security”).
- **Picture:** the ready-made client sends the whole picture on every change. Glowport only sends the changed regions to the window.

Not tried, because it needs a real Windows: resizing while running, clipboard, sound, speed with a large picture.

## RDP

### Setting up a host

In the host editor, the protocol choice gets **RDP** (port 3389) next to SSH, Telnet and serial. An RDP host has:

- **Address, port, group, name, operating system icon** like every host.
- **Sign-in:** user and password, directly on the host or via an identity from the vault (the same identities as for SSH; keys play no role for RDP). A domain goes into the user: `CORP\alex` or `alex@corp.local`.
- **Size:** “fit to tab” (default) or a fixed resolution that is then shown scaled to fit.
- **Sound:** on (default) or off.
- **Jump host:** an RDP host can run through a jump host like an SSH host. Glowport then builds the SSH tunnel itself; the RDP port does not have to be open on the network.

Quick connect understands `rdp://address` and `address:3389`.

### Connecting

- Sign-in with **NLA** (Windows requires it by default); if the server does not offer it, with TLS. Glowport does not implement the old, unencrypted RDP security.
- If the password is missing, Glowport asks as with SSH, with the “save in vault” checkbox.
- Understandable messages for the usual cases: wrong password, account locked or password expired, user not allowed to sign in via Remote Desktop, server unreachable, certificate changed.
- If someone is already signed in to the computer, Windows decides as usual (Windows 11 Pro disconnects the other session). Glowport changes nothing about that.

### The tab

- An RDP tab sits in the tab bar next to the terminals, with its own icon. It can be renamed, moved and dragged into another window without the connection dropping.
- Above the picture there is a narrow bar: **Ctrl+Alt+Del**, **Full screen**, **Sound on/off**, **Disconnect**, plus the current resolution.
- **Size:** when you resize the window, the remote computer gets the new resolution after a short moment, without signing in again. If the server cannot do that (older Windows versions, some xrdp), the picture is scaled to fit.
- **Scaling:** on a screen with scaling (e.g. 150 %) the remote computer is told the same scaling so text does not become tiny.
- **Mouse pointer:** Glowport shows the remote computer's pointer (arrow, text cursor, resize …).
- **Drop:** if the connection drops, the last picture stays, dimmed, with “Reconnect”. If you disconnect yourself, the tab closes with the usual confirmation.
- An RDP tab cannot be split, has no sidebar (info, snippets, Docker …), no recording and does not take part in multi-exec.

### Keyboard

- Glowport sends **keys**, not characters. Which character results is decided by the remote computer's keyboard layout, exactly as with Windows' Remote Desktop app.
- **In a window** the Windows key, Alt+Tab, Alt+F4, Ctrl+Esc and Glowport's own shortcuts (switch tab, palette) stay with your PC. Everything else goes to the remote computer.
- **In full screen** these shortcuts go to the remote computer too. You get out with **Ctrl+Alt+Pause** or via the bar that appears when the mouse touches the top edge.
- Windows always intercepts Ctrl+Alt+Del itself; that is what the button in the bar is for.

### Clipboard: text

Text copied on one side can be pasted on the other, in both directions, including non-ASCII characters and line breaks. Can be switched off per host.

### Clipboard: files

- **From your PC to the remote computer:** copy files or folders in Explorer, paste them on the remote computer. The remote computer then fetches them from Glowport.
- **From the remote computer to your PC:** when you copy files there, the tab's bar shows “3 files on the clipboard – Download”. Glowport downloads them into the Downloads folder (or a folder of your choice), shows the progress and then puts them on your clipboard; you then paste them in Explorer wherever you like.
  The detour has the same reason as dragging into Explorer: files that are only downloaded when pasted are complex on Windows. The elegant version (Ctrl+V directly in Explorer) can follow later.
- Can be switched off per host, together with the text clipboard.

This is the least proven part: the library supports it by design, but it has been tried the least. If it does not run reliably against a real Windows, files stay out for now rather than shipping a shaky version.

### Sound

The remote computer's sound plays through your PC's default output device. A button in the bar mutes it, a switch on the host turns it off. Playback only; your microphone does not go to the remote computer.

## FTP and FTPS

### Setting up a host

The protocol choice also offers **FTP**. An FTP host has:

- **Encryption:**
  - **FTPS, explicit** (default, port 21): the connection starts normally and switches to TLS right away. Almost all current servers can do this.
  - **FTPS, implicit** (port 990): the older way, still common at some hosting providers.
  - **None** (port 21): unencrypted, see “Warning”.
- **Sign-in:** user and password (directly or via an identity) or “anonymous”.
- **Start folder** (optional).

### Connecting

An FTP host has no terminal. “Connect” opens it in the **file manager** (Files page), your PC on the left, the server on the right. In the location picker there it appears next to the SSH hosts.

**Quick connect** (search, Ctrl+K) without a saved host: `ftp://user@address:port/folder` is unencrypted (with a warning, without “don't ask again”), `ftps://…` and `ftpes://…` are explicit FTPS; `ftps://` on port 990 means implicit FTPS. Without a user, the sign-in is anonymous. Glowport asks for the password and does not store it; a password inside the address is not accepted, because it would be readable in the search field. A confirmed certificate is listed with the known hosts as usual. If a server opened with `ftp://` supports FTPS, the warning offers to open it encrypted.

### What works in the file manager

| Works as with SFTP | Works with limits | Does not exist with FTP |
|---|---|---|
| Browse folders, sort, path bar | **Change permissions:** only if the server offers it; otherwise the menu item is missing | Searching inside files |
| Upload and download with a queue, pause, **resume** | **Search by name:** Glowport walks the folders itself (at most 5,000 entries), which takes longer | “Follow” (the folder of a terminal) |
| Create, rename, delete folders (also with their content) | **Keep modification time:** only if the server offers it | Owner names |
| View and edit in the built-in editor or your own program | **Links** are shown but not resolved | |
| Compare folders | | |
| Drag between panes, drag from Explorer | | |

- Glowport works in **passive mode** (the server does not open a connection back to you); that gets through routers and firewalls. There is no active mode.
- FTP can only transfer one file at a time per connection. For simultaneous transfers Glowport signs in several times, at most as often as the queue works in parallel. If the server allows fewer, the next transfer waits and tries again (up to six times, every two seconds); the rest is then processed one after another.
- Copying between FTP and SFTP (FTP on the right, an SSH host on the left) works; the data runs through your PC.

### Warning for unencrypted FTP

- In the host editor, “None” says in red that **password and files are readable by anyone along the way**.
- The host card and the file manager's path bar show an open red padlock.
- On the first connection Glowport asks, with “Don't ask again for this host”.
- If a server set up as “None” offers TLS, Glowport suggests switching to FTPS when connecting.

## Proxmox

- For machines that Proxmox lists as Windows, “Connect” means **RDP**: address from the guest agent, port 3389, sign-in with the Proxmox connection's identity or via a prompt.
- “Create hosts” creates them as RDP hosts and keeps them up to date like the others.
- “Start and connect” waits for Windows until the RDP port answers.
- A separate identity for Windows machines can be stored on the Proxmox connection (next to the one for Linux), because the same user rarely applies there.

## Imports

MobaXterm, WinSCP, FileZilla, Xshell and the CSV table now take over FTP entries (address, port, user, encryption; passwords only where the source contains them readably; without a user, anonymous). If the source does not reliably name the encryption (MobaXterm, Xshell, FileZilla's “FTP”, which there means “encrypt if possible”), the host becomes FTPS and carries the hint “Check encryption” in the preview. In the CSV table `ftp` means unencrypted, `ftps` and `ftpes` encrypted. Glowport's own format and the table also carry FTP hosts when exporting. RDP entries are skipped as long as RDP is not part of the program.

## Sync

RDP and FTP hosts sync like all hosts. Nothing changes on the sync server. **A device with an older version of Glowport does not know the new protocols**; it shows such hosts but cannot open them, and does not damage them when editing.

## Security

- **Certificates as with Proxmox and known hosts:** if the server's certificate is trusted, no prompt. If it is self-signed (almost always for RDP), Glowport shows the fingerprint the first time; after your confirmation it is remembered. **If it changes later, Glowport does not connect** and says so clearly. Remembered fingerprints are listed on the Known hosts page.
- **The password only goes to the server once the certificate is trusted or confirmed.** This applies to RDP and FTPS.
- Passwords are stored in the vault and never reach the interface; the core signs in.
- Files from the remote computer are only downloaded when you click, never by themselves. File names are sanitised so nothing ends up outside the target folder.
- The remote computer only sees your clipboard while the RDP tab has the focus.

## Not in this version

- RDP: redirecting printers, drives and smart cards, microphone, multiple monitors, Remote Desktop Gateway, single programs instead of the whole screen (RemoteApp), opening `.rdp` files, recording the session.
- FTP: active mode, direct server-to-server copying, sign-in with a certificate.
- Pasting files from the remote computer directly with Ctrl+V in Explorer (see above).

## Open points

- **Everything against a real Windows.** The trial ran against a simulated server. Whether resizing, clipboard and sound work against Windows 10/11 and Windows Server only shows there.
- **Files through the clipboard** (see there).
- **Speed with a large picture** (video, 4K): the library renders without the graphics card. That is surely enough for administration, probably not for films.
- **Shortcuts in full screen:** intercepting the Windows key and Alt+Tab needs a keyboard hook of its own on Windows. Some virus scanners eye such hooks; it is only active while an RDP tab in full screen has the focus.
- **Quirks of FTP servers:** older servers deliver folder listings in formats of their own. Tested against a test server of our own and the common formats; exotic ones show up in practice.
