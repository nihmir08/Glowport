# Glowport sync and shared vaults

Protocol version: 1

This document defines how Glowport syncs vaults through a server of your own and shares them with others. It was written before the code, for the same reason as [`vault.md`](vault.md): a mistake here would be the most expensive to fix later. It builds on `vault.md` (the record format stays unchanged) and on the project's principles: your own server, end-to-end encryption, sharing with permissions.

## In short

- **A server you run yourself** (`glowport-sync`, a single program or a Docker image). Without a server Glowport works exactly as before.
- **One account per person**, signed in with user name and master password. The master password never leaves the device; the server only gets a sign-in key derived from it, which cannot decrypt anything.
- **The server only sees encrypted records.** It knows who shares a vault with whom and how many records there are, but not what they contain, not even the names of the vaults.
- **Changes arrive right away:** every change goes straight to the server, the other devices fetch it within about a second. Without a network you keep working; syncing happens as soon as the server is reachable again.
- **Several vaults:** your personal one (only you, on all your devices) and any number of shared ones, each with members in the roles owner, write or read.
- **Simultaneous changes** are merged field by field. Only when two people change the same field does the newer change win, and you get a notice.
- **No reset**, just like the vault: whoever forgets their master password cannot get to their data through the server either.

## Design decisions

| Question | Decision |
| --- | --- |
| How do others get an account? | **Invitation code from the app.** The server's administrator creates codes in Glowport, sees all accounts and can disable or delete them. |
| Several vaults in the host overview | **Switcher with “All”** (All · Personal · every shared vault), default “All”; every host carries the badge of its vault. |
| Read permission and secrets | **Connect yes, view no:** members with read permission can connect, but can neither show, copy nor export passwords and private keys. |
| Second factor at sign-in | **Added later.** The protocol already provides for the extra step. |

## What sync protects against and what not

| Protects against | Does not protect against |
| --- | --- |
| A hacked or curious server: it cannot read anything and cannot change or slip in anything unnoticed | A member who copies the data of a shared vault while being a member |
| Eavesdropping on the line (TLS, and underneath only ciphertext anyway) | A member with read permission who extracts stored passwords from their computer by other means (the lock is one of the program, see “Roles”) |
| A server that presents an old state as current (every device remembers what it has already seen) | A server that holds back changes or is unreachable (it can delay, not forge) |
| Guessing attempts against an account over the network (the server slows them down) | A weak master password if the server's database is stolen (the same applies as for a stolen vault file) |
| Writes by members who may only read (the server refuses, and the other devices check the signature themselves) | Losing the master password |

## Account and devices

### Creating an account

An account is the vault that already exists plus a user name on the server. No new keys are created: the account key and both key pairs (X25519, Ed25519) have been part of every vault from the start.

- **Sync → “Set up sync”:** server address, invitation code, user name (3 to 32 characters: lower-case letters, digits, `-`, `_`, `.`), master password for confirmation.
- Uploaded are: salt and cost of Argon2id, the wrapped account key, the public and the wrapped private keys, the wrapped key of the personal vault and all records. All of this is already encrypted in the vault file and goes over unchanged.
- **The very first account** of a fresh server needs, instead of an invitation, the setup code the server prints when it starts. This account is the administrator.

### Signing in

```
device → server   user name
server → device   salt, cost of Argon2id            (made-up but fixed values for unknown names)
device            master password ─Argon2id→ master_key ─HKDF "glowport/auth/v1"→ auth_key
device → server   auth_key
server → device   device token, wrapped account key, key pairs, list of vaults
device            master_key ─HKDF "glowport/kek/v1"→ kek → unwrap account key → continue as when unlocking
```

- The server stores only a verifier of `auth_key` (SHA-256 with its own salt). `kek` cannot be computed from `auth_key` (`vault.md`, key chain); whoever has only the server must guess the master password as with a stolen vault file, at the full cost of Argon2id per attempt.
- **Guessing over the network:** at most five failed attempts per account in fifteen minutes, plus a brake per sender address (thirty). Behind a web server the server reads the address from `X-Forwarded-For` (`--trust-proxy`).
- **The device name** is added right after signing in: it is encrypted with the account key, which a new device only has afterwards.
- **No cost that is too low:** the server names salt and cost. If it names less than the usual minimum for Argon2id (19 MiB, 2 passes), Glowport does not sign in. Otherwise a malicious server could prescribe tiny values and cheaply guess the master password from the sign-in key.
- **Second factor (later):** the sign-in response can require another step (`needs`). Current versions know none and then report “This server needs a newer version”.

### Devices

- Every sign-in creates a device: ID, name (encrypted with the account key, the server does not see it), last seen. The **device token** (32 random bytes) identifies the device on every request. The server stores only its verifier; on the device it is kept in the vault file, encrypted with the account key.
- **Sync → Devices** shows all devices of the account. “Sign out” invalidates the token: the device gets nothing new any more. What it already has stays readable there for anyone who knows the master password. If a device is lost: sign it out and change the master password.
- **Syncing only happens while the vault is open.** A locked Glowport has no keys and does not talk to the server. After unlocking, it fetches first.

### Three ways onto a device

| Situation on the device | Way |
| --- | --- |
| Vault exists, no account yet | “Set up sync” as above. The vault becomes the account's personal vault. |
| No vault yet (new PC) | At first start, next to “Create vault” and “Restore backup”, there is a third way, **“Sign in with an account”**: address, user name, master password. |
| Vault exists, and so does the account (two devices that grew separately) | “I already have an account”. Beforehand Glowport writes a backup into the data folder (`glowport-vor-konto-<date>.gpvault`, with the previous master password). Then the choice: **move** the local records **into the account's personal vault** (re-encrypted, references between them are kept; duplicates are not detected) or **discard** them. From then on the account's master password applies, and starting without the master password is switched off. |

### Changing the master password

New salt, account key wrapped anew, new `auth_key`. With sync, the package goes **to the server first** (authorised with the previous `auth_key`: a stolen device token alone changes no password) and is only applied here afterwards; so it never happens that only one device knows the new password. A checkbox in the dialog: “Sign out all other devices”.

The other devices stay signed in and **note the new package at the next sync**. There, the old password keeps opening the local file until the new one is used for the first time; from then on only the new one works. The package comes from the server and cannot be verified without the new password; it therefore only replaces the old one once it unlocks and the key inside really is this account's key. A server that sends nonsense here locks nobody out.

Limit: the account key itself stays the same. Whoever has already captured it is not locked out by a new password. Exchanging the account key is not part of this version.

## What the server sees

| Sees | Does not see |
| --- | --- |
| User names, number of devices, when they were last seen, sender addresses | Master password, account key, vault keys |
| Per vault: ID, members and their roles | Names of vaults and devices |
| Per record: ID, revision, deletion mark, modification time, author, size | Kind of record (host, key, snippet …) and any content |
| Public keys of the accounts | Private keys (only wrapped) |

The server's administrator sees in Glowport the same as the server and nothing more: accounts, storage use, invitation codes. They can disable and delete accounts, but cannot reset a password or look into any vault.

## Syncing

### Principle

- The server keeps a counter (`seq`) per vault. Every accepted change gets the next number. A device remembers per vault up to which number it has everything.
- **Fetching:** “everything in this vault after number N”. The server delivers only the newest version of each record, tombstones included.
- **Sending:** the device sends changed records as they are stored in the vault file (ID, revision, deletion mark, nonce, ciphertext, signature). The server accepts if
  1. the account may write in this vault,
  2. the signature matches the account's public key (the server can check it without decrypting anything),
  3. the change builds on its state: the device names the revision it is based on; it must be the one the server has, and the new one must be above it (a record the server does not know yet is accepted with any revision),
  4. the vault's key generation matches (see “Key rotation”).
- **All or nothing:** what the program writes locally as one change (delete a host together with its port rules) goes as one package and is accepted or rejected as a whole.
- **Revisions:** as long as a change to a record the server already knows has not been accepted, another local change does not raise its revision again. Locally it is therefore always exactly one above the last synced state. The device keeps that state until the change is accepted; it is the base for merging.

### Right away

- Every local change goes to the server after a 300 ms collection time.
- Every device keeps a WebSocket connection. It only carries the message “vault X is at number N” or “something changed on your account” (invitation, role, password); fetching then happens via the normal request. After every reconnect (1, 2, 5, 10, 30 seconds) the device fetches anyway. If no WebSocket can be kept, the device asks every minute.
- The status bar shows the state: synced, syncing, offline (with the number of waiting changes), error.
- Running sessions are not affected by syncing. A changed host applies to the next connection.

### Simultaneous changes

If the server refuses because another device was faster, it sends that device's version along. The device then merges three versions: the common base, its own and the server's.

- **Field by field.** A record's content is JSON. Objects are compared key by key (including a host's own values in `own`), lists and simple values count as one field. If only one side changed a field, its value applies. If A changes the port and B the color scheme of the same host, both stay.
- **The same field on both sides:** the newer change wins (by modification time; on a tie, the server's). Glowport shows a notice: which entry, which field, whose value applies. Notices collect under Sync.
- **Change against delete:** the change wins, the entry stays or comes back, with a notice.
- Fields the program does not know take the same path. An older version therefore destroys nothing a newer one created.
- The result gets the next revision and goes to the server again.

**Rules across several records** (a group must not be inside itself, a hotkey belongs to one snippet, a reference points to something that exists) cannot be checked by the server, because it cannot read anything. Two devices can break them together. Every device defuses this when reading and rewrites nothing on its own: a dangling reference counts as “not set”, a group in a cycle appears at the top level, a duplicate hotkey applies to the entry with the smaller ID. Whoever saves the entry next cleans it up.

Limit: if A deletes a host together with its port rules and B changes the same host at the same time, the host stays, but its port rules are deleted.

### Tombstones

The server keeps tombstones for 180 days. A device that was away longer gets the whole state instead of the changes and removes locally what it knew as synced and the server no longer has. With sync, the devices use the same period instead of the usual 90 days.

### Checksum, and a server that turns back time

Numbers alone do not reliably show whether device and server have the same: after the server was restored from a backup, it hands out numbers that already existed once. That is why the server sends a **checksum over its whole state** of the vault with every fetch (ID and revision of every live record), and the device computes the same over what it believes to be the server's state.

- **If both match,** all is well.
- **If they do not match** (or the server names a smaller number than last time), the device fetches the whole state and compares record by record. If the server only has newer things, they are taken over: the device had missed something.
- **If the server lacks something that is considered synced here,** or has it in an older version, it has an older state than this device. The device takes over nothing from it, sends nothing into this vault and reports: “The server has an older state than this device.” That is either an attack or a server you restored from a backup.
- For the second case there is the button **“Upload this device's state”**: whatever is newer here goes up again one revision higher, so every other device also accepts it as new. The remaining devices then find their way back by themselves. Whoever may only read in a vault cannot upload anything and only takes over.

Nobody turns back individual records anyway: no device accepts an older revision than the one it knows.

## Several vaults

- **Personal vault:** exactly one per account, cannot be shared. Its key is wrapped with the account key.
- **Shared vaults:** any number. Whoever creates one is its owner. The name is stored encrypted inside the vault (`vault-info`).
- **Interface:** a switcher “All · Personal · <shared vaults>” on the Hosts, Keys, Snippets and Port forwarding pages, default “All”. Every entry carries the badge of its vault. Search always finds everything. When creating an entry you choose the vault; the one currently shown is suggested.
- **Moving between vaults:** a host moves by being created anew in the target (without a group) and deleted in the source. If an identity or key from another vault is attached, it comes along as a copy if wanted, otherwise the reference is dropped; a jump host from elsewhere is always dropped. Port rules, workspaces and jump references of other hosts follow it as far as they may point there. Keys, identities and snippets on their own cannot be moved yet; create them in the vault you want.
- **An entry lives in the same vault as its group.** Creating a host in a group puts it into that group's vault.
- **References:** a record of a shared vault only refers to records of the same vault (key, identity, group, jump host, custom color scheme), otherwise the other members would lack them. The personal vault may refer to anything: workspaces and port rules can name shared hosts.
- **Always personal:** known hosts, workspaces.
- **Custom color schemes** move from `settings.json` into the vault as `color-scheme` records, so a host looks the same on every device (announced this way in `vault.md`).
- **Not synced:** the program's settings (design, language, font), recordings, open tabs, transfers, starting without the master password. They belong to the device.

## Sharing

### Roles

| Role | May |
| --- | --- |
| **Owner** (exactly one) | everything in the vault, invite and remove members, change roles, transfer ownership, delete the vault |
| **Write** | create, change and delete entries; view secrets |
| **Read** | see everything and connect; change nothing; can neither show, copy nor export passwords and private keys, cannot copy entries with secrets into other vaults |

**Being honest about read permission:** whoever can connect has the vault key and therefore every secret of the vault on their computer. Glowport does not show it to them, but that is a lock in the program, not a seal. What is strictly enforced for read permission is **writing**: the server refuses it, and every device checks by itself whether a record's author was allowed to write.

### Member list

Every shared vault has a member list: vault ID, key generation, sequence number, and per member the account, public keys and role. **The owner signs it** (Ed25519). The server stores it but cannot change it: every device only accepts a list whose number is higher than the last one seen and which was signed by the owner the device knows. A server can therefore neither make itself a member nor give anyone write permission.

**Transferring ownership:** the previous owner signs a handover to a member and signs the list one last time; from the next one on, the new owner signs. Every list carries all handovers that ever happened, as a chain. So even a device that missed a handover can verify from the owner it knows up to today's, and an old handover cannot be used a second time (its position in the chain and the list number are signed along).

Records of a shared vault only count if their author is owner or may write according to this list.

### Inviting

1. The owner types the user name (the account must exist on the same server) and chooses the role.
2. Their device fetches the account's public keys and shows its **safety code** (six words from a hash of both keys; the words come from a fixed list of 512, together 54 bits). The invited person sees the same code under Sync. Whoever wants to be sure compares it through another channel (chat, phone). This protects against a hacked server slipping in false keys and thereby getting the vault key. The device remembers keys it has seen once; if they change, it warns.
3. The device wraps the vault key for the invited person and sends it with the new member list.
4. The invited person gets an invitation with the vault's name, the owner and their safety code, and accepts or declines. So that their device can show the name, it may fetch the records before accepting; it has the key with the invitation anyway. It can only write afterwards.

**Wrapping the vault key** (announced in `vault.md`): a one-time X25519 key pair of the sender → shared secret with the recipient's public key → HKDF-SHA-256 (salt: both public keys, info `"glowport/share/v1"`) → XChaCha20-Poly1305. Bound are the vault ID, the key generation and the recipient's public key. The owner also gets their key this way; on the device it is then wrapped with the account key like every vault key.

### Revoking permissions: key rotation

When a member is removed or loses write permission, the owner's device exchanges the vault's key. No device accepts a member list that takes permissions away without raising the key generation. The procedure:

1. new vault key, key generation plus one,
2. all records (tombstones too) encrypted with the new key and signed by the owner, revisions unchanged,
3. new member list, the new key wrapped for every remaining member,
4. everything as one package to the server, which only accepts it if nobody has written since it was read (otherwise start again).

- From that moment on, the server gives the removed member nothing more. Their Glowport deletes its copy of the vault as soon as it learns about it.
- The other devices fetch list, key and records. Changes that were still waiting on them are re-encrypted and sent afterwards.
- After the rotation there is no record left that the removed member signed. That is why the current member list is always enough for the devices.
- **What the rotation cannot do:** take back what the member has already seen. After removing someone, Glowport shows the vault's hosts with a stored password or key and recommends changing those credentials on the servers.

If a member leaves a vault on their own, the server removes them at once; the owner's device rotates the key the next time it is online. The owner cannot leave without transferring ownership or deleting the vault. If the administrator deletes an owner's account, the vault stays readable for the remaining members and can be copied into a vault of their own.

If the server no longer keeps a vault for an account (removed, or the owner deleted it), Glowport removes the copy on that account's devices. The owner's copy stays until they remove it themselves: a server must not be able to make anyone lose their own vault.

## The server

### Structure

- **One program** `glowport-sync` (Rust, axum, SQLite in a single file), plus a Docker image with the same program. Crates of its own: `crates/sync-proto` (messages, used by both sides), `crates/sync-server`, `crates/sync` (the program's side).
- **Interface:** HTTPS with JSON under `/v1/…`, WebSocket under `/v1/live` (the first message is the device token, so it never appears in an address). The routes in detail are in `crates/sync-server/src/lib.rs`, the messages in `crates/sync-proto`. The server names its version and the oldest one it still serves; if they do not match, Glowport says which side needs an update.
- **TLS:** the intended setup is a web server in front (NGINX or Caddy) with its own certificate; `glowport-sync` then only listens on `127.0.0.1`. For running without one, the program also takes certificate and key as files (`--tls-cert`, `--tls-key`); it picks up changed files within an hour without a restart. Glowport only connects via `https://`; `http://` is allowed solely for addresses of the own machine (tests). Certificates are checked against the system's certificate store; Glowport reports a rejected certificate as such (“The sync server's certificate is not accepted …”), not as “cannot be reached”.
- **Limits:** 256 KiB per record, 20,000 records per vault, 50 vaults per account (adjustable via the environment, see [`sync-server.md`](sync-server.md)); 50 members per vault (fixed).
- **Server log:** one line for everything that changes something or fails, with time, status, kind of request (as a pattern, without IDs) and account. Never contents, tokens or `auth_key`, and no sender addresses. Plain reads stay silent.
- **Behind a web server** the server slows down guessing by the address from `X-Forwarded-For`. It is only trusted when enabled: for every connection (web server on the same machine, the server listens on `127.0.0.1`) or only for connections from named addresses (web server on another machine).
- **Operation:** setup, commands, backup and troubleshooting are in [`sync-server.md`](sync-server.md); templates (service file, setup script, Docker, NGINX, Caddy) in the `server/` folder.

### Administration (in Glowport, administrators only)

Sync → “Manage server”: create invitation codes (valid once, for seven days), revoke open codes, see accounts with devices, last visit and storage, disable an account (no sign-in, no sync; the data stays), delete an account (including its personal vault). The same actions exist as commands of the program on the server, in case no administrator can get in any more (`glowport-sync invite`, `invites`, `revoke`, `accounts`, `disable`, `enable`, `delete`, `backup`). Only there are `admin <name>` and `noadmin <name>` available as well: whoever sits at the server's command line can make an account an administrator, so a server gets one again after a lost master password. Glowport learns about it with the next sync.

### Backup

- `glowport-sync backup <file>` writes a consistent copy of the database while running. It contains only what the server sees and is therefore as encrypted as the vaults themselves.
- Restore: stop the server, replace the file, start. Devices that had moved on report the older state and offer “Upload this device's state”.
- Every device keeps a complete copy of its vaults anyway. If the server fails, everyone keeps working with their own state.

## Changes to the vault file

The record format, the key chain and all test vectors from `vault.md` stay as they are. The file gets **format version 2**:

- `vaults` additionally holds the kind (personal, shared), key generation, the last fetched number and the signed member list (owner and own role follow from it).
- New: `base` (the last synced state of every record with a waiting change), `contacts` (public keys of other accounts seen once), `notices` (notices from syncing).
- Member lists, contacts and notices contain names. They are therefore stored in the file encrypted with the account key: whoever has the file does not see with whom it is shared.
- A pending wrapping of the account key (see “Changing the master password”) is kept in `meta` next to the current one.
- `records` additionally holds the revision the server last confirmed or delivered.
- `meta` additionally holds the sign-in to the server (address, account, device ID, device token) as one piece encrypted with the account key.
- Records by other authors count in shared vaults according to the member list; in the personal vault only the own signature counts, as before.
- On the first start of the new version Glowport converts the file and first puts a copy next to it (`vault.db.format1`). Older versions no longer open a converted file and say so.
- **Backup files** contain all vaults but no device token: whoever restores a backup signs in to the server again and counts as a new device.

## Tests

- Fixed test vectors for wrapping the vault key and for the member list signature.
- Server and two to three devices in one test: create, change, delete, in every order and with interruptions; in the end all have the same state.
- Merging: every pairing of change, delete and create, the same field and different fields, unknown fields.
- Rules across several records: groups in a cycle, duplicate hotkey, dangling reference.
- A forging server: changed, swapped, old and invented records, a forged member list, a wrong key generation, a state turned back. Everything is detected, nothing taken over.
- Permissions: writing with read permission is refused by the server and by the other devices; a removed member gets nothing more and cannot read anything new after the key rotation.
- Key rotation while another device holds changes offline.
- Sign-in: wrong password, brake, signed-out device, password change on one device and unlocking on the other.
- End-to-end with two running programs against a server on the same PC, then against a server on a dedicated machine.
- Measurements: first sync with 1,000 records, time from a change until it shows on the second device, memory of the server.

## Deliberately not in this version

- Second factor (prepared).
- History of older versions of an entry and restoring from it (the server keeps only the newest).
- Exchanging the account key.
- Sharing across servers: all members of a vault have their account on the same server.
- Sharing single entries: a whole vault is always shared.
- More than one account or server per Glowport.

## Building the Linux program

Both ways are prepared: `scripts/build-server.sh` (on Linux, e.g. WSL; produces `dist-server/glowport-sync`) and `server/Dockerfile` (built on the server).
