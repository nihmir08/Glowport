# Glowport vault format

Format version: 2 (records and key chain unchanged since 1) · implemented in `crates/core`

This document defines how Glowport stores data encrypted. It was written before the code, because a mistake here would be the most expensive to fix later: the format is synced and shared unchanged (see [`sync.md`](sync.md)).

## In short

- Everything you create (hosts, groups, identities, keys, snippets, port rules, known hosts, workspaces) is an individually encrypted record in one file, `vault.db`.
- The vault only opens with the master password. It is stored nowhere and cannot be reset.
- Whoever gets hold of the file, a backup or the sync server sees how many records there are, how large they are and when they were changed. They do not see content, kind or names.
- Only established algorithms from audited libraries are used: Argon2id, HKDF-SHA-256, XChaCha20-Poly1305, X25519, Ed25519.

## What the vault protects against and what not

| Protects against | Does not protect against |
| --- | --- |
| Theft of the PC, the disk or a backup file | Malware running under your user while the vault is open |
| Other users on the same PC who read the data folder | Someone sitting at the unlocked program |
| A curious or hacked sync server | A weak master password (Argon2id slows guessing down but does not prevent it) |
| Swapping or altering records in the file | Losing the master password (then the data is gone) |

## Key chain

```
master password ─Argon2id(salt, parameters)→ master_key (32 bytes)
master_key ─HKDF-SHA-256, info "glowport/kek/v1"──→ kek       unlocks the account key
master_key ─HKDF-SHA-256, info "glowport/auth/v1"─→ auth_key  sign-in to the sync server
kek ─decrypts→ account_key (32 bytes, random)
account_key ─decrypts→ private X25519 key (receiving shared vault keys)
account_key ─decrypts→ private Ed25519 key (signing own records)
account_key ─decrypts→ vault_key (32 bytes, random, one per vault)
vault_key ─decrypts→ every record of this vault
```

- **Argon2id:** 256 MiB memory, 4 passes, 4 lanes, salt of 16 random bytes. Measured on a desktop PC: 385 ms to unlock (the originally planned 64 MiB and 3 passes took only 67 ms, hence the increase). The values are stored in the file and can be raised on a password change.
- **Two keys derived from master_key:** the sync server only ever sees `auth_key`. `kek` cannot be computed from it.
- **Changing the password** means: new salt, new `kek`, wrap `account_key` again. The records stay untouched. Old backups remain readable with the old password.
- **Key pairs are created together with the vault**, even though they are only needed for sharing. That way the format did not have to change when sync arrived.
- **Sharing:** the `vault_key` of a shared vault is wrapped for every member with their public X25519 key (one-time key pair of the sender, HKDF, XChaCha20-Poly1305). Details are in `sync.md`.

## Encryption

One algorithm for everything: **XChaCha20-Poly1305** with 24 random bytes as nonce per operation (the length makes random nonces safe).

Every ciphertext is bound to its purpose. The bound data (AAD) is verified along with it but not encrypted:

| Ciphertext | Key | Bound data |
| --- | --- | --- |
| `account_key` | `kek` | `"glowport/account/v1"`, the number 1 (the version that defined the key chain; it does not follow the file's format version), salt, Argon2 parameters |
| private keys | `account_key` | `"glowport/x25519/v1"` or `"glowport/ed25519/v1"`, the matching public key |
| `vault_key` (own vault) | `account_key` | `"glowport/vault/v1"`, vault ID |
| record | `vault_key` | `"glowport/record/v1"`, vault ID, record ID, revision, deletion mark |

Consequences:

- A record cannot be put in the place of another or moved into another vault without decryption failing.
- An old version cannot be passed off as a newer one. A complete rollback to an old state by a malicious server is detected by the client because it remembers the highest revision seen per record (see `sync.md`).
- The deletion mark is bound as well, and tombstones are verified when reading. A deletion can therefore neither be faked nor undone without being noticed.
- Every part of the bound data is written with its length in front, so two different splits never produce the same bytes.
- A wrong master password shows when unwrapping `account_key`. There is no stored password verifier.

**Signature:** every record carries an Ed25519 signature of its author over bound data, nonce and ciphertext. Locally this is an extra check; in shared vaults it prevents the server from slipping in records.

## Records

The plaintext of a record is JSON:

```json
{ "t": "host", "v": 1, "name": "web-01", "address": "10.0.10.11", "group": "…", "own": { "user": "deploy" } }
```

- `t` is the kind, `v` the version of this kind's structure. **The kind is in the encrypted part**; from outside you cannot tell whether a record is a host or a key.
- **Unknown fields are kept.** An older version of the program that saves a record of a newer one throws nothing away.
- **Deleting** leaves a tombstone (empty content, “deleted” mark, higher revision) so the deletion later reaches other devices. Without sync, tombstones are removed locally after 90 days.
- Kinds: `vault-info` (name of the vault), `group`, `host`, `known-host`, `key`, `identity`, `authority`, `workspace`, `forward`, `snippet`, `proxmox`, later `color-scheme`.
- `host` holds in `protocol` one of `ssh` (default if the field is missing), `telnet`, `serial`, `ftp`. Any other word was saved by a newer version of the program; it stays, but cannot be connected to. For `serial`, `address` holds the port name (`COM3`, `/dev/ttyUSB0`) and `serial` the line: `{ "baud": 50…4000000, "dataBits": 5…8, "parity": "none" | "odd" | "even", "stopBits": 1 | 2, "flow": "none" | "software" | "hardware" }`. The line is not inherited. Of the inheritable values, a Telnet host only stores `user`, `port`, `reconnect`, `timeout`, `term`, `charset`, `scheme`, a serial one only `reconnect`, `charset`, `scheme`; a Telnet host's `user` and `port` only apply if it carries them itself (a group's defaults mean SSH; without its own port, 23 applies). Only an SSH host carries a password. Only an SSH host can be a jump host or carry a port rule; a host that is one cannot be switched to another protocol.
- `workspace` holds a name, `multi` (switch on multi-exec when opening) and `layout`: a tree whose nodes `{ "dir": "row" | "col", "ratio": 0…1, "a": …, "b": … }` cut an area in two and whose leaves `{ "pane": { "kind": "host", "id": "…" } }` name a saved host or, with `{ "pane": { "kind": "local", "shell": "wsl:Ubuntu" } }`, a local terminal (the ID of a shell on the machine, at most 80 characters; which shells exist is not stored in the vault). At most 32 panes. When a host is deleted, every workspace loses its panes in the same write; a workspace without panes is deleted. Typed-in addresses (quick connections) are never stored in the vault.
- `forward` is a port rule: `name`, `kind` (`local`, `remote`, `dynamic`), `host` (ID of the host it runs through), `bindAddress` and `bindPort` (where to listen: on this machine, for `remote` on the server), `destHost` and `destPort` (destination as seen from the other end; empty and 0 for `dynamic`). Whether a rule is running is not stored in the vault. When a host is deleted, its rules disappear in the same write.
- `snippet` is a saved command or a macro: `name`, `package` (name of the package as text, empty = none; packages are not records of their own), `kind` (`command` or `macro`), `command` (multi-line allowed, variables as `{{name}}` or `{{name:default}}`, at most 16 KiB), `steps` (for a macro: a list of `{ "wait": milliseconds, "keys": text }`, at most 2000 steps and 64 KiB of keys), `hotkey` (missing or e.g. `Ctrl+Alt+R`; a hotkey belongs to at most one snippet). A macro contains everything that was typed, possibly a password; like every record it is stored encrypted, and its keys never appear in any debug output.
- `proxmox` is a connection to a Proxmox server ([`management.md`](management.md)): `name`, `address` (`https://host[:port]`, nothing else), `tokenId` (`user@realm!name`), `secret` (the token's secret; it appears in no view and no debug output), `fingerprint` (missing, or the confirmed SHA-256 fingerprint of a self-signed certificate, 32 pairs separated by colons), `identity` (missing, or the ID of the identity Glowport uses to sign in to the machines of this connection; if the identity is deleted, the reference disappears in the same write). It always lives in the personal vault. A `host` can be linked to a machine: `proxmox: { connection, node, vmid, kind, name, address }`; `kind` is `qemu` or `lxc`, `name` and `address` record what Glowport last gave the host itself (it only follows along as long as the host still carries that value). Only hosts in the personal vault carry a link; it is dropped when moving into a shared vault and when duplicating, and in the same write when the connection is deleted. A link whose connection is missing does not count.
- The inheritable field `scheme` on hosts and groups names the ID of a terminal color scheme (lower-case letters, digits, hyphen). Only the interface knows which schemes exist. Imported schemes live in `settings.json` for now and not in the vault; with sync they are to move here as `color-scheme`, so a host looks the same on every device.
- `key` holds the name, kind (`ed25519`, `ecdsa`, `rsa`), length, fingerprint, the public key without comment, the **private key in OpenSSH format without a passphrase of its own** (the record's encryption protects it), origin (`generated`, `imported`) and the time `addedAt`.
- `identity` holds the name, user, optionally the ID of a key and optionally a password.
- Hosts and groups refer to these records in their inheritable values with `identity` and `key` (empty = explicitly none). When a key or identity is deleted, the core resolves the references in the same write.
- Inheritance is not stored but computed when reading: a host only stores what it sets itself (`own`); everything else comes from the group path.

## Storage

SQLite file `vault.db` in the data folder (`%APPDATA%\Glowport`, portable: in the `data` folder).

| Table | Content |
| --- | --- |
| `meta` | format version, salt, Argon2 parameters, wrapped `account_key`, public and wrapped private keys, device ID |
| `vaults` | vault ID, wrapped `vault_key` |
| `records` | record ID (16 random bytes), vault ID, revision, deletion mark, modification time, author, nonce, ciphertext, signature, sync state |

**Version 2** adds to the file what several vaults and syncing need; details in `sync.md`. The record format, the key chain and all test vectors have stayed the same.

| New | Content |
| --- | --- |
| `vaults.kind`, `epoch`, `cursor`, `roster` | kind (personal, shared), key generation, up to which server number has been fetched, signed member list |
| `records.synced` | the revision the server last confirmed or delivered (0 = the server does not know it) |
| `base` | the last synced state of every record whose change has not reached the server yet (base for merging) |
| `contacts`, `notices` | public keys of other accounts seen once; notices from syncing. Both encrypted with the account key, as is the member list in `vaults.roster` |
| `meta.next_…` | a pending wrapping of the account key after a password change on another device; it becomes the current one as soon as it unlocks |
| `meta.link` | the sign-in to the sync server, encrypted with the account key and bound to the `device_id` |

- **Conversion:** the program converts a version 1 file when opening it and first puts a copy next to it (`vault.db.format1`). Older versions of the program no longer open a converted file and say so. Tested with a file written by version 0.8.0 (`crates/core/tests/fixtures/format1.db`).
- A new file is created from the version 1 structure plus the same conversion step; new and converted files therefore look the same.
- Every change runs in a transaction. SQLite ensures that a crash in the middle leaves no half-written state.
- **Backup:** a consistent copy of the file (`.gpvault`). It is encrypted just like the original and needs the same master password. The sign-in to the sync server does not go along: whoever restores a backup signs in again.
- Settings without secret value (design, language, terminal appearance, custom color schemes) stay outside in `settings.json`.
- Also outside and **not encrypted**: recordings as text files in the `logs` folder, the terminal's background image (`background-….png` and similar) and `open-tabs.json` with the tabs currently open (host IDs and typed-in addresses, no secrets) for the question after a crash.

## Unlocking, locking, memory

0. **At startup** Glowport asks for the master password, unless the user switched that off (see “Starting without the master password”).
1. **Unlock:** read `meta` → Argon2id → HKDF → unwrap `account_key` → unwrap vault keys → decrypt records and keep them in memory in the core. `master_key` and `kek` are overwritten right afterwards.
2. **Lock** (button, auto-lock, exit): overwrite all keys and decrypted data in the core; the interface discards its copies. Running sessions stay connected; connecting again needs the open vault.
3. **Auto-lock:** adjustable (off, 5, 15, 60 minutes without input), default off. The clock runs in the core.
4. **Secrets and the interface:** passwords and private keys only leave the core when you explicitly ask to see one. Lists and editors only get “is set”.
5. **In memory:** keys and secrets live in containers that are overwritten when released (`zeroize`). None of it appears in logs or error messages.

## Starting without the master password (setting, default: off)

- **Switch:** Options → Vault → “Ask for the master password at startup”. On by default. Switching it off needs a confirmation that names the consequences; switching it on does not.
- **What is stored:** the `account_key` (`Vault::device_key`), protected with Windows DPAPI for the signed-in user account, in the file `start-unlock.bin` in the data folder. The vault's `device_id` serves as extra entropy, so the file only fits exactly this vault. It is **not** in `vault.db` and therefore neither in backups nor in syncing.
- **At startup:** if the file exists, the core opens the vault with it (`Vault::unlock_with_key`). If the key does not fit (another vault, another Windows account, an altered file), the file is deleted and the master password is requested.
- **Locked stays locked:** after “Lock vault” and after auto-lock only the master password helps. The stored key is only used at program start.
- **Changing the master password** leaves the stored key valid, because the `account_key` does not change.
- **What this means for protection:** with the prompt switched off, only the Windows sign-in protects the vault. Whoever sits at the signed-in PC, and every program running under that account, can open the vault. Against theft of the switched-off device only a good Windows password helps (better: drive encryption). Backup files and other devices still need the master password.
- **Implementation:** the stored key is not read while the window is being built but at the interface's first `vault_status`; this command and `vault_set_start_unlock` run with `#[tauri::command(async)]` off the window thread, so file and DPAPI calls do not hold up the window.
- **Other systems:** the connection for macOS (Keychain) and Linux (Secret Service) is still missing; there, switching it on reports an error.

## Libraries

`argon2`, `hkdf`, `sha2`, `chacha20poly1305`, `x25519-dalek`, `ed25519-dalek`, `rand` (operating system randomness), `zeroize`, `rusqlite` (SQLite built in). No self-written algorithms.

## Tests

- Fixed test vectors: the same inputs produce the same derivations (Argon2id, HKDF) in every version and decrypt stored sample ciphertexts.
- Round trip: create, save, lock, unlock, everything is back.
- A wrong password is rejected without changing anything.
- Every changed byte in ciphertext, nonce, bound data or signature is detected.
- Swapped records, moved records and rolled-back revisions are detected.
- Password change: the old password no longer opens, the new one opens everything.
- A crash in the middle of writing leaves a readable file.
- Measuring the unlock time on a desktop PC.

## Open points

- Whether the clipboard is cleared some time after copying a secret (suggestion: yes, after 30 seconds, can be switched off).
