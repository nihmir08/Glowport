//! Storage of the key with which Glowport opens the vault at startup without the master password.
//!
//! On Windows DPAPI protects the key: only the same Windows user account on the same PC can read it.
//! That is convenient, but does not protect against programs or people working under this account. That is why
//! the storage is switched off until the user explicitly switches it on in the settings.

use std::{fs, io, path::PathBuf};

use glowport_core::crypto::{Key, KEY_LEN};
use zeroize::Zeroizing;

pub trait KeyStore: Send {
    /// Reads the stored key. `context` binds it to exactly one vault.
    fn load(&self, context: &[u8]) -> Option<Key>;
    fn store(&self, context: &[u8], key: &Key) -> io::Result<()>;
    fn clear(&self) -> io::Result<()>;
    fn is_set(&self) -> bool;
}

/// File in the data folder whose content the operating system binds to the user account.
pub struct ProtectedFile {
    path: PathBuf,
}

impl ProtectedFile {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl KeyStore for ProtectedFile {
    fn load(&self, context: &[u8]) -> Option<Key> {
        let protected = fs::read(&self.path).ok()?;
        let plain = os::unprotect(&protected, context).ok()?;
        let key: [u8; KEY_LEN] = plain.as_slice().try_into().ok()?;
        Some(Zeroizing::new(key))
    }

    fn store(&self, context: &[u8], key: &Key) -> io::Result<()> {
        let protected = os::protect(key.as_ref(), context)?;
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        // Write next to it first, then rename: never a half-written file.
        let temp = self.path.with_extension("new");
        fs::write(&temp, protected)?;
        fs::rename(&temp, &self.path)
    }

    fn clear(&self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    fn is_set(&self) -> bool {
        self.path.is_file()
    }
}

#[cfg(windows)]
mod os {
    use std::{io, ptr};

    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB},
    };
    use zeroize::{Zeroize, Zeroizing};

    fn input(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB { cbData: bytes.len() as u32, pbData: bytes.as_ptr().cast_mut() }
    }

    /// Takes Windows' result into memory of its own and frees Windows' memory, overwritten first.
    fn take(output: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
        // SAFETY: Windows allocated `cbData` bytes at `pbData`; the region is ours until `LocalFree`.
        unsafe {
            let bytes = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
            let copy = Zeroizing::new(bytes.to_vec());
            bytes.zeroize();
            LocalFree(output.pbData.cast());
            copy
        }
    }

    pub fn protect(secret: &[u8], context: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };
        // SAFETY: all pointers point to valid buffers that outlive the call; Windows fills `output`.
        let ok = unsafe { CryptProtectData(&input(secret), ptr::null(), &input(context), ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(take(output).to_vec())
    }

    pub fn unprotect(protected: &[u8], context: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };
        // SAFETY: as above.
        let ok = unsafe { CryptUnprotectData(&input(protected), ptr::null_mut(), &input(context), ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(take(output))
    }
}

/// The connection to macOS (Keychain) and Linux (Secret Service) is still missing.
#[cfg(not(windows))]
mod os {
    use std::io;
    use zeroize::Zeroizing;

    pub fn protect(_secret: &[u8], _context: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub fn unprotect(_protected: &[u8], _context: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Storage in memory only, for testing the flows without the operating system.
#[cfg(test)]
#[derive(Default)]
pub struct MemoryStore(std::sync::Mutex<Option<(Vec<u8>, Key)>>);

#[cfg(test)]
impl KeyStore for MemoryStore {
    fn load(&self, context: &[u8]) -> Option<Key> {
        self.0.lock().unwrap().as_ref().filter(|(ctx, _)| ctx == context).map(|(_, key)| key.clone())
    }
    fn store(&self, context: &[u8], key: &Key) -> io::Result<()> {
        *self.0.lock().unwrap() = Some((context.to_vec(), key.clone()));
        Ok(())
    }
    fn clear(&self) -> io::Result<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
    fn is_set(&self) -> bool {
        self.0.lock().unwrap().is_some()
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use glowport_core::crypto::random_key;

    #[test]
    fn protected_file_round_trips_and_is_bound_to_its_vault() {
        let path = std::env::temp_dir().join(format!("glowport-keystore-{}.bin", std::process::id()));
        let store = ProtectedFile::new(path.clone());
        let key = random_key();
        assert!(!store.is_set());
        assert!(store.load(b"tresor-a").is_none());

        store.store(b"tresor-a", &key).unwrap();
        assert!(store.is_set());
        assert_eq!(store.load(b"tresor-a").unwrap().as_ref(), key.as_ref());
        assert!(store.load(b"vault-b").is_none(), "another vault does not get the key");

        // The file does not contain the key in plain text, and a changed byte makes it unusable.
        let mut bytes = fs::read(&path).unwrap();
        assert!(!bytes.windows(KEY_LEN).any(|w| w == key.as_ref()));
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(store.load(b"tresor-a").is_none());

        store.clear().unwrap();
        store.clear().unwrap();
        assert!(!store.is_set());
    }
}
