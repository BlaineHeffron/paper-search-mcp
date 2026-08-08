use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, Generate, Key, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use super::secret::SecretString;

const STORE_VERSION: u8 = 1;
const STORE_FILE: &str = "session.enc.json";
const KEYRING_SERVICE: &str = "paper-search institutional session";
const MAX_STORE_BYTES: u64 = 2 * 1024 * 1024;

pub struct StoredCookie {
    pub(crate) domain: String,
    pub(crate) include_subdomains: bool,
    pub(crate) path: String,
    pub(crate) secure: bool,
    pub(crate) http_only: bool,
    pub(crate) expires_at: i64,
    pub(crate) name: String,
    pub(crate) value: SecretString,
}

impl fmt::Debug for StoredCookie {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredCookie")
            .field("domain", &self.domain)
            .field("include_subdomains", &self.include_subdomains)
            .field("path", &self.path)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("expires_at", &self.expires_at)
            .field("name", &"<redacted>")
            .field("value", &"<redacted>")
            .finish()
    }
}

pub struct CookieJar {
    pub(crate) institution_id: String,
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) cookies: Vec<StoredCookie>,
}

impl fmt::Debug for CookieJar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CookieJar")
            .field("institution_id", &self.institution_id)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("cookie_count", &self.cookies.len())
            .finish()
    }
}

impl CookieJar {
    pub fn domains(&self) -> Vec<String> {
        self.cookies
            .iter()
            .map(|cookie| cookie.domain.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn cookie_count(&self) -> usize {
        self.cookies.len()
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub(crate) fn cookie_header(&self, host: &str, path: &str, now: i64) -> Option<SecretString> {
        let mut header = Zeroizing::new(String::new());
        for cookie in &self.cookies {
            if cookie.expires_at <= now
                || !domain_matches(host, &cookie.domain, cookie.include_subdomains)
                || !path_matches(path, &cookie.path)
            {
                continue;
            }
            if !header.is_empty() {
                header.push_str("; ");
            }
            header.push_str(&cookie.name);
            header.push('=');
            header.push_str(cookie.value.expose());
        }
        if header.is_empty() {
            None
        } else {
            Some(SecretString::new(std::mem::take(&mut *header)))
        }
    }
}

fn domain_matches(host: &str, cookie_domain: &str, include_subdomains: bool) -> bool {
    host == cookie_domain || (include_subdomains && host.ends_with(&format!(".{cookie_domain}")))
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    request_path == cookie_path
        || (request_path.starts_with(cookie_path)
            && (cookie_path.ends_with('/')
                || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProtectionStatus {
    OsKeyring,
    OsKeyringLocked,
    OsKeyringUnavailable,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("institutional secret storage is unavailable")]
    KeyringUnavailable,
    #[error("institutional secret storage is locked")]
    KeyringLocked,
    #[error("institutional session key is missing")]
    KeyMissing,
    #[error("institutional session store has insecure permissions")]
    InsecurePermissions,
    #[error("institutional session store is corrupt or cannot be decrypted")]
    CorruptStore,
    #[error("institutional session has expired")]
    Expired,
    #[error("institutional session does not exist")]
    NotFound,
    #[error("institutional storage path is not allowed")]
    UnsafePath,
    #[error("institutional storage operation failed")]
    Io,
}

pub trait KeyProvider: Send + Sync {
    fn get(&self) -> Result<Zeroizing<Vec<u8>>, StoreError>;
    fn get_or_create(&self) -> Result<Zeroizing<Vec<u8>>, StoreError>;
    fn delete(&self) -> Result<(), StoreError>;
    fn status(&self) -> KeyProtectionStatus;
}

pub struct OsKeyringProvider {
    account: String,
}

impl OsKeyringProvider {
    pub fn new(institution_id: &str, data_dir: &Path) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"paper-search-keyring-account-v1\0");
        hasher.update(institution_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(data_dir.as_os_str().as_encoded_bytes());
        Self {
            account: format!("institutional-{:x}", hasher.finalize()),
        }
    }

    fn entry(&self) -> Result<keyring::Entry, StoreError> {
        keyring::Entry::new(KEYRING_SERVICE, &self.account).map_err(classify_keyring_error)
    }
}

impl KeyProvider for OsKeyringProvider {
    fn get(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let secret = self.entry()?.get_secret().map_err(classify_keyring_error)?;
        if secret.len() != 32 {
            return Err(StoreError::CorruptStore);
        }
        Ok(Zeroizing::new(secret))
    }

    fn get_or_create(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        match self.get() {
            Ok(key) => Ok(key),
            Err(StoreError::KeyMissing) => {
                let key = Key::<XChaCha20Poly1305>::generate();
                self.entry()?
                    .set_secret(key.as_slice())
                    .map_err(classify_keyring_error)?;
                Ok(Zeroizing::new(key.to_vec()))
            }
            Err(error) => Err(error),
        }
    }

    fn delete(&self) -> Result<(), StoreError> {
        match self.entry()?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(classify_keyring_error(error)),
        }
    }

    fn status(&self) -> KeyProtectionStatus {
        match self.get() {
            Ok(_) | Err(StoreError::KeyMissing) => KeyProtectionStatus::OsKeyring,
            Err(StoreError::KeyringLocked) => KeyProtectionStatus::OsKeyringLocked,
            Err(_) => KeyProtectionStatus::OsKeyringUnavailable,
        }
    }
}

fn classify_keyring_error(error: keyring::Error) -> StoreError {
    match error {
        keyring::Error::NoEntry => StoreError::KeyMissing,
        keyring::Error::NoStorageAccess(_) => StoreError::KeyringLocked,
        keyring::Error::NoDefaultStore => StoreError::KeyringUnavailable,
        _ => StoreError::KeyringUnavailable,
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u8,
    institution_id: String,
    created_at: i64,
    expires_at: i64,
    domains: Vec<String>,
    nonce: String,
    ciphertext: String,
}

impl fmt::Debug for Envelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Envelope")
            .field("version", &self.version)
            .field("institution_id", &self.institution_id)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("domains", &self.domains)
            .field("nonce", &"<redacted>")
            .field("ciphertext", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct SessionStore {
    root: PathBuf,
    institution_id: String,
    keys: Arc<dyn KeyProvider>,
}

impl SessionStore {
    pub fn new(
        data_dir: &Path,
        institution_id: String,
        keys: Arc<dyn KeyProvider>,
    ) -> Result<Self, StoreError> {
        ensure_outside_repository(data_dir)?;
        create_private_dir(data_dir)?;
        let root = data_dir
            .join("institutional")
            .join(safe_id(&institution_id));
        create_private_dir(&data_dir.join("institutional"))?;
        create_private_dir(&root)?;
        Ok(Self {
            root,
            institution_id,
            keys,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn protection_status(&self) -> KeyProtectionStatus {
        self.keys.status()
    }

    pub fn save(&self, jar: &CookieJar) -> Result<(), StoreError> {
        self.validate_root_permissions()?;
        if jar.institution_id != self.institution_id || jar.cookies.is_empty() {
            return Err(StoreError::CorruptStore);
        }
        let key = self.keys.get_or_create()?;
        let key_bytes: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::CorruptStore)?;
        let mut key = Key::<XChaCha20Poly1305>::from(key_bytes);
        let cipher = XChaCha20Poly1305::new(&key);
        key.as_mut_slice().zeroize();
        let nonce = XNonce::generate();
        let mut plaintext = encode_jar(jar)?;
        let domains = jar.domains();
        let aad = envelope_aad(
            STORE_VERSION,
            &self.institution_id,
            jar.created_at,
            jar.expires_at,
            &domains,
        );
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| StoreError::CorruptStore)?;
        plaintext.zeroize();
        let envelope = Envelope {
            version: STORE_VERSION,
            institution_id: self.institution_id.clone(),
            created_at: jar.created_at,
            expires_at: jar.expires_at,
            domains,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        };
        let serialized = serde_json::to_vec(&envelope).map_err(|_| StoreError::Io)?;
        atomic_replace_private(&self.root, &self.root.join(STORE_FILE), &serialized)
    }

    pub fn load(&self) -> Result<CookieJar, StoreError> {
        self.validate_root_permissions()?;
        let store_path = self.root.join(STORE_FILE);
        let bytes = read_private_bounded(&store_path, MAX_STORE_BYTES)?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::CorruptStore)?;
        if envelope.version != STORE_VERSION || envelope.institution_id != self.institution_id {
            return Err(StoreError::CorruptStore);
        }
        let key = self.keys.get()?;
        let nonce = URL_SAFE_NO_PAD
            .decode(&envelope.nonce)
            .map_err(|_| StoreError::CorruptStore)?;
        if nonce.len() != 24 {
            return Err(StoreError::CorruptStore);
        }
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&envelope.ciphertext)
            .map_err(|_| StoreError::CorruptStore)?;
        let aad = envelope_aad(
            envelope.version,
            &envelope.institution_id,
            envelope.created_at,
            envelope.expires_at,
            &envelope.domains,
        );
        let key_bytes: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::CorruptStore)?;
        let mut key = Key::<XChaCha20Poly1305>::from(key_bytes);
        let cipher = XChaCha20Poly1305::new(&key);
        key.as_mut_slice().zeroize();
        let nonce_bytes: [u8; 24] = nonce
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::CorruptStore)?;
        let nonce = XNonce::from(nonce_bytes);
        let mut plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| StoreError::CorruptStore)?,
        );
        let mut jar = decode_jar(&plaintext)?;
        plaintext.zeroize();
        if jar.institution_id != envelope.institution_id
            || jar.created_at != envelope.created_at
            || jar.expires_at != envelope.expires_at
            || jar.domains() != envelope.domains
        {
            return Err(StoreError::CorruptStore);
        }
        let now = Utc::now().timestamp();
        if jar.expires_at <= now {
            return Err(StoreError::Expired);
        }
        jar.cookies.retain(|cookie| cookie.expires_at > now);
        if jar.cookies.is_empty() {
            return Err(StoreError::Expired);
        }
        Ok(jar)
    }

    pub fn clear(&self) -> Result<(), StoreError> {
        let store = self.root.join(STORE_FILE);
        match fs::remove_file(store) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Io),
        }
        self.keys.delete()
    }

    pub(crate) fn purge_and_recreate(&self) -> Result<bool, StoreError> {
        let key_deleted = self.keys.delete().is_ok();
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
                fs::remove_dir_all(&self.root).map_err(|_| StoreError::Io)?;
            }
            Ok(_) => fs::remove_file(&self.root).map_err(|_| StoreError::Io)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Io),
        }
        create_private_dir(&self.root)?;
        Ok(key_deleted)
    }

    pub fn has_store(&self) -> bool {
        self.root.join(STORE_FILE).exists()
    }

    pub fn validate_root_permissions(&self) -> Result<(), StoreError> {
        validate_private_dir(&self.root)
    }
}

fn envelope_aad(
    version: u8,
    institution_id: &str,
    created_at: i64,
    expires_at: i64,
    domains: &[String],
) -> Vec<u8> {
    format!(
        "paper-search\0institutional-cookie-jar\0{version}\0{institution_id}\0{created_at}\0{expires_at}\0{}",
        domains.join("\0")
    )
    .into_bytes()
}

fn encode_jar(jar: &CookieJar) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let mut output = Zeroizing::new(Vec::new());
    output.push(STORE_VERSION);
    put_string(&mut output, &jar.institution_id)?;
    output.extend_from_slice(&jar.created_at.to_be_bytes());
    output.extend_from_slice(&jar.expires_at.to_be_bytes());
    put_u32(&mut output, jar.cookies.len())?;
    for cookie in &jar.cookies {
        put_string(&mut output, &cookie.domain)?;
        output.push(u8::from(cookie.include_subdomains));
        put_string(&mut output, &cookie.path)?;
        output.push(u8::from(cookie.secure));
        output.push(u8::from(cookie.http_only));
        output.extend_from_slice(&cookie.expires_at.to_be_bytes());
        put_string(&mut output, &cookie.name)?;
        put_string(&mut output, cookie.value.expose())?;
    }
    Ok(output)
}

fn decode_jar(input: &[u8]) -> Result<CookieJar, StoreError> {
    let mut cursor = Cursor::new(input);
    if cursor.byte()? != STORE_VERSION {
        return Err(StoreError::CorruptStore);
    }
    let institution_id = cursor.string()?;
    let created_at = cursor.i64()?;
    let expires_at = cursor.i64()?;
    let count = cursor.u32()? as usize;
    if count == 0 || count > 4096 {
        return Err(StoreError::CorruptStore);
    }
    let mut cookies = Vec::with_capacity(count);
    for _ in 0..count {
        cookies.push(StoredCookie {
            domain: cursor.string()?,
            include_subdomains: cursor.boolean()?,
            path: cursor.string()?,
            secure: cursor.boolean()?,
            http_only: cursor.boolean()?,
            expires_at: cursor.i64()?,
            name: cursor.string()?,
            value: SecretString::new(cursor.string()?),
        });
    }
    if !cursor.done() {
        return Err(StoreError::CorruptStore);
    }
    Ok(CookieJar {
        institution_id,
        created_at,
        expires_at,
        cookies,
    })
}

fn put_u32(output: &mut Vec<u8>, value: usize) -> Result<(), StoreError> {
    let value = u32::try_from(value).map_err(|_| StoreError::CorruptStore)?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn put_string(output: &mut Vec<u8>, value: &str) -> Result<(), StoreError> {
    put_u32(output, value.len())?;
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(StoreError::CorruptStore)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(StoreError::CorruptStore)?;
        self.position = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, StoreError> {
        Ok(self.take(1)?[0])
    }

    fn boolean(&mut self) -> Result<bool, StoreError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(StoreError::CorruptStore),
        }
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| StoreError::CorruptStore)?,
        ))
    }

    fn i64(&mut self) -> Result<i64, StoreError> {
        Ok(i64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| StoreError::CorruptStore)?,
        ))
    }

    fn string(&mut self) -> Result<String, StoreError> {
        let length = self.u32()? as usize;
        if length > MAX_STORE_BYTES as usize {
            return Err(StoreError::CorruptStore);
        }
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| StoreError::CorruptStore)
    }

    fn done(&self) -> bool {
        self.position == self.input.len()
    }
}

pub(crate) fn create_private_dir(path: &Path) -> Result<(), StoreError> {
    if !path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(|_| StoreError::Io)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(path).map_err(|_| StoreError::Io)?;
    }
    validate_private_dir(path)
}

pub(crate) fn validate_private_dir(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::Io)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(StoreError::InsecurePermissions);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o777 != 0o700
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(StoreError::InsecurePermissions);
        }
    }
    Ok(())
}

pub(crate) fn validate_private_regular_file(path: &Path) -> Result<(), StoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(StoreError::NotFound)
        }
        Err(_) => return Err(StoreError::Io),
    };
    validate_private_file_metadata(&metadata)
}

fn validate_private_file_metadata(metadata: &fs::Metadata) -> Result<(), StoreError> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(StoreError::InsecurePermissions);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o777 != 0o600
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
        {
            return Err(StoreError::InsecurePermissions);
        }
    }
    Ok(())
}

pub(crate) fn read_private_bounded(path: &Path, max: u64) -> Result<Vec<u8>, StoreError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(StoreError::NotFound)
        }
        Err(_) => return Err(StoreError::InsecurePermissions),
    };
    let metadata = file.metadata().map_err(|_| StoreError::Io)?;
    validate_private_file_metadata(&metadata)?;
    read_bounded_file(file, metadata.len(), max)
}

fn read_bounded_file(file: File, length: u64, max: u64) -> Result<Vec<u8>, StoreError> {
    if length > max {
        return Err(StoreError::CorruptStore);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StoreError::Io)?;
    if bytes.len() as u64 > max {
        return Err(StoreError::CorruptStore);
    }
    Ok(bytes)
}

pub(crate) fn atomic_replace_private(
    directory: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), StoreError> {
    validate_private_dir(directory)?;
    if destination.exists() {
        validate_private_regular_file(destination)?;
    }
    let mut temporary = NamedTempFile::new_in(directory).map_err(|_| StoreError::Io)?;
    temporary.write_all(bytes).map_err(|_| StoreError::Io)?;
    temporary.as_file().sync_all().map_err(|_| StoreError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if temporary
            .as_file()
            .metadata()
            .map_err(|_| StoreError::Io)?
            .permissions()
            .mode()
            & 0o777
            != 0o600
        {
            return Err(StoreError::InsecurePermissions);
        }
    }
    temporary.persist(destination).map_err(|_| StoreError::Io)?;
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| StoreError::Io)
}

fn safe_id(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn ensure_outside_repository(data_dir: &Path) -> Result<(), StoreError> {
    let resolved = resolve_candidate(data_dir)?;
    if resolved
        .ancestors()
        .any(|ancestor| ancestor.join(".git").exists())
    {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}

fn resolve_candidate(path: &Path) -> Result<PathBuf, StoreError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| StoreError::UnsafePath)?
            .join(path)
    };
    let mut ancestor = absolute.as_path();
    let mut tail = Vec::new();
    while !ancestor.exists() {
        let name = ancestor.file_name().ok_or(StoreError::UnsafePath)?;
        tail.push(name.to_os_string());
        ancestor = ancestor.parent().ok_or(StoreError::UnsafePath)?;
    }
    let mut resolved = ancestor
        .canonicalize()
        .map_err(|_| StoreError::UnsafePath)?;
    for component in tail.into_iter().rev() {
        if component == "." || component == ".." {
            return Err(StoreError::UnsafePath);
        }
        resolved.push(component);
    }
    Ok(resolved)
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    use super::*;

    pub struct MemoryKeyProvider {
        key: Mutex<Option<Vec<u8>>>,
        status: KeyProtectionStatus,
    }

    impl MemoryKeyProvider {
        pub fn available() -> Self {
            Self {
                key: Mutex::new(None),
                status: KeyProtectionStatus::OsKeyring,
            }
        }
    }

    impl KeyProvider for MemoryKeyProvider {
        fn get(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
            self.key
                .lock()
                .map_err(|_| StoreError::KeyringUnavailable)?
                .clone()
                .map(Zeroizing::new)
                .ok_or(StoreError::KeyMissing)
        }

        fn get_or_create(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
            let mut guard = self
                .key
                .lock()
                .map_err(|_| StoreError::KeyringUnavailable)?;
            if guard.is_none() {
                *guard = Some(vec![7; 32]);
            }
            Ok(Zeroizing::new(guard.clone().expect("key initialized")))
        }

        fn delete(&self) -> Result<(), StoreError> {
            *self
                .key
                .lock()
                .map_err(|_| StoreError::KeyringUnavailable)? = None;
            Ok(())
        }

        fn status(&self) -> KeyProtectionStatus {
            self.status
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::{test_support::MemoryKeyProvider, *};

    fn jar(id: &str) -> CookieJar {
        let now = Utc::now().timestamp();
        CookieJar {
            institution_id: id.to_string(),
            created_at: now,
            expires_at: now + 3600,
            cookies: vec![StoredCookie {
                domain: "proxy.example.edu".to_string(),
                include_subdomains: true,
                path: "/".to_string(),
                secure: true,
                http_only: true,
                expires_at: now + 3600,
                name: "session".to_string(),
                value: SecretString::new("super-secret-value".to_string()),
            }],
        }
    }

    fn private_temp() -> TempDir {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        temp
    }

    #[test]
    fn encrypted_round_trip_and_no_plaintext_at_rest() {
        let temp = private_temp();
        let store = SessionStore::new(
            temp.path(),
            "example".to_string(),
            Arc::new(MemoryKeyProvider::available()),
        )
        .unwrap();
        store.save(&jar("example")).unwrap();
        let raw = fs::read(store.root.join(STORE_FILE)).unwrap();
        assert!(!raw
            .windows("super-secret-value".len())
            .any(|part| part == b"super-secret-value"));
        let loaded = store.load().unwrap();
        assert_eq!(loaded.cookie_count(), 1);
        assert_eq!(loaded.domains(), vec!["proxy.example.edu"]);
        assert_eq!(format!("{loaded:?}").contains("super-secret-value"), false);
    }

    #[test]
    fn corrupt_ciphertext_is_rejected_without_secret_in_error() {
        let temp = private_temp();
        let store = SessionStore::new(
            temp.path(),
            "example".to_string(),
            Arc::new(MemoryKeyProvider::available()),
        )
        .unwrap();
        store.save(&jar("example")).unwrap();
        let path = store.root.join(STORE_FILE);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 2;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        let error = store.load().unwrap_err();
        assert!(matches!(error, StoreError::CorruptStore));
        assert!(!format!("{error:?}").contains("super-secret-value"));
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_store_permissions_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        let temp = private_temp();
        let store = SessionStore::new(
            temp.path(),
            "example".to_string(),
            Arc::new(MemoryKeyProvider::available()),
        )
        .unwrap();
        store.save(&jar("example")).unwrap();
        fs::set_permissions(
            store.root.join(STORE_FILE),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(store.load(), Err(StoreError::InsecurePermissions)));
    }

    #[test]
    fn expired_session_is_rejected() {
        let temp = private_temp();
        let store = SessionStore::new(
            temp.path(),
            "example".to_string(),
            Arc::new(MemoryKeyProvider::available()),
        )
        .unwrap();
        let mut expired = jar("example");
        expired.expires_at = Utc::now().timestamp() - 1;
        expired.cookies[0].expires_at = expired.expires_at;
        store.save(&expired).unwrap();
        assert!(matches!(store.load(), Err(StoreError::Expired)));
    }

    #[test]
    fn secret_store_inside_repository_is_rejected() {
        let inside = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/forbidden-session-store");
        let result = SessionStore::new(
            &inside,
            "example".to_string(),
            Arc::new(MemoryKeyProvider::available()),
        );
        assert!(matches!(result, Err(StoreError::UnsafePath)));
    }

    #[test]
    fn runtime_git_worktree_is_rejected_without_build_path_assumptions() {
        let temp = private_temp();
        fs::create_dir(temp.path().join(".git")).unwrap();
        let result = SessionStore::new(
            &temp.path().join("nested/data"),
            "example".to_string(),
            Arc::new(MemoryKeyProvider::available()),
        );
        assert!(matches!(result, Err(StoreError::UnsafePath)));
    }

    #[cfg(unix)]
    #[test]
    fn writable_or_readable_data_directory_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let temp = private_temp();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o775)).unwrap();
        let result = SessionStore::new(
            temp.path(),
            "example".to_string(),
            Arc::new(MemoryKeyProvider::available()),
        );
        assert!(matches!(result, Err(StoreError::InsecurePermissions)));
    }
}
