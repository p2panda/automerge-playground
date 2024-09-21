use std::fs::File;
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::Result;
use p2panda_core::identity::PrivateKey;

/// Returns a new instance of `PrivateKey` by either loading the private key from a path or generating
/// a new one and saving it in the file system.
pub fn generate_or_load_private_key(path: PathBuf) -> Result<PrivateKey> {
    let private_key = if path.is_file() {
        load_private_key_from_file(path)?
    } else {
        let private_key = PrivateKey::new();
        save_private_key_to_file(&private_key, path)?;
        private_key
    };

    Ok(private_key)
}

/// Saves human-readable (hex-encoded) private key string (ed25519) into a file at the given path.
///
/// This method automatically creates the required directories on that path and fixes the
/// permissions of the file (0600, read and write permissions only for the owner).
#[cfg(target_os = "linux")]
fn save_private_key_to_file(private_key: &PrivateKey, path: PathBuf) -> Result<()> {
    let mut file = File::create(&path)?;
    file.write_all(private_key.to_hex().as_bytes())?;
    file.sync_all()?;

    // Set permission for sensitive information
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn save_private_key_to_file(private_key: &PrivateKey, path: PathBuf) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(private_key.to_hex().as_bytes())?;
    file.sync_all()?;

    Ok(())
}

/// Loads a private key from a file at the given path and derives ed25519 private key from it.
///
/// The private key in the file needs to be represented as a hex-encoded string.
fn load_private_key_from_file(path: PathBuf) -> Result<PrivateKey> {
    let mut file = File::open(path)?;
    let mut private_key_hex = String::new();
    file.read_to_string(&mut private_key_hex)?;
    let private_key = PrivateKey::try_from(&hex::decode(&private_key_hex)?[..])?;
    Ok(private_key)
}
