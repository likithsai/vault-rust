use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use crate::crypto::{decrypt_payload, encrypt_payload};
use crate::model::VaultData;

pub fn save_vault_to_file<P: AsRef<Path>>(
    path: P,
    vault: &VaultData,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let serialized = serde_json::to_vec(vault)?;
    let ciphertext = encrypt_payload(&serialized, password)?;

    // Atomic write via temp file to prevent corruption
    let target = path.as_ref();
    let temp_path = target.with_extension("tmp");

    let mut f = File::create(&temp_path)?;
    f.write_all(&ciphertext)?;
    f.sync_all()?;
    drop(f);

    fs::rename(temp_path, target)?;
    Ok(())
}

pub fn load_vault_from_file<P: AsRef<Path>>(
    path: P,
    password: &str,
) -> Result<VaultData, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let plaintext = decrypt_payload(&buffer, password)?;
    let vault: VaultData = serde_json::from_slice(&plaintext)?;
    Ok(vault)
}