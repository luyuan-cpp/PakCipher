use std::fs;

use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::unpack_packet;
use crate::{crypto::wrap_seed, generate_key_pair, load_private_key, load_public_key, PublicKey};

const DIRECTORY: &str = "旧项目";
const FILE: &str = "旧项目/example.rs";
const EMPTY_FILE: &str = "旧项目/empty.txt";
const CONTENT: &[u8] = b"fn main() {}\n";
const PASSPHRASE: &str = "test-only v1 compatibility passphrase";

// Encode the legacy wire layout and key derivation independently of the current writer.
fn legacy_archive(public: &PublicKey) -> Vec<u8> {
    let (seed, capsule) = wrap_seed(public).unwrap();
    let hkdf = Hkdf::<Sha256>::new(Some(b"PakCipher v1"), seed.as_slice());
    let mut key = zeroize::Zeroizing::new([0; 32]);
    hkdf.expand(b"content AES-256-GCM", key.as_mut_slice())
        .unwrap();
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).unwrap();
    hkdf.expand(b"archive HMAC-SHA256", key.as_mut_slice())
        .unwrap();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_slice()).unwrap();

    let entries = [
        (DIRECTORY, None),
        (FILE, Some(CONTENT)),
        (EMPTY_FILE, Some(&[][..])),
    ];
    let mut bytes = b"PAKC\x01\x00\x00\x00\x00\x00\x00\x00".to_vec();
    bytes.extend_from_slice(&(capsule.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&capsule);
    bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(CONTENT.len() as u64).to_le_bytes());
    for (index, (name, content)) in entries.into_iter().enumerate() {
        let size = content.map_or(u64::MAX, |data| data.len() as u64);
        let start = bytes.len();
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        if let Some(content) = content {
            let mut nonce = [0; 12];
            nonce[..4].copy_from_slice(&(index as u32).to_le_bytes());
            let mut encrypted = content.to_vec();
            let tag = cipher
                .encrypt_in_place_detached(&nonce.into(), &bytes[start..], &mut encrypted)
                .unwrap();
            bytes.extend_from_slice(&encrypted);
            bytes.extend_from_slice(&tag);
        }
    }
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    bytes
}

#[test]
fn restores_v1_single_archive_and_split_volumes() {
    let work = tempfile::tempdir().unwrap();
    let root = work.path();
    let keys = root.join("keys");
    generate_key_pair(&keys, "PakCipher compatibility test", PASSPHRASE).unwrap();
    let public = load_public_key(&keys.join("public.key")).unwrap();
    let private = load_private_key(&keys.join("private.key")).unwrap();
    let bytes = legacy_archive(&public);
    let single = root.join("legacy.pak");
    fs::write(&single, &bytes).unwrap();

    let volumes = root.join("legacy-volumes");
    fs::create_dir(&volumes).unwrap();
    let set_id = [0x42; 16];
    // Deliberately cut inside fields to exercise reads across volume boundaries.
    let splits = [
        &bytes[..32],
        &bytes[32..bytes.len() - 40],
        &bytes[bytes.len() - 40..],
    ];
    for (i, part) in splits.into_iter().enumerate() {
        let index = (i + 1) as u32;
        let mut volume = b"PKV1".to_vec();
        volume.extend_from_slice(&index.to_le_bytes());
        volume.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        volume.extend_from_slice(&set_id);
        volume.extend_from_slice(part);
        fs::write(volumes.join(format!("part-{index:06}.pak")), volume).unwrap();
    }

    for (input, name) in [
        (single, "single-restored"),
        (volumes.join("part-000001.pak"), "first-volume-restored"),
        (volumes, "volume-folder-restored"),
    ] {
        let output = root.join(name);
        unpack_packet(&input, &private, PASSPHRASE, &output, |_, _| {}).unwrap();
        assert!(output.join(DIRECTORY).is_dir());
        assert_eq!(fs::read(output.join(FILE)).unwrap(), CONTENT);
        assert_eq!(fs::read(output.join(EMPTY_FILE)).unwrap(), b"");
    }
}
