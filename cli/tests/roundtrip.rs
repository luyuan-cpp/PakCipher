use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    process::{Command, Output},
};

use pakcipher_core::{load_private_key, unpack_packet, Error};
use pgp::composed::{
    EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
};

fn rsa_key(passphrase: Option<&str>) -> SignedSecretKey {
    let subkey = SubkeyParamsBuilder::default()
        .key_type(KeyType::Rsa(2048))
        .can_encrypt(EncryptionCaps::All)
        .passphrase(passphrase.map(str::to_owned))
        .build()
        .unwrap();
    SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("PakCipher test <test@example.invalid>".into())
        .subkeys(vec![subkey])
        .build()
        .unwrap()
        .generate(rand::thread_rng())
        .unwrap()
}

fn cli(action: &str, input: &Path, key: &Path, output: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pakcipher"))
        .arg(action)
        .arg(input)
        .arg("--key-file")
        .arg(key)
        .arg("--output")
        .arg(output)
        .output()
        .unwrap()
}

fn assert_success(output: Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_roundtrip_and_archive_rejection() {
    let work = tempfile::tempdir().unwrap();
    let path = |name: &str| work.path().join(name);
    let source = path("source");
    fs::create_dir_all(source.join("nested/空目录")).unwrap();
    fs::write(source.join("empty.txt"), []).unwrap();
    fs::write(source.join("nested/notes.txt"), b"PakCipher").unwrap();
    let chunk: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    {
        let mut file = File::create(source.join("nested/large.bin")).unwrap();
        for _ in 0..50 {
            file.write_all(&chunk).unwrap();
        }
        file.write_all(b"tail").unwrap();
    }
    let key = rsa_key(None);
    let public = path("public.key");
    let private = path("private.key");
    fs::write(
        &public,
        key.to_public_key()
            .to_armored_bytes(Default::default())
            .unwrap(),
    )
    .unwrap();
    fs::write(&private, key.to_armored_bytes(Default::default()).unwrap()).unwrap();

    let archive = path("archive.pak");
    assert_success(cli("encrypt", &source, &public, &archive));
    let restored = path("restored");
    assert_success(cli("decrypt", &archive, &private, &restored));
    assert!(restored.join("nested/空目录").is_dir());
    assert_eq!(
        fs::read(restored.join("nested/notes.txt")).unwrap(),
        b"PakCipher"
    );
    assert_eq!(fs::metadata(restored.join("empty.txt")).unwrap().len(), 0);
    let mut file = File::open(restored.join("nested/large.bin")).unwrap();
    let mut buffer = vec![0; chunk.len()];
    for _ in 0..50 {
        file.read_exact(&mut buffer).unwrap();
        assert_eq!(buffer, chunk);
    }
    let mut rest = Vec::new();
    file.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"tail");

    let wrong = path("wrong.key");
    fs::write(
        &wrong,
        rsa_key(None).to_armored_bytes(Default::default()).unwrap(),
    )
    .unwrap();
    let rejected = path("rejected");
    assert!(!cli("decrypt", &archive, &wrong, &rejected).status.success());
    assert!(!rejected.exists());
    assert!(!cli("decrypt", &archive, &private, &restored)
        .status
        .success());
    assert!(!cli("encrypt", &source, &public, &archive).status.success());
    assert_eq!(
        fs::read(restored.join("nested/notes.txt")).unwrap(),
        b"PakCipher"
    );

    let mut damaged = File::options()
        .read(true)
        .write(true)
        .open(&archive)
        .unwrap();
    damaged.seek(SeekFrom::Start(1024 * 1024)).unwrap();
    let mut byte = [0];
    damaged.read_exact(&mut byte).unwrap();
    damaged.seek(SeekFrom::Current(-1)).unwrap();
    damaged.write_all(&[byte[0] ^ 1]).unwrap();
    drop(damaged);
    assert!(!cli("decrypt", &archive, &private, &rejected)
        .status
        .success());
    assert!(!rejected.exists());
}

#[test]
fn protected_key_and_empty_directory() {
    let work = tempfile::tempdir().unwrap();
    let path = |name: &str| work.path().join(name);
    let source = path("empty");
    fs::create_dir(&source).unwrap();
    let passphrase = "test-only passphrase";
    let key = rsa_key(Some(passphrase));
    let public = path("public.key");
    let private = path("private.key");
    fs::write(
        &public,
        key.to_public_key()
            .to_armored_bytes(Default::default())
            .unwrap(),
    )
    .unwrap();
    fs::write(&private, key.to_armored_bytes(Default::default()).unwrap()).unwrap();
    let archive = path("archive.pak");
    assert_success(cli("encrypt", &source, &public, &archive));
    let key = load_private_key(&private).unwrap();
    let restored = path("restored");
    assert!(matches!(
        unpack_packet(&archive, &key, "wrong", &restored, |_, _| {}),
        Err(Error::Unlock)
    ));
    assert!(!restored.exists());
    unpack_packet(&archive, &key, passphrase, &restored, |_, _| {}).unwrap();
    assert_eq!(fs::read_dir(restored).unwrap().count(), 0);
}
