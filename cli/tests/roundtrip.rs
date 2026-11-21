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
    cli_command(action, input, key, output).output().unwrap()
}

fn cli_command(action: &str, input: &Path, key: &Path, output: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pakcipher"));
    command
        .arg(action)
        .arg(input)
        .arg("--key-file")
        .arg(key)
        .arg("--output")
        .arg(output);
    command
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

#[test]
fn split_archives_require_every_intact_volume() {
    const MIB: u64 = 1024 * 1024;
    let work = tempfile::tempdir().unwrap();
    let path = |name: &str| work.path().join(name);
    let source = path("source");
    fs::create_dir_all(source.join("nested/empty")).unwrap();
    let data: Vec<u8> = (0..9 * MIB as usize).map(|i| (i % 251) as u8).collect();
    fs::write(source.join("nested/data.bin"), &data).unwrap();
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

    let volumes = path("volumes");
    let encrypt = |range| {
        cli_command("encrypt", &source, &public, &volumes)
            .args(["--volume-size", range])
            .output()
            .unwrap()
    };
    assert!(!encrypt("3:1").status.success());
    assert!(!volumes.exists());
    for (name, flags, min, max) in [
        ("only-min", vec!["--min-volume-size", "2"], 2 * MIB, 4 * MIB),
        ("only-max", vec!["--max-volume-size", "2"], MIB, 2 * MIB),
        (
            "both",
            vec!["--min-volume-size", "3", "--max-volume-size", "4"],
            3 * MIB,
            4 * MIB,
        ),
    ] {
        let output = path(name);
        assert_success(
            cli_command("encrypt", &source, &public, &output)
                .args(flags)
                .output()
                .unwrap(),
        );
        let mut parts: Vec<_> = fs::read_dir(output)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        parts.sort();
        assert!(parts.len() > 1);
        for (index, part) in parts.iter().enumerate() {
            let len = fs::metadata(part).unwrap().len();
            assert!(len <= max);
            assert!(index == parts.len() - 1 || len >= min);
        }
    }
    let invalid = cli_command("encrypt", &source, &public, &volumes)
        .args(["--min-volume-size", "4", "--max-volume-size", "3"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(!volumes.exists());
    assert_success(encrypt("1:3"));
    let mut parts: Vec<_> = fs::read_dir(&volumes)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    parts.sort();
    assert!(parts.len() >= 4);
    for (i, part) in parts.iter().enumerate() {
        assert_eq!(part, &volumes.join(format!("part-{:06}.pak", i + 1)));
        let size = fs::metadata(part).unwrap().len();
        assert!(size <= 3 * MIB);
        assert!(i == parts.len() - 1 || size >= MIB);
    }
    assert!(!encrypt("1:3").status.success());

    for (input, output) in [
        (&volumes, path("from-dir")),
        (&parts[0], path("from-first")),
    ] {
        assert_success(cli("decrypt", input, &private, &output));
        assert!(output.join("nested/empty").is_dir());
        assert!(fs::read(output.join("nested/data.bin")).unwrap() == data);
    }

    let rejected = path("rejected");
    let reject = |expected: &str| {
        let result = cli("decrypt", &volumes, &private, &rejected);
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!rejected.exists());
    };
    let displaced = path("missing.pak");
    for (part, reason) in [
        (&parts[1], "missing part-000002.pak"),
        (parts.last().unwrap(), "missing, truncated"),
    ] {
        fs::rename(part, &displaced).unwrap();
        reject(reason);
        fs::rename(&displaced, part).unwrap();
    }
    for (offset, reason) in [(16, "does not belong"), (32, "authentication failed")] {
        let mut part = File::options()
            .read(true)
            .write(true)
            .open(&parts[1])
            .unwrap();
        part.seek(SeekFrom::Start(offset)).unwrap();
        let mut byte = [0];
        part.read_exact(&mut byte).unwrap();
        part.seek(SeekFrom::Start(offset)).unwrap();
        part.write_all(&[byte[0] ^ 1]).unwrap();
        drop(part);
        reject(reason);
        let mut part = File::options().write(true).open(&parts[1]).unwrap();
        part.seek(SeekFrom::Start(offset)).unwrap();
        part.write_all(&byte).unwrap();
    }
}
