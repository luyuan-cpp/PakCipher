use std::{
    collections::HashSet,
    fs,
    io::{self, Read, Write},
    path::Path,
};

use aes_gcm::aead::AeadInPlace;
use hmac::Mac;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{derive_keys, unwrap_seed},
    packet::{
        create_directory, create_file, entry_header, nonce, output_path, read_array, read_capsule,
        read_entry, read_manifest, Authenticated, CHUNK, DIRECTORY, FOOTER, TAG,
    },
    volume::ArchiveInput,
    Error, PrivateKey, Result,
};

pub fn unpack_packet(
    packet: &Path,
    key: &PrivateKey,
    passphrase: &str,
    output: &Path,
    progress: impl Fn(u64, u64),
) -> Result<()> {
    let output = output_path(output)?;
    let mut source = ArchiveInput::open(packet)?;
    let body_len = source
        .len()?
        .checked_sub(FOOTER)
        .ok_or(Error::Format("missing authentication footer"))?;
    let (_, wrapped) = read_capsule(&mut (&mut source).take(body_len))?;
    let seed = unwrap_seed(key, passphrase, &wrapped)?;
    let (cipher, mac) = derive_keys(&seed);
    drop(seed);

    source.rewind()?;
    let mut verify = Authenticated {
        io: (&mut source).take(body_len),
        mac: mac.clone(),
    };
    if io::copy(&mut verify, &mut io::sink())? != body_len {
        return Err(Error::Authentication);
    }
    let Authenticated {
        io: _,
        mac: verified,
    } = verify;
    let expected = read_array::<32>(&mut source)?;
    verify_footer(verified, &expected)?;

    source.rewind()?;
    create_directory(&output)?;
    let result = (|| {
        let mut reader = Authenticated {
            io: (&mut source).take(body_len),
            mac,
        };
        let (version, _) = read_capsule(&mut reader)?;
        let (count, total) = read_manifest(&mut reader, &cipher, version)?;
        let mut directories = HashSet::new();
        let mut buffer = Zeroizing::new(vec![0; CHUNK]);
        let mut done = 0;
        progress(done, total);
        for index in 0..count {
            let (name, size) = read_entry(&mut reader, &cipher, version, index)?;
            if let Some((parent, _)) = name.rsplit_once('/') {
                if !directories.contains(parent) {
                    return Err(Error::Format("parent directory is missing"));
                }
            }
            let destination = output.join(&name);
            if size == DIRECTORY {
                create_directory(&destination)?;
                directories.insert(name);
                continue;
            }
            if size > total - done {
                return Err(Error::Format("entry exceeds declared total"));
            }
            let mut file = create_file(&destination)?;
            let header = entry_header(&name, size);
            let mut remaining = size;
            for part in 0..size.div_ceil(CHUNK as u64).max(1) {
                let len = remaining.min(CHUNK as u64) as usize;
                let data = &mut buffer[..len];
                reader.read_exact(data)?;
                let tag = read_array::<TAG>(&mut reader)?;
                cipher
                    .decrypt_in_place_detached(
                        &nonce(index, part).into(),
                        &header,
                        data,
                        &tag.into(),
                    )
                    .map_err(|_| Error::Authentication)?;
                file.write_all(data)?;
                data.zeroize();
                remaining -= len as u64;
                done += len as u64;
                progress(done, total);
            }
        }
        if reader.io.limit() != 0 || done != total {
            return Err(Error::Format("entry count or total does not match"));
        }
        verify_footer(reader.mac, &expected)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&output);
    }
    result
}

fn verify_footer(mac: crate::crypto::ArchiveMac, expected: &[u8; 32]) -> Result<()> {
    mac.verify_slice(expected)
        .map_err(|_| Error::Authentication)
}
