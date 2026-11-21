use std::{
    fs::{self, File},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use aes_gcm::aead::AeadInPlace;
use hmac::Mac;
use walkdir::WalkDir;
use zeroize::Zeroizing;

use crate::{
    crypto::{derive_keys, wrap_seed},
    packet::{
        create_file, entry_header, is_link, nonce, output_path, relative_path, write_header,
        Authenticated, CHUNK, DIRECTORY,
    },
    Error, PublicKey, Result,
};

struct Entry {
    source: PathBuf,
    name: String,
    size: u64,
}

pub fn pack_folder(
    folder: &Path,
    key: &PublicKey,
    output: &Path,
    progress: impl Fn(u64, u64),
) -> Result<()> {
    let root = folder.canonicalize()?;
    if !root.is_dir() {
        return Err(Error::Path(folder.display().to_string()));
    }
    let output = output_path(output)?;
    if output.starts_with(&root) {
        return Err(Error::OutputInSource);
    }

    let mut entries = Vec::new();
    let mut total = 0_u64;
    for entry in WalkDir::new(&root)
        .min_depth(1)
        .sort_by_file_name()
        .follow_links(false)
    {
        let source = entry?.into_path();
        let metadata = fs::symlink_metadata(&source)?;
        let name = relative_path(
            source
                .strip_prefix(&root)
                .expect("entry relative to walk root"),
        )?;
        if is_link(&metadata) {
            return Err(Error::Path(name));
        }
        let size = if metadata.is_dir() {
            DIRECTORY
        } else if metadata.is_file() && metadata.len() < DIRECTORY {
            total = total
                .checked_add(metadata.len())
                .ok_or(Error::Format("source is too large"))?;
            metadata.len()
        } else {
            return Err(Error::Path(name));
        };
        entries.push(Entry { source, name, size });
    }
    let count = u32::try_from(entries.len()).map_err(|_| Error::Format("too many entries"))?;
    let (seed, wrapped) = wrap_seed(key)?;
    let (cipher, mac) = derive_keys(&seed);
    drop(seed);
    let file = create_file(&output)?;

    let result = (|| {
        let mut writer = Authenticated {
            io: BufWriter::new(file),
            mac,
        };
        write_header(&mut writer, &wrapped, count, total)?;
        let mut buffer = Zeroizing::new(vec![0; CHUNK]);
        let mut done = 0;
        progress(done, total);
        for (index, entry) in (0..count).zip(entries) {
            let header = entry_header(&entry.name, entry.size);
            writer.write_all(&header)?;
            if entry.size == DIRECTORY {
                continue;
            }

            let metadata = fs::symlink_metadata(&entry.source)?;
            if is_link(&metadata) || !metadata.is_file() || metadata.len() != entry.size {
                return Err(Error::Changed(entry.name));
            }
            let mut source = File::open(&entry.source)?;
            let mut remaining = entry.size;
            for part in 0..entry.size.div_ceil(CHUNK as u64).max(1) {
                let len = remaining.min(CHUNK as u64) as usize;
                let data = &mut buffer[..len];
                source.read_exact(data)?;
                let tag = cipher
                    .encrypt_in_place_detached(&nonce(index, part).into(), &header, data)
                    .map_err(|_| Error::Authentication)?;
                writer.write_all(data)?;
                writer.write_all(&tag)?;
                remaining -= len as u64;
                done += len as u64;
                progress(done, total);
            }
            let mut extra = Zeroizing::new([0; 1]);
            if source.read(&mut extra[..])? != 0 {
                return Err(Error::Changed(entry.name));
            }
        }
        writer.io.write_all(&writer.mac.finalize().into_bytes())?;
        writer.io.flush()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&output);
    }
    result
}
