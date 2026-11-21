use std::{
    collections::HashMap,
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
        create_directory, create_file, encoded_entry_len, entry_header, is_link, nonce,
        output_path, relative_path, write_entry, write_header, Authenticated, CHUNK, DIRECTORY,
        FOOTER, TAG,
    },
    volume::VolumeWriter,
    Error, PublicKey, Result, VolumeSize,
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
    pack(folder, key, output, None, progress)
}

pub fn pack_folder_volumes(
    folder: &Path,
    key: &PublicKey,
    output: &Path,
    sizes: VolumeSize,
    progress: impl Fn(u64, u64),
) -> Result<()> {
    pack(folder, key, output, Some(sizes), progress)
}

fn pack(
    folder: &Path,
    key: &PublicKey,
    output: &Path,
    volume_sizes: Option<VolumeSize>,
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
    check_portable_names(entries.iter().map(|entry| entry.name.as_str()))?;
    let count = u32::try_from(entries.len()).map_err(|_| Error::Format("too many entries"))?;
    let (seed, wrapped) = wrap_seed(key)?;
    let (cipher, mac) = derive_keys(&seed);
    drop(seed);
    let mut archive_header = Vec::new();
    write_header(&mut archive_header, &cipher, &wrapped, count, total)?;
    let initial_len = total
        .checked_add(archive_header.len() as u64 + FOOTER)
        .ok_or(Error::Format("archive is too large"))?;
    let archive_len = entries
        .iter()
        .try_fold(initial_len, |len, entry| {
            let tags = if entry.size == DIRECTORY {
                0
            } else {
                chunk_count(entry.size) * TAG as u64
            };
            len.checked_add(encoded_entry_len(&entry.name) + tags)
        })
        .ok_or(Error::Format("archive is too large"))?;

    let emit = |destination: &mut dyn Write| {
        let mut writer = Authenticated {
            io: BufWriter::new(destination),
            mac,
        };
        writer.write_all(&archive_header)?;
        let mut buffer = Zeroizing::new(vec![0; CHUNK]);
        let mut done = 0;
        progress(done, total);
        for (index, entry) in (0..count).zip(entries) {
            write_entry(&mut writer, &cipher, index, &entry.name, entry.size)?;
            if entry.size == DIRECTORY {
                continue;
            }
            let header = entry_header(&entry.name, entry.size);

            let metadata = fs::symlink_metadata(&entry.source)?;
            if is_link(&metadata) || !metadata.is_file() || metadata.len() != entry.size {
                return Err(Error::Changed(entry.name));
            }
            let mut source = File::open(&entry.source)?;
            let mut remaining = entry.size;
            for part in 0..chunk_count(entry.size) {
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
    };
    if let Some(sizes) = volume_sizes {
        let mut volumes = VolumeWriter::new(&output, sizes, archive_len)?;
        create_directory(&output)?;
        let result = emit(&mut volumes).and_then(|()| volumes.finish());
        drop(volumes);
        if result.is_err() {
            let _ = fs::remove_dir_all(&output);
        }
        result
    } else {
        let mut file = create_file(&output)?;
        let result = emit(&mut file);
        drop(file);
        if result.is_err() {
            let _ = fs::remove_file(&output);
        }
        result
    }
}

fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK as u64).max(1)
}

fn check_portable_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut seen = HashMap::new();
    for name in names {
        let case_key = name.to_lowercase().to_uppercase();
        if let Some(first) = seen.insert(case_key, name) {
            return Err(Error::PathCaseCollision {
                first: first.to_owned(),
                second: name.to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_case_collisions_in_files_and_directories() {
        for (first, second) in [
            ("docs/report.txt", "docs/REPORT.txt"),
            ("docs", "Docs"),
            ("docs/Σ.txt", "docs/ς.txt"),
        ] {
            assert!(matches!(
                check_portable_names([first, second]),
                Err(Error::PathCaseCollision { first: a, second: b }) if a == first && b == second
            ));
        }
        assert!(check_portable_names(["a", "a/report.txt", "b", "b/REPORT.txt"]).is_ok());
    }
}
