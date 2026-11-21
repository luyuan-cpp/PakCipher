use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

use aes_gcm::{aead::AeadInPlace, Aes256Gcm};
use hmac::Mac;

use crate::{crypto::ArchiveMac, Error, Result};

const HEADER_V1: [u8; 12] = *b"PAKC\x01\x00\x00\x00\x00\x00\x00\x00";
const HEADER_V2: [u8; 12] = *b"PAKC\x02\x00\x00\x00\x00\x00\x00\x00";
const MAX_CAPSULE: usize = 8 * 1024;
const MAX_PATH: usize = 4096;
pub(crate) const CHUNK: usize = 1024 * 1024;
pub(crate) const TAG: usize = 16;
pub(crate) const FOOTER: u64 = 32;
pub(crate) const DIRECTORY: u64 = u64::MAX;

// File chunks use low chunk indices and entries never reach index u32::MAX.
const ENTRY_FIELDS_NONCE: u64 = u64::MAX;
const ENTRY_PATH_NONCE: u64 = u64::MAX - 1;
const METADATA_AAD: &[u8] = b"PakCipher v2 metadata";

#[derive(Clone, Copy)]
pub(crate) enum ArchiveVersion {
    V1,
    V2,
}

pub(crate) fn write_header(
    writer: &mut impl Write,
    cipher: &Aes256Gcm,
    wrapped: &[u8],
    count: u32,
    total: u64,
) -> Result<()> {
    if wrapped.is_empty() || wrapped.len() > MAX_CAPSULE {
        return Err(Error::Format("invalid key capsule length"));
    }
    writer.write_all(&HEADER_V2)?;
    writer.write_all(&(wrapped.len() as u32).to_le_bytes())?;
    writer.write_all(wrapped)?;
    let mut fields = [0; 12];
    fields[..4].copy_from_slice(&count.to_le_bytes());
    fields[4..].copy_from_slice(&total.to_le_bytes());
    write_metadata(writer, cipher, nonce(u32::MAX, 0), &mut fields)
}

pub(crate) fn read_capsule(reader: &mut impl Read) -> Result<(ArchiveVersion, Vec<u8>)> {
    let version = match read_array::<12>(reader)? {
        HEADER_V1 => ArchiveVersion::V1,
        HEADER_V2 => ArchiveVersion::V2,
        _ => return Err(Error::Format("unknown header or version")),
    };
    let len = u32::from_le_bytes(read_array(reader)?) as usize;
    if len == 0 || len > MAX_CAPSULE {
        return Err(Error::Format("invalid key capsule length"));
    }
    let mut wrapped = vec![0; len];
    reader.read_exact(&mut wrapped)?;
    Ok((version, wrapped))
}

pub(crate) fn read_manifest(
    reader: &mut impl Read,
    cipher: &Aes256Gcm,
    version: ArchiveVersion,
) -> Result<(u32, u64)> {
    let mut fields = read_array::<12>(reader)?;
    if matches!(version, ArchiveVersion::V2) {
        decrypt_metadata(reader, cipher, nonce(u32::MAX, 0), &mut fields)?;
    }
    let (count, total) = fields.split_at(4);
    Ok((
        u32::from_le_bytes(count.try_into().unwrap()),
        u64::from_le_bytes(total.try_into().unwrap()),
    ))
}

pub(crate) fn entry_header(path: &str, size: u64) -> Vec<u8> {
    let mut header = Vec::with_capacity(2 + path.len() + 8);
    header.extend_from_slice(&(path.len() as u16).to_le_bytes());
    header.extend_from_slice(path.as_bytes());
    header.extend_from_slice(&size.to_le_bytes());
    header
}

pub(crate) fn encoded_entry_len(path: &str) -> u64 {
    (10 + path.len() + 2 * TAG) as u64
}

pub(crate) fn write_entry(
    writer: &mut impl Write,
    cipher: &Aes256Gcm,
    index: u32,
    path: &str,
    size: u64,
) -> Result<()> {
    let mut fields = [0; 10];
    fields[..2].copy_from_slice(&(path.len() as u16).to_le_bytes());
    fields[2..].copy_from_slice(&size.to_le_bytes());
    write_metadata(
        writer,
        cipher,
        nonce(index, ENTRY_FIELDS_NONCE),
        &mut fields,
    )?;
    write_metadata(
        writer,
        cipher,
        nonce(index, ENTRY_PATH_NONCE),
        &mut path.as_bytes().to_vec(),
    )
}

pub(crate) fn read_entry(
    reader: &mut impl Read,
    cipher: &Aes256Gcm,
    version: ArchiveVersion,
    index: u32,
) -> Result<(String, u64)> {
    if matches!(version, ArchiveVersion::V1) {
        let len = u16::from_le_bytes(read_array(reader)?) as usize;
        let path = parse_path(read_path_bytes(reader, len)?)?;
        let size = u64::from_le_bytes(read_array(reader)?);
        return Ok((path, size));
    }
    let mut fields = read_array::<10>(reader)?;
    decrypt_metadata(
        reader,
        cipher,
        nonce(index, ENTRY_FIELDS_NONCE),
        &mut fields,
    )?;
    let (len, size) = fields.split_at(2);
    let len = u16::from_le_bytes(len.try_into().unwrap()) as usize;
    let size = u64::from_le_bytes(size.try_into().unwrap());
    let mut path = read_path_bytes(reader, len)?;
    decrypt_metadata(reader, cipher, nonce(index, ENTRY_PATH_NONCE), &mut path)?;
    Ok((parse_path(path)?, size))
}

fn read_path_bytes(reader: &mut impl Read, len: usize) -> Result<Vec<u8>> {
    if !(1..=MAX_PATH).contains(&len) {
        return Err(Error::Format("invalid entry path length"));
    }
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn parse_path(bytes: Vec<u8>) -> Result<String> {
    let path = String::from_utf8(bytes).map_err(|_| Error::Format("entry path is not UTF-8"))?;
    validate_path(&path)?;
    Ok(path)
}

fn write_metadata(
    writer: &mut impl Write,
    cipher: &Aes256Gcm,
    iv: [u8; 12],
    bytes: &mut [u8],
) -> Result<()> {
    let tag = cipher
        .encrypt_in_place_detached(&iv.into(), METADATA_AAD, bytes)
        .map_err(|_| Error::Authentication)?;
    writer.write_all(bytes)?;
    writer.write_all(&tag)?;
    Ok(())
}

fn decrypt_metadata(
    reader: &mut impl Read,
    cipher: &Aes256Gcm,
    iv: [u8; 12],
    bytes: &mut [u8],
) -> Result<()> {
    let tag = read_array::<TAG>(reader)?;
    cipher
        .decrypt_in_place_detached(&iv.into(), METADATA_AAD, bytes, &tag.into())
        .map_err(|_| Error::Authentication)
}

pub(crate) fn read_array<const N: usize>(reader: &mut impl Read) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn nonce(entry: u32, chunk: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(&entry.to_le_bytes());
    nonce[4..].copy_from_slice(&chunk.to_le_bytes());
    nonce
}

pub(crate) fn relative_path(path: &Path) -> Result<String> {
    let components = path
        .components()
        .map(|component| match component {
            Component::Normal(part) => part
                .to_str()
                .ok_or_else(|| Error::Path(path.display().to_string())),
            _ => Err(Error::Path(path.display().to_string())),
        })
        .collect::<Result<Vec<_>>>()?;
    let name = components.join("/");
    validate_path(&name)?;
    Ok(name)
}

fn validate_path(path: &str) -> Result<()> {
    if path.len() > MAX_PATH || !path.split('/').all(valid_component) {
        return Err(Error::Path(path.into()));
    }
    Ok(())
}

fn valid_component(name: &str) -> bool {
    if name.is_empty()
        || name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|c| c.is_control() || "\\:*?\"<>|".contains(c))
    {
        return false;
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return false;
    }
    !stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
        .is_some_and(|suffix| {
            matches!(
                suffix,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
}

pub(crate) fn output_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::Path(path.display().to_string()))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(parent.canonicalize()?.join(name))
}

pub(crate) fn create_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

pub(crate) fn create_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.recursive(false).create(path)
}

pub(crate) fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT includes junctions as well as symlinks.
        if metadata.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}

pub(crate) struct Authenticated<Io> {
    pub(crate) io: Io,
    pub(crate) mac: ArchiveMac,
}

impl<W: Write> Write for Authenticated<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let written = self.io.write(data)?;
        self.mac.update(&data[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

impl<R: Read> Read for Authenticated<R> {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        let read = self.io.read(data)?;
        self.mac.update(&data[..read]);
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::KeyInit;

    #[test]
    fn v2_encrypts_and_authenticates_metadata() {
        let cipher = Aes256Gcm::new_from_slice(&[0x33; 32]).unwrap();
        let path = "private-project-7f9a/src/payment-credential.rs";
        let size = 0x1398_ba7d_42c8_efd1_u64;
        let count = 0x9741_ed76_u32;
        let mut encoded = Vec::new();
        write_header(&mut encoded, &cipher, b"key capsule", count, size).unwrap();
        let entry_offset = encoded.len();
        write_entry(&mut encoded, &cipher, 0, path, size).unwrap();
        for plaintext in [path.as_bytes(), &size.to_le_bytes()] {
            assert!(!encoded
                .windows(plaintext.len())
                .any(|bytes| bytes == plaintext));
        }
        let mut input = encoded.as_slice();
        let (version, wrapped) = read_capsule(&mut input).unwrap();
        assert!(matches!(version, ArchiveVersion::V2));
        assert_eq!(wrapped, b"key capsule");
        assert_eq!(
            read_manifest(&mut input, &cipher, version).unwrap(),
            (count, size)
        );
        assert_eq!(
            read_entry(&mut input, &cipher, version, 0).unwrap(),
            (path.into(), size)
        );
        assert!(input.is_empty());

        // A damaged encrypted size or path must fail before it is used.
        for offset in [entry_offset, entry_offset + 10 + TAG] {
            let mut damaged = encoded.clone();
            damaged[offset] ^= 1;
            assert!(matches!(
                read_entry(&mut &damaged[entry_offset..], &cipher, version, 0),
                Err(Error::Authentication)
            ));
        }
    }
}
