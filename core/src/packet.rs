use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

use hmac::Mac;

use crate::{crypto::ArchiveMac, Error, Result};

const HEADER: [u8; 12] = *b"PAKC\x01\x00\x00\x00\x00\x00\x00\x00";
const MAX_CAPSULE: usize = 8 * 1024;
const MAX_PATH: usize = 4096;
pub(crate) const CHUNK: usize = 1024 * 1024;
pub(crate) const TAG: usize = 16;
pub(crate) const FOOTER: u64 = 32;
pub(crate) const DIRECTORY: u64 = u64::MAX;

pub(crate) fn write_header(
    writer: &mut impl Write,
    wrapped: &[u8],
    count: u32,
    total: u64,
) -> Result<()> {
    if wrapped.is_empty() || wrapped.len() > MAX_CAPSULE {
        return Err(Error::Format("invalid key capsule length"));
    }
    writer.write_all(&HEADER)?;
    writer.write_all(&(wrapped.len() as u32).to_le_bytes())?;
    writer.write_all(wrapped)?;
    writer.write_all(&count.to_le_bytes())?;
    writer.write_all(&total.to_le_bytes())?;
    Ok(())
}

pub(crate) fn read_header(reader: &mut impl Read) -> Result<(Vec<u8>, u32, u64)> {
    if read_array::<12>(reader)? != HEADER {
        return Err(Error::Format("unknown header or version"));
    }
    let len = u32::from_le_bytes(read_array(reader)?) as usize;
    if len == 0 || len > MAX_CAPSULE {
        return Err(Error::Format("invalid key capsule length"));
    }
    let mut wrapped = vec![0; len];
    reader.read_exact(&mut wrapped)?;
    let count = u32::from_le_bytes(read_array(reader)?);
    let total = u64::from_le_bytes(read_array(reader)?);
    Ok((wrapped, count, total))
}

pub(crate) fn entry_header(path: &str, size: u64) -> Vec<u8> {
    let mut header = Vec::with_capacity(2 + path.len() + 8);
    header.extend_from_slice(&(path.len() as u16).to_le_bytes());
    header.extend_from_slice(path.as_bytes());
    header.extend_from_slice(&size.to_le_bytes());
    header
}

pub(crate) fn read_entry(reader: &mut impl Read) -> Result<(String, u64)> {
    let len = u16::from_le_bytes(read_array(reader)?) as usize;
    if len == 0 || len > MAX_PATH {
        return Err(Error::Format("invalid entry path length"));
    }
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes)?;
    let path = String::from_utf8(bytes).map_err(|_| Error::Format("entry path is not UTF-8"))?;
    validate_path(&path)?;
    let size = u64::from_le_bytes(read_array(reader)?);
    Ok((path, size))
}

pub(crate) fn read_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N]> {
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
