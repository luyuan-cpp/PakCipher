use std::{
    fs::{self, File},
    io::{self, BufReader, Read, Seek, Take, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use rand::{rngs::OsRng, Rng, RngCore};

use crate::{
    packet::{create_file, is_link, read_array},
    Error, Result,
};

const MAGIC: [u8; 4] = *b"PKV1";
const HEADER_SIZE: u64 = 32;
const FIRST_PART: &str = "part-000001.pak";
const MIB: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct VolumeSize {
    min: u64,
    max: u64,
}

impl VolumeSize {
    pub fn from_mib_bounds(min: Option<u64>, max: Option<u64>) -> Result<Option<Self>> {
        if min.is_none() && max.is_none() {
            return Ok(None);
        }
        let min = min.unwrap_or(1);
        let max = max.unwrap_or_else(|| min.saturating_mul(2).min(u64::MAX / MIB));
        if min == 0 || max < min {
            return Err(Error::VolumeSize);
        }
        Ok(Some(Self {
            min: min.checked_mul(MIB).ok_or(Error::VolumeSize)?,
            max: max.checked_mul(MIB).ok_or(Error::VolumeSize)?,
        }))
    }
}

impl FromStr for VolumeSize {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let (min, max) = value.split_once(':').ok_or(Error::VolumeSize)?;
        let parse = |number: &str| number.trim().parse::<u64>().map_err(|_| Error::VolumeSize);
        Self::from_mib_bounds(Some(parse(min)?), Some(parse(max)?))?.ok_or(Error::VolumeSize)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct VolumeHeader {
    index: u32,
    archive_len: u64,
    set_id: [u8; 16],
}

impl VolumeHeader {
    fn read(reader: &mut impl Read) -> io::Result<Self> {
        if read_array::<4>(reader)? != MAGIC {
            return Err(invalid_volume("unexpected volume header"));
        }
        Ok(Self {
            index: u32::from_le_bytes(read_array(reader)?),
            archive_len: u64::from_le_bytes(read_array(reader)?),
            set_id: read_array(reader)?,
        })
    }

    fn write(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(&MAGIC)?;
        writer.write_all(&self.index.to_le_bytes())?;
        writer.write_all(&self.archive_len.to_le_bytes())?;
        writer.write_all(&self.set_id)
    }
}

fn volume_name(index: u32) -> String {
    format!("part-{index:06}.pak")
}

fn volume_index(name: &str) -> Option<u32> {
    let index = name
        .strip_prefix("part-")?
        .strip_suffix(".pak")?
        .parse()
        .ok()?;
    (index != 0 && volume_name(index) == name).then_some(index)
}

fn invalid_volume(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

pub(crate) struct VolumeWriter<'a> {
    directory: &'a Path,
    sizes: VolumeSize,
    header: VolumeHeader,
    remaining: u64,
    current: Option<(File, u64)>,
}

impl<'a> VolumeWriter<'a> {
    pub(crate) fn new(directory: &'a Path, sizes: VolumeSize, archive_len: u64) -> Result<Self> {
        let mut set_id = [0; 16];
        OsRng
            .try_fill_bytes(&mut set_id)
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(Self {
            directory,
            sizes,
            header: VolumeHeader {
                index: 0,
                archive_len,
                set_id,
            },
            remaining: archive_len,
            current: None,
        })
    }

    fn open_next(&mut self) -> io::Result<()> {
        self.header.index = self
            .header
            .index
            .checked_add(1)
            .ok_or_else(|| invalid_volume("too many volumes"))?;
        let min = self.sizes.min - HEADER_SIZE;
        let max = self.sizes.max - HEADER_SIZE;
        let size = if self.remaining <= max {
            self.remaining
        } else {
            // Leave room for a full final volume when the chosen bounds permit it.
            let upper = max.min(self.remaining.saturating_sub(min)).max(min);
            rand::thread_rng().gen_range(min..=upper)
        };
        let mut file = create_file(&self.directory.join(volume_name(self.header.index)))?;
        self.header.write(&mut file)?;
        self.current = Some((file, size));
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<()> {
        if self.remaining != 0 {
            return Err(Error::Format(
                "archive length does not match the volume set",
            ));
        }
        Ok(())
    }
}

impl Write for VolumeWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            return Err(invalid_volume("archive exceeds its declared length"));
        }
        if self.current.is_none() {
            self.open_next()?;
        }
        let (file, available) = self.current.as_mut().expect("volume is open");
        let len = (buffer.len() as u64).min(*available) as usize;
        let written = file.write(&buffer[..len])?;
        *available -= written as u64;
        self.remaining -= written as u64;
        if *available == 0 {
            self.current = None;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some((file, _)) = &mut self.current {
            file.flush()?;
        }
        Ok(())
    }
}

pub(crate) enum ArchiveInput {
    File(BufReader<File>),
    Volumes(VolumeReader),
}

impl ArchiveInput {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        if path.is_dir() {
            return Ok(Self::Volumes(VolumeReader::open(path)?));
        }
        let mut file = BufReader::new(File::open(path)?);
        let mut prefix = [0; 4];
        if file.read_exact(&mut prefix).is_ok() && prefix == MAGIC {
            if path.file_name().and_then(|name| name.to_str()) != Some(FIRST_PART) {
                return Err(Error::Volume(format!(
                    "select {FIRST_PART} or the volume folder"
                )));
            }
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            return Ok(Self::Volumes(VolumeReader::open(parent)?));
        }
        file.rewind()?;
        Ok(Self::File(file))
    }

    pub(crate) fn len(&self) -> Result<u64> {
        match self {
            Self::File(file) => Ok(file.get_ref().metadata()?.len()),
            Self::Volumes(parts) => Ok(parts.header.archive_len),
        }
    }

    pub(crate) fn rewind(&mut self) -> io::Result<()> {
        match self {
            Self::File(file) => file.rewind(),
            Self::Volumes(parts) => {
                parts.next = 0;
                parts.current = None;
                Ok(())
            }
        }
    }
}

impl Read for ArchiveInput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(file) => file.read(buffer),
            Self::Volumes(parts) => parts.read(buffer),
        }
    }
}

struct Volume {
    index: u32,
    path: PathBuf,
    payload_len: u64,
}

pub(crate) struct VolumeReader {
    header: VolumeHeader,
    volumes: Vec<Volume>,
    next: usize,
    current: Option<Take<BufReader<File>>>,
}

impl VolumeReader {
    fn open(path: &Path) -> Result<Self> {
        let mut volumes = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let Some(index) = entry.file_name().to_str().and_then(volume_index) else {
                continue;
            };
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            let payload_len = metadata
                .len()
                .checked_sub(HEADER_SIZE)
                .filter(|len| *len > 0);
            match payload_len {
                Some(payload_len) if metadata.is_file() && !is_link(&metadata) => {
                    volumes.push(Volume {
                        index,
                        path,
                        payload_len,
                    });
                }
                _ => {
                    return Err(Error::Volume(format!(
                        "unreadable or empty {}",
                        volume_name(index)
                    )))
                }
            }
        }
        volumes.sort_unstable_by_key(|part| part.index);
        let first = volumes
            .first()
            .filter(|part| part.index == 1)
            .ok_or_else(|| Error::Volume(format!("missing {FIRST_PART}")))?;
        let header = VolumeHeader::read(&mut File::open(&first.path)?)?;
        let mut total = 0_u64;
        for (expected, part) in (1..).zip(&volumes) {
            if part.index != expected {
                return Err(Error::Volume(format!("missing {}", volume_name(expected))));
            }
            total = total
                .checked_add(part.payload_len)
                .ok_or(Error::Format("archive is too large"))?;
        }
        if header.index != 1 || total != header.archive_len {
            return Err(Error::Volume(
                "volumes are missing, truncated, or have unexpected sizes".into(),
            ));
        }
        Ok(Self {
            header,
            volumes,
            next: 0,
            current: None,
        })
    }

    fn open_next(&mut self) -> io::Result<()> {
        let part = &self.volumes[self.next];
        let mut file = BufReader::new(File::open(&part.path)?);
        let header = VolumeHeader::read(&mut file)?;
        if header
            != (VolumeHeader {
                index: part.index,
                ..self.header
            })
            || file.get_ref().metadata()?.len() != part.payload_len + HEADER_SIZE
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} does not belong to this volume set or was modified",
                    volume_name(part.index)
                ),
            ));
        }
        self.next += 1;
        self.current = Some(file.take(part.payload_len));
        Ok(())
    }
}

impl Read for VolumeReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.current.is_none() {
            if self.next == self.volumes.len() {
                return Ok(0);
            }
            self.open_next()?;
        }
        let file = self.current.as_mut().expect("volume is open");
        let read = file.read(buffer)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "archive volume was truncated",
            ));
        }
        if file.limit() == 0 {
            self.current = None;
        }
        Ok(read)
    }
}
