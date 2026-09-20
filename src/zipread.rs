//! Reading single members out of remote zip archives without downloading them.
//!
//! `.conda` packages and wheels are zip files. Their central directory sits at the end, so
//! two or three HTTP range requests (the directory, then the member) are enough to pull a
//! few kilobytes of metadata out of a multi-megabyte archive. The same code reads local
//! files and `file://` URLs, which is what tests and local channels use.

use std::io::{self, Read};
use std::path::Path;

use crate::http;

/// Something whose bytes can be read by range.
pub trait RangeSource {
    /// Total size in bytes.
    fn len(&self) -> u64;
    /// The bytes in `[start, start + len)`.
    fn read_range(&self, start: u64, len: u64) -> io::Result<Vec<u8>>;
}

/// A local file.
pub struct FileSource {
    file: std::fs::File,
    len: u64,
}

impl FileSource {
    /// Open `path`.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self { file, len })
    }
}

impl RangeSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_range(&self, start: u64, len: u64) -> io::Result<Vec<u8>> {
        use std::io::Seek;
        let mut file = &self.file;
        file.seek(io::SeekFrom::Start(start))?;
        let mut buf = vec![0; len as usize];
        file.read_exact(&mut buf)?;
        Ok(buf)
    }
}

/// A URL served with HTTP range support. Opening it fetches the archive's tail (where the
/// central directory lives) with one suffix-range request that also reports the total size,
/// so listing the members needs no further round trip.
pub struct HttpSource {
    url: String,
    len: u64,
    tail: Vec<u8>,
}

impl HttpSource {
    /// Fetch the tail of `url`. Servers that ignore ranges are rejected up front so a
    /// package is never downloaded whole by accident.
    pub fn open(url: &str) -> io::Result<Self> {
        let (len, tail) = http::get_tail(url, EOCD_SEARCH_WINDOW).map_err(io::Error::other)?;
        Ok(Self {
            url: url.to_string(),
            len,
            tail,
        })
    }
}

impl RangeSource for HttpSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_range(&self, start: u64, len: u64) -> io::Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let tail_start = self.len - self.tail.len() as u64;
        if start >= tail_start && start + len <= self.len {
            let from = (start - tail_start) as usize;
            return Ok(self.tail[from..from + len as usize].to_vec());
        }
        http::get_range(&self.url, start, start + len - 1).map_err(io::Error::other)
    }
}

/// Open `location`, which is an `http(s)://` URL, a `file://` URL, or a filesystem path.
pub fn open(location: &str) -> io::Result<Box<dyn RangeSource>> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(Box::new(HttpSource::open(location)?));
    }
    let path = location.strip_prefix("file://").unwrap_or(location);
    Ok(Box::new(FileSource::open(Path::new(path))?))
}

/// One member of the archive, as listed in the central directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Member name, with `/` separators.
    pub name: String,
    /// 0 = stored, 8 = deflate.
    pub method: u16,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    /// Offset of the local file header.
    pub local_header_offset: u64,
}

/// Largest member accepted by [`read_entry`]; metadata members are kilobytes, never more.
pub const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
/// EOCD (22 bytes) plus the maximal comment, plus the zip64 locator that may precede it.
const EOCD_SEARCH_WINDOW: u64 = 22 + 65_535 + 20;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn u16_at(buf: &[u8], at: usize) -> io::Result<u16> {
    buf.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| invalid("truncated zip structure"))
}

fn u32_at(buf: &[u8], at: usize) -> io::Result<u32> {
    buf.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| invalid("truncated zip structure"))
}

fn u64_at(buf: &[u8], at: usize) -> io::Result<u64> {
    buf.get(at..at + 8)
        .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
        .ok_or_else(|| invalid("truncated zip structure"))
}

/// List the archive's members by reading its central directory.
pub fn central_directory(source: &dyn RangeSource) -> io::Result<Vec<Entry>> {
    let len = source.len();
    if len < 22 {
        return Err(invalid("too small to be a zip archive"));
    }
    let window = EOCD_SEARCH_WINDOW.min(len);
    let tail_start = len - window;
    let tail = source.read_range(tail_start, window)?;
    let eocd = (0..=tail.len().saturating_sub(22))
        .rev()
        .find(|&i| u32_at(&tail, i).ok() == Some(EOCD_SIGNATURE))
        .ok_or_else(|| invalid("no end-of-central-directory record; not a zip archive"))?;

    let mut entries = u64::from(u16_at(&tail, eocd + 10)?);
    let mut cd_size = u64::from(u32_at(&tail, eocd + 12)?);
    let mut cd_offset = u64::from(u32_at(&tail, eocd + 16)?);

    // Zip64: any saturated field means the real values live in the zip64 record.
    if entries == 0xffff || cd_size == 0xffff_ffff || cd_offset == 0xffff_ffff {
        let locator = eocd
            .checked_sub(20)
            .filter(|&i| u32_at(&tail, i).ok() == Some(ZIP64_LOCATOR_SIGNATURE))
            .ok_or_else(|| invalid("zip64 archive without a zip64 locator"))?;
        let zip64_offset = u64_at(&tail, locator + 8)?;
        let record = source.read_range(zip64_offset, 56)?;
        if u32_at(&record, 0)? != ZIP64_EOCD_SIGNATURE {
            return Err(invalid("bad zip64 end-of-central-directory record"));
        }
        entries = u64_at(&record, 32)?;
        cd_size = u64_at(&record, 40)?;
        cd_offset = u64_at(&record, 48)?;
    }

    if cd_size > MAX_ENTRY_BYTES {
        return Err(invalid("central directory too large"));
    }
    let cd = source.read_range(cd_offset, cd_size)?;
    let mut out = Vec::with_capacity(entries.min(4096) as usize);
    let mut pos = 0usize;
    for _ in 0..entries {
        if u32_at(&cd, pos)? != CENTRAL_SIGNATURE {
            return Err(invalid("bad central directory entry"));
        }
        let method = u16_at(&cd, pos + 10)?;
        let mut compressed_size = u64::from(u32_at(&cd, pos + 20)?);
        let mut uncompressed_size = u64::from(u32_at(&cd, pos + 24)?);
        let name_len = usize::from(u16_at(&cd, pos + 28)?);
        let extra_len = usize::from(u16_at(&cd, pos + 30)?);
        let comment_len = usize::from(u16_at(&cd, pos + 32)?);
        let mut local_header_offset = u64::from(u32_at(&cd, pos + 42)?);
        let name_start = pos + 46;
        let name = cd
            .get(name_start..name_start + name_len)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .ok_or_else(|| invalid("truncated central directory"))?;

        // Zip64 extra field (id 0x0001) carries the saturated values, in this order.
        let extra = cd
            .get(name_start + name_len..name_start + name_len + extra_len)
            .ok_or_else(|| invalid("truncated central directory"))?;
        let mut e = 0;
        while e + 4 <= extra.len() {
            let id = u16_at(extra, e)?;
            let size = usize::from(u16_at(extra, e + 2)?);
            let body = extra.get(e + 4..e + 4 + size).unwrap_or(&[]);
            if id == 0x0001 {
                let mut b = 0;
                for target in [&mut uncompressed_size, &mut compressed_size, &mut local_header_offset] {
                    if *target == 0xffff_ffff && b + 8 <= body.len() {
                        *target = u64_at(body, b)?;
                        b += 8;
                    }
                }
            }
            e += 4 + size;
        }

        out.push(Entry {
            name,
            method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
        });
        pos = name_start + name_len + extra_len + comment_len;
    }
    Ok(out)
}

/// Read and decompress one member.
pub fn read_entry(source: &dyn RangeSource, entry: &Entry) -> io::Result<Vec<u8>> {
    if entry.compressed_size > MAX_ENTRY_BYTES || entry.uncompressed_size > MAX_ENTRY_BYTES {
        return Err(invalid("zip member too large"));
    }
    let header = source.read_range(entry.local_header_offset, 30)?;
    if u32_at(&header, 0)? != LOCAL_SIGNATURE {
        return Err(invalid("bad local file header"));
    }
    let name_len = u64::from(u16_at(&header, 26)?);
    let extra_len = u64::from(u16_at(&header, 28)?);
    let data_start = entry.local_header_offset + 30 + name_len + extra_len;
    let data = source.read_range(data_start, entry.compressed_size)?;
    match entry.method {
        0 => Ok(data),
        8 => {
            let mut out = Vec::with_capacity(entry.uncompressed_size as usize);
            flate2::read::DeflateDecoder::new(data.as_slice())
                .take(MAX_ENTRY_BYTES)
                .read_to_end(&mut out)?;
            Ok(out)
        }
        other => Err(invalid(&format!("unsupported zip compression method {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> FileSource {
        FileSource::open(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/archives")
                .join(name),
        )
        .unwrap()
    }

    #[test]
    fn lists_and_reads_stored_members_of_a_conda_archive() {
        let src = fixture("zlib-1.3.2-h25fd6f3_3.conda");
        let entries = central_directory(&src).unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "metadata.json",
                "pkg-zlib-1.3.2-h25fd6f3_3.tar.zst",
                "info-zlib-1.3.2-h25fd6f3_3.tar.zst"
            ]
        );
        let info = entries.iter().find(|e| e.name.starts_with("info-")).unwrap();
        assert_eq!(info.method, 0);
        assert_eq!(info.compressed_size, 9478);
        let bytes = read_entry(&src, info).unwrap();
        assert_eq!(bytes.len(), 9478);
        assert_eq!(&bytes[..4], &[0x28, 0xb5, 0x2f, 0xfd], "zstd magic");
        let metadata = read_entry(&src, &entries[0]).unwrap();
        assert!(
            String::from_utf8(metadata)
                .unwrap()
                .contains("conda_pkg_format_version")
        );
    }

    #[test]
    fn lists_and_inflates_deflated_members_of_a_wheel() {
        let src = fixture("six-1.17.0-py2.py3-none-any.whl");
        let entries = central_directory(&src).unwrap();
        let license = entries
            .iter()
            .find(|e| e.name == "six-1.17.0.dist-info/LICENSE")
            .unwrap();
        assert_eq!(license.method, 8);
        let text = String::from_utf8(read_entry(&src, license).unwrap()).unwrap();
        assert!(text.starts_with("Copyright (c) 2010-2024 Benjamin Peterson"));
        assert_eq!(text.len(), license.uncompressed_size as usize);
    }

    #[test]
    fn rejects_non_archives_and_oversized_members() {
        let dir = tempfile::tempdir().unwrap();
        let tiny = dir.path().join("tiny");
        std::fs::write(&tiny, b"hello").unwrap();
        assert!(central_directory(&FileSource::open(&tiny).unwrap()).is_err());
        let junk = dir.path().join("junk");
        std::fs::write(&junk, vec![0u8; 4096]).unwrap();
        let err = central_directory(&FileSource::open(&junk).unwrap()).unwrap_err();
        assert!(err.to_string().contains("not a zip archive"));

        let src = fixture("zlib-1.3.2-h25fd6f3_3.conda");
        let mut entry = central_directory(&src).unwrap()[0].clone();
        entry.compressed_size = MAX_ENTRY_BYTES + 1;
        assert!(read_entry(&src, &entry).is_err());
        let mut entry = central_directory(&src).unwrap()[0].clone();
        entry.method = 12;
        assert!(read_entry(&src, &entry).unwrap_err().to_string().contains("method 12"));
        let mut entry = central_directory(&src).unwrap()[0].clone();
        entry.local_header_offset = 1;
        assert!(read_entry(&src, &entry).is_err(), "bad local header");
    }

    #[test]
    fn open_handles_file_urls_and_paths() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/archives/six-1.17.0-py2.py3-none-any.whl");
        let by_path = open(path.to_str().unwrap()).unwrap();
        let by_url = open(&format!("file://{}", path.display())).unwrap();
        assert_eq!(by_path.len(), by_url.len());
        assert!(open("/definitely/missing.zip").is_err());
    }
}
