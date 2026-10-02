//! Turning a file's bytes into XML documents.
//!
//! Receivers send aggregate reports as plain XML, gzip, or zip (Google uses
//! zip, Microsoft and Yahoo gzip). The format is recognised from the leading
//! bytes, not the file name, because mail clients rename attachments.
//! Everything is read through a hard size cap: a few kilobytes of gzip can
//! expand to gigabytes, and a report parser must not be the thing that runs a
//! mail administrator's laptop out of memory.

use flate2::read::GzDecoder;
use std::io::{Cursor, Read};

/// Largest decompressed document accepted. Real reports are kilobytes to a
/// few megabytes; 64 MiB is generous and still bounded.
pub const MAX_XML_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ZIP_ENTRIES: usize = 64;

fn read_capped(reader: impl Read, what: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    reader
        .take(MAX_XML_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("cannot decompress {what}: {e}"))?;
    if out.len() as u64 > MAX_XML_BYTES {
        return Err(format!(
            "{what} expands beyond {} MiB; refusing it",
            MAX_XML_BYTES / 1024 / 1024
        ));
    }
    Ok(out)
}

/// A file's bytes, refusing to buffer more than the cap.
pub fn read_file(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "no such file".to_string(),
        kind => format!("cannot read ({kind})"),
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_XML_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read ({})", e.kind()))?;
    if bytes.len() as u64 > MAX_XML_BYTES {
        return Err(format!(
            "file is larger than {} MiB; refusing it",
            MAX_XML_BYTES / 1024 / 1024
        ));
    }
    Ok(bytes)
}

/// The XML documents inside `bytes`, with a label for each.
pub fn documents(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Ok(vec![(
            "gzip".into(),
            read_capped(GzDecoder::new(bytes), "gzip data")?,
        )]);
    }
    if bytes.starts_with(b"PK\x03\x04") {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
            .map_err(|e| format!("not a readable zip: {e}"))?;
        if archive.len() > MAX_ZIP_ENTRIES {
            return Err(format!(
                "zip has {} entries; refusing more than {MAX_ZIP_ENTRIES}",
                archive.len()
            ));
        }
        let mut docs = Vec::new();
        let mut total = 0u64;
        for i in 0..archive.len() {
            let entry = archive
                .by_index(i)
                .map_err(|e| format!("zip entry {i}: {e}"))?;
            if entry.is_dir() || !entry.name().to_ascii_lowercase().ends_with(".xml") {
                continue;
            }
            let name = entry.name().to_string();
            let data = read_capped(entry, &format!("zip entry {name:?}"))?;
            total += data.len() as u64;
            if total > MAX_XML_BYTES {
                return Err("zip expands beyond the size limit in total; refusing it".into());
            }
            docs.push((name, data));
        }
        if docs.is_empty() {
            return Err("zip contains no .xml entry".into());
        }
        return Ok(docs);
    }
    if bytes.len() as u64 > MAX_XML_BYTES {
        return Err(format!(
            "file is larger than {} MiB; refusing it",
            MAX_XML_BYTES / 1024 / 1024
        ));
    }
    Ok(vec![("xml".into(), bytes.to_vec())])
}
