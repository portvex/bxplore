//! Structural PE editing: sections, imports, header fix-ups.
//! Every operation works on the whole file buffer and re-parses it first,
//! so callers never hold stale layout information.

// Every editor has the same `&mut Vec<u8>` signature so the GUI can queue any of them.
#![allow(clippy::ptr_arg)]

use super::{Pe, align_up};
use crate::model::{Endian, Rd};

type Res<T> = Result<T, String>;

fn w16(data: &mut [u8], off: usize, v: u16) {
    if let Some(b) = data.get_mut(off..off + 2) {
        b.copy_from_slice(&v.to_le_bytes());
    }
}

pub fn w32(data: &mut [u8], off: usize, v: u32) {
    if let Some(b) = data.get_mut(off..off + 4) {
        b.copy_from_slice(&v.to_le_bytes());
    }
}

fn w64(data: &mut [u8], off: usize, v: u64) {
    if let Some(b) = data.get_mut(off..off + 8) {
        b.copy_from_slice(&v.to_le_bytes());
    }
}

fn pe_of(data: &[u8]) -> Res<Pe> {
    Pe::parse(data).ok_or_else(|| "not a valid PE file".to_string())
}

/// Parse and check that the layout is sane enough to move data around.
/// The viewers tolerate anything; the structural editors refuse files whose
/// alignments or section bounds would make the arithmetic meaningless.
fn layout_of(data: &[u8]) -> Res<Pe> {
    let pe = pe_of(data)?;
    let bad = |what: &str| Err(format!("the file layout is damaged ({what}); structural editing is not possible"));
    if !pe.file_align.is_power_of_two() || pe.file_align > 0x1_0000 {
        return bad("FileAlignment is not a power of two up to 64 KB");
    }
    if !pe.section_align.is_power_of_two() || pe.section_align > 0x1000_0000 {
        return bad("SectionAlignment is not a power of two up to 256 MB");
    }
    // The parser drops every section header that is not in the file, so a
    // cut-off table shows as fewer sections than the file header declares.
    if Rd::new(data, Endian::Little).u16(pe.file_hdr + 2) as usize != pe.sections.len() {
        return bad("the section table is truncated");
    }
    for s in &pe.sections {
        if s.rsize > 0 && s.roff as usize > data.len() {
            return bad("a section starts beyond the end of the file");
        }
        if s.va as u64 + s.vsize.max(s.rsize) as u64 > 0xF000_0000 {
            return bad("a section does not fit in the 4 GB image");
        }
    }
    // Bounds the RVA of a new section for every editor that builds content
    // for it; without sections that RVA follows from SizeOfHeaders alone.
    if pe.image_end() > 0xF000_0000 {
        return bad("the image does not fit in 4 GB");
    }
    Ok(pe)
}

pub fn checksum(data: &[u8], pe: &Pe) -> u32 {
    let skip = pe.opt + 64;
    let mut sum: u64 = 0;
    let mut i = 0;
    while i < data.len() {
        let word = if i == skip || i == skip + 2 {
            0
        } else if i + 1 < data.len() {
            u16::from_le_bytes([data[i], data[i + 1]]) as u64
        } else {
            data[i] as u64
        };
        sum += word;
        sum = (sum & 0xFFFF) + (sum >> 16);
        i += 2;
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    (sum as u32).wrapping_add(data.len() as u32)
}

pub fn fix_checksum(data: &mut Vec<u8>) -> Res<String> {
    let pe = pe_of(data)?;
    let c = checksum(data, &pe);
    w32(data, pe.opt + 64, c);
    Ok(format!("CheckSum set to {c:08X}"))
}

pub fn fix_size_of_image(data: &mut Vec<u8>) -> Res<String> {
    let pe = pe_of(data)?;
    let v = pe.next_section_rva();
    w32(data, pe.opt + 56, v);
    Ok(format!("SizeOfImage set to {v:08X}"))
}

pub fn fix_size_of_headers(data: &mut Vec<u8>) -> Res<String> {
    let pe = pe_of(data)?;
    let end = (pe.sec_table + pe.sections.len() * 40) as u64;
    let mut v = align_up(end, pe.file_align.max(1) as u64) as u32;
    if let Some(first) = pe.sections.iter().filter(|s| s.rsize > 0).map(|s| s.roff).min()
        && first as u64 >= end
    {
        v = v.min(first);
    }
    w32(data, pe.opt + 60, v);
    Ok(format!("SizeOfHeaders set to {v:08X}"))
}

/// The security directory stores a file offset, so it has to follow any
/// insertion or removal of bytes in front of it.
fn shift_security(data: &mut [u8], pe: &Pe, at: usize, delta: i64) {
    let (off, size) = pe.dir(data, 4);
    if off != 0 && size != 0 && off as usize >= at {
        w32(data, pe.dirs_off + 4 * 8, (off as i64 + delta) as u32);
    }
}

pub fn remove_overlay(data: &mut Vec<u8>) -> Res<String> {
    let pe = pe_of(data)?;
    let end = pe.raw_end();
    if end >= data.len() {
        return Ok("The file has no overlay".into());
    }
    let removed = data.len() - end;
    let (soff, _) = pe.dir(data, 4);
    if soff as usize >= end {
        w32(data, pe.dirs_off + 32, 0);
        w32(data, pe.dirs_off + 36, 0);
    }
    data.truncate(end);
    Ok(format!("Removed {removed} bytes of overlay"))
}

pub fn remove_signature(data: &mut Vec<u8>) -> Res<String> {
    let pe = pe_of(data)?;
    let (off, size) = pe.dir(data, 4);
    if off == 0 || pe.num_dirs <= 4 {
        return Ok("The file is not signed".into());
    }
    let (off, size) = (off as usize, size as usize);
    w32(data, pe.dirs_off + 32, 0);
    w32(data, pe.dirs_off + 36, 0);
    if off >= pe.raw_end() && off < data.len() && off + size + 8 >= data.len() {
        data.truncate(off);
    }
    Ok("Authenticode signature removed".into())
}

/// Whether a data directory is mapped through the headers and reaches past
/// `at`. An RVA below the first section maps to the same file offset, so
/// bytes inserted at `at`, or a section placed there, would leave the data
/// such a directory finds behind or hide it.
fn header_mapped_past(data: &[u8], pe: &Pe, at: u64) -> bool {
    (0..pe.num_dirs).filter(|i| *i != 4).any(|i| {
        let (rva, size) = pe.dir(data, i);
        rva != 0 && pe.section_of_rva(rva).is_none() && pe.rva_to_off(rva).is_some() && rva as u64 + size as u64 > at
    })
}

/// Make room for one more section header by inserting one file alignment
/// unit of padding after the headers and moving all raw data down. RVAs do
/// not change; only file pointers are adjusted.
fn grow_headers(data: &mut Vec<u8>, pe: &Pe) -> Res<()> {
    let fa = pe.file_align.max(1);
    let at = pe.sections.iter().filter(|s| s.rsize > 0).map(|s| s.roff).min().unwrap_or(pe.size_of_headers) as usize;
    let first_va = pe.sections.iter().map(|s| s.va).min().unwrap_or(u32::MAX);
    let table_end = pe.sec_table + (pe.sections.len() + 1) * 40;
    if fa < 40 || at > data.len() || at < pe.sec_table + pe.sections.len() * 40 || at + fa as usize > first_va as usize || table_end > at + fa as usize {
        return Err("there is no room in the headers for another section header, and the headers cannot be enlarged".into());
    }
    if header_mapped_past(data, pe, at as u64) {
        return Err("a data directory is mapped through the headers, so the headers cannot be enlarged for another section header".into());
    }
    // Debug directory entries hold raw file pointers.
    let (dbg_rva, dbg_size) = pe.dir(data, 6);
    let mut fixes: Vec<(usize, u32)> = Vec::new();
    if let Some(off) = (dbg_rva != 0).then(|| pe.rva_to_off(dbg_rva)).flatten() {
        let rd = Rd::new(data, Endian::Little);
        for i in 0..(dbg_size as usize / 28).min(256) {
            let ptr = rd.u32(off + i * 28 + 24);
            if ptr as usize >= at {
                fixes.push((off + i * 28 + 24, ptr.wrapping_add(fa)));
            }
        }
    }
    let symtab = Rd::new(data, Endian::Little).u32(pe.file_hdr + 8);
    if symtab as usize >= at {
        fixes.push((pe.file_hdr + 8, symtab.wrapping_add(fa)));
    }
    for (off, v) in fixes {
        w32(data, off, v);
    }
    for s in &pe.sections {
        if s.roff as usize >= at && s.roff != 0 {
            w32(data, s.hdr_off + 20, s.roff.wrapping_add(fa));
        }
    }
    shift_security(data, pe, at, fa as i64);
    w32(data, pe.opt + 60, (at as u32) + fa);
    data.splice(at..at, vec![0u8; fa as usize]);
    Ok(())
}

/// Append a new section. Returns its RVA.
pub fn add_section(data: &mut Vec<u8>, name: &str, content: &[u8], vsize: u32, chars: u32) -> Res<u32> {
    let pe = layout_of(data)?;
    if content.len() > u32::MAX as usize / 2 {
        return Err("the section content is too large".into());
    }
    if name.len() > 8 {
        return Err("section names are limited to 8 bytes".into());
    }
    if content.is_empty() && vsize == 0 {
        return Err("the new section would be empty".into());
    }
    let n = pe.sections.len();
    if n >= 0xFFFF {
        return Err("too many sections".into());
    }
    let new_hdr = pe.sec_table + n * 40;
    let first_raw = pe.sections.iter().filter(|s| s.rsize > 0).map(|s| s.roff as usize).min().unwrap_or(data.len());
    let limit = (pe.size_of_headers as usize).min(first_raw).min(data.len());
    if new_hdr + 40 > limit {
        // The second pass can still refuse (occupied slack, 4 GB limits), and
        // an error must leave the buffer as it was, not with grown headers.
        let backup = data.clone();
        grow_headers(data, &pe)?;
        let result = add_section(data, name, content, vsize, chars);
        if result.is_err() {
            *data = backup;
        }
        return result;
    }
    // A directory in the slack can begin with zero fields (a TLS directory
    // without raw data does), so the bytes alone do not show that it is there.
    let in_slot = (0..pe.num_dirs).filter(|i| *i != 4).any(|i| {
        let (rva, size) = pe.dir(data, i);
        let len = if i == 9 { size.max(4 * pe.ptr_size() as u32 + 8) } else { size.max(1) };
        rva != 0 && pe.section_of_rva(rva).is_none() && (rva as u64) < new_hdr as u64 + 40 && rva as u64 + len as u64 > new_hdr as u64
    });
    if in_slot || data[new_hdr..new_hdr + 40].iter().any(|b| *b != 0) {
        return Err("the header slack after the section table is occupied (bound imports or other data)".into());
    }
    let fa = pe.file_align.max(1) as u64;
    let va = pe.next_section_rva();
    // RVA 0 in a data directory means "no directory", and below the end of
    // the headers the section would share its addresses with them.
    if (va as u64) < (pe.size_of_headers as u64).max(new_hdr as u64 + 40) {
        return Err(format!("the new section would land at RVA {va:08X}, inside the headers"));
    }
    if va as u64 + vsize.max(content.len() as u32) as u64 > 0xF000_0000 {
        return Err("the new section does not fit in the 4 GB image".into());
    }
    let raw_end = pe.raw_end().min(data.len());
    // The new section takes the RVAs from `va` on, and its raw data moves
    // everything behind `raw_end` down the file.
    let taken = if content.is_empty() { va as u64 } else { (va as u64).min(raw_end as u64) };
    if header_mapped_past(data, &pe, taken) {
        return Err("a data directory is mapped through the headers where the new section goes".into());
    }
    let (roff, rsize) = if content.is_empty() {
        (0u32, 0u32)
    } else {
        let roff = align_up(raw_end as u64, fa) as usize;
        let rsize = align_up(content.len() as u64, fa) as usize;
        if roff + rsize > u32::MAX as usize {
            return Err("the file would exceed 4 GB".into());
        }
        let mut block = vec![0u8; roff - raw_end];
        block.extend_from_slice(content);
        block.resize(roff - raw_end + rsize, 0);
        let added = block.len() as i64;
        data.splice(raw_end..raw_end, block);
        shift_security(data, &pe, raw_end, added);
        (roff as u32, rsize as u32)
    };
    let vsize = vsize.max(content.len() as u32);
    let mut hdr = [0u8; 40];
    hdr[..name.len()].copy_from_slice(name.as_bytes());
    hdr[8..12].copy_from_slice(&vsize.to_le_bytes());
    hdr[12..16].copy_from_slice(&va.to_le_bytes());
    hdr[16..20].copy_from_slice(&rsize.to_le_bytes());
    hdr[20..24].copy_from_slice(&roff.to_le_bytes());
    hdr[36..40].copy_from_slice(&chars.to_le_bytes());
    data[new_hdr..new_hdr + 40].copy_from_slice(&hdr);
    w16(data, pe.file_hdr + 2, (n + 1) as u16);
    let image = align_up(va as u64 + vsize as u64, pe.section_align.max(1) as u64) as u32;
    w32(data, pe.opt + 56, image);
    Ok(va)
}

/// Append a section whose content was built for the RVA `base`. A file
/// without sections can get another RVA once its headers are enlarged; the
/// content would then point at the wrong place, so that is refused and the
/// buffer is left as it was.
fn add_section_at(data: &mut Vec<u8>, base: u32, name: &str, content: &[u8], chars: u32) -> Res<u32> {
    let backup = data.clone();
    let va = add_section(data, name, content, content.len() as u32, chars)?;
    if va != base {
        *data = backup;
        return Err(format!("the new section would land at RVA {va:08X} instead of {base:08X} once the headers are enlarged"));
    }
    Ok(va)
}

pub fn delete_section(data: &mut Vec<u8>, idx: usize) -> Res<String> {
    let pe = layout_of(data)?;
    let s = pe.sections.get(idx).ok_or("no such section")?.clone();
    let n = pe.sections.len();

    // Clear data directories that live inside the section.
    for d in 0..pe.num_dirs {
        if d == 4 {
            continue;
        }
        let (rva, _) = pe.dir(data, d);
        if rva != 0 && pe.section_of_rva(rva) == Some(idx) {
            w32(data, pe.dirs_off + d * 8, 0);
            w32(data, pe.dirs_off + d * 8 + 4, 0);
        }
    }

    // Remove the raw data unless another section shares it.
    let start = s.roff as usize;
    let end = (start + s.rsize as usize).min(data.len());
    let shared =
        pe.sections.iter().enumerate().any(|(i, o)| i != idx && o.rsize > 0 && (o.roff as usize) < end && (o.roff as usize + o.rsize as usize) > start);
    let mut removed = 0usize;
    if s.rsize > 0 && start < end && start >= pe.sec_table + n * 40 && !shared {
        removed = end - start;
        data.drain(start..end);
        for o in &pe.sections {
            if o.roff as usize >= end {
                w32(data, o.hdr_off + 20, o.roff - removed as u32);
            }
        }
        shift_security(data, &pe, end, -(removed as i64));
    }

    // Remove the header entry.
    let from = s.hdr_off + 40;
    let table_end = pe.sec_table + n * 40;
    data.copy_within(from..table_end, s.hdr_off);
    data[table_end - 40..table_end].fill(0);
    w16(data, pe.file_hdr + 2, (n - 1) as u16);
    fix_size_of_image(data)?;
    let mut msg = format!("Section {} deleted, {removed} bytes removed from the file", s.name);
    if idx != n - 1 {
        msg.push_str(". It was not the last section, so the image now has a gap in its virtual layout and may not load");
    }
    Ok(msg)
}

#[derive(Clone, Debug, PartialEq)]
pub enum NewImport {
    Name(String),
    Ordinal(u16),
}

/// Rebuild the import directory in a new section, keeping all existing
/// descriptors (and their original thunks) and appending the new modules.
pub fn add_imports(data: &mut Vec<u8>, list: &[(String, Vec<NewImport>)]) -> Res<String> {
    let pe = layout_of(data)?;
    if pe.num_dirs < 2 {
        return Err("the optional header has no import data directory".into());
    }
    if list.is_empty() || list.iter().any(|(_, f)| f.is_empty()) {
        return Err("nothing to add".into());
    }
    let ps = pe.ptr_size();
    let old = pe.imports(data);
    let old_bytes: Vec<u8> = old.iter().flat_map(|m| Rd::new(data, Endian::Little).bytes(m.desc_off, 20).to_vec()).collect();
    let base = pe.next_section_rva() as usize;

    let descs = (old.len() + list.len() + 1) * 20;
    let mut cursor = descs;
    let mut tables = Vec::new();
    for (_, funcs) in list {
        let ilt = cursor;
        cursor += (funcs.len() + 1) * ps;
        let iat = cursor;
        cursor += (funcs.len() + 1) * ps;
        tables.push((ilt, iat));
    }
    let mut blob = vec![0u8; cursor];
    blob[..old_bytes.len()].copy_from_slice(&old_bytes);
    for (i, (dll, funcs)) in list.iter().enumerate() {
        let (ilt, iat) = tables[i];
        let name_off = blob.len();
        blob.extend_from_slice(dll.as_bytes());
        blob.push(0);
        for (k, f) in funcs.iter().enumerate() {
            let thunk: u64 = match f {
                NewImport::Ordinal(o) => (1u64 << (ps * 8 - 1)) | *o as u64,
                NewImport::Name(n) => {
                    if !blob.len().is_multiple_of(2) {
                        blob.push(0);
                    }
                    let hn = blob.len();
                    blob.extend_from_slice(&[0, 0]);
                    blob.extend_from_slice(n.as_bytes());
                    blob.push(0);
                    (base + hn) as u64
                }
            };
            for t in [ilt, iat] {
                if ps == 8 {
                    w64(&mut blob, t + k * 8, thunk);
                } else {
                    w32(&mut blob, t + k * 4, thunk as u32);
                }
            }
        }
        let d = (old.len() + i) * 20;
        w32(&mut blob, d, (base + ilt) as u32);
        w32(&mut blob, d + 12, (base + name_off) as u32);
        w32(&mut blob, d + 16, (base + iat) as u32);
    }

    let va = add_section_at(data, base as u32, ".idata2", &blob, 0xC000_0040)?;
    w32(data, pe.dirs_off + 8, va);
    w32(data, pe.dirs_off + 12, descs as u32);
    let total: usize = list.iter().map(|(_, f)| f.len()).sum();
    Ok(format!("Import table rebuilt in new section .idata2 at RVA {va:08X}: {} module(s), {total} function(s) added", list.len()))
}

/// Replace the raw data of the section at `idx`, growing or shrinking the file.
/// Only allowed for the last section in both file and virtual order.
pub fn resize_last_section(data: &mut Vec<u8>, idx: usize, content: &[u8]) -> Res<()> {
    let pe = layout_of(data)?;
    if content.len() > u32::MAX as usize / 2 {
        return Err("the section content is too large".into());
    }
    let s = pe.sections.get(idx).ok_or("no such section")?.clone();
    let start = s.roff as usize;
    // Raw data may be mapped over the headers (PointerToRawData 0 in tiny or
    // packed files); replacing it would replace the headers as well.
    let headers = (pe.sec_table + pe.sections.len() * 40).max(pe.size_of_headers as usize);
    if s.rsize == 0 || start > data.len() {
        return Err("the section has no raw data in the file".into());
    }
    if start < headers {
        return Err("the section's raw data overlaps the headers".into());
    }
    let end = (start + s.rsize as usize).min(data.len());
    let new_rsize = align_up(content.len() as u64, pe.file_align.max(1) as u64) as usize;
    let mut block = content.to_vec();
    block.resize(new_rsize, 0);
    atomic(data, |data| {
        data.splice(start..end, block);
        shift_security(data, &pe, end, new_rsize as i64 - (end - start) as i64);
        w32(data, s.hdr_off + 8, content.len() as u32);
        w32(data, s.hdr_off + 16, new_rsize as u32);
        fix_size_of_image(data)?;
        Ok(String::new())
    })
    .map(drop)
}

// ---------------------------------------------------------------------------
// Imports: remove, rename, unbind

fn cstr_len(data: &[u8], off: usize) -> usize {
    data.get(off..).map_or(0, |b| b.iter().take(4096).position(|c| *c == 0).unwrap_or(0))
}

fn check_name(name: &str) -> Res<()> {
    if name.is_empty() || name.len() > 512 || !name.bytes().all(|b| (0x21..0x7f).contains(&b)) {
        return Err("names must be 1 to 512 printable ASCII characters without spaces".into());
    }
    Ok(())
}

/// Remove one module from the import directory. Its IAT slots stay in the
/// image but are no longer filled by the loader, so code that still calls
/// through them will crash.
pub fn remove_import_module(data: &mut Vec<u8>, module: usize) -> Res<String> {
    let pe = layout_of(data)?;
    let mods = pe.imports(data);
    let m = mods.get(module).ok_or("no such import module")?;
    let first = mods[0].desc_off;
    let end = first + (mods.len() + 1) * 20;
    if end > data.len() {
        return Err("the import directory is truncated".into());
    }
    data.copy_within(m.desc_off + 20..end, m.desc_off);
    data[end - 20..end].fill(0);
    let (_, size) = pe.dir(data, 1);
    if size >= 40 {
        w32(data, pe.dirs_off + 12, size - 20);
    }
    Ok(format!("Removed {} from the import directory ({} function(s)). Its IAT slots are no longer resolved", m.name, m.funcs.len()))
}

/// Rename an imported module (`func` is None) or one of its functions.
/// The new name is written in place when it fits, otherwise into a new section.
pub fn rename_import(data: &mut Vec<u8>, module: usize, func: Option<usize>, new_name: &str) -> Res<String> {
    check_name(new_name)?;
    let pe = layout_of(data)?;
    let mods = pe.imports(data);
    let m = mods.get(module).ok_or("no such import module")?;
    let rd = Rd::new(data, Endian::Little);
    match func {
        None => {
            let name_off = pe.rva_to_off(rd.u32(m.desc_off + 12)).ok_or("the module name is not inside the file")?;
            let old = cstr_len(data, name_off);
            if new_name.len() <= old {
                data[name_off..name_off + old].fill(0);
                data[name_off..name_off + new_name.len()].copy_from_slice(new_name.as_bytes());
                return Ok(format!("Module renamed to {new_name} in place"));
            }
            let mut blob = new_name.as_bytes().to_vec();
            blob.push(0);
            let va = add_section(data, ".names", &blob, blob.len() as u32, 0x4000_0040)?;
            // Adding a section can move raw data, so locate the descriptor again.
            let pe = pe_of(data)?;
            let desc = pe.imports(data).get(module).ok_or("the import directory changed unexpectedly")?.desc_off;
            w32(data, desc + 12, va);
            Ok(format!("Module renamed to {new_name}; the name is stored in a new section at RVA {va:08X}"))
        }
        Some(fi) => {
            let f = m.funcs.get(fi).ok_or("no such function")?;
            let hn = f.hint_name_off.ok_or("the function is imported by ordinal and has no name")?;
            let old = cstr_len(data, hn + 2);
            if new_name.len() <= old {
                data[hn + 2..hn + 2 + old].fill(0);
                data[hn + 2..hn + 2 + new_name.len()].copy_from_slice(new_name.as_bytes());
                return Ok(format!("Function renamed to {new_name} in place"));
            }
            let ps = pe.ptr_size();
            let old_thunk = rd.uint(f.thunk_off, ps);
            let iat_rva = f.iat_rva;
            let mut blob = vec![0u8, 0];
            blob.extend_from_slice(new_name.as_bytes());
            blob.push(0);
            let va = add_section(data, ".names", &blob, blob.len() as u32, 0x4000_0040)?;
            // Adding a section can move raw data, so locate the thunks again.
            let pe = pe_of(data)?;
            let mods = pe.imports(data);
            let thunk_off = mods.get(module).and_then(|m| m.funcs.get(fi)).ok_or("the import directory changed unexpectedly")?.thunk_off;
            let iat_off = pe.rva_to_off(iat_rva);
            let put = |data: &mut Vec<u8>, off: usize| if ps == 8 { w64(data, off, va as u64) } else { w32(data, off, va) };
            put(data, thunk_off);
            // An unbound IAT mirrors the lookup table and has to follow it.
            if let Some(io) = iat_off.filter(|io| *io != thunk_off)
                && Rd::new(data, Endian::Little).uint(io, ps) == old_thunk
            {
                put(data, io);
            }
            Ok(format!("Function renamed to {new_name}; the name is stored in a new section at RVA {va:08X}"))
        }
    }
}

/// Undo import binding: clear the bound timestamps, restore the IAT from the
/// lookup tables and drop the bound import directory.
pub fn unbind_imports(data: &mut Vec<u8>) -> Res<String> {
    let pe = layout_of(data)?;
    let ps = pe.ptr_size();
    let mut restored = 0usize;
    let mut bound = 0usize;
    for m in pe.imports(data) {
        let rd = Rd::new(data, Endian::Little);
        let oft = rd.u32(m.desc_off);
        if rd.u32(m.desc_off + 4) != 0 {
            bound += 1;
        }
        let mut copies = Vec::new();
        if oft != 0 {
            for f in &m.funcs {
                if let Some(io) = pe.rva_to_off(f.iat_rva).filter(|io| *io != f.thunk_off && rd.has(*io, ps)) {
                    let v = rd.uint(f.thunk_off, ps);
                    if rd.uint(io, ps) != v {
                        copies.push((io, v));
                    }
                }
            }
        }
        for (io, v) in copies {
            if ps == 8 {
                w64(data, io, v);
            } else {
                w32(data, io, v as u32);
            }
            restored += 1;
        }
        w32(data, m.desc_off + 4, 0);
        w32(data, m.desc_off + 8, 0);
    }
    let had_dir = pe.dir(data, 11).0 != 0;
    if pe.num_dirs > 11 {
        w32(data, pe.dirs_off + 11 * 8, 0);
        w32(data, pe.dirs_off + 11 * 8 + 4, 0);
    }
    if bound == 0 && restored == 0 && !had_dir {
        return Ok("The imports are not bound; nothing to do".into());
    }
    Ok(format!("Unbound {bound} module(s), restored {restored} IAT entr(ies){}", if had_dir { ", bound import directory removed" } else { "" }))
}

// ---------------------------------------------------------------------------
// Exports: parse into a model, edit the model, write a fresh directory

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExportFn {
    /// 0 marks an unused ordinal slot.
    pub rva: u32,
    /// Set when the entry forwards to another DLL ("NTDLL.RtlAllocateHeap").
    pub forwarder: Option<String>,
    pub names: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExportTable {
    pub dll_name: String,
    pub base: u32,
    pub characteristics: u32,
    pub time: u32,
    pub major: u16,
    pub minor: u16,
    /// Index plus `base` is the ordinal.
    pub funcs: Vec<ExportFn>,
}

const MAX_EXPORTS: usize = 65536;

pub fn parse_exports(data: &[u8], pe: &Pe) -> Option<ExportTable> {
    let rd = Rd::new(data, Endian::Little);
    let (rva, size) = pe.dir(data, 0);
    let off = (rva != 0).then(|| pe.rva_to_off(rva)).flatten()?;
    if !rd.has(off, 40) {
        return None;
    }
    let nfuncs = (rd.u32(off + 20) as usize).min(MAX_EXPORTS);
    let nnames = (rd.u32(off + 24) as usize).min(MAX_EXPORTS);
    let mut t = ExportTable {
        dll_name: pe.rva_to_off(rd.u32(off + 12)).map(|o| rd.cstr(o, 256)).unwrap_or_default(),
        base: rd.u32(off + 16),
        characteristics: rd.u32(off),
        time: rd.u32(off + 4),
        major: rd.u16(off + 8),
        minor: rd.u16(off + 10),
        funcs: Vec::new(),
    };
    if let Some(funcs) = pe.rva_to_off(rd.u32(off + 28)) {
        for i in 0..nfuncs {
            if !rd.has(funcs + i * 4, 4) {
                break;
            }
            let frva = rd.u32(funcs + i * 4);
            let forwarder = (frva >= rva && frva < rva.wrapping_add(size)).then(|| pe.rva_to_off(frva).map(|o| rd.cstr(o, 256))).flatten();
            t.funcs.push(ExportFn { rva: frva, forwarder, names: Vec::new() });
        }
    }
    if let (Some(names), Some(ords)) = (pe.rva_to_off(rd.u32(off + 32)), pe.rva_to_off(rd.u32(off + 36))) {
        for i in 0..nnames {
            if !rd.has(names + i * 4, 4) || !rd.has(ords + i * 2, 2) {
                break;
            }
            let idx = rd.u16(ords + i * 2) as usize;
            if let (Some(f), Some(o)) = (t.funcs.get_mut(idx), pe.rva_to_off(rd.u32(names + i * 4))) {
                f.names.push(rd.cstr(o, 512));
            }
        }
    }
    Some(t)
}

/// Write the export table into a new `.edata2` section and point the export
/// directory at it. Names are sorted, as the loader's binary search requires.
pub fn write_exports(data: &mut Vec<u8>, t: &ExportTable) -> Res<String> {
    let pe = layout_of(data)?;
    if pe.num_dirs < 1 {
        return Err("the optional header has no export data directory".into());
    }
    if t.funcs.len() > MAX_EXPORTS {
        return Err("too many exported functions".into());
    }
    check_name(&t.dll_name)?;
    let mut names: Vec<(&str, u16)> = Vec::new();
    for (i, f) in t.funcs.iter().enumerate() {
        for n in &f.names {
            check_name(n)?;
            names.push((n, i as u16));
        }
        if let Some(fw) = &f.forwarder {
            check_name(fw)?;
        }
    }
    names.sort();
    if names.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err("two exports have the same name".into());
    }
    let base = pe.next_section_rva();
    let eat = 40;
    let npt = eat + t.funcs.len() * 4;
    let ot = npt + names.len() * 4;
    let strings = ot + names.len() * 2;
    let mut blob = vec![0u8; strings];
    let push_str = |blob: &mut Vec<u8>, s: &str| {
        let rva = base + blob.len() as u32;
        blob.extend_from_slice(s.as_bytes());
        blob.push(0);
        rva
    };
    let name_rva = push_str(&mut blob, &t.dll_name);
    for (i, (n, ord)) in names.iter().enumerate() {
        let rva = push_str(&mut blob, n);
        w32(&mut blob, npt + i * 4, rva);
        w16(&mut blob, ot + i * 2, *ord);
    }
    for (i, f) in t.funcs.iter().enumerate() {
        let rva = match &f.forwarder {
            Some(fw) => push_str(&mut blob, fw),
            None => f.rva,
        };
        w32(&mut blob, eat + i * 4, rva);
    }
    w32(&mut blob, 0, t.characteristics);
    w32(&mut blob, 4, t.time);
    w16(&mut blob, 8, t.major);
    w16(&mut blob, 10, t.minor);
    w32(&mut blob, 12, name_rva);
    w32(&mut blob, 16, t.base);
    w32(&mut blob, 20, t.funcs.len() as u32);
    w32(&mut blob, 24, names.len() as u32);
    w32(&mut blob, 28, base + eat as u32);
    w32(&mut blob, 32, base + npt as u32);
    w32(&mut blob, 36, base + ot as u32);
    let va = add_section_at(data, base, ".edata2", &blob, 0x4000_0040)?;
    w32(data, pe.dirs_off, va);
    w32(data, pe.dirs_off + 4, blob.len() as u32);
    Ok(format!("Export directory rebuilt in new section .edata2 at RVA {va:08X}: {} function(s), {} name(s)", t.funcs.len(), names.len()))
}

// ---------------------------------------------------------------------------
// Base relocations: parse into a list, edit the list, write it back

/// Relocations read for the viewer. A larger table is shown cut off, and the
/// editors refuse it instead of writing the shortened list back.
const MAX_RELOCS: usize = 4_000_000;

/// IMAGE_REL_BASED_HIGHADJ: the entry is followed by a slot that holds the
/// low half of its value instead of a type and offset.
const REL_HIGHADJ: u8 = 4;
const HIGHADJ_REFUSED: &str = "the relocation table has HIGHADJ entries, which take two slots each; it cannot be rewritten";

/// Every base relocation as (RVA, type). Padding entries and the parameter
/// slot of a HIGHADJ entry are left out.
pub fn parse_relocs(data: &[u8], pe: &Pe) -> Vec<(u32, u8)> {
    relocs_of(data, pe).0
}

/// The whole relocation list, for an editor that writes it back.
fn editable_relocs(data: &[u8], pe: &Pe) -> Res<Vec<(u32, u8)>> {
    let (list, _, complete) = relocs_of(data, pe);
    if !complete {
        return Err(format!("the relocation table is too large to edit (more than {MAX_RELOCS} entries)"));
    }
    // The list does not carry the parameter slots, and sorting would part the pairs.
    if list.iter().any(|r| r.1 == REL_HIGHADJ) {
        return Err(HIGHADJ_REFUSED.into());
    }
    Ok(list)
}

/// The relocation list, whether the blocks fill the directory exactly, and
/// whether the list is complete (the cap was not reached).
/// A directory whose Size reaches past its last block covers bytes that are
/// not relocations, so it must not be rewritten where it is.
fn relocs_of(data: &[u8], pe: &Pe) -> (Vec<(u32, u8)>, bool, bool) {
    let rd = Rd::new(data, Endian::Little);
    let (rva, size) = pe.dir(data, 5);
    let Some(mut off) = (rva != 0).then(|| pe.rva_to_off(rva)).flatten() else { return (Vec::new(), false, true) };
    let dir_end = off.saturating_add(size as usize);
    let end = dir_end.min(data.len());
    let mut out = Vec::new();
    while end.saturating_sub(off) >= 8 && out.len() < MAX_RELOCS {
        let page = rd.u32(off);
        let block = rd.u32(off + 4) as usize;
        if block < 8 {
            break;
        }
        // A block never reaches past the directory, whatever its size field says.
        let mut parameter = false;
        for i in 0..((block - 8) / 2).min((end - off - 8) / 2) {
            let e = rd.u16(off + 8 + i * 2);
            if std::mem::take(&mut parameter) {
                continue;
            }
            if e >> 12 != 0 {
                out.push((page.wrapping_add((e & 0xFFF) as u32), (e >> 12) as u8));
                parameter = (e >> 12) as u8 == REL_HIGHADJ;
            }
        }
        off = off.saturating_add(block);
    }
    let complete = out.len() < MAX_RELOCS;
    (out, off == dir_end, complete)
}

fn serialize_relocs(list: &[(u32, u8)]) -> Vec<u8> {
    let mut sorted = list.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut out = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let page = sorted[i].0 & !0xFFF;
        let n = sorted[i..].iter().take_while(|r| r.0 & !0xFFF == page).count();
        // Blocks are padded to a multiple of four bytes with an absolute entry.
        let entries = n + n % 2;
        out.extend_from_slice(&page.to_le_bytes());
        out.extend_from_slice(&((8 + entries * 2) as u32).to_le_bytes());
        for (rva, ty) in &sorted[i..i + n] {
            out.extend_from_slice(&(((*ty as u16) << 12) | (*rva & 0xFFF) as u16).to_le_bytes());
        }
        if n % 2 == 1 {
            out.extend_from_slice(&[0, 0]);
        }
        i += n;
    }
    out
}

/// Write the relocation list: in place when it fits in the current
/// directory or in the unused tail of its section, otherwise into a new
/// `.reloc2` section.
pub fn write_relocs(data: &mut Vec<u8>, list: &[(u32, u8)]) -> Res<String> {
    let pe = layout_of(data)?;
    if pe.num_dirs < 6 {
        return Err("the optional header has no base relocation data directory".into());
    }
    if list.iter().any(|r| r.1 == 0 || r.1 > 15) {
        return Err("relocation types are 1 to 15".into());
    }
    if list.iter().any(|r| r.1 == REL_HIGHADJ) {
        return Err("a HIGHADJ relocation (type 4) takes two slots and cannot be written".into());
    }
    if relocs_of(data, &pe).0.iter().any(|r| r.1 == REL_HIGHADJ) {
        return Err(HIGHADJ_REFUSED.into());
    }
    let blob = serialize_relocs(list);
    let (rva, size) = pe.dir(data, 5);
    // In place only when the directory is exactly its blocks and lies inside
    // the raw data of one section: its Size comes from the file, and what
    // follows a shorter table belongs to something else.
    let exact = relocs_of(data, &pe).1;
    let in_place = pe.section_of_rva(rva).map(|i| &pe.sections[i]).and_then(|s| {
        let d = (rva - s.va) as u64;
        let (old_end, new_end) = (d + size as u64, d + blob.len() as u64);
        let inside = |end: u64| end <= s.rsize as u64 && s.roff as u64 + end <= data.len() as u64;
        if !exact || !inside(old_end) {
            return None;
        }
        let off = s.roff as usize + d as usize;
        if new_end <= old_end {
            return Some((off, None));
        }
        // A longer table may take the padding behind it, the way a table
        // moved to `.reloc2` leaves a padded tail: only when the table is the
        // last thing in its section, the bytes are unused (all zero, no data
        // directory starts there) and the section stays clear of the next one.
        let tail = data.get(off + size as usize..off + blob.len())?;
        let free = old_end >= s.vsize as u64
            && s.vsize != 0
            && inside(new_end)
            && tail.iter().all(|b| *b == 0)
            && (0..pe.num_dirs).all(|i| {
                let start = pe.dir(data, i).0 as u64;
                i == 4 || start < rva as u64 + size as u64 || start >= s.va as u64 + new_end
            })
            && pe.sections.iter().all(|o| o.va <= s.va || o.va as u64 >= s.va as u64 + new_end);
        free.then_some((off, Some((s.hdr_off, s.va as u64, new_end))))
    });
    match in_place {
        Some((off, grown)) => {
            data[off..off + size as usize].fill(0);
            data[off..off + blob.len()].copy_from_slice(&blob);
            w32(data, pe.dirs_off + 5 * 8 + 4, blob.len() as u32);
            if let Some((hdr, va, vsize)) = grown {
                // The section now ends with the table, and the image covers it.
                w32(data, hdr + 8, vsize as u32);
                let image = align_up(va + vsize, pe.section_align.max(1) as u64) as u32;
                if image > Rd::new(data, Endian::Little).u32(pe.opt + 56) {
                    w32(data, pe.opt + 56, image);
                }
            }
            Ok(format!("Relocation table rewritten in place: {} entr(ies), {} bytes", list.len(), blob.len()))
        }
        None => {
            if blob.is_empty() {
                w32(data, pe.dirs_off + 5 * 8, 0);
                w32(data, pe.dirs_off + 5 * 8 + 4, 0);
                return Ok("Relocation table removed".into());
            }
            let va = add_section(data, ".reloc2", &blob, blob.len() as u32, 0x4200_0040)?;
            w32(data, pe.dirs_off + 5 * 8, va);
            w32(data, pe.dirs_off + 5 * 8 + 4, blob.len() as u32);
            Ok(format!("Relocation table rebuilt in new section .reloc2 at RVA {va:08X}: {} entr(ies)", list.len()))
        }
    }
}

/// Relocation type for a pointer sized absolute address in this image.
pub fn pointer_reloc_type(pe: &Pe) -> u8 {
    if pe.is64 { 10 } else { 3 }
}

pub fn add_reloc(data: &mut Vec<u8>, rva: u32, ty: u8) -> Res<String> {
    let pe = layout_of(data)?;
    if pe.rva_to_off(rva).is_none() {
        return Err(format!("RVA {rva:08X} is not inside the file"));
    }
    let mut list = editable_relocs(data, &pe)?;
    if list.iter().any(|r| r.0 == rva) {
        return Err(format!("RVA {rva:08X} already has a relocation"));
    }
    list.push((rva, ty));
    write_relocs(data, &list)
}

pub fn remove_reloc(data: &mut Vec<u8>, rva: u32) -> Res<String> {
    let pe = layout_of(data)?;
    let mut list = editable_relocs(data, &pe)?;
    let before = list.len();
    list.retain(|r| r.0 != rva);
    if list.len() == before {
        return Err(format!("RVA {rva:08X} has no relocation"));
    }
    write_relocs(data, &list)
}

// ---------------------------------------------------------------------------
// TLS callbacks

/// File offset of the TLS directory, when the file has one. A directory can
/// exist without a callback array; `add_tls_callback` then creates the array.
pub fn tls_directory(data: &[u8], pe: &Pe) -> Option<usize> {
    let (rva, _) = pe.dir(data, 9);
    (rva != 0).then(|| pe.rva_to_off(rva)).flatten()
}

/// Most callbacks the viewer lists; the editors refuse a longer array.
const MAX_TLS_CALLBACKS: usize = 1024;

/// File offset of the callback array and the callbacks (VAs) in it.
pub fn tls_callbacks(data: &[u8], pe: &Pe) -> Option<(usize, Vec<u64>)> {
    tls_callbacks_of(data, pe).map(|(array, list, _)| (array, list))
}

/// The callback array, and whether the list is all of it: the terminator or
/// the end of the file was reached before the cap.
fn tls_callbacks_of(data: &[u8], pe: &Pe) -> Option<(usize, Vec<u64>, bool)> {
    let rd = Rd::new(data, Endian::Little);
    let dir = tls_directory(data, pe)?;
    let ps = pe.ptr_size();
    let array = pe.va_to_off(rd.uint(dir + 3 * ps, ps))?;
    let mut list = Vec::new();
    loop {
        let at = array + list.len() * ps;
        if !rd.has(at, ps) {
            return Some((array, list, true));
        }
        let v = rd.uint(at, ps);
        if v == 0 {
            return Some((array, list, true));
        }
        if list.len() == MAX_TLS_CALLBACKS {
            return Some((array, list, false));
        }
        list.push(v);
    }
}

/// The callbacks for an editor, which writes the whole list back: a list cut
/// at the cap would drop the rest.
fn editable_tls_callbacks(data: &[u8], pe: &Pe) -> Res<Option<(usize, Vec<u64>)>> {
    match tls_callbacks_of(data, pe) {
        Some((_, _, false)) => Err(format!("the TLS callback array has more than {MAX_TLS_CALLBACKS} entries; it cannot be edited")),
        found => Ok(found.map(|(array, list, _)| (array, list))),
    }
}

/// Check that `len` bytes at `rva` are file bytes in one piece that an editor
/// may rewrite: inside the raw data of a single section, inside the file, and
/// with that raw data behind the headers. A range that only starts in a
/// section would spill into whatever follows it in the file. A range mapped
/// through the headers, or through a section whose raw data lies over them,
/// shares its bytes with the header structures and with every section header
/// added later, so the editors that add sections do not touch it. The error
/// names `what` and which of the two it is.
fn mapped_whole(data: &[u8], pe: &Pe, what: &str, rva: u32, len: usize) -> Res<()> {
    let outside = || format!("the {what} is not fully inside its section's raw data");
    let Some(last) = len.checked_sub(1).and_then(|d| u32::try_from(d).ok()).and_then(|d| rva.checked_add(d)) else { return Err(outside()) };
    let Some(start) = pe.rva_to_off(rva) else { return Err(outside()) };
    let section = pe.section_of_rva(rva);
    let behind_headers =
        section.is_some_and(|i| pe.sections[i].roff >= pe.size_of_headers) && start >= pe.sec_table.saturating_add(pe.sections.len().saturating_mul(40));
    if !behind_headers {
        return Err(format!(
            "the {what} is mapped through the headers (it lies outside every section, or in a section whose raw data overlaps the headers); bxplore does not edit TLS data there"
        ));
    }
    let whole = pe.section_of_rva(last) == section && pe.rva_to_off(last).is_some_and(|end| start.checked_add(len - 1) == Some(end) && end < data.len());
    if whole { Ok(()) } else { Err(outside()) }
}

/// The TLS directory for an editor: its file offset, once the whole
/// directory is known to be file bytes of one section behind the headers.
fn editable_tls_directory(data: &[u8], pe: &Pe) -> Res<Option<usize>> {
    let (rva, _) = pe.dir(data, 9);
    let Some(dir) = tls_directory(data, pe) else { return Ok(None) };
    // IMAGE_TLS_DIRECTORY: four pointers and two 32-bit fields.
    mapped_whole(data, pe, "TLS directory", rva, 4 * pe.ptr_size() + 8)?;
    Ok(Some(dir))
}

fn has_relocs(data: &[u8], pe: &Pe) -> bool {
    pe.dir(data, 5).0 != 0 && Rd::new(data, Endian::Little).u16(pe.file_hdr + 18) & 1 == 0
}

fn put_ptr(data: &mut [u8], pe: &Pe, off: usize, v: u64) {
    if pe.is64 {
        w64(data, off, v);
    } else {
        w32(data, off, v as u32);
    }
}

/// Run an edit that takes several fallible steps; a failure in a later step
/// puts the buffer back, so an error always means nothing changed.
fn atomic(data: &mut Vec<u8>, edit: impl FnOnce(&mut Vec<u8>) -> Res<String>) -> Res<String> {
    let backup = data.clone();
    let result = edit(data);
    if result.is_err() {
        *data = backup;
    }
    result
}

/// Remove one TLS callback. The array is shortened in place and the
/// relocation of the slot that becomes the terminator is dropped.
pub fn remove_tls_callback(data: &mut Vec<u8>, index: usize) -> Res<String> {
    atomic(data, |data| remove_tls_callback_inner(data, index))
}

fn remove_tls_callback_inner(data: &mut Vec<u8>, index: usize) -> Res<String> {
    let pe = layout_of(data)?;
    let dir = editable_tls_directory(data, &pe)?.ok_or("the file has no TLS callback array")?;
    let (array, mut list) = editable_tls_callbacks(data, &pe)?.ok_or("the file has no TLS callback array")?;
    if index >= list.len() {
        return Err("no such TLS callback".into());
    }
    let ps = pe.ptr_size();
    // The array is rewritten up to and including its terminator.
    let array_va = Rd::new(data, Endian::Little).uint(dir + 3 * ps, ps);
    let array_rva = array_va.checked_sub(pe.image_base).and_then(|v| u32::try_from(v).ok());
    let Some(array_rva) = array_rva else {
        return Err("the TLS callback array is not fully inside its section's raw data".into());
    };
    mapped_whole(data, &pe, "TLS callback array", array_rva, (list.len() + 1) * ps)?;
    let removed = list.remove(index);
    let last = array + list.len() * ps;
    for (i, v) in list.iter().enumerate() {
        put_ptr(data, &pe, array + i * ps, *v);
    }
    put_ptr(data, &pe, last, 0);
    // A relocation on the new terminator would turn it into a bogus callback
    // as soon as the image is rebased. Its RVA follows from the array's own:
    // a file offset can belong to several sections, or to none.
    let rva = array_rva + (list.len() * ps) as u32;
    if editable_relocs(data, &pe)?.iter().any(|r| r.0 == rva) {
        remove_reloc(data, rva)?;
    }
    Ok(format!("TLS callback {removed:X} removed, {} left", list.len()))
}

/// Add a TLS callback. The array is rebuilt in a new section and gets
/// relocations when the image has a relocation table.
pub fn add_tls_callback(data: &mut Vec<u8>, callback_va: u64) -> Res<String> {
    atomic(data, |data| add_tls_callback_inner(data, callback_va))
}

fn add_tls_callback_inner(data: &mut Vec<u8>, callback_va: u64) -> Res<String> {
    let pe = layout_of(data)?;
    let (rva, _) = pe.dir(data, 9);
    editable_tls_directory(data, &pe)?.ok_or("the file has no TLS directory to attach a callback to")?;
    if pe.va_to_off(callback_va).is_none() {
        return Err(format!("{callback_va:X} is not an address inside the image"));
    }
    let mut list = editable_tls_callbacks(data, &pe)?.map(|t| t.1).unwrap_or_default();
    if list.contains(&callback_va) {
        return Err("this callback is already registered".into());
    }
    list.push(callback_va);
    let ps = pe.ptr_size();
    let mut blob = vec![0u8; (list.len() + 1) * ps];
    for (i, v) in list.iter().enumerate() {
        put_ptr(&mut blob, &pe, i * ps, *v);
    }
    let relocate = has_relocs(data, &pe);
    if relocate {
        editable_relocs(data, &pe)?;
    }
    let ty = pointer_reloc_type(&pe);
    // The directory stores the array as a virtual address of the image's pointer size.
    let top = if pe.is64 { u64::MAX } else { u32::MAX as u64 };
    let base = pe.next_section_rva();
    let array_va = pe.image_base.checked_add(base as u64).filter(|v| v.checked_add(blob.len() as u64).is_some_and(|end| end <= top));
    let array_va = array_va.ok_or("the image base leaves no room for the new section")?;
    let va = add_section_at(data, base, ".tlscb", &blob, 0x4000_0040)?;
    // Adding a section can move raw data, and the directory with it.
    let pe = pe_of(data)?;
    let dir = editable_tls_directory(data, &pe)?.ok_or("the TLS directory is no longer mapped once the section is added")?;
    put_ptr(data, &pe, dir + 3 * ps, array_va);
    if relocate {
        let mut relocs = editable_relocs(data, &pe)?;
        relocs.extend((0..list.len()).map(|i| (va + (i * ps) as u32, ty)));
        // The directory field holding the array address needs one as well.
        let field = rva + (3 * ps) as u32;
        if !relocs.iter().any(|r| r.0 == field) {
            relocs.push((field, ty));
        }
        write_relocs(data, &relocs)?;
    }
    Ok(format!("TLS callback {callback_va:X} added ({} in total); the array now lives in a new section at RVA {va:08X}", list.len()))
}

// ---------------------------------------------------------------------------
// Delay imports

pub struct DelayModule {
    pub name: String,
    pub name_rva: u32,
    pub iat_rva: u32,
    /// Lookup entries as they must appear in a normal import lookup table.
    pub thunks: Vec<u64>,
}

/// Lookup entries read across all delay modules. Descriptors may share one
/// lookup table, so a cap per module would not bound the total.
const MAX_DELAY_THUNKS: usize = 65536;

pub fn delay_imports(data: &[u8], pe: &Pe) -> Vec<DelayModule> {
    delay_imports_of(data, pe).0
}

const SCN_MEM_WRITE: u32 = 0x8000_0000;

/// The delay modules, and whether the list is complete (no cap was reached).
fn delay_imports_of(data: &[u8], pe: &Pe) -> (Vec<DelayModule>, bool) {
    let rd = Rd::new(data, Endian::Little);
    let (rva, _) = pe.dir(data, 13);
    let Some(mut off) = (rva != 0).then(|| pe.rva_to_off(rva)).flatten() else { return (Vec::new(), true) };
    let ps = pe.ptr_size();
    let flag = 1u64 << (ps * 8 - 1);
    let mut out = Vec::new();
    let mut budget = MAX_DELAY_THUNKS;
    let mut complete = true;
    while rd.has(off, 32) {
        if rd.bytes(off, 32).iter().all(|b| *b == 0) {
            break;
        }
        if out.len() >= 1024 {
            complete = false;
            break;
        }
        // Old 32 bit images store virtual addresses instead of RVAs.
        let by_rva = rd.u32(off) & 1 != 0;
        let fix = |v: u64| -> u32 { if by_rva { v as u32 } else { v.wrapping_sub(pe.image_base) as u32 } };
        let name_rva = fix(rd.u32(off + 4) as u64);
        let iat_rva = fix(rd.u32(off + 12) as u64);
        let int_rva = fix(rd.u32(off + 16) as u64);
        let mut thunks = Vec::new();
        if let Some(t) = pe.rva_to_off(int_rva) {
            while rd.has(t + thunks.len() * ps, ps) {
                let v = rd.uint(t + thunks.len() * ps, ps);
                if v == 0 {
                    break;
                }
                if budget == 0 {
                    complete = false;
                    break;
                }
                budget -= 1;
                thunks.push(if v & flag != 0 { v } else { fix(v) as u64 });
            }
        }
        out.push(DelayModule { name: pe.rva_to_off(name_rva).map(|o| rd.cstr(o, 256)).unwrap_or_default(), name_rva, iat_rva, thunks });
        off += 32;
    }
    (out, complete)
}

/// Turn delay-loaded imports into ordinary imports. Each delay module gets
/// a normal import descriptor whose address table is the delay IAT, so the
/// loader fills those slots at start-up and the delay-load stubs are never
/// reached. The delay import directory is then cleared. A read-only section
/// that holds a delay IAT is made writable; a delay IAT outside every
/// section is refused.
pub fn convert_delay_imports(data: &mut Vec<u8>) -> Res<String> {
    let pe = layout_of(data)?;
    if pe.num_dirs < 14 {
        return Err("the optional header has no delay import data directory".into());
    }
    let (delay, complete) = delay_imports_of(data, &pe);
    if delay.is_empty() || delay.iter().all(|m| m.thunks.is_empty()) {
        return Err("the file has no delay imports".into());
    }
    if !complete {
        return Err(format!("the delay import tables are too large to convert (more than 1024 modules or {MAX_DELAY_THUNKS} functions)"));
    }
    let ps = pe.ptr_size();
    // The loader writes the resolved addresses into the delay IAT, and it
    // only unprotects the range of the IAT data directory. A protected delay
    // IAT (.didat, usually merged into .rdata) is read-only and outside it.
    let mut read_only: Vec<usize> = Vec::new();
    for m in &delay {
        let last = (m.thunks.len().max(1) - 1) * ps;
        let sec = pe.section_of_rva(m.iat_rva).filter(|i| m.iat_rva.checked_add(last as u32).and_then(|end| pe.section_of_rva(end)) == Some(*i));
        let Some(i) = sec else {
            return Err(format!("the delay import address table of {} (RVA {:08X}) is not inside a section, so the loader cannot fill it", m.name, m.iat_rva));
        };
        if pe.sections[i].chars & SCN_MEM_WRITE == 0 && !read_only.contains(&i) {
            read_only.push(i);
        }
    }
    let old = pe.imports(data);
    let old_bytes: Vec<u8> = old.iter().flat_map(|m| Rd::new(data, Endian::Little).bytes(m.desc_off, 20).to_vec()).collect();
    let base = pe.next_section_rva();
    let descs = (old.len() + delay.len() + 1) * 20;
    let mut blob = vec![0u8; descs];
    blob[..old_bytes.len()].copy_from_slice(&old_bytes);
    let mut funcs = 0;
    for (i, m) in delay.iter().enumerate() {
        let ilt = blob.len();
        for t in &m.thunks {
            if ps == 8 {
                blob.extend_from_slice(&t.to_le_bytes());
            } else {
                blob.extend_from_slice(&(*t as u32).to_le_bytes());
            }
        }
        blob.resize(blob.len() + ps, 0);
        let d = (old.len() + i) * 20;
        w32(&mut blob, d, base + ilt as u32);
        w32(&mut blob, d + 12, m.name_rva);
        w32(&mut blob, d + 16, m.iat_rva);
        funcs += m.thunks.len();
    }
    let va = add_section_at(data, base, ".idata2", &blob, 0xC000_0040)?;
    w32(data, pe.dirs_off + 8, va);
    w32(data, pe.dirs_off + 12, descs as u32);
    w32(data, pe.dirs_off + 13 * 8, 0);
    w32(data, pe.dirs_off + 13 * 8 + 4, 0);
    // The section table stays where it is when a section is added.
    let mut made_writable = String::new();
    for i in read_only {
        let s = &pe.sections[i];
        w32(data, s.hdr_off + 36, s.chars | SCN_MEM_WRITE);
        made_writable.push_str(&format!("; section {} holds a delay import address table and was made writable so that the loader can fill it", s.name));
    }
    Ok(format!(
        "{} delay-loaded module(s) with {funcs} function(s) converted to ordinary imports; the import directory now lives in .idata2 at RVA {va:08X}{made_writable}",
        delay.len()
    ))
}
