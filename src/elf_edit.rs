//! Structural ELF editing of the dynamic section: needed libraries, SONAME,
//! RPATH and RUNPATH.
//!
//! Changes are made in place whenever possible: a string that already exists
//! in the dynamic string table is reused, a shorter replacement overwrites
//! the old string, and new entries use spare slots of the dynamic table.
//! When that is not enough, the string table (and if necessary the dynamic
//! table) is copied to the end of the file and mapped by turning the
//! `PT_NOTE` program header into a `PT_LOAD`, the classic way to gain a
//! segment without moving anything else.

use crate::model::{Endian, clamp_off, read_uint, uint_bytes};

type Res<T> = Result<T, String>;

pub const DT_NULL: u64 = 0;
pub const DT_NEEDED: u64 = 1;
pub const DT_STRTAB: u64 = 5;
pub const DT_STRSZ: u64 = 10;
pub const DT_SONAME: u64 = 14;
pub const DT_RPATH: u64 = 15;
pub const DT_RUNPATH: u64 = 29;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_NOTE: u32 = 4;
const SHT_DYNAMIC: u32 = 6;
const SHT_DYNSYM: u32 = 11;
const SHT_VERDEF: u32 = 0x6fff_fffd;
const SHT_VERNEED: u32 = 0x6fff_fffe;

fn is_string_tag(tag: u64) -> bool {
    matches!(tag, DT_NEEDED | DT_SONAME | DT_RPATH | DT_RUNPATH | 0x7fff_fffd | 0x7fff_ffff)
}

#[derive(Clone, Debug)]
struct Ph {
    off: usize,
    ty: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

#[derive(Clone, Debug)]
struct Sh {
    off: usize,
    ty: u32,
    addr: u64,
    offset: u64,
    size: u64,
}

struct Elf {
    is64: bool,
    en: Endian,
    phs: Vec<Ph>,
    shs: Vec<Sh>,
    /// File offset and capacity (in entries) of the dynamic table.
    dyn_off: usize,
    dyn_cap: usize,
    dyn_ph: usize,
    /// Entries up to, not including, the terminating DT_NULL.
    entries: Vec<(u64, u64)>,
    str_vaddr: u64,
    str_off: usize,
    str_size: usize,
}

#[derive(Clone, Debug)]
pub struct DynEntry {
    pub tag: u64,
    pub value: u64,
    /// Text for string valued tags.
    pub text: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DynInfo {
    pub entries: Vec<DynEntry>,
    /// Unused slots in the dynamic table after the terminator.
    pub spare_slots: usize,
    /// Whether the file has a PT_NOTE header that can be repurposed when
    /// the tables have to grow.
    pub can_grow: bool,
}

impl Elf {
    fn p(&self) -> usize {
        if self.is64 { 8 } else { 4 }
    }

    fn word(&self, data: &[u8], off: usize, size: usize) -> u64 {
        read_uint(data, off, size, self.en).unwrap_or(0)
    }

    fn put(&self, data: &mut [u8], off: usize, size: usize, v: u64) {
        if let Some(b) = off.checked_add(size).and_then(|e| data.get_mut(off..e)) {
            b.copy_from_slice(&uint_bytes(v, size, self.en));
        }
    }

    fn parse(data: &[u8]) -> Res<Elf> {
        if data.len() < 0x34 || &data[..4] != b"\x7fELF" {
            return Err("not an ELF file".into());
        }
        let is64 = match data[4] {
            1 => false,
            2 => true,
            _ => return Err("unknown ELF class".into()),
        };
        let en = match data[5] {
            1 => Endian::Little,
            2 => Endian::Big,
            _ => return Err("unknown ELF data encoding".into()),
        };
        let mut e =
            Elf { is64, en, phs: Vec::new(), shs: Vec::new(), dyn_off: 0, dyn_cap: 0, dyn_ph: 0, entries: Vec::new(), str_vaddr: 0, str_off: 0, str_size: 0 };
        let p = e.p();
        let (phoff, shoff, tail) = if is64 { (0x20, 0x28, 0x36) } else { (0x1C, 0x20, 0x2A) };
        let ph_table = clamp_off(e.word(data, phoff, p));
        let sh_table = clamp_off(e.word(data, shoff, p));
        let phentsize = e.word(data, tail, 2) as usize;
        let phnum = e.word(data, tail + 2, 2) as usize;
        let shentsize = e.word(data, tail + 4, 2) as usize;
        let shnum = e.word(data, tail + 6, 2) as usize;
        if phentsize < if is64 { 56 } else { 32 } {
            return Err("the file has no usable program headers".into());
        }
        for i in 0..phnum {
            let o = ph_table + i * phentsize;
            if o + phentsize > data.len() {
                return Err("the program header table is truncated".into());
            }
            let w = |f: usize| e.word(data, o + f, p);
            e.phs.push(if is64 {
                Ph { off: o, ty: e.word(data, o, 4) as u32, offset: w(8), vaddr: w(16), filesz: w(32), memsz: w(40), align: w(48) }
            } else {
                Ph { off: o, ty: e.word(data, o, 4) as u32, offset: w(4), vaddr: w(8), filesz: w(16), memsz: w(20), align: w(28) }
            });
        }
        if shentsize >= if is64 { 64 } else { 40 } {
            for i in 0..shnum {
                let o = sh_table + i * shentsize;
                if o + shentsize > data.len() {
                    break;
                }
                let w = |f: usize| e.word(data, o + f, p);
                let ty = e.word(data, o + 4, 4) as u32;
                e.shs.push(if is64 {
                    Sh { off: o, ty, addr: w(16), offset: w(24), size: w(32) }
                } else {
                    Sh { off: o, ty, addr: w(12), offset: w(16), size: w(20) }
                });
            }
        }
        e.dyn_ph = e.phs.iter().position(|h| h.ty == PT_DYNAMIC).ok_or("the file has no dynamic section (statically linked)")?;
        let d = &e.phs[e.dyn_ph];
        e.dyn_off = clamp_off(d.offset);
        e.dyn_cap = clamp_off(d.filesz) / (2 * p);
        if e.dyn_off + e.dyn_cap * 2 * p > data.len() || e.dyn_cap == 0 || e.dyn_cap > 65536 {
            return Err("the dynamic section is outside the file".into());
        }
        for i in 0..e.dyn_cap {
            let o = e.dyn_off + i * 2 * p;
            let tag = e.word(data, o, p);
            if tag == DT_NULL {
                break;
            }
            e.entries.push((tag, e.word(data, o + p, p)));
        }
        if e.entries.len() >= e.dyn_cap {
            return Err("the dynamic section has no terminating entry".into());
        }
        let find = |tag: u64| e.entries.iter().find(|x| x.0 == tag).map(|x| x.1);
        e.str_vaddr = find(DT_STRTAB).ok_or("the dynamic section has no string table")?;
        e.str_size = clamp_off(find(DT_STRSZ).ok_or("the dynamic section has no string table size")?);
        e.str_off = e.vaddr_to_off(e.str_vaddr).ok_or("the dynamic string table is not inside a loaded segment")?;
        if e.str_off.checked_add(e.str_size).is_none_or(|end| end > data.len()) || e.str_size == 0 {
            return Err("the dynamic string table is outside the file".into());
        }
        Ok(e)
    }

    fn vaddr_to_off(&self, va: u64) -> Option<usize> {
        self.phs.iter().find(|h| h.ty == PT_LOAD && va >= h.vaddr && va - h.vaddr < h.filesz).map(|h| clamp_off(h.offset.wrapping_add(va - h.vaddr)))
    }

    fn string(&self, data: &[u8], idx: u64) -> Option<String> {
        let idx = usize::try_from(idx).ok().filter(|i| *i < self.str_size)?;
        let b = &data[self.str_off + idx..self.str_off + self.str_size];
        let end = b.iter().position(|c| *c == 0)?;
        Some(String::from_utf8_lossy(&b[..end]).into_owned())
    }

    /// Offset of an existing `s\0` in the string table, if any.
    fn find_string(&self, data: &[u8], s: &str) -> Option<u64> {
        let table = &data[self.str_off..self.str_off + self.str_size];
        let mut needle = s.as_bytes().to_vec();
        needle.push(0);
        table.windows(needle.len()).position(|w| w == needle).map(|i| i as u64)
    }

    /// Every string table offset referenced from outside the dynamic table.
    /// None when the file has no section headers to find them with.
    fn other_refs(&self, data: &[u8]) -> Option<Vec<u64>> {
        if self.shs.is_empty() {
            return None;
        }
        let mut refs = Vec::new();
        for s in &self.shs {
            let (off, size) = (clamp_off(s.offset), clamp_off(s.size));
            if off.checked_add(size).is_none_or(|e| e > data.len()) {
                continue;
            }
            match s.ty {
                SHT_DYNSYM => {
                    let ent = if self.is64 { 24 } else { 16 };
                    refs.extend((0..size / ent).map(|i| self.word(data, off + i * ent, 4)));
                }
                SHT_VERNEED => {
                    let mut o = off;
                    for _ in 0..4096 {
                        if o + 16 > off + size {
                            break;
                        }
                        refs.push(self.word(data, o + 4, 4));
                        let mut a = o + self.word(data, o + 8, 4) as usize;
                        for _ in 0..self.word(data, o + 2, 2).min(4096) {
                            if a + 16 > off + size {
                                break;
                            }
                            refs.push(self.word(data, a + 8, 4));
                            let next = self.word(data, a + 12, 4) as usize;
                            if next == 0 {
                                break;
                            }
                            a += next;
                        }
                        let next = self.word(data, o + 12, 4) as usize;
                        if next == 0 {
                            break;
                        }
                        o += next;
                    }
                }
                SHT_VERDEF => {
                    let mut o = off;
                    for _ in 0..4096 {
                        if o + 20 > off + size {
                            break;
                        }
                        let mut a = o + self.word(data, o + 12, 4) as usize;
                        for _ in 0..self.word(data, o + 6, 2).min(4096) {
                            if a + 8 > off + size {
                                break;
                            }
                            refs.push(self.word(data, a, 4));
                            let next = self.word(data, a + 4, 4) as usize;
                            if next == 0 {
                                break;
                            }
                            a += next;
                        }
                        let next = self.word(data, o + 16, 4) as usize;
                        if next == 0 {
                            break;
                        }
                        o += next;
                    }
                }
                _ => {}
            }
        }
        Some(refs)
    }

    fn write_entries(&self, data: &mut [u8], off: usize, cap: usize, entries: &[(u64, u64)]) {
        let p = self.p();
        for i in 0..cap {
            let (tag, val) = entries.get(i).copied().unwrap_or((DT_NULL, 0));
            self.put(data, off + i * 2 * p, p, tag);
            self.put(data, off + i * 2 * p + p, p, val);
        }
    }

    fn set_ph(&self, data: &mut [u8], h: &Ph, ty: u32, flags: u32, offset: u64, vaddr: u64, size: u64, align: u64) {
        let p = self.p();
        self.put(data, h.off, 4, ty as u64);
        if self.is64 {
            self.put(data, h.off + 4, 4, flags as u64);
            for (f, v) in [(8, offset), (16, vaddr), (24, vaddr), (32, size), (40, size), (48, align)] {
                self.put(data, h.off + f, p, v);
            }
        } else {
            for (f, v) in [(4, offset), (8, vaddr), (12, vaddr), (16, size), (20, size), (28, align)] {
                self.put(data, h.off + f, p, v);
            }
            self.put(data, h.off + 24, 4, flags as u64);
        }
    }

    fn set_sh(&self, data: &mut [u8], s: &Sh, addr: u64, offset: u64, size: u64) {
        let p = self.p();
        let base = if self.is64 { 16 } else { 12 };
        self.put(data, s.off + base, p, addr);
        self.put(data, s.off + base + p, p, offset);
        self.put(data, s.off + base + 2 * p, p, size);
    }
}

pub fn info(data: &[u8]) -> Res<DynInfo> {
    let e = Elf::parse(data)?;
    let entries = e
        .entries
        .iter()
        .map(|(tag, value)| DynEntry { tag: *tag, value: *value, text: is_string_tag(*tag).then(|| e.string(data, *value)).flatten() })
        .collect();
    Ok(DynInfo { entries, spare_slots: e.dyn_cap - e.entries.len() - 1, can_grow: e.phs.iter().any(|h| h.ty == PT_NOTE) })
}

enum Val {
    Raw(u64),
    Str(String),
}

fn check(s: &str) -> Res<()> {
    if s.is_empty() || s.len() > 4096 || s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("the value must be 1 to 4096 characters without control characters".into());
    }
    Ok(())
}

/// Write the wanted dynamic entries, growing the string table and the
/// dynamic table when they do not fit where they are.
fn commit(data: &mut Vec<u8>, e: &Elf, wanted: Vec<(u64, Val)>) -> Res<&'static str> {
    let p = e.p();
    let mut new_strings: Vec<u8> = Vec::new();
    let mut entries: Vec<(u64, u64)> = Vec::new();
    for (tag, val) in wanted {
        let v = match val {
            Val::Raw(v) => v,
            Val::Str(s) => match e.find_string(data, &s) {
                Some(i) => i,
                None => {
                    // Reuse a string queued by an earlier entry of this same edit.
                    let mut needle = s.as_bytes().to_vec();
                    needle.push(0);
                    let at = match new_strings.windows(needle.len()).position(|w| w == needle) {
                        Some(i) => i,
                        None => {
                            new_strings.extend_from_slice(&needle);
                            new_strings.len() - needle.len()
                        }
                    };
                    (e.str_size + at) as u64
                }
            },
        };
        entries.push((tag, v));
    }
    let fits = entries.len() < e.dyn_cap;
    if new_strings.is_empty() && fits {
        e.write_entries(data, e.dyn_off, e.dyn_cap, &entries);
        return Ok("in place");
    }

    // A string table that already ends the file (from an earlier edit) can simply be extended.
    let str_end = e.str_off + e.str_size;
    let tail = e
        .phs
        .iter()
        .position(|h| h.ty == PT_LOAD && clamp_off(h.offset) <= e.str_off && clamp_off(h.offset.wrapping_add(h.filesz)) == str_end && h.filesz == h.memsz);
    if let (Some(t), true, true) = (tail, str_end == data.len(), fits) {
        let h = &e.phs[t];
        let grown = h.filesz + new_strings.len() as u64;
        data.extend_from_slice(&new_strings);
        let new_size = (e.str_size + new_strings.len()) as u64;
        e.set_ph(data, h, PT_LOAD, 6, h.offset, h.vaddr, grown, h.align);
        for x in entries.iter_mut().filter(|x| x.0 == DT_STRSZ) {
            x.1 = new_size;
        }
        e.write_entries(data, e.dyn_off, e.dyn_cap, &entries);
        if let Some(s) = e.shs.iter().find(|s| s.addr == e.str_vaddr && s.ty == 3) {
            e.set_sh(data, s, s.addr, s.offset, new_size);
        }
        return Ok("string table extended at the end of the file");
    }

    // Otherwise the tables move to the end of the file. If an earlier edit
    // already created a segment there it is extended; if not, the PT_NOTE
    // program header is turned into a PT_LOAD that maps the new data.
    let file_off = data.len().div_ceil(16) * 16;
    let (seg, seg_off, seg_vaddr, align, created) = match tail {
        Some(t) => (t, e.phs[t].offset, e.phs[t].vaddr, e.phs[t].align, false),
        None => {
            let note = e
                .phs
                .iter()
                .rposition(|h| h.ty == PT_NOTE)
                .ok_or("the tables have to grow, but the file has no PT_NOTE program header that could be turned into a new segment")?;
            if e.phs[note + 1..].iter().any(|h| h.ty == PT_LOAD) {
                return Err("the tables have to grow, but the PT_NOTE program header is not after the last PT_LOAD, so the segment order would break".into());
            }
            let loads = e.phs.iter().filter(|h| h.ty == PT_LOAD);
            let align = loads.clone().map(|h| h.align).max().unwrap_or(0x1000).clamp(0x1000, 0x1000_0000);
            if !align.is_power_of_two() {
                return Err("the segment alignment is not a power of two".into());
            }
            let top = loads.map(|h| h.vaddr.saturating_add(h.memsz)).max().unwrap_or(0);
            // Loaders require vaddr and file offset to be congruent modulo the alignment.
            let vaddr =
                top.checked_next_multiple_of(align).and_then(|v| v.checked_add(file_off as u64 % align)).ok_or("the image has no address space left")?;
            (note, file_off as u64, vaddr, align, true)
        }
    };
    // Address of the appended data inside the segment.
    let vaddr = (file_off as u64).checked_sub(seg_off).and_then(|d| seg_vaddr.checked_add(d)).ok_or("the image has no address space left")?;
    if !e.is64 && vaddr > 0xFFF0_0000 {
        return Err("the image has no address space left".into());
    }

    let move_dynamic = !fits;
    let dyn_bytes = if move_dynamic { (entries.len() + 4) * 2 * p } else { 0 };
    let new_str_size = e.str_size + new_strings.len();
    let str_vaddr = vaddr + dyn_bytes as u64;
    for x in entries.iter_mut() {
        match x.0 {
            DT_STRTAB => x.1 = str_vaddr,
            DT_STRSZ => x.1 = new_str_size as u64,
            _ => {}
        }
    }
    let mut blob = vec![0u8; dyn_bytes];
    blob.extend_from_slice(&data[e.str_off..e.str_off + e.str_size]);
    blob.extend_from_slice(&new_strings);
    if move_dynamic {
        e.write_entries(&mut blob, 0, dyn_bytes / (2 * p), &entries);
    }
    data.resize(file_off, 0);
    data.extend_from_slice(&blob);
    if move_dynamic {
        let d = &e.phs[e.dyn_ph];
        e.set_ph(data, d, PT_DYNAMIC, 6, file_off as u64, vaddr, dyn_bytes as u64, p as u64);
        if let Some(s) = e.shs.iter().find(|s| s.ty == SHT_DYNAMIC) {
            e.set_sh(data, s, vaddr, file_off as u64, dyn_bytes as u64);
        }
    } else {
        e.write_entries(data, e.dyn_off, e.dyn_cap, &entries);
    }
    let seg_size = data.len() as u64 - seg_off;
    e.set_ph(data, &e.phs[seg], PT_LOAD, 6, seg_off, seg_vaddr, seg_size, align);
    if let Some(s) = e.shs.iter().find(|s| s.addr == e.str_vaddr && s.ty == 3) {
        e.set_sh(data, s, str_vaddr, (file_off + dyn_bytes) as u64, new_str_size as u64);
    }
    Ok(match (created, move_dynamic) {
        (true, true) => "the dynamic and string tables were moved to a new segment at the end of the file (the PT_NOTE header now maps it)",
        (true, false) => "the string table was moved to a new segment at the end of the file (the PT_NOTE header now maps it)",
        (false, _) => "the tables were rewritten in the segment at the end of the file",
    })
}

/// Run an edit and check that the result can still be read back. On any
/// failure the buffer is restored, so a refused edit never changes the file.
fn checked(data: &mut Vec<u8>, edit: impl FnOnce(&mut Vec<u8>) -> Res<String>) -> Res<String> {
    let backup = data.clone();
    let result = edit(data).and_then(|msg| match Elf::parse(data) {
        Ok(_) => Ok(msg),
        Err(e) => Err(format!("the file layout is too unusual to edit safely (after the change: {e})")),
    });
    if result.is_err() {
        *data = backup;
    }
    result
}

fn current(e: &Elf) -> Vec<(u64, Val)> {
    e.entries.iter().map(|(t, v)| (*t, Val::Raw(*v))).collect()
}

/// Add a `DT_NEEDED` entry, after the existing ones.
pub fn add_needed(data: &mut Vec<u8>, name: &str) -> Res<String> {
    checked(data, |data| add_needed_inner(data, name))
}

fn add_needed_inner(data: &mut Vec<u8>, name: &str) -> Res<String> {
    check(name)?;
    let e = Elf::parse(data)?;
    if e.entries.iter().any(|(t, v)| *t == DT_NEEDED && e.string(data, *v).as_deref() == Some(name)) {
        return Err(format!("{name} is already a needed library"));
    }
    let mut wanted = current(&e);
    let at = e.entries.iter().rposition(|x| x.0 == DT_NEEDED).map_or(0, |i| i + 1);
    wanted.insert(at, (DT_NEEDED, Val::Str(name.into())));
    let how = commit(data, &e, wanted)?;
    Ok(format!("Added needed library {name} ({how})"))
}

/// Overwrite the string at `idx` when the new one fits and nothing else
/// points into the bytes that change.
fn overwrite_in_place(data: &mut [u8], e: &Elf, entry: usize, new: &str) -> bool {
    let idx = e.entries[entry].1;
    let Some(old) = e.string(data, idx) else { return false };
    if new.len() > old.len() {
        return false;
    }
    let Some(mut refs) = e.other_refs(data) else { return false };
    refs.extend(e.entries.iter().enumerate().filter(|(i, x)| *i != entry && is_string_tag(x.0)).map(|(_, x)| x.1));
    // Any other reference into the string (including its shared tail) rules this out.
    if refs.iter().any(|r| *r >= idx && *r <= idx + old.len() as u64) {
        return false;
    }
    let at = e.str_off + idx as usize;
    data[at..at + old.len()].fill(0);
    data[at..at + new.len()].copy_from_slice(new.as_bytes());
    true
}

/// Set `DT_SONAME`, `DT_RPATH` or `DT_RUNPATH`, adding the entry when missing.
pub fn set_string(data: &mut Vec<u8>, tag: u64, value: &str) -> Res<String> {
    checked(data, |data| set_string_inner(data, tag, value))
}

fn set_string_inner(data: &mut Vec<u8>, tag: u64, value: &str) -> Res<String> {
    check(value)?;
    if !matches!(tag, DT_SONAME | DT_RPATH | DT_RUNPATH) {
        return Err("only SONAME, RPATH and RUNPATH can be set".into());
    }
    let e = Elf::parse(data)?;
    let name = tag_name(tag);
    let existing = e.entries.iter().position(|x| x.0 == tag);
    if let Some(i) = existing
        && overwrite_in_place(data, &e, i, value)
    {
        return Ok(format!("{name} set to {value} (overwritten in place)"));
    }
    let mut wanted = current(&e);
    match existing {
        Some(i) => wanted[i].1 = Val::Str(value.into()),
        None => wanted.push((tag, Val::Str(value.into()))),
    }
    let how = commit(data, &e, wanted)?;
    Ok(format!("{name} set to {value} ({how})"))
}

/// Change the name of one needed library.
pub fn rename_needed(data: &mut Vec<u8>, old: &str, new: &str) -> Res<String> {
    checked(data, |data| rename_needed_inner(data, old, new))
}

fn rename_needed_inner(data: &mut Vec<u8>, old: &str, new: &str) -> Res<String> {
    check(new)?;
    let e = Elf::parse(data)?;
    let i = e
        .entries
        .iter()
        .position(|(t, v)| *t == DT_NEEDED && e.string(data, *v).as_deref() == Some(old))
        .ok_or_else(|| format!("{old} is not a needed library"))?;
    if overwrite_in_place(data, &e, i, new) {
        return Ok(format!("Needed library {old} renamed to {new} (overwritten in place)"));
    }
    let mut wanted = current(&e);
    wanted[i].1 = Val::Str(new.into());
    let how = commit(data, &e, wanted)?;
    Ok(format!("Needed library {old} renamed to {new} ({how})"))
}

/// Remove the dynamic entry at `index` (a needed library, SONAME, RPATH or RUNPATH).
pub fn remove_entry(data: &mut Vec<u8>, index: usize) -> Res<String> {
    checked(data, |data| remove_entry_inner(data, index))
}

fn remove_entry_inner(data: &mut Vec<u8>, index: usize) -> Res<String> {
    let e = Elf::parse(data)?;
    let (tag, v) = *e.entries.get(index).ok_or("no such dynamic entry")?;
    if !matches!(tag, DT_NEEDED | DT_SONAME | DT_RPATH | DT_RUNPATH) {
        return Err("only needed libraries, SONAME, RPATH and RUNPATH can be removed".into());
    }
    let text = e.string(data, v).unwrap_or_default();
    let mut wanted = current(&e);
    wanted.remove(index);
    commit(data, &e, wanted)?;
    Ok(format!("Removed {} {text}", tag_name(tag)))
}

pub fn tag_name(tag: u64) -> &'static str {
    match tag {
        DT_NEEDED => "NEEDED",
        DT_SONAME => "SONAME",
        DT_RPATH => "RPATH",
        DT_RUNPATH => "RUNPATH",
        _ => "entry",
    }
}

// ---------------------------------------------------------------------------
// Section headers: add a data section, remove a section that is not loaded

struct Shdrs {
    is64: bool,
    en: Endian,
    off: usize,
    entsize: usize,
    num: usize,
    strndx: usize,
}

pub struct SectionInfo {
    pub name: String,
    pub ty: u32,
    pub flags: u64,
    pub offset: u64,
    pub size: u64,
    /// The program needs the section at run time: it has SHF_ALLOC, or its
    /// bytes lie inside a segment. Section flags are only a hint; what is
    /// loaded is decided by the program headers.
    pub loaded: bool,
}

/// Symbols handled per symbol table when a section is removed.
const MAX_SYMBOLS: usize = 4_000_000;

/// The bytes a section has in the file. SHT_NULL and SHT_NOBITS sections have
/// none, whatever their offset and size say; for the others both come from
/// the file and can point anywhere.
fn file_range(s: &SectionInfo) -> (usize, usize) {
    if matches!(s.ty, 0 | 8) { (0, 0) } else { (clamp_off(s.offset), clamp_off(s.size)) }
}

fn overlaps(a: (usize, usize), b: (usize, usize)) -> bool {
    a.1 > 0 && b.1 > 0 && a.0 < b.0.saturating_add(b.1) && b.0 < a.0.saturating_add(a.1)
}

/// File range (offset, length) of the program header table, if there is one.
pub fn program_headers(data: &[u8]) -> Option<(usize, usize)> {
    let s = Shdrs::class(data).ok()?;
    let (phoff, tail) = if s.is64 { (0x20, 0x36) } else { (0x1C, 0x2A) };
    let off = clamp_off(s.word(data, phoff, s.p()));
    let len = (s.word(data, tail, 2) as usize) * (s.word(data, tail + 2, 2) as usize);
    (off != 0 && len != 0).then_some((off, len))
}

impl Shdrs {
    /// Class, byte order and the section header fields of the ELF header, unchecked.
    fn class(data: &[u8]) -> Res<Shdrs> {
        if data.len() < 0x34 || &data[..4] != b"\x7fELF" {
            return Err("not an ELF file".into());
        }
        let is64 = match data[4] {
            1 => false,
            2 => true,
            _ => return Err("unknown ELF class".into()),
        };
        let en = match data[5] {
            1 => Endian::Little,
            2 => Endian::Big,
            _ => return Err("unknown ELF data encoding".into()),
        };
        let w = |off: usize, size: usize| read_uint(data, off, size, en).unwrap_or(0);
        let (shoff, tail) = if is64 { (0x28, 0x3A) } else { (0x20, 0x2E) };
        Ok(Shdrs {
            is64,
            en,
            off: clamp_off(w(shoff, if is64 { 8 } else { 4 })),
            entsize: w(tail, 2) as usize,
            num: w(tail + 2, 2) as usize,
            strndx: w(tail + 4, 2) as usize,
        })
    }

    fn parse(data: &[u8]) -> Res<Shdrs> {
        let s = Shdrs::class(data)?;
        let is64 = s.is64;
        if s.num == 0 || s.off == 0 {
            return Err("the file has no section headers".into());
        }
        if s.entsize != if is64 { 64 } else { 40 } {
            return Err("unexpected section header size".into());
        }
        if s.strndx == 0 {
            return Err("the file has no section name table".into());
        }
        if s.num >= 0xff00 || s.strndx >= s.num {
            return Err("extended section numbering is not supported".into());
        }
        if s.off.checked_add(s.num * s.entsize).is_none_or(|e| e > data.len()) {
            return Err("the section header table is truncated".into());
        }
        Ok(s)
    }

    fn p(&self) -> usize {
        if self.is64 { 8 } else { 4 }
    }

    fn word(&self, data: &[u8], off: usize, size: usize) -> u64 {
        read_uint(data, off, size, self.en).unwrap_or(0)
    }

    fn put(&self, data: &mut [u8], off: usize, size: usize, v: u64) {
        if let Some(b) = off.checked_add(size).and_then(|e| data.get_mut(off..e)) {
            b.copy_from_slice(&uint_bytes(v, size, self.en));
        }
    }

    /// Field offsets inside a section header: flags, offset, size, link, info.
    fn fields(&self) -> (usize, usize, usize, usize, usize) {
        if self.is64 { (8, 24, 32, 40, 44) } else { (8, 16, 20, 24, 28) }
    }

    /// File ranges of the segments a program uses at run time: loaded ones,
    /// and those the loader or the dynamic linker reads through their headers.
    fn segments(&self, data: &[u8]) -> Vec<(usize, usize)> {
        let Some((table, len)) = program_headers(data) else { return Vec::new() };
        let entsize = self.word(data, if self.is64 { 0x36 } else { 0x2A }, 2) as usize;
        let (offset, filesz) = if self.is64 { (8, 32) } else { (4, 16) };
        let mut out = Vec::new();
        if entsize < if self.is64 { 56 } else { 32 } {
            return out;
        }
        for i in 0..len / entsize {
            let h = table.saturating_add(i * entsize);
            // PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_PHDR, PT_TLS, PT_GNU_EH_FRAME, PT_GNU_RELRO
            if matches!(self.word(data, h, 4), 1..=4 | 6 | 7 | 0x6474_e550 | 0x6474_e552) {
                out.push((clamp_off(self.word(data, h.saturating_add(offset), self.p())), clamp_off(self.word(data, h.saturating_add(filesz), self.p()))));
            }
        }
        out
    }

    /// The header structures of the file: ELF header, program headers, section headers.
    fn header_ranges(&self, data: &[u8]) -> [(usize, usize); 3] {
        [(0, if self.is64 { 0x40 } else { 0x34 }), program_headers(data).unwrap_or((0, 0)), (self.off, self.num * self.entsize)]
    }

    /// Header fields of one section; `loaded` reflects its flags only.
    fn info(&self, data: &[u8], i: usize) -> SectionInfo {
        self.info_in(data, i, &[])
    }

    fn info_in(&self, data: &[u8], i: usize, segments: &[(usize, usize)]) -> SectionInfo {
        let h = self.off + i * self.entsize;
        let (flags, offset, size, _, _) = self.fields();
        let p = self.p();
        let st = self.off + self.strndx * self.entsize;
        let (st_off, st_size) = (clamp_off(self.word(data, st + offset, p)), clamp_off(self.word(data, st + size, p)));
        let name_off = self.word(data, h, 4) as usize;
        let name = data
            .get(st_off..st_off.saturating_add(st_size).min(data.len()))
            .and_then(|t| t.get(name_off..))
            .map(|t| String::from_utf8_lossy(&t[..t.iter().position(|c| *c == 0).unwrap_or(0)]).into_owned())
            .unwrap_or_default();
        let ty = self.word(data, h + 4, 4) as u32;
        let (flags, offset, size) = (self.word(data, h + flags, p), self.word(data, h + offset, p), self.word(data, h + size, p));
        let mut info = SectionInfo { name, ty, flags, offset, size, loaded: false };
        info.loaded = flags & 2 != 0 || segments.iter().any(|seg| overlaps(file_range(&info), *seg));
        info
    }

    fn set_header(&self, data: &mut [u8], shoff: usize, num: usize, strndx: usize) {
        let (off_field, tail) = if self.is64 { (0x28, 0x3A) } else { (0x20, 0x2E) };
        self.put(data, off_field, self.p(), shoff as u64);
        self.put(data, tail + 2, 2, num as u64);
        self.put(data, tail + 4, 2, strndx as u64);
    }
}

pub fn sections(data: &[u8]) -> Res<Vec<SectionInfo>> {
    let s = Shdrs::parse(data)?;
    let segments = s.segments(data);
    Ok((0..s.num).map(|i| s.info_in(data, i, &segments)).collect())
}

/// Run a section edit and check the headers still read back; restore on failure.
fn checked_sections(data: &mut Vec<u8>, edit: impl FnOnce(&mut Vec<u8>) -> Res<String>) -> Res<String> {
    let backup = data.clone();
    let result = edit(data)
        .and_then(|msg| Shdrs::parse(data).map(|_| msg).map_err(|e| format!("the file layout is too unusual to edit safely (after the change: {e})")));
    if result.is_err() {
        *data = backup;
    }
    result
}

/// Append a section that is not loaded at run time (like `objcopy --add-section`).
/// The content, a new section name table and a new header table go to the end of the file.
pub fn add_section(data: &mut Vec<u8>, name: &str, content: &[u8]) -> Res<String> {
    check(name)?;
    if name.len() > 255 || content.len() > u32::MAX as usize / 2 {
        return Err("the section name or content is too large".into());
    }
    checked_sections(data, |data| {
        let s = Shdrs::parse(data)?;
        if (0..s.num).any(|i| s.info(data, i).name == name) {
            return Err(format!("a section named {name} already exists"));
        }
        let p = s.p();
        let (_, offset, size, _, _) = s.fields();
        let st = s.off + s.strndx * s.entsize;
        let (st_off, st_size) = (clamp_off(s.word(data, st + offset, p)), clamp_off(s.word(data, st + size, p)));
        let mut names = data.get(st_off..st_off.saturating_add(st_size)).ok_or("the section name table is outside the file")?.to_vec();
        let name_index = names.len();
        names.extend_from_slice(name.as_bytes());
        names.push(0);
        let mut table = data[s.off..s.off + s.num * s.entsize].to_vec();
        // A header table at the very end of the file is simply replaced, unless
        // a segment maps it: the new content would then be loaded after all.
        // Nor when another header or the content of a section lies in it; the
        // old table then stays where it is.
        let headers = s.header_ranges(data);
        let table_range = headers[2];
        let shared = overlaps(table_range, headers[0])
            || overlaps(table_range, headers[1])
            || s.segments(data).iter().any(|seg| overlaps(table_range, *seg))
            || (0..s.num).any(|i| overlaps(file_range(&s.info(data, i)), table_range));
        if s.off + s.num * s.entsize == data.len() && !shared {
            data.truncate(s.off);
        }
        let align = |data: &mut Vec<u8>| data.resize(data.len().div_ceil(8) * 8, 0);
        align(data);
        let content_off = data.len();
        data.extend_from_slice(content);
        align(data);
        let names_off = data.len();
        data.extend_from_slice(&names);
        align(data);
        let table_off = data.len();
        // The name table section now points at the new copy.
        s.put(&mut table, s.strndx * s.entsize + offset, p, names_off as u64);
        s.put(&mut table, s.strndx * s.entsize + size, p, names.len() as u64);
        let mut hdr = vec![0u8; s.entsize];
        s.put(&mut hdr, 0, 4, name_index as u64);
        s.put(&mut hdr, 4, 4, 1); // SHT_PROGBITS
        s.put(&mut hdr, offset, p, content_off as u64);
        s.put(&mut hdr, size, p, content.len() as u64);
        let addralign = if s.is64 { 48 } else { 32 };
        s.put(&mut hdr, addralign, p, 1);
        table.extend_from_slice(&hdr);
        data.extend_from_slice(&table);
        s.set_header(data, table_off, s.num + 1, s.strndx);
        Ok(format!("Section {name} added ({} bytes at offset {content_off:X}); it is not loaded at run time", content.len()))
    })
}

/// Remove a section that is not loaded at run time. Its bytes are zeroed and
/// every index that refers to a later section is adjusted.
pub fn remove_section(data: &mut Vec<u8>, index: usize) -> Res<String> {
    checked_sections(data, |data| {
        let s = Shdrs::parse(data)?;
        if index == 0 || index >= s.num {
            return Err("no such section".into());
        }
        if index == s.strndx {
            return Err("the section name table cannot be removed".into());
        }
        let victim = s.info_in(data, index, &s.segments(data));
        if victim.flags & 2 != 0 {
            return Err(format!("{} is loaded at run time; removing it would break the program", victim.name));
        }
        if victim.loaded {
            return Err(format!("{} lies inside a loaded segment; removing it would break the program", victim.name));
        }
        // Closing the gap in the section header table must not move bytes of the other headers.
        let headers = s.header_ranges(data);
        if overlaps(headers[2], headers[0]) || overlaps(headers[2], headers[1]) {
            return Err("the section header table overlaps the ELF header or the program headers".into());
        }
        // Nor bytes the program uses at run time, or the content of another section.
        if s.segments(data).iter().any(|seg| overlaps(headers[2], *seg)) {
            return Err("the section header table lies inside a loaded segment; it cannot be rewritten".into());
        }
        if (0..s.num).any(|i| i != index && overlaps(file_range(&s.info(data, i)), headers[2])) {
            return Err("the section header table overlaps the content of a section; it cannot be rewritten".into());
        }
        let p = s.p();
        let (flags_f, offset, size, link, info) = s.fields();
        if (0..s.num).any(|i| i != index && s.word(data, s.off + i * s.entsize + link, 4) as usize == index) {
            return Err(format!("another section depends on {} (through its link field)", victim.name));
        }
        let symsize = if s.is64 { 24 } else { 16 };
        let (info_at, shndx_at) = if s.is64 { (4, 6) } else { (12, 14) };
        // File ranges of the symbol tables seen so far, and their symbols in total.
        let mut symtabs: Vec<(usize, usize)> = Vec::new();
        let mut symbols = 0usize;
        // Everything else that can name the section is checked before anything is written.
        for i in (0..s.num).filter(|i| *i != index) {
            let h = s.off + i * s.entsize;
            let ty = s.word(data, h + 4, 4);
            // sh_info is a section index for relocation sections and when SHF_INFO_LINK is set.
            if (matches!(ty, 4 | 9) || s.word(data, h + flags_f, p) & 0x40 != 0) && s.word(data, h + info, 4) as usize == index {
                return Err(format!("{} applies to {} (through its info field); remove it first", s.info(data, i).name, victim.name));
            }
            // Section groups and extended symbol index tables store section indexes in their content.
            if matches!(ty, 17 | 18) {
                return Err("the file has section groups or an extended symbol index table; their section indexes cannot be adjusted".into());
            }
            if matches!(ty, 2 | 11) {
                let (o, n) = (clamp_off(s.word(data, h + offset, p)), clamp_off(s.word(data, h + size, p)) / symsize);
                // Every symbol's section index is rewritten below: all of them, and nothing else.
                let range = (o, n * symsize);
                if o.checked_add(range.1).is_none_or(|end| end > data.len()) {
                    return Err("a symbol table lies outside the file; its section indexes cannot be adjusted".into());
                }
                // The limit is on the whole file: a header costs nothing, a walk over its symbols does.
                symbols = symbols.saturating_add(n);
                if symbols > MAX_SYMBOLS {
                    return Err(format!("the symbol tables have more than {MAX_SYMBOLS} symbols; their section indexes cannot be adjusted"));
                }
                if headers.iter().any(|r| overlaps(range, *r)) {
                    return Err("a symbol table overlaps the file's header tables; its section indexes cannot be adjusted".into());
                }
                // Shared symbols would be renumbered once per table.
                if symtabs.iter().any(|r| overlaps(range, *r)) {
                    return Err("two symbol tables overlap each other; their section indexes cannot be adjusted".into());
                }
                symtabs.push(range);
                for k in 0..n {
                    let at = o.saturating_add(k * symsize);
                    // The section's own STT_SECTION symbol may go; any other symbol would become undefined.
                    if s.word(data, at.saturating_add(shndx_at), 2) as usize == index && s.word(data, at.saturating_add(info_at), 1) & 0xf != 3 {
                        return Err(format!("a symbol is defined in {}; removing the section would leave it undefined", victim.name));
                    }
                }
            }
        }
        let fix = |v: u64| -> u64 {
            match (v as usize).cmp(&index) {
                std::cmp::Ordering::Greater => v - 1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Less => v,
            }
        };
        // Section indexes stored in symbols.
        for i in (0..s.num).filter(|i| *i != index) {
            let h = s.off + i * s.entsize;
            if !matches!(s.word(data, h + 4, 4), 2 | 11) {
                continue;
            }
            let (o, n) = (clamp_off(s.word(data, h + offset, p)), clamp_off(s.word(data, h + size, p)) / symsize);
            for k in 0..n {
                let at = o + k * symsize + shndx_at;
                let v = s.word(data, at, 2);
                if v != 0 && v < 0xff00 && at + 2 <= data.len() {
                    s.put(data, at, 2, fix(v));
                }
            }
        }
        // Links between sections.
        for i in 0..s.num {
            let h = s.off + i * s.entsize;
            let ty = s.word(data, h + 4, 4);
            let l = s.word(data, h + link, 4);
            s.put(data, h + link, 4, fix(l));
            // sh_info is a section index for relocation sections and when SHF_INFO_LINK is set.
            if matches!(ty, 4 | 9) || s.word(data, h + flags_f, p) & 0x40 != 0 {
                let v = s.word(data, h + info, 4);
                s.put(data, h + info, 4, fix(v));
            }
        }
        // Zero the content unless another section or one of the file's header
        // tables shares the bytes (or it has none, like .bss). The range is the
        // one the loaded check used, so the two cannot disagree.
        let (start, len) = file_range(&victim);
        let shared = (0..s.num).any(|i| i != index && overlaps(file_range(&s.info(data, i)), (start, len)));
        let zero = len > 0 && !shared && start.saturating_add(len) <= data.len() && !headers.iter().any(|r| overlaps((start, len), *r));
        if zero {
            data[start..start + len].fill(0);
        }
        // Close the gap in the header table.
        let from = s.off + (index + 1) * s.entsize;
        let end = s.off + s.num * s.entsize;
        data.copy_within(from..end, from - s.entsize);
        data[end - s.entsize..end].fill(0);
        if end == data.len() {
            data.truncate(end - s.entsize);
        }
        s.set_header(data, s.off, s.num - 1, fix(s.strndx as u64) as usize);
        Ok(if zero {
            format!("Section {} removed; {len} bytes of content zeroed", victim.name)
        } else if len == 0 {
            format!("Section {} removed; it had no content in the file", victim.name)
        } else {
            format!("Section {} removed; its {len} bytes are shared with other parts of the file and were left as they are", victim.name)
        })
    })
}
