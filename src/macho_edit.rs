//! Structural Mach-O editing: add, remove and change load commands that name
//! libraries and search paths. New commands are written into the padding
//! between the load commands and the first section, so nothing else moves.
//! In a universal binary every architecture is edited.
//!
//! Any change invalidates the code signature; re-sign with
//! `codesign -f -s - <file>` before running the result on macOS.

// The editors share one `&mut Vec<u8>` signature so the GUI can queue any of them.
#![allow(clippy::ptr_arg)]

use crate::model::{Endian, Rd, read_uint, uint_bytes};

type Res<T> = Result<T, String>;

pub const LC_LOAD_DYLIB: u32 = 0xC;
pub const LC_ID_DYLIB: u32 = 0xD;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
pub const LC_RPATH: u32 = 0x8000_001C;
pub const LC_REEXPORT_DYLIB: u32 = 0x8000_001F;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_CODE_SIGNATURE: u32 = 0x1D;

#[derive(Clone, Debug)]
pub struct Cmd {
    pub off: usize,
    pub cmd: u32,
    pub size: usize,
}

#[derive(Clone, Debug)]
pub struct Slice {
    pub base: usize,
    pub size: usize,
    pub is64: bool,
    pub endian: Endian,
    pub cmds: Vec<Cmd>,
    /// End of the load commands (absolute file offset).
    pub cmds_end: usize,
    /// First byte used by section or segment data (absolute file offset).
    pub first_data: usize,
}

impl Slice {
    fn hdr_size(&self) -> usize {
        if self.is64 { 32 } else { 28 }
    }

    pub fn free_space(&self) -> usize {
        self.first_data.saturating_sub(self.cmds_end)
    }

    /// The path stored in a dylib or rpath command.
    pub fn path(&self, data: &[u8], c: &Cmd) -> Option<String> {
        let rd = Rd::new(data, self.endian);
        let str_off = rd.u32(c.off + 8) as usize;
        is_path_cmd(c.cmd).then(|| rd.cstr(c.off + str_off, c.size.saturating_sub(str_off)))
    }
}

pub fn is_dylib_cmd(cmd: u32) -> bool {
    matches!(cmd, LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB)
}

pub fn is_path_cmd(cmd: u32) -> bool {
    is_dylib_cmd(cmd) || cmd == LC_RPATH
}

fn parse_slice(data: &[u8], base: usize, size: usize) -> Option<Slice> {
    let end = base.checked_add(size)?.min(data.len());
    let (endian, is64) = match data.get(base..base.checked_add(4)?)? {
        [0xCE, 0xFA, 0xED, 0xFE] => (Endian::Little, false),
        [0xCF, 0xFA, 0xED, 0xFE] => (Endian::Little, true),
        [0xFE, 0xED, 0xFA, 0xCE] => (Endian::Big, false),
        [0xFE, 0xED, 0xFA, 0xCF] => (Endian::Big, true),
        _ => return None,
    };
    let rd = Rd::new(data, endian);
    let hdr = if is64 { 32 } else { 28 };
    let ncmds = rd.u32(base + 16) as usize;
    let sizeofcmds = rd.u32(base + 20) as usize;
    let cmds_end = base + hdr + sizeofcmds;
    if cmds_end > end {
        return None;
    }
    let p = if is64 { 8 } else { 4 };
    let mut cmds = Vec::new();
    let mut first_data = end;
    let mut off = base + hdr;
    for _ in 0..ncmds.min(4096) {
        if off + 8 > cmds_end {
            return None;
        }
        let cmd = rd.u32(off);
        let csize = rd.u32(off + 4) as usize;
        if csize < 8 || off + csize > cmds_end {
            return None;
        }
        if cmd == 0x1 || cmd == 0x19 {
            // Sections tell where data really starts; __TEXT itself begins at 0.
            let nsects = rd.u32(off + 8 + 16 + 4 * p + 8) as usize;
            let sec_size = if is64 { 80 } else { 68 };
            let mut s = off + 8 + 16 + 4 * p + 16;
            for _ in 0..nsects.min(4096) {
                if s + sec_size > off + csize {
                    break;
                }
                let soff = rd.u32(s + 32 + 2 * p) as usize;
                let zero_fill = matches!(rd.u32(s + 32 + 2 * p + 24) & 0xff, 1 | 12 | 18);
                if soff != 0 && !zero_fill {
                    first_data = first_data.min(base + soff);
                }
                s += sec_size;
            }
            let fileoff = crate::model::clamp_off(rd.uint(off + 8 + 16 + 2 * p, p));
            let filesize = rd.uint(off + 8 + 16 + 3 * p, p);
            if fileoff != 0 && filesize != 0 {
                first_data = first_data.min(base + fileoff);
            }
        }
        cmds.push(Cmd { off, cmd, size: csize });
        off += csize;
    }
    Some(Slice { base, size: end - base, is64, endian, cmds, cmds_end, first_data })
}

/// Every architecture in the file: one for a thin file, several for a universal one.
pub fn slices(data: &[u8]) -> Vec<Slice> {
    let be = |off| read_uint(data, off, 4, Endian::Big).unwrap_or(0);
    let wide = match data.get(..4) {
        Some([0xCA, 0xFE, 0xBA, 0xBE]) => false,
        Some([0xCA, 0xFE, 0xBA, 0xBF]) => true,
        _ => return parse_slice(data, 0, data.len()).into_iter().collect(),
    };
    let n = be(4) as usize;
    if n == 0 || n > 30 {
        return Vec::new();
    }
    let ent = if wide { 32 } else { 20 };
    let w = if wide { 8 } else { 4 };
    (0..n)
        .filter_map(|i| {
            let e = 8 + i * ent;
            let off = crate::model::clamp_off(read_uint(data, e + 8, w, Endian::Big)?);
            let size = crate::model::clamp_off(read_uint(data, e + 8 + w, w, Endian::Big)?);
            parse_slice(data, off, size)
        })
        .collect()
}

fn put32(data: &mut [u8], off: usize, v: u32, endian: Endian) {
    if let Some(b) = data.get_mut(off..off + 4) {
        b.copy_from_slice(&uint_bytes(v as u64, 4, endian));
    }
}

fn set_counts(data: &mut [u8], s: &Slice, ncmds: usize, sizeofcmds: usize) {
    put32(data, s.base + 16, ncmds as u32, s.endian);
    put32(data, s.base + 20, sizeofcmds as u32, s.endian);
}

fn check_path(path: &str) -> Res<()> {
    if path.is_empty() || path.len() > 1024 || path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("the path must be 1 to 1024 characters without control characters".into());
    }
    Ok(())
}

fn path_command(cmd: u32, path: &str, endian: Endian, template: Option<&[u8]>) -> Vec<u8> {
    let fixed = if cmd == LC_RPATH { 12 } else { 24 };
    let size = (fixed + path.len() + 1).div_ceil(8) * 8;
    let mut c = vec![0u8; size];
    put32(&mut c, 0, cmd, endian);
    put32(&mut c, 4, size as u32, endian);
    put32(&mut c, 8, fixed as u32, endian);
    if cmd != LC_RPATH {
        match template {
            // Keep timestamp and versions when a command is being rewritten.
            Some(t) if t.len() >= 24 => c[12..24].copy_from_slice(&t[12..24]),
            _ => {
                put32(&mut c, 12, 2, endian);
                put32(&mut c, 16, 0x1_0000, endian);
                put32(&mut c, 20, 0x1_0000, endian);
            }
        }
    }
    c[fixed..fixed + path.len()].copy_from_slice(path.as_bytes());
    c
}

/// Insert `bytes` as load command number `index` (or at the end).
fn insert(data: &mut [u8], s: &Slice, index: usize, bytes: &[u8]) -> Res<()> {
    if bytes.len() > s.free_space() {
        return Err(format!(
            "not enough header padding for the new load command: {} bytes needed, {} free. Relink with -headerpad to make room",
            bytes.len(),
            s.free_space()
        ));
    }
    let at = s.cmds.get(index).map_or(s.cmds_end, |c| c.off);
    data.copy_within(at..s.cmds_end, at + bytes.len());
    data[at..at + bytes.len()].copy_from_slice(bytes);
    set_counts(data, s, s.cmds.len() + 1, s.cmds_end - s.base - s.hdr_size() + bytes.len());
    Ok(())
}

fn remove(data: &mut [u8], s: &Slice, index: usize) -> Res<Cmd> {
    let c = s.cmds.get(index).ok_or("no such load command")?.clone();
    data.copy_within(c.off + c.size..s.cmds_end, c.off);
    data[s.cmds_end - c.size..s.cmds_end].fill(0);
    set_counts(data, s, s.cmds.len() - 1, s.cmds_end - s.base - s.hdr_size() - c.size);
    Ok(c)
}

fn all_slices(data: &[u8]) -> Res<Vec<Slice>> {
    let s = slices(data);
    if s.is_empty() { Err("not a Mach-O file".into()) } else { Ok(s) }
}

/// Run an edit and check that every architecture can still be read back.
/// On any failure the buffer is restored.
fn checked(data: &mut Vec<u8>, edit: impl FnOnce(&mut Vec<u8>) -> Res<String>) -> Res<String> {
    let backup = data.clone();
    let before = slices(data).len();
    let result =
        edit(data).and_then(|msg| if slices(data).len() == before { Ok(msg) } else { Err("the file layout is too unusual to edit safely".to_string()) });
    if result.is_err() {
        *data = backup;
    }
    result
}

const RESIGN: &str = "The code signature is now invalid; re-sign with: codesign -f -s - <file>";

/// Add a load command naming a library (`LC_LOAD_DYLIB`, weak or re-export)
/// or a run path (`LC_RPATH`) to every architecture.
pub fn add_path_command(data: &mut Vec<u8>, cmd: u32, path: &str) -> Res<String> {
    checked(data, |data| add_path_command_inner(data, cmd, path))
}

fn add_path_command_inner(data: &mut Vec<u8>, cmd: u32, path: &str) -> Res<String> {
    check_path(path)?;
    if !is_path_cmd(cmd) || cmd == LC_ID_DYLIB {
        return Err("unsupported load command type".into());
    }
    let list = all_slices(data)?;
    for s in &list {
        if s.cmds.iter().any(|c| c.cmd == cmd && s.path(data, c).as_deref() == Some(path)) {
            return Err(format!("{path} is already present"));
        }
        let need = path_command(cmd, path, s.endian, None).len();
        if need > s.free_space() {
            return Err(format!("not enough header padding: {need} bytes needed, {} free. Relink with -headerpad to make room", s.free_space()));
        }
    }
    for s in &list {
        // Keep the signature command last, as the system tools expect.
        let index = s.cmds.iter().position(|c| c.cmd == LC_CODE_SIGNATURE).unwrap_or(s.cmds.len());
        insert(data, s, index, &path_command(cmd, path, s.endian, None))?;
    }
    Ok(format!("Added {} {path} to {} architecture(s). {RESIGN}", if cmd == LC_RPATH { "run path" } else { "library" }, list.len()))
}

/// Remove the library or run path command with this path from every architecture.
pub fn remove_path_command(data: &mut Vec<u8>, cmd: u32, path: &str) -> Res<String> {
    checked(data, |data| remove_path_command_inner(data, cmd, path))
}

fn remove_path_command_inner(data: &mut Vec<u8>, cmd: u32, path: &str) -> Res<String> {
    let list = all_slices(data)?;
    let mut n = 0;
    for s in &list {
        if let Some(i) = s.cmds.iter().position(|c| c.cmd == cmd && s.path(data, c).as_deref() == Some(path)) {
            remove(data, s, i)?;
            n += 1;
        }
    }
    if n == 0 {
        return Err(format!("{path} was not found"));
    }
    Ok(format!("Removed {path} from {n} architecture(s). {RESIGN}"))
}

/// Change the path of a library or run path command in every architecture.
pub fn change_path(data: &mut Vec<u8>, cmd: u32, old: &str, new: &str) -> Res<String> {
    check_path(new)?;
    let list = all_slices(data)?;
    let mut work = data.clone();
    let mut n = 0;
    for s in &list {
        let Some(i) = s.cmds.iter().position(|c| c.cmd == cmd && s.path(&work, c).as_deref() == Some(old)) else { continue };
        let old_bytes = work[s.cmds[i].off..s.cmds[i].off + s.cmds[i].size].to_vec();
        let new_cmd = path_command(cmd, new, s.endian, Some(&old_bytes));
        remove(&mut work, s, i)?;
        // Only this slice's header changed, so reparse just it.
        let s2 = parse_slice(&work, s.base, s.size).ok_or("the load commands became unreadable")?;
        insert(&mut work, &s2, i, &new_cmd)?;
        n += 1;
    }
    if n == 0 {
        return Err(format!("{old} was not found"));
    }
    *data = work;
    Ok(format!("Changed {old} to {new} in {n} architecture(s). {RESIGN}"))
}

/// Remove the code signature load command. The signature data stays in
/// `__LINKEDIT` but is no longer referenced.
pub fn remove_signature(data: &mut Vec<u8>) -> Res<String> {
    checked(data, remove_signature_inner)
}

fn remove_signature_inner(data: &mut Vec<u8>) -> Res<String> {
    let list = all_slices(data)?;
    let mut n = 0;
    for s in &list {
        if let Some(i) = s.cmds.iter().position(|c| c.cmd == LC_CODE_SIGNATURE) {
            remove(data, s, i)?;
            n += 1;
        }
    }
    if n == 0 {
        return Ok("The file is not signed".into());
    }
    Ok(format!("Code signature command removed from {n} architecture(s). arm64 binaries need a signature to run: codesign -f -s - <file>"))
}
