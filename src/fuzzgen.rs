//! Structure-aware fuzzing: the fuzzer's bytes are read as a list of choices
//! (format, counts, names, field values) and turned into a mostly valid PE,
//! ELF or Mach-O file, so mutations reach the tables behind the headers
//! instead of dying at the first magic number check. Each builder also
//! records what it wrote, so the parsers can be checked for the right answer
//! and not only for not crashing.
//!
//! Every function here takes arbitrary bytes and must not panic.

/// The fuzzer input read as a stream of choices. Past the end every read is 0,
/// so any input, including an empty one, gives a file.
pub struct Gen<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Gen<'a> {
    pub fn new(d: &'a [u8]) -> Self {
        Gen { d, p: 0 }
    }

    pub fn byte(&mut self) -> u8 {
        let b = self.d.get(self.p).copied().unwrap_or(0);
        self.p = self.p.saturating_add(1);
        b
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.byte(), self.byte()])
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }

    /// A number in 0..n (0 when n is 0).
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { self.u16() as usize % n }
    }

    /// True with probability k/256. Past the end of the input it is false, so a
    /// short input gives a plain file rather than one with every option on.
    pub fn chance(&mut self, k: u8) -> bool {
        255 - self.byte() < k
    }

    /// A little machine code: short, so the structure gets most of the input.
    fn code(&mut self) -> Vec<u8> {
        let n = 1 + self.below(48);
        let mut c = self.bytes(n);
        c.push(0xc3);
        c
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }

    /// A short printable identifier, never empty.
    pub fn name(&mut self, prefix: &str) -> String {
        const ABC: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
        let len = 1 + self.below(12);
        let mut s = prefix.to_string();
        for _ in 0..len {
            s.push(ABC[self.below(ABC.len())] as char);
        }
        s
    }

    /// Bytes left unread, for the editors that run after a file is built.
    pub fn rest(&self) -> &'a [u8] {
        self.d.get(self.p..).unwrap_or(&[])
    }
}

/// What a builder put into the file, for checking the parsers' answers.
#[derive(Debug, Clone, Default)]
pub struct Expect {
    pub entry: Option<u64>,
    /// PE: (DLL, functions); a function is a name or an ordinal.
    pub imports: Vec<(String, Vec<Result<String, u16>>)>,
    /// PE: exported names, sorted.
    pub exports: Vec<String>,
    /// PE: (RVA, type), sorted.
    pub relocs: Vec<(u32, u8)>,
    /// ELF: DT_NEEDED in order, DT_SONAME, DT_RUNPATH.
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub runpath: Option<String>,
    /// Mach-O: (load command, path) in order.
    pub paths: Vec<(u32, String)>,
}

#[derive(Clone, Copy)]
pub enum Kind {
    Pe,
    Elf,
    MachO,
}

/// Little or big endian integer writes into a growable buffer.
#[derive(Clone, Copy)]
struct W {
    be: bool,
}

impl W {
    fn put(self, buf: &mut Vec<u8>, off: usize, v: u64, n: usize) {
        if buf.len() < off + n {
            buf.resize(off + n, 0);
        }
        let b = v.to_le_bytes();
        for i in 0..n {
            buf[off + i] = if self.be { b[n - 1 - i] } else { b[i] };
        }
    }
}

const LE: W = W { be: false };

fn align(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

fn cstr(buf: &mut Vec<u8>, s: &str) -> usize {
    let at = buf.len();
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
    at
}

// --- PE ---------------------------------------------------------------------

/// A PE32 or PE32+ image with code, imports, exports and relocations, each in
/// its own section.
pub fn pe(g: &mut Gen) -> (Vec<u8>, Expect) {
    let is64 = g.chance(160);
    let ps = if is64 { 8 } else { 4 };
    let image_base: u64 = if is64 { 0x1_4000_0000 } else { 0x40_0000 };
    let (sa, fa) = (0x1000usize, 0x200usize);
    let mut exp = Expect::default();

    // .text
    let text_rva = 0x1000u32;
    let text = g.code();
    let entry = text_rva + g.below(text.len()) as u32;
    exp.entry = Some(image_base + entry as u64);

    // .idata: descriptors, then lookup tables, address tables, names, hint/names.
    let idata_rva = text_rva + align(text.len(), sa) as u32;
    let nmods = g.below(5);
    let mut mods = Vec::new();
    for i in 0..nmods {
        let dll = format!("{}{i}.dll", g.name("m"));
        let nf = 1 + g.below(6);
        let funcs: Vec<Result<String, u16>> =
            (0..nf).map(|j| if g.chance(48) { Err(1 + g.u16() % 0x7fff) } else { Ok(format!("{}{j}", g.name("F"))) }).collect();
        mods.push((dll, funcs));
    }
    let mut idata = vec![0u8; (nmods + 1) * 20];
    for (i, (dll, funcs)) in mods.iter().enumerate() {
        let mut thunks = Vec::new();
        for f in funcs {
            thunks.push(match f {
                Err(ord) => (*ord as u64) | if is64 { 1 << 63 } else { 1 << 31 },
                Ok(name) => {
                    let at = align(idata.len(), 2);
                    idata.resize(at, 0);
                    LE.put(&mut idata, at, g.u16() as u64, 2);
                    cstr(&mut idata, name);
                    (idata_rva as usize + at) as u64
                }
            });
        }
        let table = |idata: &mut Vec<u8>| {
            let at = align(idata.len(), ps);
            idata.resize(at, 0);
            for (k, t) in thunks.iter().enumerate() {
                LE.put(idata, at + k * ps, *t, ps);
            }
            LE.put(idata, at + thunks.len() * ps, 0, ps);
            idata_rva + at as u32
        };
        let ilt = table(&mut idata);
        let iat = table(&mut idata);
        let name = idata_rva + cstr(&mut idata, dll) as u32;
        let d = i * 20;
        LE.put(&mut idata, d, ilt as u64, 4);
        LE.put(&mut idata, d + 12, name as u64, 4);
        LE.put(&mut idata, d + 16, iat as u64, 4);
    }
    exp.imports = mods;

    // .edata
    let edata_rva = idata_rva + align(idata.len().max(1), sa) as u32;
    let mut names: Vec<String> = (0..g.below(6)).map(|i| format!("{}{i}", g.name("E"))).collect();
    names.sort();
    names.dedup();
    let mut edata = vec![0u8; 40];
    let mut export_dir = (0u32, 0u32);
    if !names.is_empty() {
        let n = names.len();
        let funcs = 40;
        let name_ptrs = funcs + 4 * n;
        let ords = name_ptrs + 4 * n;
        edata.resize(ords + 2 * n, 0);
        for (i, name) in names.iter().enumerate() {
            LE.put(&mut edata, funcs + 4 * i, (text_rva + g.below(text.len()) as u32) as u64, 4);
            let s = edata_rva + cstr(&mut edata, name) as u32;
            LE.put(&mut edata, name_ptrs + 4 * i, s as u64, 4);
            LE.put(&mut edata, ords + 2 * i, i as u64, 2);
        }
        let dll = edata_rva + cstr(&mut edata, "fuzz.dll") as u32;
        LE.put(&mut edata, 12, dll as u64, 4);
        LE.put(&mut edata, 16, 1, 4);
        LE.put(&mut edata, 20, n as u64, 4);
        LE.put(&mut edata, 24, n as u64, 4);
        LE.put(&mut edata, 28, (edata_rva as usize + funcs) as u64, 4);
        LE.put(&mut edata, 32, (edata_rva as usize + name_ptrs) as u64, 4);
        LE.put(&mut edata, 36, (edata_rva as usize + ords) as u64, 4);
        export_dir = (edata_rva, edata.len() as u32);
    }
    exp.exports = names;

    // .reloc: one block for the code page.
    let reloc_rva = edata_rva + align(edata.len(), sa) as u32;
    let ty: u8 = if is64 { 10 } else { 3 };
    let mut offs: Vec<u16> = (0..g.below(8)).map(|_| (g.u16() % 0x1000) & !7).collect();
    offs.sort();
    offs.dedup();
    let mut reloc = Vec::new();
    if !offs.is_empty() {
        let entries = align(offs.len(), 2);
        LE.put(&mut reloc, 0, text_rva as u64, 4);
        LE.put(&mut reloc, 4, (8 + 2 * entries) as u64, 4);
        for (i, o) in offs.iter().enumerate() {
            LE.put(&mut reloc, 8 + 2 * i, ((ty as u64) << 12) | *o as u64, 2);
        }
        reloc.resize(8 + 2 * entries, 0);
        exp.relocs = offs.iter().map(|o| (text_rva + *o as u32, ty)).collect();
    }

    // Headers.
    let sections: Vec<(&str, u32, Vec<u8>, u32)> = vec![
        (".text", text_rva, text, 0x6000_0020),
        (".idata", idata_rva, idata, 0xC000_0040),
        (".edata", edata_rva, edata, 0x4000_0040),
        (".reloc", reloc_rva, reloc, 0x4200_0040),
    ];
    let lfanew = 0x80;
    let opt = lfanew + 24;
    let opt_size = if is64 { 0xF0 } else { 0xE0 };
    let sec_tab = opt + opt_size;
    let headers = align(sec_tab + 40 * sections.len(), fa);
    let mut f = vec![0u8; headers];
    f[..2].copy_from_slice(b"MZ");
    LE.put(&mut f, 0x3c, lfanew as u64, 4);
    f[lfanew..lfanew + 4].copy_from_slice(b"PE\0\0");
    let machine = match (is64, g.below(4)) {
        (true, 0) => 0xAA64,
        (true, _) => 0x8664,
        (false, _) => 0x14c,
    };
    LE.put(&mut f, lfanew + 4, machine, 2);
    LE.put(&mut f, lfanew + 6, sections.len() as u64, 2);
    LE.put(&mut f, lfanew + 20, opt_size as u64, 2);
    LE.put(&mut f, lfanew + 22, if is64 { 0x22 } else { 0x102 }, 2);
    LE.put(&mut f, opt, if is64 { 0x20b } else { 0x10b }, 2);
    LE.put(&mut f, opt + 16, entry as u64, 4);
    if is64 {
        LE.put(&mut f, opt + 24, image_base, 8);
    } else {
        LE.put(&mut f, opt + 28, image_base, 4);
    }
    LE.put(&mut f, opt + 32, sa as u64, 4);
    LE.put(&mut f, opt + 36, fa as u64, 4);
    LE.put(&mut f, opt + 40, 6, 2);
    LE.put(&mut f, opt + 48, 6, 2);
    let image_end = sections.last().map_or(0x1000, |s| s.1 as usize + align(s.2.len().max(1), sa));
    LE.put(&mut f, opt + 56, image_end as u64, 4);
    LE.put(&mut f, opt + 60, headers as u64, 4);
    LE.put(&mut f, opt + 68, 2 + g.below(2) as u64, 2);
    let dirs = opt + if is64 { 112 } else { 96 };
    LE.put(&mut f, dirs - 4, 16, 4);
    let set_dir = |f: &mut Vec<u8>, i: usize, (rva, size): (u32, u32)| {
        LE.put(f, dirs + 8 * i, rva as u64, 4);
        LE.put(f, dirs + 8 * i + 4, size as u64, 4);
    };
    set_dir(&mut f, 0, export_dir);
    if nmods > 0 {
        set_dir(&mut f, 1, (idata_rva, ((nmods + 1) * 20) as u32));
    }
    if !exp.relocs.is_empty() {
        set_dir(&mut f, 5, (reloc_rva, sections[3].2.len() as u32));
    }
    let mut raw = headers;
    for (i, (name, rva, data, flags)) in sections.iter().enumerate() {
        let s = sec_tab + 40 * i;
        f[s..s + name.len()].copy_from_slice(name.as_bytes());
        let raw_size = align(data.len(), fa);
        LE.put(&mut f, s + 8, data.len().max(1) as u64, 4);
        LE.put(&mut f, s + 12, *rva as u64, 4);
        LE.put(&mut f, s + 16, raw_size as u64, 4);
        LE.put(&mut f, s + 20, if raw_size == 0 { 0 } else { raw as u64 }, 4);
        LE.put(&mut f, s + 36, *flags as u64, 4);
        f.resize(raw, 0);
        f.extend_from_slice(data);
        raw += raw_size;
        f.resize(raw, 0);
    }
    (f, exp)
}

// --- ELF --------------------------------------------------------------------

/// An ELF executable or shared object (32 or 64 bit, either byte order) with
/// a dynamic section, dynamic symbols and section headers.
pub fn elf(g: &mut Gen) -> (Vec<u8>, Expect) {
    let is64 = g.chance(170);
    let w = W { be: g.chance(40) };
    let p = if is64 { 8 } else { 4 };
    let base: u64 = if is64 { 0x40_0000 } else { 0x8048000 };
    let mut exp = Expect::default();
    let (ehsize, phsize, shsize, dynsize, symsize) = if is64 { (64, 56, 64, 16, 24) } else { (52, 32, 40, 8, 16) };

    // Strings first, so their offsets are known.
    let mut dynstr = vec![0u8];
    let needed: Vec<String> = (0..g.below(5)).map(|i| format!("lib{}{i}.so", g.name(""))).collect();
    let needed_off: Vec<usize> = needed.iter().map(|n| cstr(&mut dynstr, n)).collect();
    let soname = g.chance(128).then(|| format!("lib{}.so.1", g.name("")));
    let soname_off = soname.as_ref().map(|s| cstr(&mut dynstr, s));
    let runpath = g.chance(100).then(|| format!("$ORIGIN/{}", g.name("")));
    let runpath_off = runpath.as_ref().map(|s| cstr(&mut dynstr, s));
    let syms: Vec<String> = (0..g.below(6)).map(|i| format!("{}{i}", g.name("s"))).collect();
    let sym_off: Vec<usize> = syms.iter().map(|s| cstr(&mut dynstr, s)).collect();

    let nph = 2;
    let text_off = ehsize + nph * phsize;
    let text = g.code();
    let dynsym_off = align(text_off + text.len(), 8);
    let nsym = syms.len() + 1;
    let dynstr_off = dynsym_off + nsym * symsize;
    let dynamic_off = align(dynstr_off + dynstr.len(), 8);
    let mut tags: Vec<(u64, u64)> = needed_off.iter().map(|o| (1, *o as u64)).collect();
    if let Some(o) = soname_off {
        tags.push((14, o as u64));
    }
    if let Some(o) = runpath_off {
        tags.push((29, o as u64));
    }
    tags.extend([(5, base + dynstr_off as u64), (10, dynstr.len() as u64), (6, base + dynsym_off as u64), (11, symsize as u64), (0, 0)]);
    let shstr_off = dynamic_off + tags.len() * dynsize;
    let mut shstr = vec![0u8];
    let names: Vec<usize> = [".text", ".dynsym", ".dynstr", ".dynamic", ".shstrtab"].iter().map(|n| cstr(&mut shstr, n)).collect();
    let sh_off = align(shstr_off + shstr.len(), 8);
    let nsh = 6;
    let end = sh_off + nsh * shsize;

    let mut f = vec![0u8; end];
    f[..4].copy_from_slice(b"\x7fELF");
    f[4] = if is64 { 2 } else { 1 };
    f[5] = if w.be { 2 } else { 1 };
    f[6] = 1;
    let e_type = if g.chance(128) { 3 } else { 2 };
    let machine = match (is64, g.below(3)) {
        (true, 0) => 183,
        (true, _) => 62,
        (false, 0) => 40,
        (false, _) => 3,
    };
    let entry = base + (text_off + g.below(text.len())) as u64;
    exp.entry = Some(entry);
    w.put(&mut f, 16, e_type, 2);
    w.put(&mut f, 18, machine, 2);
    w.put(&mut f, 20, 1, 4);
    w.put(&mut f, 24, entry, p);
    w.put(&mut f, 24 + p, ehsize as u64, p); // e_phoff
    w.put(&mut f, 24 + 2 * p, sh_off as u64, p); // e_shoff
    let h = 24 + 3 * p + 4;
    w.put(&mut f, h, ehsize as u64, 2);
    w.put(&mut f, h + 2, phsize as u64, 2);
    w.put(&mut f, h + 4, nph as u64, 2);
    w.put(&mut f, h + 6, shsize as u64, 2);
    w.put(&mut f, h + 8, nsh as u64, 2);
    w.put(&mut f, h + 10, 5, 2); // e_shstrndx

    // Program headers: one PT_LOAD for everything, then PT_DYNAMIC.
    let phdr = |f: &mut Vec<u8>, i: usize, ty: u64, flags: u64, off: usize, size: usize| {
        let o = ehsize + i * phsize;
        w.put(f, o, ty, 4);
        if is64 {
            w.put(f, o + 4, flags, 4);
            w.put(f, o + 8, off as u64, 8);
            w.put(f, o + 16, base + off as u64, 8);
            w.put(f, o + 24, base + off as u64, 8);
            w.put(f, o + 32, size as u64, 8);
            w.put(f, o + 40, size as u64, 8);
            w.put(f, o + 48, 0x1000, 8);
        } else {
            w.put(f, o + 4, off as u64, 4);
            w.put(f, o + 8, base + off as u64, 4);
            w.put(f, o + 12, base + off as u64, 4);
            w.put(f, o + 16, size as u64, 4);
            w.put(f, o + 20, size as u64, 4);
            w.put(f, o + 24, flags, 4);
            w.put(f, o + 28, 0x1000, 4);
        }
    };
    phdr(&mut f, 0, 1, 7, 0, end);
    phdr(&mut f, 1, 2, 6, dynamic_off, tags.len() * dynsize);

    f[text_off..text_off + text.len()].copy_from_slice(&text);
    for (i, o) in sym_off.iter().enumerate() {
        let s = dynsym_off + (i + 1) * symsize;
        w.put(&mut f, s, *o as u64, 4);
        let value = base + (text_off + g.below(text.len())) as u64;
        if is64 {
            f[s + 4] = 0x12;
            w.put(&mut f, s + 6, 1, 2);
            w.put(&mut f, s + 8, value, 8);
        } else {
            w.put(&mut f, s + 4, value, 4);
            f[s + 12] = 0x12;
            w.put(&mut f, s + 14, 1, 2);
        }
    }
    f[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(&dynstr);
    for (i, (tag, val)) in tags.iter().enumerate() {
        w.put(&mut f, dynamic_off + i * dynsize, *tag, p);
        w.put(&mut f, dynamic_off + i * dynsize + p, *val, p);
    }
    f[shstr_off..shstr_off + shstr.len()].copy_from_slice(&shstr);

    // Section headers: null, .text, .dynsym, .dynstr, .dynamic, .shstrtab.
    let secs: [(usize, u64, u64, usize, usize, u64, u64, u64); 5] = [
        (names[0], 1, 6, text_off, text.len(), 0, 0, 16),
        (names[1], 11, 2, dynsym_off, nsym * symsize, 3, 1, symsize as u64),
        (names[2], 3, 2, dynstr_off, dynstr.len(), 0, 0, 0),
        (names[3], 6, 3, dynamic_off, tags.len() * dynsize, 3, 0, dynsize as u64),
        (names[4], 3, 0, shstr_off, shstr.len(), 0, 0, 0),
    ];
    for (i, (name, ty, flags, off, size, link, info, entsize)) in secs.iter().enumerate() {
        let s = sh_off + (i + 1) * shsize;
        let addr = if *flags & 2 != 0 { base + *off as u64 } else { 0 };
        w.put(&mut f, s, *name as u64, 4);
        w.put(&mut f, s + 4, *ty, 4);
        if is64 {
            w.put(&mut f, s + 8, *flags, 8);
            w.put(&mut f, s + 16, addr, 8);
            w.put(&mut f, s + 24, *off as u64, 8);
            w.put(&mut f, s + 32, *size as u64, 8);
            w.put(&mut f, s + 40, *link, 4);
            w.put(&mut f, s + 44, *info, 4);
            w.put(&mut f, s + 48, 8, 8);
            w.put(&mut f, s + 56, *entsize, 8);
        } else {
            w.put(&mut f, s + 8, *flags, 4);
            w.put(&mut f, s + 12, addr, 4);
            w.put(&mut f, s + 16, *off as u64, 4);
            w.put(&mut f, s + 20, *size as u64, 4);
            w.put(&mut f, s + 24, *link, 4);
            w.put(&mut f, s + 28, *info, 4);
            w.put(&mut f, s + 32, 4, 4);
            w.put(&mut f, s + 36, *entsize, 4);
        }
    }
    exp.needed = needed;
    exp.soname = soname;
    exp.runpath = runpath;
    (f, exp)
}

// --- Mach-O -----------------------------------------------------------------

const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_MAIN: u32 = 0x8000_0028;

/// A 64-bit Mach-O executable with __TEXT, __LINKEDIT, dylibs, rpaths, a
/// symbol table and classic bind opcodes, optionally inside a universal file.
pub fn macho(g: &mut Gen) -> (Vec<u8>, Expect) {
    let mut exp = Expect::default();
    let arm = g.chance(128);
    let vm: u64 = 0x1_0000_0000;

    let mut paths: Vec<(u32, String)> = Vec::new();
    for i in 0..g.below(5) {
        let cmd = match g.below(4) {
            0 => crate::macho_edit::LC_LOAD_WEAK_DYLIB,
            1 => crate::macho_edit::LC_RPATH,
            _ => crate::macho_edit::LC_LOAD_DYLIB,
        };
        let path = if cmd == crate::macho_edit::LC_RPATH { format!("@loader_path/{}{i}", g.name("")) } else { format!("/usr/lib/lib{}{i}.dylib", g.name("")) };
        paths.push((cmd, path));
    }

    // Load commands, with the file offsets filled in once the layout is known.
    let mut cmds: Vec<Vec<u8>> = Vec::new();
    let seg = |name: &str, vmaddr: u64, vmsize: u64, fileoff: u64, filesize: u64, prot: u64, sects: &[(&str, u64, u64, u64)]| {
        let mut c = vec![0u8; 72 + 80 * sects.len()];
        LE.put(&mut c, 0, LC_SEGMENT_64 as u64, 4);
        let len = c.len() as u64;
        LE.put(&mut c, 4, len, 4);
        c[8..8 + name.len()].copy_from_slice(name.as_bytes());
        LE.put(&mut c, 24, vmaddr, 8);
        LE.put(&mut c, 32, vmsize, 8);
        LE.put(&mut c, 40, fileoff, 8);
        LE.put(&mut c, 48, filesize, 8);
        LE.put(&mut c, 56, prot, 4);
        LE.put(&mut c, 60, prot, 4);
        LE.put(&mut c, 64, sects.len() as u64, 4);
        for (i, (sname, addr, size, off)) in sects.iter().enumerate() {
            let s = 72 + 80 * i;
            c[s..s + sname.len()].copy_from_slice(sname.as_bytes());
            c[s + 16..s + 16 + name.len()].copy_from_slice(name.as_bytes());
            LE.put(&mut c, s + 32, *addr, 8);
            LE.put(&mut c, s + 40, *size, 8);
            LE.put(&mut c, s + 48, *off, 4);
            LE.put(&mut c, s + 52, 4, 4);
            LE.put(&mut c, s + 64, 0x8000_0400, 4);
        }
        c
    };
    let path_cmd = |cmd: u32, path: &str| {
        let str_off = if cmd == crate::macho_edit::LC_RPATH { 12 } else { 24 };
        let size = align(str_off + path.len() + 1, 8);
        let mut c = vec![0u8; size];
        LE.put(&mut c, 0, cmd as u64, 4);
        LE.put(&mut c, 4, size as u64, 4);
        LE.put(&mut c, 8, str_off as u64, 4);
        if str_off == 24 {
            LE.put(&mut c, 16, 0x1_0000, 4);
            LE.put(&mut c, 20, 0x1_0000, 4);
        }
        c[str_off..str_off + path.len()].copy_from_slice(path.as_bytes());
        c
    };

    // Sizes of what goes behind the commands.
    let text = g.code();
    let nsyms = g.below(6);
    let sym_names: Vec<String> = (0..nsyms).map(|i| format!("_{}{i}", g.name(""))).collect();
    // Bind opcodes: set a library and symbol, point into __TEXT, bind; plus raw opcode bytes.
    let mut bind = Vec::new();
    for s in &sym_names {
        bind.push(0x10 | (1 + g.below(paths.len().max(1)) as u8).min(15));
        bind.push(0x40);
        bind.extend_from_slice(s.as_bytes());
        bind.push(0);
        bind.push(0x51);
        bind.push(0x71);
        bind.push(g.byte() & 0x7f);
        bind.push(0x90 | (g.byte() >> 4) & 0x30);
    }
    if g.chance(64) {
        let n = g.below(16);
        bind.extend(g.bytes(n));
    }
    bind.push(0);

    // Commands in their final order, with placeholder offsets for the sizes.
    let padding = align(g.below(0x400), 8);
    let cmd_sizes = 72 + (72 + 80) + 72 + 48 + 24 + 24 + paths.iter().map(|(c, p)| path_cmd(*c, p).len()).sum::<usize>();
    let text_off = align(32 + cmd_sizes + padding, 16);
    let text_end = text_off + text.len();
    let link_off = align(text_end, 0x1000);
    let bind_off = link_off;
    let sym_off = align(bind_off + bind.len(), 8);
    let str_off = sym_off + 16 * nsyms;
    let mut strtab = vec![0u8, 0];
    let strx: Vec<usize> = sym_names.iter().map(|s| cstr(&mut strtab, s)).collect();
    let end = str_off + strtab.len();

    cmds.push(seg("__PAGEZERO", 0, vm, 0, 0, 0, &[]));
    cmds.push(seg(
        "__TEXT",
        vm,
        align(text_end, 0x1000) as u64,
        0,
        text_end as u64,
        5,
        &[("__text", vm + text_off as u64, text.len() as u64, text_off as u64)],
    ));
    cmds.push(seg("__LINKEDIT", vm + link_off as u64, align(end - link_off, 0x1000) as u64, link_off as u64, (end - link_off) as u64, 1, &[]));
    let mut dyld = vec![0u8; 48];
    LE.put(&mut dyld, 0, LC_DYLD_INFO_ONLY as u64, 4);
    LE.put(&mut dyld, 4, 48, 4);
    LE.put(&mut dyld, 16, bind_off as u64, 4);
    LE.put(&mut dyld, 20, bind.len() as u64, 4);
    cmds.push(dyld);
    let mut symtab = vec![0u8; 24];
    LE.put(&mut symtab, 0, LC_SYMTAB as u64, 4);
    LE.put(&mut symtab, 4, 24, 4);
    LE.put(&mut symtab, 8, sym_off as u64, 4);
    LE.put(&mut symtab, 12, nsyms as u64, 4);
    LE.put(&mut symtab, 16, str_off as u64, 4);
    LE.put(&mut symtab, 20, strtab.len() as u64, 4);
    cmds.push(symtab);
    let entry_off = text_off + g.below(text.len());
    let mut main = vec![0u8; 24];
    LE.put(&mut main, 0, LC_MAIN as u64, 4);
    LE.put(&mut main, 4, 24, 4);
    LE.put(&mut main, 8, entry_off as u64, 8);
    cmds.push(main);
    for (c, p) in &paths {
        cmds.push(path_cmd(*c, p));
    }

    let mut f = vec![0u8; 32];
    LE.put(&mut f, 0, 0xfeed_facf, 4);
    LE.put(&mut f, 4, if arm { 0x0100_000c } else { 0x0100_0007 }, 4);
    LE.put(&mut f, 8, if arm { 0 } else { 3 }, 4);
    LE.put(&mut f, 12, 2, 4);
    LE.put(&mut f, 16, cmds.len() as u64, 4);
    LE.put(&mut f, 20, cmds.iter().map(Vec::len).sum::<usize>() as u64, 4);
    LE.put(&mut f, 24, 0x0020_0085, 4);
    for c in &cmds {
        f.extend_from_slice(c);
    }
    f.resize(text_off, 0);
    f.extend_from_slice(&text);
    f.resize(bind_off, 0);
    f.extend_from_slice(&bind);
    f.resize(sym_off, 0);
    for (i, x) in strx.iter().enumerate() {
        let s = sym_off + 16 * i;
        f.resize(s + 16, 0);
        LE.put(&mut f, s, *x as u64, 4);
        f[s + 4] = 0x0f;
        f[s + 5] = 1;
        LE.put(&mut f, s + 8, vm + (text_off + g.below(text.len())) as u64, 8);
    }
    f.resize(str_off, 0);
    f.extend_from_slice(&strtab);
    exp.entry = Some(vm + entry_off as u64);
    exp.paths = paths;

    // Sometimes wrap the slice in a universal header.
    if g.chance(48) {
        let off = 0x1000usize;
        let mut fat = vec![0u8; off];
        let be = W { be: true };
        be.put(&mut fat, 0, 0xcafe_babe, 4);
        be.put(&mut fat, 4, 1, 4);
        be.put(&mut fat, 8, if arm { 0x0100_000c } else { 0x0100_0007 }, 4);
        be.put(&mut fat, 16, off as u64, 4);
        be.put(&mut fat, 20, f.len() as u64, 4);
        be.put(&mut fat, 24, 12, 4);
        fat.extend_from_slice(&f);
        return (fat, exp);
    }
    (f, exp)
}

/// Builds one file from the input.
pub fn build(g: &mut Gen) -> (Kind, Vec<u8>, Expect) {
    match g.below(3) {
        0 => {
            let (f, e) = pe(g);
            (Kind::Pe, f, e)
        }
        1 => {
            let (f, e) = elf(g);
            (Kind::Elf, f, e)
        }
        _ => {
            let (f, e) = macho(g);
            (Kind::MachO, f, e)
        }
    }
}
