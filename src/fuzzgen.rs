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
    /// PE: TLS callback VAs, in order.
    pub tls_callbacks: Vec<u64>,
    /// PE: text the dump must contain (PDB path, Rich header, .NET method names).
    pub shows: Vec<String>,
    /// PE: the CompanyName of the version resource.
    pub company: Option<String>,
    /// ELF: DT_NEEDED in order, DT_SONAME, DT_RUNPATH.
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub runpath: Option<String>,
    /// Mach-O: (load command, path) in order.
    pub paths: Vec<(u32, String)>,
    /// Mach-O: the file carries a valid ad hoc code signature.
    pub signed: bool,
    /// ELF: a GNU hash table over this many dynamic symbols.
    pub gnu_hashed: Option<usize>,
    /// ELF: dynamic symbols carry versions (GLIBC_2.2.5 from the first DT_NEEDED).
    pub versioned: bool,
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

    // Header layout: a Rich header after the DOS stub, and sometimes headers
    // with no room left, so adding a section has to grow them.
    let nsec = 5;
    let opt_size = if is64 { 0xF0 } else { 0xE0 };
    let rich = if g.chance(128) { rich_header(g) } else { Vec::new() };
    let tight = g.chance(64);
    let lfanew = if tight { 0x400 - 40 * nsec - opt_size - 24 } else { align(0x80 + rich.len(), 8) };
    let rich = if 0x80 + rich.len() <= lfanew { rich } else { Vec::new() };
    let opt = lfanew + 24;
    let sec_tab = opt + opt_size;
    let headers = align(sec_tab + 40 * nsec, fa);

    // .rdata: TLS directory and callbacks, a debug directory with a CodeView
    // record, and a .NET header with metadata and method bodies.
    let rdata_rva = reloc_rva + align(reloc.len().max(1), sa) as u32;
    let rdata_raw = headers + [text.len(), idata.len(), edata.len(), reloc.len()].iter().map(|l| align(*l, fa)).sum::<usize>();
    let va = |off: usize| image_base + rdata_rva as u64 + off as u64;
    let mut rdata = Vec::new();
    let mut tls_dir = (0u32, 0u32);
    if g.chance(128) {
        let dir_size = if is64 { 40 } else { 24 };
        let callbacks: Vec<u64> = (0..1 + g.below(3)).map(|_| image_base + (text_rva as usize + g.below(text.len())) as u64).collect();
        let index = dir_size;
        let array = align(index + 4, ps);
        let template = array + (callbacks.len() + 1) * ps;
        rdata.resize(template + 8, 0);
        for (k, v) in [va(template), va(template + 8), va(index), va(array)].iter().enumerate() {
            LE.put(&mut rdata, k * ps, *v, ps);
        }
        for (k, cb) in callbacks.iter().enumerate() {
            LE.put(&mut rdata, array + k * ps, *cb, ps);
        }
        tls_dir = (rdata_rva, dir_size as u32);
        exp.tls_callbacks = callbacks;
    }
    let mut debug_dir = (0u32, 0u32);
    if g.chance(128) {
        let at = align(rdata.len(), 4);
        let pdb = format!("C:\\fuzz\\{}.pdb", g.name("p"));
        let mut rsds = b"RSDS".to_vec();
        rsds.extend(g.bytes(16));
        rsds.extend(1u32.to_le_bytes());
        rsds.extend(pdb.as_bytes());
        rsds.push(0);
        let rec = at + 28;
        rdata.resize(rec, 0);
        LE.put(&mut rdata, at + 12, 2, 4); // IMAGE_DEBUG_TYPE_CODEVIEW
        LE.put(&mut rdata, at + 16, rsds.len() as u64, 4);
        LE.put(&mut rdata, at + 20, (rdata_rva as usize + rec) as u64, 4);
        LE.put(&mut rdata, at + 24, (rdata_raw + rec) as u64, 4);
        rdata.extend(rsds);
        debug_dir = (rdata_rva + at as u32, 28);
        exp.shows.push(pdb);
    }
    let mut clr_dir = (0u32, 0u32);
    if g.chance(96) {
        let at = align(rdata.len(), 4);
        let (md, methods) = dotnet_metadata(g, rdata_rva as usize + at + 72);
        rdata.resize(at + 72, 0);
        LE.put(&mut rdata, at, 72, 4);
        LE.put(&mut rdata, at + 4, 2, 2);
        LE.put(&mut rdata, at + 6, 5, 2);
        LE.put(&mut rdata, at + 8, (rdata_rva as usize + at + 72) as u64, 4);
        LE.put(&mut rdata, at + 12, md.len() as u64, 4);
        LE.put(&mut rdata, at + 16, 1, 4); // ILONLY
        LE.put(&mut rdata, at + 20, 0x0600_0001, 4);
        rdata.extend(md);
        clr_dir = (rdata_rva + at as u32, 72);
        exp.shows.extend(methods);
    }
    if !rich.is_empty() {
        exp.shows.push("Rich Header".into());
    }

    // Headers.
    let sections: Vec<(&str, u32, Vec<u8>, u32)> = vec![
        (".text", text_rva, text, 0x6000_0020),
        (".idata", idata_rva, idata, 0xC000_0040),
        (".edata", edata_rva, edata, 0x4000_0040),
        (".reloc", reloc_rva, reloc, 0x4200_0040),
        (".rdata", rdata_rva, rdata, 0xC000_0040),
    ];
    debug_assert_eq!(sections.len(), nsec);
    let mut f = vec![0u8; headers];
    f[..2].copy_from_slice(b"MZ");
    LE.put(&mut f, 0x3c, lfanew as u64, 4);
    f[0x80..0x80 + rich.len()].copy_from_slice(&rich);
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
    set_dir(&mut f, 6, debug_dir);
    set_dir(&mut f, 9, tls_dir);
    set_dir(&mut f, 14, clr_dir);
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
    debug_assert_eq!(raw, rdata_raw + align(sections[4].2.len(), fa));
    // A version resource, written by the resource editor into a new .rsrc section.
    if !tight && g.chance(96) {
        use crate::pe::resources::{self, ResId};
        let company = g.name("Co");
        let mut root = resources::ResDir::default();
        resources::insert(&mut root, &ResId::Id(16), &ResId::Id(1), &ResId::Id(1033), version_info(&company));
        if resources::apply(&mut f, &root).is_ok() {
            exp.company = Some(company);
        }
    }
    (f, exp)
}

/// A Rich header ("DanS", tool entries, "Rich", key), every word XORed with the key.
fn rich_header(g: &mut Gen) -> Vec<u8> {
    let key = g.u32() | 1;
    let mut words = vec![0x536E_6144 ^ key, key, key, key];
    for _ in 0..1 + g.below(6) {
        words.push(g.u32() ^ key);
        words.push((1 + g.below(200) as u32) ^ key);
    }
    let mut b: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    b.extend_from_slice(b"Rich");
    b.extend(key.to_le_bytes());
    b
}

/// A VS_VERSIONINFO with one CompanyName string.
fn version_info(company: &str) -> Vec<u8> {
    fn block(key: &str, value: &[u8], text: bool, children: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0u8; 6];
        b.extend(key.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
        b.resize(align(b.len(), 4), 0);
        b.extend_from_slice(value);
        for c in children {
            b.resize(align(b.len(), 4), 0);
            b.extend_from_slice(c);
        }
        let len = b.len() as u64;
        LE.put(&mut b, 0, len, 2);
        LE.put(&mut b, 2, if text { value.len() / 2 } else { value.len() } as u64, 2);
        LE.put(&mut b, 4, text as u64, 2);
        b
    }
    let utf16z = |s: &str| -> Vec<u8> { s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect() };
    let mut fixed = vec![0u8; 52];
    LE.put(&mut fixed, 0, 0xFEEF_04BD, 4);
    LE.put(&mut fixed, 4, 0x1_0000, 4);
    let string = block("CompanyName", &utf16z(company), true, &[]);
    let table = block("040904B0", &[], true, &[string]);
    let sfi = block("StringFileInfo", &[], true, &[table]);
    block("VS_VERSION_INFO", &fixed, false, &[sfi])
}

/// ECMA-335 metadata placed at `rva`: a Module, one TypeDef and a few
/// MethodDefs whose tiny-format IL bodies follow the metadata. Returns the
/// bytes and the method names.
fn dotnet_metadata(g: &mut Gen, rva: usize) -> (Vec<u8>, Vec<String>) {
    let methods: Vec<String> = (0..1 + g.below(4)).map(|i| format!("{}{i}", g.name("M"))).collect();
    // Heaps. Every index fits in 2 bytes (HeapSizes 0).
    let mut strings = vec![0u8];
    let module = cstr(&mut strings, "fuzz.dll");
    let ty = cstr(&mut strings, "Program");
    let ns = cstr(&mut strings, "Fuzz");
    let names: Vec<usize> = methods.iter().map(|m| cstr(&mut strings, m)).collect();
    strings.resize(align(strings.len(), 4), 0);
    let blob = vec![0u8, 3, 0x00, 0x00, 0x01, 0]; // index 1: default, 0 params, void
    let guid = g.bytes(16);
    let us = vec![0u8; 4];
    // #~: header, row counts, then Module (10 bytes), TypeDef (14), MethodDef (14) rows.
    let mut t = Vec::new();
    t.extend(0u32.to_le_bytes());
    t.extend([2, 0, 0, 1]);
    t.extend((1u64 | 1 << 2 | 1 << 6).to_le_bytes()); // valid: Module, TypeDef, MethodDef
    t.extend(0u64.to_le_bytes());
    for n in [1u32, 1, methods.len() as u32] {
        t.extend(n.to_le_bytes());
    }
    for v in [0u16, module as u16, 1, 0, 0] {
        t.extend(v.to_le_bytes());
    }
    t.extend(0x0010_0001u32.to_le_bytes()); // public, before field init
    for v in [ty as u16, ns as u16, 0, 1, 1] {
        t.extend(v.to_le_bytes());
    }
    // Method bodies go after the metadata; their RVAs are filled in below.
    let body_rows = t.len();
    for n in &names {
        t.extend(0u32.to_le_bytes());
        for v in [0u16, 0x0096, *n as u16, 1, 1] {
            t.extend(v.to_le_bytes());
        }
    }
    t.resize(align(t.len(), 4), 0);
    let streams: [(&str, &Vec<u8>); 5] = [("#~", &t), ("#Strings", &strings), ("#US", &us), ("#GUID", &guid), ("#Blob", &blob)];
    let version = b"v4.0.30319\0\0";
    let mut md = Vec::new();
    md.extend(0x424A_5342u32.to_le_bytes());
    md.extend([1, 0, 1, 0]);
    md.extend(0u32.to_le_bytes());
    md.extend((version.len() as u32).to_le_bytes());
    md.extend_from_slice(version);
    md.extend(0u16.to_le_bytes());
    md.extend((streams.len() as u16).to_le_bytes());
    let header_len = md.len() + streams.iter().map(|(n, _)| 8 + align(n.len() + 1, 4)).sum::<usize>();
    let mut at = header_len;
    let mut table_at = 0;
    for (name, data) in &streams {
        if *name == "#~" {
            table_at = at;
        }
        md.extend((at as u32).to_le_bytes());
        md.extend((data.len() as u32).to_le_bytes());
        md.extend_from_slice(name.as_bytes());
        md.push(0);
        md.resize(align(md.len(), 4), 0);
        at += data.len();
    }
    for (_, data) in &streams {
        md.extend_from_slice(data);
    }
    // Tiny IL bodies: nop..., ret.
    for i in 0..methods.len() {
        let body = md.len();
        let code_len = 1 + g.below(6);
        md.push((code_len as u8) << 2 | 2);
        md.extend(std::iter::repeat_n(0u8, code_len - 1));
        md.push(0x2A);
        let row = table_at + body_rows + 14 * i;
        LE.put(&mut md, row, (rva + body) as u64, 4);
    }
    (md, methods)
}

// --- ELF --------------------------------------------------------------------

/// The GNU symbol hash (DT_GNU_HASH).
fn gnu_hash(name: &str) -> u32 {
    name.bytes().fold(5381u32, |h, c| h.wrapping_mul(33).wrapping_add(c as u32))
}

/// The System V symbol hash, used by version records.
fn elf_hash(name: &str) -> u32 {
    let mut h = 0u32;
    for c in name.bytes() {
        h = (h << 4).wrapping_add(c as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// One section of a built ELF file. `link` is a section index.
struct ElfSec {
    ty: u32,
    flags: u64,
    data: Vec<u8>,
    link: usize,
    info: u64,
    entsize: u64,
}

/// An ELF executable or shared object (32 or 64 bit, either byte order) with
/// a dynamic section and dynamic symbols, and optionally a GNU hash table,
/// symbol versions, dynamic and static relocations, a static symbol table,
/// a build ID note and a .comment section.
pub fn elf(g: &mut Gen) -> (Vec<u8>, Expect) {
    let is64 = g.chance(170);
    let w = W { be: g.chance(40) };
    let p = if is64 { 8 } else { 4 };
    let base: u64 = if is64 { 0x40_0000 } else { 0x804_8000 };
    let mut exp = Expect::default();
    let (ehsize, phsize, shsize, dynsize, symsize, relasize) = if is64 { (64, 56, 64, 16, 24, 24) } else { (52, 32, 40, 8, 16, 12) };

    // Every choice is drawn here, before the two layout passes below.
    let needed: Vec<String> = (0..g.below(5)).map(|i| format!("lib{}{i}.so", g.name(""))).collect();
    let soname = g.chance(128).then(|| format!("lib{}.so.1", g.name("")));
    let runpath = g.chance(100).then(|| format!("$ORIGIN/{}", g.name("")));
    let syms: Vec<String> = (0..g.below(6)).map(|i| format!("{}{i}", g.name("s"))).collect();
    let text = g.code();
    let sym_at: Vec<usize> = syms.iter().map(|_| g.below(text.len())).collect();
    let with_hash = g.chance(160);
    let with_versions = !needed.is_empty() && !syms.is_empty() && g.chance(140);
    let versioned: Vec<bool> = syms.iter().map(|_| g.chance(128)).collect();
    let rela_dyn: Vec<(usize, u64)> = (0..if g.chance(128) { 1 + g.below(4) } else { 0 }).map(|_| (g.below(text.len()), g.below(0x100) as u64)).collect();
    let with_symtab = g.chance(150);
    let rela_text: Vec<(usize, usize)> =
        if with_symtab { (0..g.below(4)).map(|_| (g.below(text.len()), g.below(syms.len() + 2))).collect() } else { Vec::new() };
    let with_note = g.chance(128);
    let build_id = g.bytes(20);
    let with_comment = g.chance(128);
    let e_type = if g.chance(128) { 3 } else { 2 };
    let machine = match (is64, g.below(3)) {
        (true, 0) => 183,
        (true, _) => 62,
        (false, 0) => 40,
        (false, _) => 3,
    };
    let entry_at = g.below(text.len());
    const VERSION: &str = "GLIBC_2.2.5";

    let mut dynstr = vec![0u8];
    let needed_off: Vec<usize> = needed.iter().map(|n| cstr(&mut dynstr, n)).collect();
    let soname_off = soname.as_ref().map(|s| cstr(&mut dynstr, s));
    let runpath_off = runpath.as_ref().map(|s| cstr(&mut dynstr, s));
    let sym_off: Vec<usize> = syms.iter().map(|s| cstr(&mut dynstr, s)).collect();
    let version_off = with_versions.then(|| cstr(&mut dynstr, VERSION));

    // Section indexes, in file order; .shstrtab is last.
    let mut order: Vec<&'static str> = vec![".text", ".dynsym", ".dynstr"];
    if with_hash {
        order.push(".gnu.hash");
    }
    if with_versions {
        order.extend([".gnu.version", ".gnu.version_r"]);
    }
    if !rela_dyn.is_empty() {
        order.push(".rela.dyn");
    }
    order.push(".dynamic");
    if with_note {
        order.push(".note.gnu.build-id");
    }
    if with_comment {
        order.push(".comment");
    }
    if with_symtab {
        order.extend([".symtab", ".strtab"]);
        if !rela_text.is_empty() {
            order.push(".rela.text");
        }
    }
    order.push(".shstrtab");
    let idx = |n: &str| order.iter().position(|o| *o == n).map_or(0, |i| i + 1);

    // Builds every section; `addr` gives a section's address (0 in the first pass).
    let build = |addr: &dyn Fn(&str) -> u64| -> Vec<ElfSec> {
        let text_addr = addr(".text");
        let mut secs = Vec::new();
        let mut s = |_name: &'static str, ty, flags, data, link: &str, info, entsize| {
            secs.push(ElfSec { ty, flags, data, link: idx(link), info, entsize });
        };
        let sym = |out: &mut Vec<u8>, name: u64, info: u8, shndx: u64, value: u64| {
            let o = out.len();
            out.resize(o + symsize, 0);
            w.put(out, o, name, 4);
            if is64 {
                out[o + 4] = info;
                w.put(out, o + 6, shndx, 2);
                w.put(out, o + 8, value, 8);
            } else {
                w.put(out, o + 4, value, 4);
                out[o + 12] = info;
                w.put(out, o + 14, shndx, 2);
            }
        };
        s(".text", 1, 6, text.clone(), "", 0, 0);
        let mut dynsym = vec![0u8; symsize];
        for (i, o) in sym_off.iter().enumerate() {
            sym(&mut dynsym, *o as u64, 0x12, idx(".text") as u64, text_addr + sym_at[i] as u64);
        }
        s(".dynsym", 11, 2, dynsym, ".dynstr", 1, symsize as u64);
        s(".dynstr", 3, 2, dynstr.clone(), "", 0, 0);
        if with_hash {
            // One bucket holding every symbol from index 1, a one word bloom filter.
            let shift = 6u32;
            let bits = (8 * p) as u32;
            let mut bloom = 0u64;
            for n in &syms {
                let h = gnu_hash(n);
                bloom |= 1 << (h % bits) | 1 << ((h >> shift) % bits);
            }
            let mut d = Vec::new();
            for v in [1u64, 1, 1, shift as u64] {
                let o = d.len();
                w.put(&mut d, o, v, 4);
            }
            let o = d.len();
            w.put(&mut d, o, bloom, p);
            let o = d.len();
            w.put(&mut d, o, if syms.is_empty() { 0 } else { 1 }, 4);
            for (i, n) in syms.iter().enumerate() {
                let last = i + 1 == syms.len();
                let o = d.len();
                w.put(&mut d, o, (gnu_hash(n) & !1 | last as u32) as u64, 4);
            }
            s(".gnu.hash", 0x6fff_fff6, 2, d, ".dynsym", 0, 0);
        }
        if let Some(vo) = version_off {
            let mut versym = vec![0u8; 2];
            for v in &versioned {
                let o = versym.len();
                w.put(&mut versym, o, if *v { 2 } else { 1 }, 2);
            }
            s(".gnu.version", 0x6fff_ffff, 2, versym, ".dynsym", 0, 2);
            let mut need = vec![0u8; 32];
            w.put(&mut need, 0, 1, 2);
            w.put(&mut need, 2, 1, 2);
            w.put(&mut need, 4, needed_off[0] as u64, 4);
            w.put(&mut need, 8, 16, 4);
            w.put(&mut need, 16, elf_hash(VERSION) as u64, 4);
            w.put(&mut need, 22, 2, 2);
            w.put(&mut need, 24, vo as u64, 4);
            s(".gnu.version_r", 0x6fff_fffe, 2, need, ".dynstr", 1, 0);
        }
        let rela = |out: &mut Vec<u8>, off: u64, sym: u64, ty: u64, addend: u64| {
            let o = out.len();
            out.resize(o + relasize, 0);
            w.put(out, o, off, p);
            w.put(out, o + p, if is64 { sym << 32 | ty } else { sym << 8 | ty }, p);
            w.put(out, o + 2 * p, addend, p);
        };
        if !rela_dyn.is_empty() {
            let mut d = Vec::new();
            for (at, addend) in &rela_dyn {
                // R_X86_64_RELATIVE and R_386_RELATIVE are both 8.
                rela(&mut d, text_addr + *at as u64, 0, 8, *addend);
            }
            s(".rela.dyn", 4, 2, d, ".dynsym", 0, relasize as u64);
        }
        let mut tags: Vec<(u64, u64)> = needed_off.iter().map(|o| (1, *o as u64)).collect();
        if let Some(o) = soname_off {
            tags.push((14, o as u64));
        }
        if let Some(o) = runpath_off {
            tags.push((29, o as u64));
        }
        tags.extend([(5, addr(".dynstr")), (10, dynstr.len() as u64), (6, addr(".dynsym")), (11, symsize as u64)]);
        if with_hash {
            tags.push((0x6fff_fef5, addr(".gnu.hash")));
        }
        if with_versions {
            tags.extend([(0x6fff_fff0, addr(".gnu.version")), (0x6fff_fffe, addr(".gnu.version_r")), (0x6fff_ffff, 1)]);
        }
        if !rela_dyn.is_empty() {
            tags.extend([(7, addr(".rela.dyn")), (8, (rela_dyn.len() * relasize) as u64), (9, relasize as u64)]);
        }
        tags.push((0, 0));
        let mut d = Vec::new();
        for (tag, val) in tags {
            let o = d.len();
            w.put(&mut d, o, tag, p);
            w.put(&mut d, o + p, val, p);
        }
        s(".dynamic", 6, 3, d, ".dynstr", 0, dynsize as u64);
        if with_note {
            let mut d = vec![0u8; 16];
            w.put(&mut d, 0, 4, 4);
            w.put(&mut d, 4, 20, 4);
            w.put(&mut d, 8, 3, 4); // NT_GNU_BUILD_ID
            d[12..16].copy_from_slice(b"GNU\0");
            d.extend_from_slice(&build_id);
            s(".note.gnu.build-id", 7, 2, d, "", 0, 0);
        }
        if with_comment {
            s(".comment", 1, 0x30, b"GCC: (fuzzgen) 1.0\0".to_vec(), "", 0, 1);
        }
        if with_symtab {
            let mut strtab = vec![0u8];
            let mut symtab = vec![0u8; symsize];
            sym(&mut symtab, 0, 0x03, idx(".text") as u64, text_addr); // section symbol
            let file = cstr(&mut strtab, "fuzz.c");
            sym(&mut symtab, file as u64, 0x04, 0xfff1, 0);
            for (i, n) in syms.iter().enumerate() {
                let o = cstr(&mut strtab, n);
                sym(&mut symtab, o as u64, 0x12, idx(".text") as u64, text_addr + sym_at[i] as u64);
            }
            s(".symtab", 2, 0, symtab, ".strtab", 3, symsize as u64);
            s(".strtab", 3, 0, strtab, "", 0, 0);
            if !rela_text.is_empty() {
                let mut d = Vec::new();
                for (at, sym) in &rela_text {
                    // R_X86_64_PC32 and R_386_PC32 are both 2.
                    rela(&mut d, *at as u64, *sym as u64, 2, 0);
                }
                s(".rela.text", 4, 0x40, d, ".symtab", idx(".text") as u64, relasize as u64);
            }
        }
        secs
    };

    // First pass for the sizes, then the layout, then the real contents.
    let nph = if with_note { 3 } else { 2 };
    let names = {
        let mut shstr = vec![0u8];
        let offs: Vec<usize> = order.iter().map(|n| cstr(&mut shstr, n)).collect();
        (shstr, offs)
    };
    let sizes: Vec<usize> = build(&|_| 0).iter().map(|s| s.data.len()).chain([names.0.len()]).collect();
    let mut offs = Vec::new();
    let mut at = ehsize + nph * phsize;
    for sz in &sizes {
        at = align(at, 8);
        offs.push(at);
        at += sz;
    }
    let sh_off = align(at, 8);
    let nsh = order.len() + 1;
    let end = sh_off + nsh * shsize;
    let addr = |n: &str| order.iter().position(|o| *o == n).map_or(0, |i| base + offs[i] as u64);
    let mut secs = build(&addr);
    secs.push(ElfSec { ty: 3, flags: 0, data: names.0.clone(), link: 0, info: 0, entsize: 0 });

    let mut f = vec![0u8; end];
    f[..4].copy_from_slice(b"\x7fELF");
    f[4] = if is64 { 2 } else { 1 };
    f[5] = if w.be { 2 } else { 1 };
    f[6] = 1;
    let entry = addr(".text") + entry_at as u64;
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
    w.put(&mut f, h + 10, order.len() as u64, 2); // e_shstrndx: the last section

    // Program headers: one PT_LOAD for everything, PT_DYNAMIC, and PT_NOTE.
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
    let sec_of = |n: &str| order.iter().position(|o| *o == n).map(|i| (offs[i], sizes[i]));
    if let Some((off, size)) = sec_of(".dynamic") {
        phdr(&mut f, 1, 2, 6, off, size);
    }
    if let Some((off, size)) = sec_of(".note.gnu.build-id") {
        phdr(&mut f, 2, 4, 4, off, size);
    }

    for (i, sec) in secs.iter().enumerate() {
        let off = offs[i];
        f[off..off + sec.data.len()].copy_from_slice(&sec.data);
        let s = sh_off + (i + 1) * shsize;
        let a = if sec.flags & 2 != 0 { base + off as u64 } else { 0 };
        w.put(&mut f, s, names.1[i] as u64, 4);
        w.put(&mut f, s + 4, sec.ty as u64, 4);
        let fields = [sec.flags, a, off as u64, sec.data.len() as u64];
        if is64 {
            for (k, v) in fields.iter().enumerate() {
                w.put(&mut f, s + 8 + 8 * k, *v, 8);
            }
            w.put(&mut f, s + 40, sec.link as u64, 4);
            w.put(&mut f, s + 44, sec.info, 4);
            // Notes are 4 byte aligned on 64-bit files too; readers pad the fields to sh_addralign.
            w.put(&mut f, s + 48, if sec.ty == 7 { 4 } else { 8 }, 8);
            w.put(&mut f, s + 56, sec.entsize, 8);
        } else {
            for (k, v) in fields.iter().enumerate() {
                w.put(&mut f, s + 8 + 4 * k, *v, 4);
            }
            w.put(&mut f, s + 24, sec.link as u64, 4);
            w.put(&mut f, s + 28, sec.info, 4);
            w.put(&mut f, s + 32, 4, 4);
            w.put(&mut f, s + 36, sec.entsize, 4);
        }
    }
    exp.needed = needed;
    exp.soname = soname;
    exp.runpath = runpath;
    exp.gnu_hashed = with_hash.then_some(syms.len());
    exp.versioned = with_versions;
    (f, exp)
}

// --- Mach-O -----------------------------------------------------------------

const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_MAIN: u32 = 0x8000_0028;
const LC_CODE_SIGNATURE: u32 = 0x1D;

/// An ad hoc code signature over `code`: a SuperBlob holding one CodeDirectory
/// (version 0x20400, SHA-256, 4 KB pages) with the hash of every page.
fn code_signature(code: &[u8], ident: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let be = W { be: true };
    let pages = code.len().div_ceil(0x1000);
    let hash_off = 88 + ident.len() + 1;
    let cd_len = hash_off + 32 * pages;
    let mut cd = vec![0u8; 88];
    be.put(&mut cd, 0, 0xfade_0c02, 4);
    be.put(&mut cd, 4, cd_len as u64, 4);
    be.put(&mut cd, 8, 0x20400, 4);
    be.put(&mut cd, 12, 0x2, 4); // adhoc
    be.put(&mut cd, 16, hash_off as u64, 4);
    be.put(&mut cd, 20, 88, 4); // identOffset
    be.put(&mut cd, 28, pages as u64, 4);
    be.put(&mut cd, 32, code.len() as u64, 4); // codeLimit
    cd[36] = 32; // hashSize
    cd[37] = 2; // SHA-256
    cd[39] = 12; // 4 KB pages
    cd.extend_from_slice(ident.as_bytes());
    cd.push(0);
    for page in code.chunks(0x1000) {
        cd.extend_from_slice(&Sha256::digest(page));
    }
    let mut sb = vec![0u8; 20];
    be.put(&mut sb, 0, 0xfade_0cc0, 4);
    be.put(&mut sb, 4, (20 + cd.len()) as u64, 4);
    be.put(&mut sb, 8, 1, 4);
    be.put(&mut sb, 16, 20, 4); // index 0: type 0 (CodeDirectory) at offset 20
    sb.extend_from_slice(&cd);
    sb
}

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
    let signed = g.chance(128);

    // Commands in their final order, with placeholder offsets for the sizes.
    let padding = align(g.below(0x400), 8);
    let cmd_sizes = 72 + (72 + 80) + 72 + 48 + 24 + 24 + if signed { 16 } else { 0 } + paths.iter().map(|(c, p)| path_cmd(*c, p).len()).sum::<usize>();
    let text_off = align(32 + cmd_sizes + padding, 16);
    let text_end = text_off + text.len();
    let link_off = align(text_end, 0x1000);
    let bind_off = link_off;
    let sym_off = align(bind_off + bind.len(), 8);
    let str_off = sym_off + 16 * nsyms;
    let mut strtab = vec![0u8, 0];
    let strx: Vec<usize> = sym_names.iter().map(|s| cstr(&mut strtab, s)).collect();
    let end = str_off + strtab.len();
    // An ad hoc signature at the end of __LINKEDIT hashes every page before it.
    const IDENT: &str = "gen.fuzz";
    let sig_off = align(end, 16);
    let pages = sig_off.div_ceil(0x1000);
    let sig_len = 20 + 88 + IDENT.len() + 1 + 32 * pages;
    let link_end = if signed { sig_off + sig_len } else { end };

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
    cmds.push(seg("__LINKEDIT", vm + link_off as u64, align(link_end - link_off, 0x1000) as u64, link_off as u64, (link_end - link_off) as u64, 1, &[]));
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
    if signed {
        let mut c = vec![0u8; 16];
        LE.put(&mut c, 0, LC_CODE_SIGNATURE as u64, 4);
        LE.put(&mut c, 4, 16, 4);
        LE.put(&mut c, 8, sig_off as u64, 4);
        LE.put(&mut c, 12, sig_len as u64, 4);
        cmds.push(c);
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
    if signed {
        f.resize(sig_off, 0);
        let sig = code_signature(&f, IDENT);
        debug_assert_eq!(sig.len(), sig_len);
        f.extend_from_slice(&sig);
    }
    exp.signed = signed;
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
