//! ELF32 / ELF64 parser (both byte orders).

use crate::model::*;

const MAX_ROWS: usize = 200_000;
/// Memory the symbol, versioning, hash and relocation grids of one file may
/// take together. `MAX_ROWS` is per section, and every section header may
/// name the same bytes: 400 headers over one range of 800 KB asked for 79
/// million rows.
pub const GRID_BUDGET: usize = 256 << 20;

/// What is left of `GRID_BUDGET`.
struct Budget(std::cell::Cell<usize>);

impl Budget {
    /// Add a row and charge its cells and text. Returns false, without
    /// adding it, once the budget is used up.
    fn push(&self, g: &mut Grid, row: Vec<Cell>, span: Option<(usize, usize)>) -> bool {
        let left = self.0.get();
        if left == 0 {
            return false;
        }
        let cost: usize = row.iter().map(|c| c.text.len() + std::mem::size_of::<Cell>()).sum();
        self.0.set(left.saturating_sub(cost));
        g.push(row, span);
        true
    }

    fn spent(&self) -> bool {
        self.0.get() == 0
    }

    /// Row count for a title; says so when the budget cut the grid short.
    fn count(&self, n: usize) -> String {
        if self.spent() { format!("first {n} shown") } else { n.to_string() }
    }
}

const ET: Names = &[(0, "ET_NONE"), (1, "ET_REL (relocatable)"), (2, "ET_EXEC (executable)"), (3, "ET_DYN (shared object / PIE)"), (4, "ET_CORE (core dump)")];

const EM: Names = &[
    (0, "None"),
    (2, "SPARC"),
    (3, "Intel 80386"),
    (8, "MIPS"),
    (20, "PowerPC"),
    (21, "PowerPC64"),
    (22, "S390"),
    (40, "ARM"),
    (42, "SuperH"),
    (43, "SPARC V9"),
    (50, "IA-64"),
    (62, "x86-64"),
    (183, "AArch64"),
    (243, "RISC-V"),
    (247, "BPF"),
    (258, "LoongArch"),
];

const CLASS: Names = &[(1, "ELF32"), (2, "ELF64")];
const DATA: Names = &[(1, "Little endian"), (2, "Big endian")];
const OSABI: Names =
    &[(0, "System V"), (1, "HP-UX"), (2, "NetBSD"), (3, "Linux"), (6, "Solaris"), (9, "FreeBSD"), (12, "OpenBSD"), (97, "ARM"), (255, "Standalone")];

const PT: Names = &[
    (0, "NULL"),
    (1, "LOAD"),
    (2, "DYNAMIC"),
    (3, "INTERP"),
    (4, "NOTE"),
    (5, "SHLIB"),
    (6, "PHDR"),
    (7, "TLS"),
    (0x6474e550, "GNU_EH_FRAME"),
    (0x6474e551, "GNU_STACK"),
    (0x6474e552, "GNU_RELRO"),
    (0x6474e553, "GNU_PROPERTY"),
];

const PF: Names = &[(1, "X"), (2, "W"), (4, "R")];

const SHT: Names = &[
    (0, "NULL"),
    (1, "PROGBITS"),
    (2, "SYMTAB"),
    (3, "STRTAB"),
    (4, "RELA"),
    (5, "HASH"),
    (6, "DYNAMIC"),
    (7, "NOTE"),
    (8, "NOBITS"),
    (9, "REL"),
    (10, "SHLIB"),
    (11, "DYNSYM"),
    (14, "INIT_ARRAY"),
    (15, "FINI_ARRAY"),
    (16, "PREINIT_ARRAY"),
    (17, "GROUP"),
    (18, "SYMTAB_SHNDX"),
    (19, "RELR"),
    (0x6ffffff6, "GNU_HASH"),
    (0x6ffffffd, "GNU_VERDEF"),
    (0x6ffffffe, "GNU_VERNEED"),
    (0x6fffffff, "GNU_VERSYM"),
];

const SHF: Names = &[
    (0x1, "WRITE"),
    (0x2, "ALLOC"),
    (0x4, "EXECINSTR"),
    (0x10, "MERGE"),
    (0x20, "STRINGS"),
    (0x40, "INFO_LINK"),
    (0x80, "LINK_ORDER"),
    (0x200, "GROUP"),
    (0x400, "TLS"),
    (0x800, "COMPRESSED"),
];

const DT: Names = &[
    (0, "NULL"),
    (1, "NEEDED"),
    (2, "PLTRELSZ"),
    (3, "PLTGOT"),
    (4, "HASH"),
    (5, "STRTAB"),
    (6, "SYMTAB"),
    (7, "RELA"),
    (8, "RELASZ"),
    (9, "RELAENT"),
    (10, "STRSZ"),
    (11, "SYMENT"),
    (12, "INIT"),
    (13, "FINI"),
    (14, "SONAME"),
    (15, "RPATH"),
    (16, "SYMBOLIC"),
    (17, "REL"),
    (18, "RELSZ"),
    (19, "RELENT"),
    (20, "PLTREL"),
    (21, "DEBUG"),
    (22, "TEXTREL"),
    (23, "JMPREL"),
    (24, "BIND_NOW"),
    (25, "INIT_ARRAY"),
    (26, "FINI_ARRAY"),
    (27, "INIT_ARRAYSZ"),
    (28, "FINI_ARRAYSZ"),
    (29, "RUNPATH"),
    (30, "FLAGS"),
    (32, "PREINIT_ARRAY"),
    (33, "PREINIT_ARRAYSZ"),
    (35, "RELRSZ"),
    (36, "RELR"),
    (37, "RELRENT"),
    (0x6ffffef5, "GNU_HASH"),
    (0x6ffffff0, "VERSYM"),
    (0x6ffffff9, "RELACOUNT"),
    (0x6ffffffa, "RELCOUNT"),
    (0x6ffffffb, "FLAGS_1"),
    (0x6ffffffc, "VERDEF"),
    (0x6ffffffd, "VERDEFNUM"),
    (0x6ffffffe, "VERNEED"),
    (0x6fffffff, "VERNEEDNUM"),
];

const STT: [&str; 7] = ["NOTYPE", "OBJECT", "FUNC", "SECTION", "FILE", "COMMON", "TLS"];
const STB: [&str; 3] = ["LOCAL", "GLOBAL", "WEAK"];
const STV: [&str; 4] = ["DEFAULT", "INTERNAL", "HIDDEN", "PROTECTED"];

struct Sh {
    name: String,
    ty: u32,
    addr: u64,
    offset: usize,
    size: usize,
    link: usize,
    hdr: usize,
}

struct Ph {
    ty: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

pub fn parse(data: &[u8]) -> Option<Parsed> {
    if data.len() < 0x34 || &data[..4] != b"\x7fELF" {
        return None;
    }
    let is64 = data[4] == 2;
    let en = if data[5] == 2 { Endian::Big } else { Endian::Little };
    let rd = Rd::new(data, en);
    let p = if is64 { 8 } else { 4 };
    let hex = |off: usize, size: usize| cell(data, off, size, Kind::Hex, en);
    let mut nodes = Vec::new();
    let budget = Budget(std::cell::Cell::new(GRID_BUDGET));

    // Header
    let mut f = Fields::new(data, en);
    f.add("e_ident[EI_MAG]", 0, 4, Kind::Bytes).note("\\x7FELF");
    f.add("e_ident[EI_CLASS]", 4, 1, Kind::Enum(CLASS));
    f.add("e_ident[EI_DATA]", 5, 1, Kind::Enum(DATA));
    f.add("e_ident[EI_VERSION]", 6, 1, Kind::Hex);
    f.add("e_ident[EI_OSABI]", 7, 1, Kind::Enum(OSABI));
    f.add("e_ident[EI_ABIVERSION]", 8, 1, Kind::Hex);
    f.add("e_ident[EI_PAD]", 9, 7, Kind::Bytes);
    f.seq(
        16,
        &[
            ("e_type", 2, Kind::Enum(ET)),
            ("e_machine", 2, Kind::Enum(EM)),
            ("e_version", 4, Kind::Hex),
            ("e_entry", p, Kind::Hex),
            ("e_phoff", p, Kind::Hex),
            ("e_shoff", p, Kind::Hex),
            ("e_flags", 4, Kind::Hex),
            ("e_ehsize", 2, Kind::Hex),
            ("e_phentsize", 2, Kind::Hex),
            ("e_phnum", 2, Kind::Dec),
            ("e_shentsize", 2, Kind::Hex),
            ("e_shnum", 2, Kind::Dec),
            ("e_shstrndx", 2, Kind::Dec),
        ],
    );
    let ehsize = if is64 { 64 } else { 52 };
    nodes.push(Node::grid("ELF Header", f.finish()).with_span(0, ehsize));

    let e_type = rd.u16(16);
    let machine = rd.u16(18);
    let entry = rd.uint(24, p);
    let phoff = clamp_off(rd.uint(24 + p, p));
    let shoff = clamp_off(rd.uint(24 + 2 * p, p));
    let tail = 24 + 3 * p + 4;
    let phentsize = rd.u16(tail + 2) as usize;
    let phnum = rd.u16(tail + 4) as usize;
    let shentsize = rd.u16(tail + 6) as usize;
    let shnum = rd.u16(tail + 8) as usize;
    let shstrndx = rd.u16(tail + 10) as usize;

    // Program headers
    let mut phs = Vec::new();
    let mut g = Grid::new(&["Type", "Type Name", "Flags", "Offset", "VirtAddr", "PhysAddr", "FileSize", "MemSize", "Align", "Perm"]);
    if phoff != 0 && phentsize >= if is64 { 56 } else { 32 } {
        for i in 0..phnum {
            let h = phoff + i * phentsize;
            if !rd.has(h, phentsize) {
                break;
            }
            // (type, flags, offset, vaddr, paddr, filesz, memsz, align) field offsets
            let o: [usize; 8] = if is64 { [0, 4, 8, 16, 24, 32, 40, 48] } else { [0, 24, 4, 8, 12, 16, 20, 28] };
            let ph = Ph {
                ty: rd.u32(h + o[0]),
                flags: rd.u32(h + o[1]),
                offset: rd.uint(h + o[2], p),
                vaddr: rd.uint(h + o[3], p),
                filesz: rd.uint(h + o[5], p),
                memsz: rd.uint(h + o[6], p),
            };
            g.push(
                vec![
                    cell(data, h + o[0], 4, Kind::Enum(PT), en),
                    Cell::text(lookup(PT, ph.ty as u64).unwrap_or("?")),
                    cell(data, h + o[1], 4, Kind::Flags(PF), en),
                    hex(h + o[2], p),
                    hex(h + o[3], p),
                    hex(h + o[4], p),
                    hex(h + o[5], p),
                    hex(h + o[6], p),
                    hex(h + o[7], p),
                    Cell::text(flags_text(PF, ph.flags as u64)),
                ],
                Some((h, phentsize)),
            );
            phs.push(ph);
        }
        nodes.push(Node::grid(format!("Program Headers ({})", phs.len()), g).with_span(phoff, phnum * phentsize));
    }

    // Section headers
    let mut shs: Vec<Sh> = Vec::new();
    if shoff != 0 && shentsize >= if is64 { 64 } else { 40 } {
        for i in 0..shnum {
            let h = shoff + i * shentsize;
            if !rd.has(h, shentsize) {
                break;
            }
            shs.push(Sh {
                name: String::new(),
                ty: rd.u32(h + 4),
                addr: rd.uint(h + 8 + p, p),
                offset: clamp_off(rd.uint(h + 8 + 2 * p, p)),
                size: clamp_off(rd.uint(h + 8 + 3 * p, p)),
                link: rd.u32(h + 8 + 4 * p) as usize,
                hdr: h,
            });
        }
        let strtab = shs.get(shstrndx).map(|s| s.offset).unwrap_or(0);
        for s in &mut shs {
            s.name = rd.cstr(strtab.saturating_add(rd.u32(s.hdr) as usize), 256);
        }
        let mut g =
            Grid::new(&["#", "Name", "Name Idx", "Type", "Type Name", "Flags", "Address", "Offset", "Size", "Link", "Info", "Align", "EntSize", "Flag Names"]);
        for (i, s) in shs.iter().enumerate() {
            let h = s.hdr;
            g.push(
                vec![
                    Cell::text(i.to_string()),
                    Cell::text(s.name.clone()),
                    hex(h, 4),
                    cell(data, h + 4, 4, Kind::Enum(SHT), en),
                    Cell::text(lookup(SHT, s.ty as u64).unwrap_or("?")),
                    cell(data, h + 8, p, Kind::Flags(SHF), en),
                    hex(h + 8 + p, p),
                    hex(h + 8 + 2 * p, p),
                    hex(h + 8 + 3 * p, p),
                    hex(h + 8 + 4 * p, 4),
                    hex(h + 12 + 4 * p, 4),
                    hex(h + 16 + 4 * p, p),
                    hex(h + 16 + 5 * p, p),
                    Cell::text(flags_text(SHF, rd.uint(h + 8, p))),
                ],
                (s.ty != 8).then_some((s.offset, s.size)),
            );
        }
        nodes.push(Node::grid(format!("Section Headers ({})", shs.len()), g).with_span(shoff, shnum * shentsize));
    }

    let va_to_off = |va: u64| -> Option<usize> {
        phs.iter().find(|h| h.ty == 1 && va >= h.vaddr && va - h.vaddr < h.filesz).map(|h| clamp_off(h.offset.wrapping_add(va - h.vaddr)))
    };

    // Dynamic section
    let mut needed = Vec::new();
    let mut soname = String::new();
    let dynamic = shs
        .iter()
        .find(|s| s.ty == 6)
        .map(|s| (s.offset, s.size, shs.get(s.link).map(|l| l.offset)))
        .or_else(|| phs.iter().find(|h| h.ty == 2).map(|h| (clamp_off(h.offset), clamp_off(h.filesz), None)));
    if let Some((doff, dsize, mut strtab)) = dynamic {
        let n = (dsize / (2 * p)).min(4096);
        if strtab.is_none() {
            strtab = (0..n).find(|i| rd.uint(doff + i * 2 * p, p) == 5).and_then(|i| va_to_off(rd.uint(doff + i * 2 * p + p, p)));
        }
        let mut g = Grid::new(&["Tag", "Tag Name", "Value", "Meaning"]);
        for i in 0..n {
            let o = doff + i * 2 * p;
            if !rd.has(o, 2 * p) {
                break;
            }
            let tag = rd.uint(o, p);
            let val = rd.uint(o + p, p);
            let mut meaning = String::new();
            if matches!(tag, 1 | 14 | 15 | 29)
                && let Some(st) = strtab
            {
                meaning = rd.cstr(st.saturating_add(clamp_off(val)), 1024);
                match tag {
                    1 => needed.push(meaning.clone()),
                    14 => soname = meaning.clone(),
                    _ => {}
                }
            }
            g.push(
                vec![cell(data, o, p, Kind::Enum(DT), en), Cell::text(lookup(DT, tag).unwrap_or("?")), hex(o + p, p), Cell::text(meaning)],
                Some((o, 2 * p)),
            );
            if tag == 0 {
                break;
            }
        }
        nodes.push(Node::grid(format!("Dynamic Section ({})", g.rows.len()), g).with_span(doff, dsize));
    }

    // Symbol tables
    let symsize = if is64 { 24 } else { 16 };
    let sym_name = |symtab: &Sh, idx: usize| -> String {
        let o = symtab.offset + idx * symsize;
        let st = shs.get(symtab.link).map(|l| l.offset).unwrap_or(0);
        if idx == 0 || !rd.has(o, symsize) { String::new() } else { rd.cstr(st + rd.u32(o) as usize, 512) }
    };
    let mut sym_nodes = Vec::new();
    let mut symbols: Vec<(u64, String)> = Vec::new();
    let mut functions: Vec<(u64, u64)> = Vec::new();
    for s in shs.iter().filter(|s| s.ty == 2 || s.ty == 11) {
        let mut g = Grid::new(&["#", "Name", "Value", "Size", "Type", "Bind", "Visibility", "Section"]);
        let n = (s.size / symsize).min(MAX_ROWS);
        for i in 0..n {
            let o = s.offset + i * symsize;
            if !rd.has(o, symsize) {
                break;
            }
            let (value, size, info, other, shndx) = if is64 { (o + 8, o + 16, o + 4, o + 5, o + 6) } else { (o + 4, o + 8, o + 12, o + 13, o + 14) };
            let inf = rd.u8(info);
            let ndx = rd.u16(shndx);
            let addr = rd.uint(value, p);
            if ndx != 0 && ndx < 0xff00 && addr != 0 && inf & 0xf <= 2 && symbols.len() < MAX_ROWS {
                symbols.push((addr, sym_name(s, i)));
                let len = rd.uint(size, p);
                if inf & 0xf == 2 && len != 0 {
                    functions.push((addr, addr.saturating_add(len)));
                }
            }
            let sec = match ndx {
                0 => "UNDEF".to_string(),
                0xfff1 => "ABS".to_string(),
                0xfff2 => "COMMON".to_string(),
                n => shs.get(n as usize).map(|x| x.name.clone()).unwrap_or_else(|| n.to_string()),
            };
            let row = vec![
                Cell::text(i.to_string()),
                Cell::text(sym_name(s, i)),
                hex(value, p),
                hex(size, p),
                Cell::text(STT.get((inf & 0xf) as usize).copied().unwrap_or("?")),
                Cell::text(STB.get((inf >> 4) as usize).copied().unwrap_or("?")),
                Cell::text(STV[(rd.u8(other) & 3) as usize]),
                Cell::text(sec),
            ];
            if !budget.push(&mut g, row, Some((o, symsize))) {
                break;
            }
        }
        sym_nodes.push(Node::grid(format!("{} ({})", s.name, budget.count(g.rows.len())), g).with_span(s.offset, s.size));
    }
    if !sym_nodes.is_empty() {
        nodes.push(Node::text("Symbols", "Select a symbol table.").with_children(sym_nodes));
    }

    // Symbol versioning: which version of which library each dynamic symbol binds to.
    let strtab_of = |sec: &Sh| shs.get(sec.link).map(|l| l.offset).unwrap_or(0);
    let mut version_names: std::collections::HashMap<u16, String> = std::collections::HashMap::new();
    let mut ver_nodes = Vec::new();
    for sec in shs.iter().filter(|x| x.ty == 0x6fff_fffe) {
        let st = strtab_of(sec);
        let mut g = Grid::new(&["Library", "Version", "Index", "Hash", "Flags"]);
        let mut o = sec.offset;
        let sec_end = sec.offset.saturating_add(sec.size);
        for _ in 0..4096 {
            if !rd.has(o, 16) || o >= sec_end || g.rows.len() >= MAX_ROWS || budget.spent() {
                break;
            }
            let file = rd.cstr(st.saturating_add(rd.u32(o + 4) as usize), 256);
            let mut a = o.saturating_add(rd.u32(o + 8) as usize);
            for _ in 0..rd.u16(o + 2).min(4096) {
                // Entries may share one aux chain, so the rows are capped, not only the chain.
                if !rd.has(a, 16) || a >= sec_end || g.rows.len() >= MAX_ROWS {
                    break;
                }
                let name = rd.cstr(st.saturating_add(rd.u32(a + 8) as usize), 256);
                let index = rd.u16(a + 6);
                version_names.insert(index & 0x7fff, format!("{name} ({file})"));
                if !budget.push(&mut g, vec![Cell::text(file.clone()), Cell::text(name), hex(a + 6, 2), hex(a, 4), hex(a + 4, 2)], Some((a, 16))) {
                    break;
                }
                let next = rd.u32(a + 12) as usize;
                if next == 0 {
                    break;
                }
                a = a.saturating_add(next);
            }
            let next = rd.u32(o + 12) as usize;
            if next == 0 {
                break;
            }
            o = o.saturating_add(next);
        }
        ver_nodes.push(Node::grid(format!("Needed Versions ({})", budget.count(g.rows.len())), g).with_span(sec.offset, sec.size));
    }
    for sec in shs.iter().filter(|x| x.ty == 0x6fff_fffd) {
        let st = strtab_of(sec);
        let mut g = Grid::new(&["Index", "Version", "Parents", "Flags", "Hash"]);
        let mut o = sec.offset;
        for _ in 0..4096 {
            if !rd.has(o, 20) || o >= sec.offset.saturating_add(sec.size) || budget.spent() {
                break;
            }
            let mut names = Vec::new();
            let mut a = o.saturating_add(rd.u32(o + 12) as usize);
            for _ in 0..rd.u16(o + 6).min(64) {
                if !rd.has(a, 8) {
                    break;
                }
                names.push(rd.cstr(st.saturating_add(rd.u32(a) as usize), 256));
                let next = rd.u32(a + 4) as usize;
                if next == 0 {
                    break;
                }
                a = a.saturating_add(next);
            }
            let name = names.first().cloned().unwrap_or_default();
            version_names.insert(rd.u16(o + 4) & 0x7fff, name.clone());
            let flags = rd.u16(o + 2);
            let row = vec![
                hex(o + 4, 2),
                Cell::text(name),
                Cell::text(names.iter().skip(1).cloned().collect::<Vec<_>>().join(", ")),
                Cell::text(if flags & 1 != 0 { "BASE" } else { "" }),
                hex(o + 8, 4),
            ];
            if !budget.push(&mut g, row, Some((o, 20))) {
                break;
            }
            let next = rd.u32(o + 16) as usize;
            if next == 0 {
                break;
            }
            o = o.saturating_add(next);
        }
        ver_nodes.push(Node::grid(format!("Defined Versions ({})", budget.count(g.rows.len())), g).with_span(sec.offset, sec.size));
    }
    for sec in shs.iter().filter(|x| x.ty == 0x6fff_ffff) {
        let Some(dynsym) = shs.get(sec.link) else { continue };
        let mut g = Grid::new(&["#", "Symbol", "Version Index", "Version"]);
        for i in 0..(sec.size / 2).min(MAX_ROWS) {
            let o = sec.offset + i * 2;
            if !rd.has(o, 2) {
                break;
            }
            let v = rd.u16(o);
            let text = match v & 0x7fff {
                0 => "local".to_string(),
                1 => "global (unversioned)".to_string(),
                n => version_names.get(&n).cloned().unwrap_or_else(|| format!("version {n}")),
            };
            let row = vec![
                Cell::text(i.to_string()),
                Cell::text(sym_name(dynsym, i)),
                hex(o, 2),
                Cell::text(format!("{text}{}", if v & 0x8000 != 0 { " (hidden)" } else { "" })),
            ];
            if !budget.push(&mut g, row, Some((o, 2))) {
                break;
            }
        }
        ver_nodes.insert(0, Node::grid(format!("Symbol Versions ({})", budget.count(g.rows.len())), g).with_span(sec.offset, sec.size));
    }
    if !ver_nodes.is_empty() {
        nodes.push(Node::text("Symbol Versioning", "Select a table.").with_children(ver_nodes));
    }

    // GNU hash table: header, and a check that every hashed symbol's chain
    // entry really carries the hash of its name.
    for sec in shs.iter().filter(|x| x.ty == 0x6fff_fff6) {
        let Some(dynsym) = shs.get(sec.link) else { continue };
        let o = sec.offset;
        let (nbuckets, symoffset, bloom_size) = (rd.u32(o) as usize, rd.u32(o + 4) as usize, rd.u32(o + 8) as usize);
        let mut f = Fields::new(data, en);
        f.seq(o, &[("nbuckets", 4, Kind::Dec), ("symoffset", 4, Kind::Dec), ("bloom_size", 4, Kind::Dec), ("bloom_shift", 4, Kind::Dec)]);
        let buckets = o.saturating_add(16).saturating_add(bloom_size.saturating_mul(p));
        let chains = buckets.saturating_add(nbuckets.saturating_mul(4));
        let nsyms = (dynsym.size / symsize).min(MAX_ROWS);
        let (mut good, mut bad) = (0usize, 0usize);
        let mut cut = false;
        let mut g = Grid::new(&["#", "Symbol", "Hash", "Bucket", "Chain Value", "Check"]);
        for i in symoffset..nsyms {
            let c = chains.saturating_add((i - symoffset).saturating_mul(4));
            if !rd.has(c, 4) || c >= o.saturating_add(sec.size) {
                break;
            }
            if budget.spent() {
                cut = true;
                break;
            }
            let name = sym_name(dynsym, i);
            let h = name.bytes().fold(5381u32, |h, b| h.wrapping_mul(33).wrapping_add(b as u32));
            let ok = h | 1 == rd.u32(c) | 1;
            if ok {
                good += 1;
            } else {
                bad += 1;
            }
            let row = vec![
                Cell::text(i.to_string()),
                Cell::text(name),
                Cell::text(format!("{h:08X}")),
                Cell::text(if nbuckets == 0 { String::new() } else { (h as usize % nbuckets).to_string() }),
                hex(c, 4),
                Cell::text(if ok { "ok" } else { "MISMATCH" }),
            ];
            if !budget.push(&mut g, row, Some((c, 4))) {
                cut = true;
                break;
            }
        }
        f.note(if cut {
            format!("only the first {} hashed symbols were checked; {bad} of them do not match their chain entry", good + bad)
        } else if bad == 0 {
            format!("all {good} hashed symbols verify")
        } else {
            format!("{bad} of {} hashed symbols do NOT match their chain entry", good + bad)
        });
        nodes.push(
            Node::grid("GNU Hash", f.finish())
                .with_span(o, sec.size)
                .with_children(vec![Node::grid(format!("Hashed Symbols ({})", budget.count(g.rows.len())), g)]),
        );
    }

    // Relocations
    let mut rel_nodes = Vec::new();
    for s in shs.iter().filter(|s| s.ty == 4 || s.ty == 9) {
        let rela = s.ty == 4;
        let ent = if rela { 3 * p } else { 2 * p };
        let symtab = shs.get(s.link);
        let mut g = Grid::new(&["Offset", "Info", "Type", "Symbol", "Addend"]);
        for i in 0..(s.size / ent).min(MAX_ROWS) {
            let o = s.offset + i * ent;
            if !rd.has(o, ent) {
                break;
            }
            let info = rd.uint(o + p, p);
            let (sym, ty) = if is64 { ((info >> 32) as usize, info & 0xffff_ffff) } else { ((info >> 8) as usize, info & 0xff) };
            let row = vec![
                hex(o, p),
                hex(o + p, p),
                Cell::text(ty.to_string()),
                Cell::text(symtab.map(|t| sym_name(t, sym)).unwrap_or_default()),
                if rela { hex(o + 2 * p, p) } else { Cell::text("") },
            ];
            if !budget.push(&mut g, row, Some((o, ent))) {
                break;
            }
        }
        rel_nodes.push(Node::grid(format!("{} ({})", s.name, budget.count(g.rows.len())), g).with_span(s.offset, s.size));
    }
    if !rel_nodes.is_empty() {
        nodes.push(Node::text("Relocations", "Select a relocation section.").with_children(rel_nodes));
    }

    // Notes
    let mut build_id = String::new();
    let mut ranges: Vec<(usize, usize)> = shs.iter().filter(|s| s.ty == 7).map(|s| (s.offset, s.size)).collect();
    if ranges.is_empty() {
        ranges = phs.iter().filter(|h| h.ty == 4).map(|h| (clamp_off(h.offset), clamp_off(h.filesz))).collect();
    }
    let mut g = Grid::new(&["Offset", "Owner", "Type", "Size", "Description"]);
    for (start, size) in ranges {
        let mut o = start;
        while rd.has(o, 12) && o + 12 <= start.saturating_add(size) && g.rows.len() < 1024 {
            let namesz = rd.u32(o) as usize;
            let descsz = rd.u32(o + 4) as usize;
            let ty = rd.u32(o + 8);
            let name = rd.cstr(o + 12, namesz.min(64));
            let desc_off = o + 12 + namesz.div_ceil(4) * 4;
            let desc = rd.bytes(desc_off, descsz.min(64));
            let text = if name == "GNU" && ty == 3 {
                build_id = hex_bytes(desc).to_lowercase();
                format!("Build ID: {build_id}")
            } else if name == "GNU" && ty == 1 && descsz >= 16 {
                format!("ABI tag: OS {} version {}.{}.{}", rd.u32(desc_off), rd.u32(desc_off + 4), rd.u32(desc_off + 8), rd.u32(desc_off + 12))
            } else {
                hex_bytes(desc)
            };
            g.push(
                vec![Cell::text(format!("{o:08X}")), Cell::text(name), Cell::text(format!("{ty:X}")), Cell::text(format!("{descsz:X}")), Cell::text(text)],
                Some((o, 12 + namesz + descsz)),
            );
            let next = desc_off + descsz.div_ceil(4) * 4;
            if next <= o {
                break;
            }
            o = next;
        }
    }
    if !g.rows.is_empty() {
        nodes.push(Node::grid("Notes", g));
    }

    // Summary and address maps
    let interp = phs.iter().find(|h| h.ty == 3).map(|h| rd.cstr(clamp_off(h.offset), clamp_off(h.filesz))).unwrap_or_default();
    let description = format!(
        "{} {} for {}",
        if is64 { "ELF64" } else { "ELF32" },
        match e_type {
            1 => "relocatable object",
            2 => "executable",
            3 => "shared object / PIE",
            4 => "core dump",
            _ => "file",
        },
        lookup(EM, machine as u64).unwrap_or("unknown machine")
    );
    let mut info = vec![
        ("File Type".to_string(), description.clone()),
        ("Byte Order".into(), if en == Endian::Big { "big endian" } else { "little endian" }.into()),
        ("OS ABI".into(), lookup(OSABI, data[7] as u64).unwrap_or("?").into()),
        ("Entry Point".into(), format!("{entry:X}")),
    ];
    if !interp.is_empty() {
        info.push(("Interpreter".into(), interp));
    }
    if !soname.is_empty() {
        info.push(("SONAME".into(), soname));
    }
    if !needed.is_empty() {
        info.push(("Needed Libraries".into(), needed.join(", ")));
    }
    if !build_id.is_empty() {
        info.push(("Build ID".into(), build_id));
    }
    if shs.is_empty() {
        info.push(("Sections".into(), "no section headers (stripped)".into()));
    }

    let mut maps: Vec<Map> = Vec::new();
    let loads: Vec<&Ph> = phs.iter().filter(|h| h.ty == 1).collect();
    if !loads.is_empty() {
        // Prefer section granularity inside loadable segments when available.
        for s in shs.iter().filter(|s| s.addr != 0 && s.ty != 8 && s.size > 0) {
            maps.push(Map {
                name: s.name.clone(),
                vaddr: s.addr,
                vsize: s.size as u64,
                offset: s.offset as u64,
                fsize: s.size as u64,
                exec: rd.uint(s.hdr + 8, p) & 4 != 0,
            });
        }
        for (i, h) in loads.iter().enumerate() {
            maps.push(Map { name: format!("LOAD #{i}"), vaddr: h.vaddr, vsize: h.memsz, offset: h.offset, fsize: h.filesz, exec: h.flags & 1 != 0 });
        }
    } else {
        for s in shs.iter().filter(|s| s.ty == 1 && s.size > 0) {
            maps.push(Map {
                name: s.name.clone(),
                vaddr: s.addr,
                vsize: s.size as u64,
                offset: s.offset as u64,
                fsize: s.size as u64,
                exec: rd.uint(s.hdr + 8, p) & 4 != 0,
            });
        }
    }

    let arch = match machine {
        3 => Arch::X86,
        62 => Arch::X64,
        40 => Arch::Arm,
        183 => Arch::Arm64,
        _ => Arch::Other,
    };
    Some(Parsed {
        format: Format::Elf,
        description,
        root: Node::tool("File", Tool::FileInfo, kv_grid(info)).with_children(nodes),
        maps,
        image_base: 0,
        entry: (entry != 0).then_some(entry),
        arch,
        symbols,
        functions,
    })
}
