//! PE32 / PE32+ parser. Produces the node tree and exposes the layout
//! information the editing operations in `edit.rs` rely on.

pub mod consts;
pub mod dotnet;
pub mod edit;
mod ordlookup;
pub mod resources;
pub mod sig;

use crate::model::*;
use consts::*;

const LE: Endian = Endian::Little;
const MAX_ROWS: usize = 200_000;

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub vsize: u32,
    pub va: u32,
    pub rsize: u32,
    pub roff: u32,
    pub chars: u32,
    pub hdr_off: usize,
}

#[derive(Clone, Debug)]
pub struct Pe {
    pub lfanew: usize,
    pub is64: bool,
    pub machine: u16,
    pub file_hdr: usize,
    pub opt: usize,
    pub opt_size: usize,
    pub sec_table: usize,
    pub sections: Vec<Section>,
    pub image_base: u64,
    pub section_align: u32,
    pub file_align: u32,
    pub size_of_headers: u32,
    pub entry: u32,
    pub dirs_off: usize,
    pub num_dirs: usize,
}

pub struct ImportFn {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    /// File offset of the lookup table entry.
    pub thunk_off: usize,
    pub iat_rva: u32,
    pub hint_name_off: Option<usize>,
}

pub struct ImportModule {
    pub name: String,
    pub desc_off: usize,
    pub funcs: Vec<ImportFn>,
}

pub fn align_up(v: u64, a: u64) -> u64 {
    if a <= 1 { v } else { v.div_ceil(a) * a }
}

impl Pe {
    pub fn parse(data: &[u8]) -> Option<Pe> {
        let rd = Rd::new(data, LE);
        if data.len() < 0x40 || rd.u16(0) != 0x5A4D {
            return None;
        }
        let lfanew = rd.u32(0x3C) as usize;
        if !rd.has(lfanew, 24) || rd.u32(lfanew) != 0x0000_4550 {
            return None;
        }
        let file_hdr = lfanew + 4;
        let machine = rd.u16(file_hdr);
        let nsec = rd.u16(file_hdr + 2) as usize;
        let opt_size = rd.u16(file_hdr + 16) as usize;
        let opt = file_hdr + 20;
        let magic = rd.u16(opt);
        let is64 = magic == 0x20b;
        let (image_base, num_dirs_off) = if is64 { (rd.u64(opt + 24), opt + 108) } else { (rd.u32(opt + 28) as u64, opt + 92) };
        let dirs_off = num_dirs_off + 4;
        let declared = rd.u32(num_dirs_off) as usize;
        let room = (opt + opt_size).saturating_sub(dirs_off) / 8;
        let num_dirs = declared.min(16).min(room);
        let sec_table = opt + opt_size;
        let mut sections = Vec::new();
        for i in 0..nsec {
            let h = sec_table + i * 40;
            if !rd.has(h, 40) {
                break;
            }
            sections.push(Section {
                name: rd.cstr(h, 8),
                vsize: rd.u32(h + 8),
                va: rd.u32(h + 12),
                rsize: rd.u32(h + 16),
                roff: rd.u32(h + 20),
                chars: rd.u32(h + 36),
                hdr_off: h,
            });
        }
        Some(Pe {
            lfanew,
            is64,
            machine,
            file_hdr,
            opt,
            opt_size,
            sec_table,
            sections,
            image_base,
            section_align: rd.u32(opt + 32),
            file_align: rd.u32(opt + 36),
            size_of_headers: rd.u32(opt + 60),
            entry: rd.u32(opt + 16),
            dirs_off,
            num_dirs,
        })
    }

    pub fn ptr_size(&self) -> usize {
        if self.is64 { 8 } else { 4 }
    }

    pub fn dir(&self, data: &[u8], i: usize) -> (u32, u32) {
        if i >= self.num_dirs {
            return (0, 0);
        }
        let rd = Rd::new(data, LE);
        (rd.u32(self.dirs_off + i * 8), rd.u32(self.dirs_off + i * 8 + 4))
    }

    pub fn section_of_rva(&self, rva: u32) -> Option<usize> {
        self.sections.iter().position(|s| {
            let span = s.vsize.max(s.rsize).max(1);
            rva >= s.va && (rva - s.va) < span
        })
    }

    pub fn rva_to_off(&self, rva: u32) -> Option<usize> {
        if let Some(i) = self.section_of_rva(rva) {
            let s = &self.sections[i];
            let d = rva - s.va;
            return (d < s.rsize).then(|| s.roff as usize + d as usize);
        }
        let first = self.sections.iter().map(|s| s.va).min().unwrap_or(u32::MAX);
        (rva < first && rva < self.size_of_headers.max(0x1000)).then_some(rva as usize)
    }

    /// Convert a VA stored in the image (TLS, load config) to a file offset.
    pub fn va_to_off(&self, va: u64) -> Option<usize> {
        let rva = va.checked_sub(self.image_base)?;
        self.rva_to_off(u32::try_from(rva).ok()?)
    }

    /// End of the last section's raw data; everything after it is overlay.
    pub fn raw_end(&self) -> usize {
        self.sections.iter().filter(|s| s.rsize > 0).map(|s| s.roff as usize + s.rsize as usize).max().unwrap_or(self.size_of_headers as usize)
    }

    /// End of the image, aligned: where the next section would start. An
    /// empty section counts as one byte, the span `section_of_rva` gives it,
    /// so the result lies past every section an RVA can resolve to.
    pub fn image_end(&self) -> u64 {
        let end = self.sections.iter().map(|s| s.va as u64 + s.vsize.max(s.rsize).max(1) as u64).max().unwrap_or(self.size_of_headers as u64);
        align_up(end, self.section_align.max(1) as u64)
    }

    /// `image_end` as an RVA. The structural editors refuse a layout whose
    /// image end does not fit (`edit::layout_of`) before they rely on it.
    pub fn next_section_rva(&self) -> u32 {
        self.image_end() as u32
    }

    pub fn arch(&self) -> Arch {
        match self.machine {
            0x14c => Arch::X86,
            0x8664 => Arch::X64,
            0x1c0 | 0x1c2 | 0x1c4 => Arch::Arm,
            0xaa64 => Arch::Arm64,
            _ => Arch::Other,
        }
    }

    pub fn imports(&self, data: &[u8]) -> Vec<ImportModule> {
        let rd = Rd::new(data, LE);
        let (rva, _) = self.dir(data, 1);
        let mut out = Vec::new();
        let Some(mut off) = (rva != 0).then(|| self.rva_to_off(rva)).flatten() else {
            return out;
        };
        let ps = self.ptr_size();
        let ord_flag = 1u64 << (ps * 8 - 1);
        while rd.has(off, 20) && out.len() < 4096 {
            let oft = rd.u32(off);
            let name_rva = rd.u32(off + 12);
            let ft = rd.u32(off + 16);
            if name_rva == 0 && ft == 0 {
                break;
            }
            let name = self.rva_to_off(name_rva).map(|o| rd.cstr(o, 256)).unwrap_or_default();
            let mut funcs = Vec::new();
            let lookup = if oft != 0 { oft } else { ft };
            if let Some(mut t) = self.rva_to_off(lookup) {
                let mut idx = 0u32;
                while rd.has(t, ps) && funcs.len() < 65536 {
                    let v = rd.uint(t, ps);
                    if v == 0 {
                        break;
                    }
                    let iat_rva = ft.wrapping_add(idx * ps as u32);
                    if v & ord_flag != 0 {
                        funcs.push(ImportFn { name: None, ordinal: Some(v as u16), thunk_off: t, iat_rva, hint_name_off: None });
                    } else {
                        let hn = self.rva_to_off(v as u32);
                        funcs.push(ImportFn {
                            name: Some(hn.map(|o| rd.cstr(o + 2, 512)).unwrap_or_else(|| "<invalid>".into())),
                            ordinal: None,
                            thunk_off: t,
                            iat_rva,
                            hint_name_off: hn,
                        });
                    }
                    t += ps;
                    idx += 1;
                }
            }
            out.push(ImportModule { name, desc_off: off, funcs });
            off += 20;
        }
        out
    }

    pub fn imphash(&self, data: &[u8]) -> Option<String> {
        use md5::{Digest, Md5};
        let mods = self.imports(data);
        if mods.is_empty() {
            return None;
        }
        let mut parts = Vec::new();
        for m in &mods {
            let lower = m.name.to_lowercase();
            let base = ["dll", "ocx", "sys"].iter().find_map(|e| lower.strip_suffix(&format!(".{e}"))).unwrap_or(&lower).to_string();
            for f in &m.funcs {
                match (&f.name, f.ordinal) {
                    (Some(n), _) => parts.push(format!("{base}.{}", n.to_lowercase())),
                    // Same convention as pefile: well known ordinals become names.
                    (None, Some(o)) => match ordlookup::lookup(&lower, o) {
                        Some(n) => parts.push(format!("{base}.{}", n.to_lowercase())),
                        None => parts.push(format!("{base}.ord{o}")),
                    },
                    _ => {}
                }
            }
        }
        Some(hex_bytes(&Md5::digest(parts.join(",").as_bytes())).to_lowercase())
    }
}

fn hx(v: u64, digits: usize) -> Cell {
    Cell::text(format!("{v:0digits$X}"))
}

fn c32(data: &[u8], off: usize) -> Cell {
    cell(data, off, 4, Kind::Hex, LE)
}

fn c16(data: &[u8], off: usize) -> Cell {
    cell(data, off, 2, Kind::Hex, LE)
}

// ---------------------------------------------------------------------------

pub fn parse(data: &[u8]) -> Option<(Parsed, Pe)> {
    let pe = Pe::parse(data)?;
    let rd = Rd::new(data, LE);
    let mut nodes = Vec::new();

    // DOS header
    let mut f = Fields::new(data, LE);
    let names =
        ["e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno"];
    for (i, n) in names.iter().enumerate() {
        f.add(n, i * 2, 2, Kind::Hex);
    }
    f.add("e_res", 0x1C, 8, Kind::Bytes);
    f.add("e_oemid", 0x24, 2, Kind::Hex);
    f.add("e_oeminfo", 0x26, 2, Kind::Hex);
    f.add("e_res2", 0x28, 20, Kind::Bytes);
    f.add("e_lfanew", 0x3C, 4, Kind::Hex);
    let mut dos = Node::grid("Dos Header", f.finish()).with_span(0, 0x40);
    if let Some(rich) = rich_header(data, &pe) {
        dos.children.push(rich);
    }
    nodes.push(dos);

    // NT headers
    let mut f = Fields::new(data, LE);
    f.add("Signature", pe.lfanew, 4, Kind::Hex).note("PE\\0\\0");
    let mut nt = Node::grid("Nt Headers", f.finish()).with_span(pe.lfanew, 24 + pe.opt_size);

    let mut f = Fields::new(data, LE);
    f.seq(
        pe.file_hdr,
        &[
            ("Machine", 2, Kind::Enum(MACHINE)),
            ("NumberOfSections", 2, Kind::Hex),
            ("TimeDateStamp", 4, Kind::Time),
            ("PointerToSymbolTable", 4, Kind::Hex),
            ("NumberOfSymbols", 4, Kind::Hex),
            ("SizeOfOptionalHeader", 2, Kind::Hex),
            ("Characteristics", 2, Kind::Flags(FILE_CHARS)),
        ],
    );
    nt.children.push(Node::grid("File Header", f.finish()).with_span(pe.file_hdr, 20));

    let mut f = Fields::new(data, LE);
    let o = pe.opt;
    let mut off = f.seq(
        o,
        &[
            ("Magic", 2, Kind::Enum(OPT_MAGIC)),
            ("MajorLinkerVersion", 1, Kind::Hex),
            ("MinorLinkerVersion", 1, Kind::Hex),
            ("SizeOfCode", 4, Kind::Hex),
            ("SizeOfInitializedData", 4, Kind::Hex),
            ("SizeOfUninitializedData", 4, Kind::Hex),
            ("AddressOfEntryPoint", 4, Kind::Hex),
            ("BaseOfCode", 4, Kind::Hex),
        ],
    );
    if let Some(i) = pe.section_of_rva(pe.entry) {
        // Row index 6 is AddressOfEntryPoint.
        f.grid.rows[6][4].text = format!("in section {}", pe.sections[i].name);
    }
    let p = pe.ptr_size();
    if !pe.is64 {
        off = f.seq(off, &[("BaseOfData", 4, Kind::Hex)]);
    }
    off = f.seq(
        off,
        &[
            ("ImageBase", p, Kind::Hex),
            ("SectionAlignment", 4, Kind::Hex),
            ("FileAlignment", 4, Kind::Hex),
            ("MajorOperatingSystemVersion", 2, Kind::Hex),
            ("MinorOperatingSystemVersion", 2, Kind::Hex),
            ("MajorImageVersion", 2, Kind::Hex),
            ("MinorImageVersion", 2, Kind::Hex),
            ("MajorSubsystemVersion", 2, Kind::Hex),
            ("MinorSubsystemVersion", 2, Kind::Hex),
            ("Win32VersionValue", 4, Kind::Hex),
            ("SizeOfImage", 4, Kind::Hex),
            ("SizeOfHeaders", 4, Kind::Hex),
            ("CheckSum", 4, Kind::Hex),
            ("Subsystem", 2, Kind::Enum(SUBSYSTEM)),
            ("DllCharacteristics", 2, Kind::Flags(DLL_CHARS)),
            ("SizeOfStackReserve", p, Kind::Hex),
            ("SizeOfStackCommit", p, Kind::Hex),
            ("SizeOfHeapReserve", p, Kind::Hex),
            ("SizeOfHeapCommit", p, Kind::Hex),
            ("LoaderFlags", 4, Kind::Hex),
            ("NumberOfRvaAndSizes", 4, Kind::Hex),
        ],
    );
    let _ = off;
    let mut opt = Node::grid("Optional Header", f.finish()).with_span(pe.opt, pe.opt_size);

    let mut f = Fields::new(data, LE);
    for (i, dir_name) in DIR_NAMES.iter().enumerate().take(pe.num_dirs) {
        let d = pe.dirs_off + i * 8;
        let (rva, size) = pe.dir(data, i);
        f.add(&format!("{dir_name} RVA"), d, 4, Kind::Hex);
        if rva != 0 && i != 4 {
            if let Some(s) = pe.section_of_rva(rva) {
                f.note(format!("in section {}", pe.sections[s].name));
            } else {
                f.note("not in any section");
            }
        } else if rva != 0 {
            f.note("file offset");
        }
        f.add(&format!("{dir_name} Size"), d + 4, 4, Kind::Hex);
        let _ = size;
    }
    opt.children.push(Node::grid("Data Directories", f.finish()).with_span(pe.dirs_off, pe.num_dirs * 8));
    nt.children.push(opt);
    nodes.push(nt);

    // Sections
    let mut g = Grid::new(&[
        "Name",
        "Virtual Size",
        "Virtual Address",
        "Raw Size",
        "Raw Address",
        "Reloc Address",
        "Linenumbers",
        "Relocs N",
        "Lines N",
        "Characteristics",
        "Entropy",
        "Flags",
    ]);
    for s in &pe.sections {
        let h = s.hdr_off;
        let raw = rd.bytes(s.roff as usize, s.rsize as usize);
        g.push(
            vec![
                cell(data, h, 8, Kind::Str, LE),
                c32(data, h + 8),
                c32(data, h + 12),
                c32(data, h + 16),
                c32(data, h + 20),
                c32(data, h + 24),
                c32(data, h + 28),
                c16(data, h + 32),
                c16(data, h + 34),
                cell(data, h + 36, 4, Kind::Flags(SECTION_CHARS), LE),
                Cell::text(format!("{:.3}", entropy(raw))),
                Cell::text(flags_text(SECTION_CHARS, s.chars as u64)),
            ],
            Some((h, 40)),
        );
    }
    nodes.push(Node::tool("Section Headers", Tool::PeSections, g).with_span(pe.sec_table, pe.sections.len() * 40));

    let builders: [fn(&[u8], &Pe) -> Option<Node>; 12] = [
        export_dir,
        import_dir,
        resources::node,
        exception_dir,
        security_dir,
        reloc_dir,
        debug_dir,
        tls_dir,
        load_config_dir,
        bound_import_dir,
        delay_import_dir,
        clr_dir,
    ];
    for (i, b) in builders.iter().enumerate() {
        if let Some(n) = b(data, &pe) {
            nodes.push(n);
        } else if i == 2 {
            nodes.push(Node::tool("Resource Directory", Tool::PeResources, Grid::default()));
        }
    }

    let raw_end = pe.raw_end();
    if raw_end < data.len() {
        let g = kv_grid(vec![
            ("Offset".into(), format!("{raw_end:08X}")),
            ("Size".into(), size_text((data.len() - raw_end) as u64)),
            ("Entropy".into(), format!("{:.3}", entropy(&data[raw_end..]))),
        ]);
        nodes.push(Node::grid("Overlay", g).with_span(raw_end, data.len() - raw_end));
    }

    nodes.push(Node::tool("Import Editor", Tool::PeImportAdder, Grid::default()));
    nodes.push(Node::tool("Export Editor", Tool::PeExports, Grid::default()));
    nodes.push(Node::tool("Relocations and TLS", Tool::PeRelocs, Grid::default()));
    nodes.push(Node::tool("Rebuilder", Tool::PeRebuilder, Grid::default()));

    // Summary
    let kind = if rd.u16(pe.file_hdr + 18) & 0x2000 != 0 { "DLL" } else { "executable" };
    let description = format!("{} {} for {}", if pe.is64 { "PE32+" } else { "PE32" }, kind, lookup(MACHINE, pe.machine as u64).unwrap_or("unknown machine"));
    let mut info = vec![
        ("File Type".to_string(), description.clone()),
        ("Subsystem".into(), lookup(SUBSYSTEM, rd.u16(pe.opt + 68) as u64).unwrap_or("?").into()),
        ("Compiled".into(), time_text(rd.u32(pe.file_hdr + 4) as u64)),
        ("Entry Point RVA".into(), format!("{:08X}", pe.entry)),
        ("Image Base".into(), format!("{:X}", pe.image_base)),
        ("Sections".into(), pe.sections.iter().map(|s| s.name.clone()).collect::<Vec<_>>().join(", ")),
    ];
    if let Some(h) = pe.imphash(data) {
        info.push(("Imphash".into(), h));
    }
    if pe.dir(data, 14).0 != 0 {
        info.push((".NET".into(), "managed assembly (CLR header present)".into()));
    }
    if raw_end < data.len() {
        info.push(("Overlay".into(), format!("{} at {raw_end:08X}", size_text((data.len() - raw_end) as u64))));
    }
    let stored = rd.u32(pe.opt + 64);
    let computed = edit::checksum(data, &pe);
    info.push((
        "CheckSum".into(),
        format!(
            "stored {stored:08X}, computed {computed:08X}{}",
            if stored == 0 {
                " (not set)"
            } else if stored == computed {
                " (valid)"
            } else {
                " (mismatch)"
            }
        ),
    ));

    let mut maps = vec![Map {
        name: "Headers".into(),
        vaddr: pe.image_base,
        vsize: pe.size_of_headers as u64,
        offset: 0,
        fsize: (pe.size_of_headers as u64).min(data.len() as u64),
        exec: false,
    }];
    for s in &pe.sections {
        maps.push(Map {
            name: s.name.clone(),
            vaddr: pe.image_base.wrapping_add(s.va as u64),
            vsize: s.vsize.max(s.rsize) as u64,
            offset: s.roff as u64,
            fsize: (s.rsize as u64).min((data.len() as u64).saturating_sub(s.roff as u64)),
            exec: s.chars & 0x2000_0020 != 0,
        });
    }

    // Named addresses for the disassembler: imports, exports, entry point.
    let va = |rva: u32| pe.image_base.wrapping_add(rva as u64);
    let mut symbols: Vec<(u64, String)> = Vec::new();
    for m in pe.imports(data) {
        let dll = m.name.rsplit_once('.').map_or(m.name.as_str(), |x| x.0).to_string();
        for f in &m.funcs {
            let name = match (&f.name, f.ordinal) {
                (Some(n), _) => n.clone(),
                (None, o) => format!("#{}", o.unwrap_or(0)),
            };
            symbols.push((va(f.iat_rva), format!("{dll}!{name}")));
        }
    }
    if let Some(t) = edit::parse_exports(data, &pe) {
        for f in t.funcs.iter().filter(|f| f.forwarder.is_none() && f.rva != 0) {
            if let Some(n) = f.names.first() {
                symbols.push((va(f.rva), n.clone()));
            }
        }
    }
    if pe.entry != 0 {
        symbols.push((va(pe.entry), "EntryPoint".into()));
    }
    // x64 records every non-leaf function in the exception directory.
    let mut functions: Vec<(u64, u64)> = Vec::new();
    if pe.machine == 0x8664 {
        let (rva, size) = pe.dir(data, 3);
        if let Some(off) = (rva != 0).then(|| pe.rva_to_off(rva)).flatten() {
            for i in 0..(size as usize / 12).min(MAX_ROWS) {
                if !rd.has(off + i * 12, 12) {
                    break;
                }
                // Chained entries describe a fragment of a function, not a function of their own.
                let chained = pe.rva_to_off(rd.u32(off + i * 12 + 8)).is_some_and(|u| rd.u8(u) >> 3 & 4 != 0);
                if !chained {
                    functions.push((va(rd.u32(off + i * 12)), va(rd.u32(off + i * 12 + 4))));
                }
            }
        }
    }

    let root = Node::tool("File", Tool::FileInfo, kv_grid(info)).with_children(nodes);
    let parsed = Parsed {
        format: Format::Pe,
        description,
        root,
        maps,
        image_base: pe.image_base,
        entry: (pe.entry != 0).then_some(pe.image_base.wrapping_add(pe.entry as u64)),
        arch: pe.arch(),
        symbols,
        functions,
    };
    Some((parsed, pe))
}

fn rich_header(data: &[u8], pe: &Pe) -> Option<Node> {
    let rd = Rd::new(data, LE);
    let end = pe.lfanew.min(data.len());
    let stub = data.get(0x40..end)?;
    let pos = 0x40 + stub.windows(4).rposition(|w| w == b"Rich")?;
    let key = rd.u32(pos + 4);
    let mut start = pos;
    loop {
        if start < 0x44 {
            return None;
        }
        start -= 4;
        if rd.u32(start) ^ key == 0x536E_6144 {
            break;
        }
    }
    let mut g = Grid::new(&["Offset", "Product Id", "Build", "Use Count", "Raw (decoded)"]);
    let mut o = start + 16;
    while o + 8 <= pos {
        let a = rd.u32(o) ^ key;
        let c = rd.u32(o + 4) ^ key;
        g.push(
            vec![
                Cell::text(format!("{o:08X}")),
                Cell::text(format!("{}", a >> 16)),
                Cell::text(format!("{}", a & 0xFFFF)),
                Cell::text(format!("{c}")),
                Cell::text(format!("{a:08X} {c:08X}")),
            ],
            Some((o, 8)),
        );
        o += 8;
    }
    let mut n = Node::grid("Rich Header", g).with_span(start, pos + 8 - start);
    n.children.push(Node::text("Rich Key", format!("XOR key: {key:08X}\nHeader range: {start:08X} - {:08X}", pos + 8)));
    Some(n)
}

fn export_dir(data: &[u8], pe: &Pe) -> Option<Node> {
    let rd = Rd::new(data, LE);
    let (rva, size) = pe.dir(data, 0);
    let off = (rva != 0).then(|| pe.rva_to_off(rva)).flatten()?;
    let mut f = Fields::new(data, LE);
    f.seq(
        off,
        &[
            ("Characteristics", 4, Kind::Hex),
            ("TimeDateStamp", 4, Kind::Time),
            ("MajorVersion", 2, Kind::Hex),
            ("MinorVersion", 2, Kind::Hex),
            ("Name", 4, Kind::Hex),
            ("Base", 4, Kind::Hex),
            ("NumberOfFunctions", 4, Kind::Hex),
            ("NumberOfNames", 4, Kind::Hex),
            ("AddressOfFunctions", 4, Kind::Hex),
            ("AddressOfNames", 4, Kind::Hex),
            ("AddressOfNameOrdinals", 4, Kind::Hex),
        ],
    );
    if let Some(o) = pe.rva_to_off(rd.u32(off + 12)) {
        f.grid.rows[4][4].text = rd.cstr(o, 256);
    }
    let base = rd.u32(off + 16);
    let nfuncs = (rd.u32(off + 20) as usize).min(MAX_ROWS);
    let nnames = (rd.u32(off + 24) as usize).min(MAX_ROWS);
    let funcs = pe.rva_to_off(rd.u32(off + 28));
    let names = pe.rva_to_off(rd.u32(off + 32));
    let ords = pe.rva_to_off(rd.u32(off + 36));
    let mut name_of: Vec<Option<(usize, usize)>> = vec![None; nfuncs];
    if let (Some(names), Some(ords)) = (names, ords) {
        for i in 0..nnames {
            let idx = rd.u16(ords + i * 2) as usize;
            if idx < nfuncs && name_of[idx].is_none() {
                name_of[idx] = Some((names + i * 4, i));
            }
        }
    }
    let mut g = Grid::new(&["Ordinal", "Function RVA", "Name Ordinal", "Name RVA", "Name", "Forwarder"]);
    if let Some(funcs) = funcs {
        #[allow(clippy::needless_range_loop)] // i is an ordinal, not just an index
        for i in 0..nfuncs {
            let fo = funcs + i * 4;
            if !rd.has(fo, 4) {
                break;
            }
            let frva = rd.u32(fo);
            if frva == 0 && name_of[i].is_none() {
                continue;
            }
            let fwd =
                if frva >= rva && frva < rva.wrapping_add(size) { pe.rva_to_off(frva).map(|o| rd.cstr(o, 256)).unwrap_or_default() } else { String::new() };
            let (name_ord, name_rva, name) = match name_of[i] {
                Some((noff, ni)) => {
                    let nrva = rd.u32(noff);
                    (Cell::text(format!("{ni:04X}")), c32(data, noff), pe.rva_to_off(nrva).map(|o| rd.cstr(o, 512)).unwrap_or_default())
                }
                None => (Cell::text("n/a"), Cell::text("n/a"), String::new()),
            };
            g.push(vec![Cell::text(format!("{:08X}", base as usize + i)), c32(data, fo), name_ord, name_rva, Cell::text(name), Cell::text(fwd)], Some((fo, 4)));
        }
    }
    let mut n = Node::grid("Export Directory", f.finish()).with_span(off, 40);
    n.children.push(Node::grid(format!("Exported Functions ({})", g.rows.len()), g));
    Some(n)
}

fn import_dir(data: &[u8], pe: &Pe) -> Option<Node> {
    let mods = pe.imports(data);
    if mods.is_empty() {
        return None;
    }
    let ps = pe.ptr_size();
    let mut g = Grid::new(&["Module Name", "Imports", "OFTs", "TimeDateStamp", "ForwarderChain", "Name RVA", "FTs (IAT)"]);
    let mut children = Vec::new();
    for m in &mods {
        let d = m.desc_off;
        g.push(
            vec![
                Cell::text(m.name.clone()),
                Cell::text(m.funcs.len().to_string()),
                c32(data, d),
                c32(data, d + 4),
                c32(data, d + 8),
                c32(data, d + 12),
                c32(data, d + 16),
            ],
            Some((d, 20)),
        );
        let mut fg = Grid::new(&["Thunk Offset", "Thunk Value", "IAT RVA", "Hint", "Name"]);
        for f in &m.funcs {
            let (hint, name) = match (&f.name, f.ordinal) {
                (Some(n), _) => (f.hint_name_off.map(|o| c16(data, o)).unwrap_or_else(|| Cell::text("n/a")), Cell::text(n.clone())),
                (None, o) => (Cell::text("n/a"), Cell::text(format!("Ordinal {:04X}", o.unwrap_or(0)))),
            };
            fg.push(
                vec![
                    Cell::text(format!("{:08X}", f.thunk_off)),
                    cell(data, f.thunk_off, ps, Kind::Hex, LE),
                    Cell::text(format!("{:08X}", f.iat_rva)),
                    hint,
                    name,
                ],
                Some((f.thunk_off, ps)),
            );
        }
        children.push(Node::grid(format!("{} ({})", m.name, m.funcs.len()), fg));
    }
    let first = mods[0].desc_off;
    Some(Node::grid("Import Directory", g).with_span(first, (mods.len() + 1) * 20).with_children(children))
}

fn delay_import_dir(data: &[u8], pe: &Pe) -> Option<Node> {
    let rd = Rd::new(data, LE);
    let (rva, _) = pe.dir(data, 13);
    let mut off = (rva != 0).then(|| pe.rva_to_off(rva)).flatten()?;
    let ps = pe.ptr_size();
    let ord_flag = 1u64 << (ps * 8 - 1);
    let mut g =
        Grid::new(&["Module Name", "Imports", "Attributes", "Name RVA", "Module Handle", "IAT", "Name Table", "Bound IAT", "Unload Table", "TimeDateStamp"]);
    let mut children = Vec::new();
    let start = off;
    while rd.has(off, 32) && children.len() < 4096 {
        let attrs = rd.u32(off);
        let name_rva = rd.u32(off + 4);
        if name_rva == 0 {
            break;
        }
        // Old style descriptors store VAs instead of RVAs.
        let fix = |v: u32| -> u32 { if attrs & 1 != 0 { v } else { (v as u64).wrapping_sub(pe.image_base) as u32 } };
        let name = pe.rva_to_off(fix(name_rva)).map(|o| rd.cstr(o, 256)).unwrap_or_default();
        let int = fix(rd.u32(off + 16));
        let mut fg = Grid::new(&["Thunk Offset", "Thunk Value", "Hint", "Name"]);
        if let Some(mut t) = pe.rva_to_off(int) {
            while rd.has(t, ps) && fg.rows.len() < 65536 {
                let v = rd.uint(t, ps);
                if v == 0 {
                    break;
                }
                let (hint, fname) = if v & ord_flag != 0 {
                    (Cell::text("n/a"), format!("Ordinal {:04X}", v as u16))
                } else {
                    match pe.rva_to_off(fix(v as u32)) {
                        Some(o) => (c16(data, o), rd.cstr(o + 2, 512)),
                        None => (Cell::text("n/a"), "<invalid>".into()),
                    }
                };
                fg.push(vec![Cell::text(format!("{t:08X}")), cell(data, t, ps, Kind::Hex, LE), hint, Cell::text(fname)], Some((t, ps)));
                t += ps;
            }
        }
        let mut row = vec![Cell::text(name.clone()), Cell::text(fg.rows.len().to_string())];
        for i in 0..8 {
            row.push(c32(data, off + i * 4));
        }
        g.push(row, Some((off, 32)));
        children.push(Node::grid(format!("{} ({})", name, fg.rows.len()), fg));
        off += 32;
    }
    Some(Node::grid("Delay Import Directory", g).with_span(start, off - start + 32).with_children(children))
}

fn bound_import_dir(data: &[u8], pe: &Pe) -> Option<Node> {
    let rd = Rd::new(data, LE);
    let (rva, size) = pe.dir(data, 11);
    let base = (rva != 0).then(|| pe.rva_to_off(rva)).flatten()?;
    let mut g = Grid::new(&["Module Name", "TimeDateStamp", "Date", "OffsetModuleName", "NumberOfModuleForwarderRefs"]);
    let mut off = base;
    while rd.has(off, 8) && g.rows.len() < 4096 {
        let ts = rd.u32(off);
        let name_off = rd.u16(off + 4) as usize;
        if ts == 0 && name_off == 0 {
            break;
        }
        g.push(
            vec![Cell::text(rd.cstr(base + name_off, 256)), c32(data, off), Cell::text(time_text(ts as u64)), c16(data, off + 4), c16(data, off + 6)],
            Some((off, 8)),
        );
        off += 8;
    }
    Some(Node::grid("Bound Import Directory", g).with_span(base, size as usize))
}

fn exception_dir(data: &[u8], pe: &Pe) -> Option<Node> {
    let rd = Rd::new(data, LE);
    let (rva, size) = pe.dir(data, 3);
    let off = (rva != 0).then(|| pe.rva_to_off(rva)).flatten()?;
    let (entry, cols): (usize, &[&'static str]) = match pe.machine {
        0x8664 => (12, &["Offset", "Begin Address", "End Address", "Unwind Info"]),
        0xaa64 | 0x1c4 => (8, &["Offset", "Begin Address", "Unwind Data"]),
        _ => return None,
    };
    let mut g = Grid::new(cols);
    let n = (size as usize / entry).min(MAX_ROWS);
    for i in 0..n {
        let o = off + i * entry;
        if !rd.has(o, entry) {
            break;
        }
        let mut row = vec![Cell::text(format!("{o:08X}"))];
        for k in 0..entry / 4 {
            row.push(c32(data, o + k * 4));
        }
        g.push(row, Some((o, entry)));
    }
    Some(Node::grid(format!("Exception Directory ({})", g.rows.len()), g).with_span(off, size as usize))
}

fn security_dir(data: &[u8], pe: &Pe) -> Option<Node> {
    let rd = Rd::new(data, LE);
    let (off, size) = pe.dir(data, 4);
    let (off, size) = (off as usize, size as usize);
    if off == 0 || !rd.has(off, 8) {
        return None;
    }
    let mut f = Fields::new(data, LE);
    f.seq(off, &[("dwLength", 4, Kind::Hex), ("wRevision", 2, Kind::Hex), ("wCertificateType", 2, Kind::Enum(CERT_TYPE))]);
    let len = (rd.u32(off) as usize).min(size).min(data.len() - off);
    let blob = rd.bytes(off + 8, len.saturating_sub(8));
    let mut n = Node::grid("Security Directory", f.finish()).with_span(off, size.min(data.len() - off));
    n.children.push(Node::text("Authenticode Signature", sig::describe(data, pe, blob)).with_span(off + 8, blob.len()));
    Some(n)
}

fn reloc_dir(data: &[u8], pe: &Pe) -> Option<Node> {
    let rd = Rd::new(data, LE);
    let (rva, size) = pe.dir(data, 5);
    let base = (rva != 0).then(|| pe.rva_to_off(rva)).flatten()?;
    let end = base + size as usize;
    let mut g = Grid::new(&["Block RVA", "Block Size", "Entry Offset", "Value", "Type", "Target RVA"]);
    let mut off = base;
    let mut blocks = 0;
    let mut total = 0usize;
    while off + 8 <= end && rd.has(off, 8) {
        let page = rd.u32(off);
        let bsize = rd.u32(off + 4) as usize;
        if bsize < 8 {
            break;
        }
        blocks += 1;
        let n = (bsize - 8) / 2;
        total += n;
        for i in 0..n {
            if g.rows.len() >= MAX_ROWS {
                break;
            }
            let eo = off + 8 + i * 2;
            let v = rd.u16(eo);
            let ty = (v >> 12) as u64;
            g.push(
                vec![
                    if i == 0 { c32(data, off) } else { hx(page as u64, 8) },
                    if i == 0 { c32(data, off + 4) } else { hx(bsize as u64, 8) },
                    Cell::text(format!("{eo:08X}")),
                    c16(data, eo),
                    Cell::text(lookup(RELOC_TYPE, ty).map(str::to_string).unwrap_or_else(|| ty.to_string())),
                    hx(page as u64 + (v & 0xFFF) as u64, 8),
                ],
                Some((eo, 2)),
            );
        }
        off += bsize;
    }
    let title = format!("Relocation Directory ({blocks} blocks, {total} entries)");
    let mut n = Node::grid(title, g).with_span(base, size as usize);
    if total > MAX_ROWS {
        n.children.push(Node::text("Note", format!("Only the first {MAX_ROWS} of {total} relocation entries are listed.")));
    }
    Some(n)
}

fn debug_dir(data: &[u8], pe: &Pe) -> Option<Node> {
    let rd = Rd::new(data, LE);
    let (rva, size) = pe.dir(data, 6);
    let off = (rva != 0).then(|| pe.rva_to_off(rva)).flatten()?;
    let mut g =
        Grid::new(&["Characteristics", "TimeDateStamp", "Major", "Minor", "Type", "Type Name", "SizeOfData", "AddressOfRawData", "PointerToRawData", "Info"]);
    let mut pdbs: Vec<(String, String, String)> = Vec::new();
    for i in 0..(size as usize / 28).min(256) {
        let o = off + i * 28;
        if !rd.has(o, 28) {
            break;
        }
        let ty = rd.u32(o + 12);
        let dsize = rd.u32(o + 16) as usize;
        let ptr = rd.u32(o + 24) as usize;
        let mut info = String::new();
        if ty == 2 && rd.has(ptr, 24) && rd.bytes(ptr, 4) == b"RSDS" {
            let g1 = rd.u32(ptr + 4);
            let g2 = rd.u16(ptr + 8);
            let g3 = rd.u16(ptr + 10);
            let rest = hex_bytes(rd.bytes(ptr + 12, 8));
            let age = rd.u32(ptr + 20);
            let path = rd.cstr(ptr + 24, dsize.saturating_sub(24).min(1024));
            info = format!("RSDS {{{g1:08X}-{g2:04X}-{g3:04X}-{}-{}}} age {age} pdb: {path}", &rest[..4], &rest[4..]);
            // Key under which a symbol server stores this PDB.
            let file = path.rsplit(['\\', '/']).next().unwrap_or(&path).to_string();
            pdbs.push((path, format!("{g1:08X}{g2:04X}{g3:04X}{rest}{age:X}"), file));
        } else if ty == 16 {
            info = "reproducible build".into();
        } else if ty == 20 && rd.has(ptr, 4) {
            let v = rd.u32(ptr);
            info = format!("{v:08X}{}", if v & 1 != 0 { " CET_COMPAT" } else { "" });
        }
        g.push(
            vec![
                c32(data, o),
                c32(data, o + 4),
                c16(data, o + 8),
                c16(data, o + 10),
                c32(data, o + 12),
                Cell::text(lookup(DEBUG_TYPE, ty as u64).unwrap_or("?")),
                c32(data, o + 16),
                c32(data, o + 20),
                c32(data, o + 24),
                Cell::text(info),
            ],
            Some((ptr, dsize)),
        );
    }
    let mut n = Node::grid("Debug Directory", g).with_span(off, size as usize);
    if !pdbs.is_empty() {
        let mut t = String::new();
        for (path, key, file) in &pdbs {
            t.push_str(&format!(
                "PDB path:         {path}\nPDB file:         {file}\nSymbol key:       {key}  (GUID followed by age, as symbol servers index it)\n"
            ));
            t.push_str(&format!("Symbol store path: {file}/{key}/{file}\n"));
            t.push_str(&format!("Microsoft server:  https://msdl.microsoft.com/download/symbols/{file}/{key}/{file}\n\n"));
        }
        t.push_str("The URL only resolves for binaries whose symbols Microsoft publishes. Nothing is downloaded by this program.\n");
        n.children.push(Node::text("PDB Lookup", t));
    }
    Some(n)
}

fn tls_dir(data: &[u8], pe: &Pe) -> Option<Node> {
    let rd = Rd::new(data, LE);
    let (rva, _) = pe.dir(data, 9);
    let off = (rva != 0).then(|| pe.rva_to_off(rva)).flatten()?;
    let p = pe.ptr_size();
    let mut f = Fields::new(data, LE);
    let end = f.seq(
        off,
        &[
            ("StartAddressOfRawData", p, Kind::Hex),
            ("EndAddressOfRawData", p, Kind::Hex),
            ("AddressOfIndex", p, Kind::Hex),
            ("AddressOfCallBacks", p, Kind::Hex),
            ("SizeOfZeroFill", 4, Kind::Hex),
            ("Characteristics", 4, Kind::Hex),
        ],
    );
    let mut n = Node::grid("TLS Directory", f.finish()).with_span(off, end - off);
    if let Some(mut cb) = pe.va_to_off(rd.uint(off + 3 * p, p)) {
        let mut g = Grid::new(&["Offset", "Callback VA"]);
        while rd.has(cb, p) && g.rows.len() < 256 {
            if rd.uint(cb, p) == 0 {
                break;
            }
            g.push(vec![Cell::text(format!("{cb:08X}")), cell(data, cb, p, Kind::Hex, LE)], Some((cb, p)));
            cb += p;
        }
        if !g.rows.is_empty() {
            n.children.push(Node::grid(format!("TLS Callbacks ({})", g.rows.len()), g));
        }
    }
    Some(n)
}

fn load_config_dir(data: &[u8], pe: &Pe) -> Option<Node> {
    let rd = Rd::new(data, LE);
    let (rva, _) = pe.dir(data, 10);
    let off = (rva != 0).then(|| pe.rva_to_off(rva)).flatten()?;
    let size = rd.u32(off) as usize;
    let p = pe.ptr_size();
    let mut list: Vec<(&str, usize, Kind)> = vec![
        ("Size", 4, Kind::Hex),
        ("TimeDateStamp", 4, Kind::Time),
        ("MajorVersion", 2, Kind::Hex),
        ("MinorVersion", 2, Kind::Hex),
        ("GlobalFlagsClear", 4, Kind::Hex),
        ("GlobalFlagsSet", 4, Kind::Hex),
        ("CriticalSectionDefaultTimeout", 4, Kind::Hex),
        ("DeCommitFreeBlockThreshold", p, Kind::Hex),
        ("DeCommitTotalFreeThreshold", p, Kind::Hex),
        ("LockPrefixTable", p, Kind::Hex),
        ("MaximumAllocationSize", p, Kind::Hex),
        ("VirtualMemoryThreshold", p, Kind::Hex),
    ];
    if pe.is64 {
        list.push(("ProcessAffinityMask", 8, Kind::Hex));
        list.push(("ProcessHeapFlags", 4, Kind::Hex));
    } else {
        list.push(("ProcessHeapFlags", 4, Kind::Hex));
        list.push(("ProcessAffinityMask", 4, Kind::Hex));
    }
    list.extend_from_slice(&[
        ("CSDVersion", 2, Kind::Hex),
        ("DependentLoadFlags", 2, Kind::Hex),
        ("EditList", p, Kind::Hex),
        ("SecurityCookie", p, Kind::Hex),
        ("SEHandlerTable", p, Kind::Hex),
        ("SEHandlerCount", p, Kind::Hex),
        ("GuardCFCheckFunctionPointer", p, Kind::Hex),
        ("GuardCFDispatchFunctionPointer", p, Kind::Hex),
        ("GuardCFFunctionTable", p, Kind::Hex),
        ("GuardCFFunctionCount", p, Kind::Hex),
        ("GuardFlags", 4, Kind::Flags(GUARD_FLAGS)),
    ]);
    let mut f = Fields::new(data, LE);
    let mut o = off;
    for (name, sz, kind) in list {
        if o + sz > off + size.max(4) {
            break;
        }
        f.add(name, o, sz, kind);
        o += sz;
    }
    Some(Node::grid("Load Config Directory", f.finish()).with_span(off, size))
}

/// Locate the .NET metadata of a managed image.
pub fn metadata<'a>(data: &'a [u8], pe: &Pe) -> Option<dotnet::Md<'a>> {
    let rd = Rd::new(data, LE);
    let (rva, _) = pe.dir(data, 14);
    let off = (rva != 0).then(|| pe.rva_to_off(rva)).flatten()?;
    let md = pe.rva_to_off(rd.u32(off + 8)).filter(|m| rd.u32(*m) == 0x424A_5342)?;
    let mut so = md + 16 + (rd.u32(md + 12) as usize).min(256);
    let nstreams = rd.u16(so + 2) as usize;
    so += 4;
    let mut streams: Vec<dotnet::Stream> = Vec::new();
    for _ in 0..nstreams.min(64) {
        if !rd.has(so, 8) {
            break;
        }
        let name = rd.cstr(so + 8, 32);
        streams.push((name.clone(), md.saturating_add(rd.u32(so) as usize), rd.u32(so + 4) as usize));
        so += 8 + (name.len() + 1).div_ceil(4) * 4;
    }
    dotnet::Md::parse(data, &streams)
}

/// IL of the method with row id `rid` (1 based) in the MethodDef table.
pub fn method_il(data: &[u8], pe: &Pe, rid: usize) -> Option<String> {
    let md = metadata(data, pe)?;
    let (rva, title) = md.method(rid)?;
    Some(match (rva != 0).then(|| pe.rva_to_off(rva)).flatten() {
        Some(off) => md.il(off, &title),
        None => format!(".method {title}\n// no body: abstract, extern or runtime provided\n"),
    })
}

fn clr_dir(data: &[u8], pe: &Pe) -> Option<Node> {
    let rd = Rd::new(data, LE);
    let (rva, _) = pe.dir(data, 14);
    let off = (rva != 0).then(|| pe.rva_to_off(rva)).flatten()?;
    let mut f = Fields::new(data, LE);
    f.seq(
        off,
        &[
            ("cb", 4, Kind::Hex),
            ("MajorRuntimeVersion", 2, Kind::Hex),
            ("MinorRuntimeVersion", 2, Kind::Hex),
            ("MetaData RVA", 4, Kind::Hex),
            ("MetaData Size", 4, Kind::Hex),
            ("Flags", 4, Kind::Flags(CLR_FLAGS)),
            ("EntryPointToken", 4, Kind::Hex),
            ("Resources RVA", 4, Kind::Hex),
            ("Resources Size", 4, Kind::Hex),
            ("StrongNameSignature RVA", 4, Kind::Hex),
            ("StrongNameSignature Size", 4, Kind::Hex),
            ("CodeManagerTable RVA", 4, Kind::Hex),
            ("CodeManagerTable Size", 4, Kind::Hex),
            ("VTableFixups RVA", 4, Kind::Hex),
            ("VTableFixups Size", 4, Kind::Hex),
            ("ExportAddressTableJumps RVA", 4, Kind::Hex),
            ("ExportAddressTableJumps Size", 4, Kind::Hex),
            ("ManagedNativeHeader RVA", 4, Kind::Hex),
            ("ManagedNativeHeader Size", 4, Kind::Hex),
        ],
    );
    let mut n = Node::grid(".NET Directory", f.finish()).with_span(off, 72);
    if let Some(md) = metadata(data, pe) {
        let mut g = Grid::new(&["Token", "RVA", "File Offset", "Method", "Signature"]);
        for m in md.methods() {
            let fo = (m.rva != 0).then(|| pe.rva_to_off(m.rva)).flatten();
            g.push(
                vec![
                    Cell::text(format!("{:08X}", m.token)),
                    Cell::text(format!("{:08X}", m.rva)),
                    Cell::text(fo.map(|o| format!("{o:08X}")).unwrap_or_default()),
                    Cell::text(m.name),
                    Cell::text(m.signature),
                ],
                fo.map(|o| (o, 1)),
            );
        }
        let cut = if md.resolved_spent() { ", names cut short" } else { "" };
        n.children.push(Node::tool(format!("Methods ({}{cut})", g.rows.len()), Tool::DotnetIl, g));
    }
    if let Some(md) = pe.rva_to_off(rd.u32(off + 8)).filter(|m| rd.u32(*m) == 0x424A_5342) {
        let mut f = Fields::new(data, LE);
        let vlen = rd.u32(md + 12) as usize;
        f.seq(
            md,
            &[
                ("Signature", 4, Kind::Hex),
                ("MajorVersion", 2, Kind::Hex),
                ("MinorVersion", 2, Kind::Hex),
                ("Reserved", 4, Kind::Hex),
                ("VersionLength", 4, Kind::Hex),
                ("Version", vlen.min(256), Kind::Str),
                ("Flags", 2, Kind::Hex),
                ("Streams", 2, Kind::Hex),
            ],
        );
        let mut so = md + 16 + vlen.min(256);
        let nstreams = rd.u16(so + 2) as usize;
        so += 4;
        let mut g = Grid::new(&["Name", "Offset", "Size", "File Offset"]);
        let mut streams: Vec<dotnet::Stream> = Vec::new();
        for _ in 0..nstreams.min(64) {
            if !rd.has(so, 8) {
                break;
            }
            let name = rd.cstr(so + 8, 32);
            let hdr_len = 8 + (name.len() + 1).div_ceil(4) * 4;
            streams.push((name.clone(), md.saturating_add(rd.u32(so) as usize), rd.u32(so + 4) as usize));
            g.push(
                vec![Cell::text(name), c32(data, so), c32(data, so + 4), Cell::text(format!("{:08X}", md + rd.u32(so) as usize))],
                Some((md + rd.u32(so) as usize, rd.u32(so + 4) as usize)),
            );
            so += hdr_len;
        }
        n.children.push(
            Node::grid("MetaData Header", f.finish())
                .with_span(md, so - md)
                .with_children(vec![Node::grid("MetaData Streams", g).with_children(dotnet::nodes(data, &streams))]),
        );
    }
    Some(n)
}

#[cfg(test)]
mod tests;
