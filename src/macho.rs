//! Mach-O parser: thin 32/64 bit images and fat (universal) binaries.

use crate::model::*;

const MAX_ROWS: usize = 200_000;
const BE: Endian = Endian::Big;

const CPU: Names =
    &[(7, "x86"), (0x0100_0007, "x86_64"), (12, "ARM"), (0x0100_000C, "ARM64"), (0x0200_000C, "ARM64_32"), (18, "PowerPC"), (0x0100_0012, "PowerPC64")];

const FILETYPE: Names = &[
    (1, "MH_OBJECT"),
    (2, "MH_EXECUTE"),
    (3, "MH_FVMLIB"),
    (4, "MH_CORE"),
    (5, "MH_PRELOAD"),
    (6, "MH_DYLIB"),
    (7, "MH_DYLINKER"),
    (8, "MH_BUNDLE"),
    (9, "MH_DYLIB_STUB"),
    (10, "MH_DSYM"),
    (11, "MH_KEXT_BUNDLE"),
    (12, "MH_FILESET"),
];

const MH_FLAGS: Names = &[
    (0x1, "NOUNDEFS"),
    (0x2, "INCRLINK"),
    (0x4, "DYLDLINK"),
    (0x8, "BINDATLOAD"),
    (0x10, "PREBOUND"),
    (0x20, "SPLIT_SEGS"),
    (0x80, "TWOLEVEL"),
    (0x100, "FORCE_FLAT"),
    (0x200, "NOMULTIDEFS"),
    (0x400, "NOFIXPREBINDING"),
    (0x2000, "SUBSECTIONS_VIA_SYMBOLS"),
    (0x8000, "WEAK_DEFINES"),
    (0x10000, "BINDS_TO_WEAK"),
    (0x20000, "ALLOW_STACK_EXECUTION"),
    (0x100000, "NO_REEXPORTED_DYLIBS"),
    (0x200000, "PIE"),
    (0x800000, "HAS_TLV_DESCRIPTORS"),
    (0x1000000, "NO_HEAP_EXECUTION"),
    (0x2000000, "APP_EXTENSION_SAFE"),
];

const LC: Names = &[
    (0x1, "LC_SEGMENT"),
    (0x2, "LC_SYMTAB"),
    (0x4, "LC_THREAD"),
    (0x5, "LC_UNIXTHREAD"),
    (0xb, "LC_DYSYMTAB"),
    (0xc, "LC_LOAD_DYLIB"),
    (0xd, "LC_ID_DYLIB"),
    (0xe, "LC_LOAD_DYLINKER"),
    (0xf, "LC_ID_DYLINKER"),
    (0x11, "LC_ROUTINES"),
    (0x12, "LC_SUB_FRAMEWORK"),
    (0x13, "LC_SUB_UMBRELLA"),
    (0x14, "LC_SUB_CLIENT"),
    (0x15, "LC_SUB_LIBRARY"),
    (0x16, "LC_TWOLEVEL_HINTS"),
    (0x8000_0018, "LC_LOAD_WEAK_DYLIB"),
    (0x19, "LC_SEGMENT_64"),
    (0x1a, "LC_ROUTINES_64"),
    (0x1b, "LC_UUID"),
    (0x8000_001c, "LC_RPATH"),
    (0x1d, "LC_CODE_SIGNATURE"),
    (0x1e, "LC_SEGMENT_SPLIT_INFO"),
    (0x8000_001f, "LC_REEXPORT_DYLIB"),
    (0x20, "LC_LAZY_LOAD_DYLIB"),
    (0x21, "LC_ENCRYPTION_INFO"),
    (0x22, "LC_DYLD_INFO"),
    (0x8000_0022, "LC_DYLD_INFO_ONLY"),
    (0x8000_0023, "LC_LOAD_UPWARD_DYLIB"),
    (0x24, "LC_VERSION_MIN_MACOSX"),
    (0x25, "LC_VERSION_MIN_IPHONEOS"),
    (0x26, "LC_FUNCTION_STARTS"),
    (0x27, "LC_DYLD_ENVIRONMENT"),
    (0x8000_0028, "LC_MAIN"),
    (0x29, "LC_DATA_IN_CODE"),
    (0x2a, "LC_SOURCE_VERSION"),
    (0x2b, "LC_DYLIB_CODE_SIGN_DRS"),
    (0x2c, "LC_ENCRYPTION_INFO_64"),
    (0x2d, "LC_LINKER_OPTION"),
    (0x2e, "LC_LINKER_OPTIMIZATION_HINT"),
    (0x2f, "LC_VERSION_MIN_TVOS"),
    (0x30, "LC_VERSION_MIN_WATCHOS"),
    (0x31, "LC_NOTE"),
    (0x32, "LC_BUILD_VERSION"),
    (0x8000_0033, "LC_DYLD_EXPORTS_TRIE"),
    (0x8000_0034, "LC_DYLD_CHAINED_FIXUPS"),
    (0x8000_0035, "LC_FILESET_ENTRY"),
];

const PROT: Names = &[(1, "R"), (2, "W"), (4, "X")];

const PLATFORM: Names = &[
    (1, "macOS"),
    (2, "iOS"),
    (3, "tvOS"),
    (4, "watchOS"),
    (5, "bridgeOS"),
    (6, "Mac Catalyst"),
    (7, "iOS Simulator"),
    (8, "tvOS Simulator"),
    (9, "watchOS Simulator"),
    (10, "DriverKit"),
    (11, "visionOS"),
    (12, "visionOS Simulator"),
];

const TOOL: Names = &[(1, "clang"), (2, "swift"), (3, "ld"), (4, "lld")];

fn version(v: u32) -> String {
    format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)
}

struct Slice {
    nodes: Vec<Node>,
    info: Vec<(String, String)>,
    description: String,
    maps: Vec<Map>,
    entry: Option<u64>,
    arch: Arch,
    symbols: Vec<(u64, String)>,
}

pub fn parse(data: &[u8]) -> Option<Parsed> {
    if data.len() < 8 {
        return None;
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    match magic {
        0xCAFE_BABE | 0xCAFE_BABF => parse_fat(data, magic == 0xCAFE_BABF),
        _ => {
            let s = parse_slice(data, 0, data.len(), &crate::macho_dyld::Budget::new())?;
            Some(Parsed {
                format: Format::MachO,
                description: s.description,
                root: Node::tool("File", Tool::FileInfo, kv_grid(s.info)).with_children(s.nodes),
                maps: s.maps,
                image_base: 0,
                entry: s.entry,
                arch: s.arch,
                symbols: s.symbols,
                functions: Vec::new(),
            })
        }
    }
}

fn parse_fat(data: &[u8], wide: bool) -> Option<Parsed> {
    let rd = Rd::new(data, BE);
    let n = rd.u32(4) as usize;
    // Java class files share the 0xCAFEBABE magic; their "count" is a version number.
    if n == 0 || n > 30 {
        return None;
    }
    let ent = if wide { 32 } else { 20 };
    let mut f = Fields::new(data, BE);
    f.add("magic", 0, 4, Kind::Hex).note(if wide { "FAT_MAGIC_64" } else { "FAT_MAGIC" });
    f.add("nfat_arch", 4, 4, Kind::Dec);
    let mut g = Grid::new(&["CPU Type", "CPU Name", "CPU Subtype", "Offset", "Size", "Align"]);
    let mut children = vec![];
    let mut first: Option<Slice> = None;
    let mut names = Vec::new();
    // One budget for the whole file: the entries may all name the same bytes.
    let budget = crate::macho_dyld::Budget::new();
    for i in 0..n {
        let e = 8 + i * ent;
        if !rd.has(e, ent) {
            break;
        }
        let cpu = rd.u32(e) as u64;
        let w = if wide { 8 } else { 4 };
        let off = clamp_off(rd.uint(e + 8, w));
        let size = clamp_off(rd.uint(e + 8 + w, w));
        let mut name = lookup(CPU, cpu).unwrap_or("?").to_string();
        if cpu == 0x0100_000C && rd.u32(e + 4) & 0xff == 2 {
            name = "ARM64E".into();
        }
        g.push(
            vec![
                cell(data, e, 4, Kind::Enum(CPU), BE),
                Cell::text(name.clone()),
                cell(data, e + 4, 4, Kind::Hex, BE),
                cell(data, e + 8, w, Kind::Hex, BE),
                cell(data, e + 8 + w, w, Kind::Hex, BE),
                cell(data, e + 8 + 2 * w, 4, Kind::Hex, BE),
            ],
            Some((off, size)),
        );
        names.push(name.clone());
        if let Some(s) = parse_slice(data, off, size, &budget) {
            children.push(
                Node::grid(format!("Architecture: {name}"), kv_grid(s.info.clone()))
                    .with_span(off, size.min(data.len().saturating_sub(off)))
                    .with_children(s.nodes.clone()),
            );
            if first.is_none() {
                first = Some(s);
            }
        }
    }
    let first = first?;
    let description = format!("Mach-O universal binary ({})", names.join(", "));
    let info = vec![
        ("File Type".to_string(), description.clone()),
        ("Architectures".into(), names.join(", ")),
        ("Note".into(), format!("Address conversion and disassembly use the first architecture ({})", names[0])),
    ];
    let mut nodes = vec![Node::grid("Fat Header", f.finish()).with_span(0, 8).with_children(vec![Node::grid("Fat Architectures", g).with_span(8, n * ent)])];
    nodes.extend(children);
    Some(Parsed {
        format: Format::MachO,
        description,
        root: Node::tool("File", Tool::FileInfo, kv_grid(info)).with_children(nodes),
        maps: first.maps,
        image_base: 0,
        entry: first.entry,
        arch: first.arch,
        symbols: first.symbols,
        functions: Vec::new(),
    })
}

fn parse_slice(data: &[u8], base: usize, size: usize, budget: &crate::macho_dyld::Budget) -> Option<Slice> {
    let end = base.checked_add(size)?.min(data.len());
    let m = data.get(base..base + 4)?;
    let (en, is64) = match m {
        [0xCE, 0xFA, 0xED, 0xFE] => (Endian::Little, false),
        [0xCF, 0xFA, 0xED, 0xFE] => (Endian::Little, true),
        [0xFE, 0xED, 0xFA, 0xCE] => (Endian::Big, false),
        [0xFE, 0xED, 0xFA, 0xCF] => (Endian::Big, true),
        _ => return None,
    };
    let rd = Rd::new(data, en);
    let hex = |off: usize, size: usize| cell(data, off, size, Kind::Hex, en);
    let mut nodes = Vec::new();

    let mut f = Fields::new(data, en);
    let mut list: Vec<(&str, usize, Kind)> = vec![
        ("magic", 4, Kind::Hex),
        ("cputype", 4, Kind::Enum(CPU)),
        ("cpusubtype", 4, Kind::Hex),
        ("filetype", 4, Kind::Enum(FILETYPE)),
        ("ncmds", 4, Kind::Dec),
        ("sizeofcmds", 4, Kind::Hex),
        ("flags", 4, Kind::Flags(MH_FLAGS)),
    ];
    if is64 {
        list.push(("reserved", 4, Kind::Hex));
    }
    let hdr_end = f.seq(base, &list);
    nodes.push(Node::grid("Mach Header", f.finish()).with_span(base, hdr_end - base));

    let cpu = rd.u32(base + 4);
    let filetype = rd.u32(base + 12);
    let ncmds = rd.u32(base + 16) as usize;
    let p = if is64 { 8 } else { 4 };

    let mut cmd_nodes = Vec::new();
    let mut seg_grid = Grid::new(&["Name", "VM Address", "VM Size", "File Offset", "File Size", "Max Prot", "Init Prot", "Sections", "Flags", "Protection"]);
    let mut sec_grid = Grid::new(&["Section", "Segment", "Address", "Size", "Offset", "Align", "Reloc Off", "Relocs", "Flags", "Entropy"]);
    let mut maps = Vec::new();
    let mut dylibs: Vec<String> = Vec::new();
    let mut dylib_grid = Grid::new(&["#", "Command", "Library", "Current Version", "Compatibility Version"]);
    let mut symtab: Option<(usize, usize, usize, usize)> = None;
    let mut entry_off: Option<u64> = None;
    let mut text_vmaddr: Option<u64> = None;
    let mut info: Vec<(String, String)> = Vec::new();
    let mut rpaths = Vec::new();
    let mut signed = false;
    let mut symbols: Vec<(u64, String)> = Vec::new();
    let mut sig: Option<(usize, usize)> = None;
    let mut dy = crate::macho_dyld::Ctx {
        data,
        base,
        is64,
        segs: Vec::new(),
        image_base: 0,
        sects: Vec::new(),
        dylibs: Vec::new(),
        dyld_info: None,
        exports_trie: None,
        chained: None,
        budget,
    };

    let mut off = hdr_end;
    for i in 0..ncmds.min(4096) {
        if !rd.has(off, 8) || off >= end {
            break;
        }
        let cmd = rd.u32(off);
        let cmdsize = rd.u32(off + 4) as usize;
        if cmdsize < 8 {
            break;
        }
        let name = lookup(LC, cmd as u64).map(str::to_string).unwrap_or_else(|| format!("LC_{cmd:X}"));
        let mut f = Fields::new(data, en);
        f.add("cmd", off, 4, Kind::Enum(LC));
        f.add("cmdsize", off + 4, 4, Kind::Hex);
        let mut title = format!("{i}: {name}");
        let b = off + 8;
        let lc_str = |field_off: usize| rd.cstr(off + rd.u32(field_off) as usize, cmdsize.saturating_sub(rd.u32(field_off) as usize));
        match cmd {
            0x1 | 0x19 => {
                let segname = rd.cstr(b, 16);
                title = format!("{i}: {name} ({segname})");
                let after = f.seq(
                    b,
                    &[
                        ("segname", 16, Kind::Str),
                        ("vmaddr", p, Kind::Hex),
                        ("vmsize", p, Kind::Hex),
                        ("fileoff", p, Kind::Hex),
                        ("filesize", p, Kind::Hex),
                        ("maxprot", 4, Kind::Flags(PROT)),
                        ("initprot", 4, Kind::Flags(PROT)),
                        ("nsects", 4, Kind::Dec),
                        ("flags", 4, Kind::Hex),
                    ],
                );
                let vmaddr = rd.uint(b + 16, p);
                let fileoff = rd.uint(b + 16 + 2 * p, p);
                let filesize = rd.uint(b + 16 + 3 * p, p);
                let initprot = rd.u32(b + 16 + 4 * p + 4);
                let nsects = rd.u32(b + 16 + 4 * p + 8) as usize;
                if segname == "__TEXT" {
                    text_vmaddr = Some(vmaddr);
                }
                if dy.segs.len() < crate::macho_dyld::MAX_SEGS {
                    if segname == "__TEXT" && !dy.segs.iter().any(|s| s.name == "__TEXT") {
                        dy.image_base = vmaddr;
                    }
                    dy.segs.push(crate::macho_dyld::Seg { name: segname.clone(), vmaddr, vmsize: rd.uint(b + 16 + p, p), fileoff, filesize });
                }
                seg_grid.push(
                    vec![
                        cell(data, b, 16, Kind::Str, en),
                        hex(b + 16, p),
                        hex(b + 16 + p, p),
                        hex(b + 16 + 2 * p, p),
                        hex(b + 16 + 3 * p, p),
                        cell(data, b + 16 + 4 * p, 4, Kind::Flags(PROT), en),
                        cell(data, b + 16 + 4 * p + 4, 4, Kind::Flags(PROT), en),
                        Cell::text(nsects.to_string()),
                        hex(b + 16 + 4 * p + 12, 4),
                        Cell::text(flags_text(PROT, initprot as u64)),
                    ],
                    Some((base + clamp_off(fileoff), clamp_off(filesize))),
                );
                let sect_size = if is64 { 80 } else { 68 };
                let mut had_sections = false;
                for k in 0..nsects.min(1024) {
                    let s = after + k * sect_size;
                    if !rd.has(s, sect_size) {
                        break;
                    }
                    let addr = rd.uint(s + 32, p);
                    let ssize = rd.uint(s + 32 + p, p);
                    let soff = rd.u32(s + 32 + 2 * p) as usize;
                    let flags = rd.u32(s + 32 + 2 * p + 16);
                    let zero_fill = matches!(flags & 0xff, 1 | 12 | 18);
                    dy.sects.push(crate::macho_dyld::Sect {
                        name: rd.cstr(s, 16),
                        seg: rd.cstr(s + 16, 16),
                        addr,
                        size: ssize,
                        offset: if zero_fill { 0 } else { soff },
                    });
                    let raw = if zero_fill || soff == 0 { &[][..] } else { rd.bytes(base + soff, clamp_off(ssize)) };
                    sec_grid.push(
                        vec![
                            cell(data, s, 16, Kind::Str, en),
                            cell(data, s + 16, 16, Kind::Str, en),
                            hex(s + 32, p),
                            hex(s + 32 + p, p),
                            hex(s + 32 + 2 * p, 4),
                            hex(s + 32 + 2 * p + 4, 4),
                            hex(s + 32 + 2 * p + 8, 4),
                            hex(s + 32 + 2 * p + 12, 4),
                            hex(s + 32 + 2 * p + 16, 4),
                            Cell::text(format!("{:.3}", entropy(raw))),
                        ],
                        (!raw.is_empty()).then_some((base + soff, clamp_off(ssize))),
                    );
                    if !raw.is_empty() {
                        had_sections = true;
                        maps.push(Map {
                            name: format!("{},{}", rd.cstr(s + 16, 16), rd.cstr(s, 16)),
                            vaddr: addr,
                            vsize: ssize,
                            offset: (base + soff) as u64,
                            fsize: ssize,
                            exec: flags & 0x8000_0400 != 0,
                        });
                    }
                }
                let _ = had_sections;
                if filesize > 0 {
                    maps.push(Map { name: segname, vaddr: vmaddr, vsize: rd.uint(b + 16 + p, p), offset: base as u64 + fileoff, fsize: filesize, exec: false });
                }
            }
            0x2 => {
                f.seq(b, &[("symoff", 4, Kind::Hex), ("nsyms", 4, Kind::Dec), ("stroff", 4, Kind::Hex), ("strsize", 4, Kind::Hex)]);
                symtab = Some((rd.u32(b) as usize, rd.u32(b + 4) as usize, rd.u32(b + 8) as usize, rd.u32(b + 12) as usize));
            }
            0xb => {
                let names = [
                    "ilocalsym",
                    "nlocalsym",
                    "iextdefsym",
                    "nextdefsym",
                    "iundefsym",
                    "nundefsym",
                    "tocoff",
                    "ntoc",
                    "modtaboff",
                    "nmodtab",
                    "extrefsymoff",
                    "nextrefsyms",
                    "indirectsymoff",
                    "nindirectsyms",
                    "extreloff",
                    "nextrel",
                    "locreloff",
                    "nlocrel",
                ];
                for (k, n) in names.iter().enumerate() {
                    f.add(n, b + k * 4, 4, Kind::Hex);
                }
            }
            0xc | 0xd | 0x8000_0018 | 0x8000_001f | 0x20 | 0x8000_0023 => {
                f.seq(
                    b,
                    &[("name offset", 4, Kind::Hex), ("timestamp", 4, Kind::Hex), ("current_version", 4, Kind::Hex), ("compatibility_version", 4, Kind::Hex)],
                );
                let lib = lc_str(b);
                f.grid.rows[2][4].text = lib.clone();
                f.grid.rows[4][4].text = version(rd.u32(b + 8));
                f.grid.rows[5][4].text = version(rd.u32(b + 12));
                title = format!("{i}: {name} ({})", lib.rsplit('/').next().unwrap_or(&lib));
                if cmd == 0xd {
                    info.push(("Install Name".into(), lib.clone()));
                } else {
                    dylibs.push(lib.clone());
                    dylib_grid.push(
                        vec![
                            Cell::text(dylibs.len().to_string()),
                            Cell::text(name.clone()),
                            Cell::text(lib),
                            Cell::text(version(rd.u32(b + 8))),
                            Cell::text(version(rd.u32(b + 12))),
                        ],
                        Some((off, cmdsize)),
                    );
                }
            }
            0xe | 0xf | 0x27 | 0x8000_001c | 0x12 | 0x13 | 0x14 | 0x15 => {
                f.add("string offset", b, 4, Kind::Hex);
                let s = lc_str(b);
                f.note(s.clone());
                if cmd == 0x8000_001c {
                    rpaths.push(s);
                } else if cmd == 0xe {
                    info.push(("Dynamic Linker".into(), s));
                }
            }
            0x1b => {
                f.add("uuid", b, 16, Kind::Bytes);
                info.push(("UUID".into(), hex_bytes(rd.bytes(b, 16))));
            }
            0x1d | 0x1e | 0x26 | 0x29 | 0x2b | 0x2e | 0x8000_0033 | 0x8000_0034 => {
                f.seq(b, &[("dataoff", 4, Kind::Hex), ("datasize", 4, Kind::Hex)]);
                let range = (rd.u32(b) as usize, rd.u32(b + 4) as usize);
                match cmd {
                    0x1d => {
                        signed = true;
                        sig = Some(range);
                    }
                    0x8000_0033 => dy.exports_trie = Some(range),
                    0x8000_0034 => dy.chained = Some(range),
                    _ => {}
                }
            }
            0x22 | 0x8000_0022 => {
                let names = [
                    "rebase_off",
                    "rebase_size",
                    "bind_off",
                    "bind_size",
                    "weak_bind_off",
                    "weak_bind_size",
                    "lazy_bind_off",
                    "lazy_bind_size",
                    "export_off",
                    "export_size",
                ];
                for (k, n) in names.iter().enumerate() {
                    f.add(n, b + k * 4, 4, Kind::Hex);
                }
                let pair = |k: usize| (rd.u32(b + k * 8) as usize, rd.u32(b + k * 8 + 4) as usize);
                dy.dyld_info = Some([pair(0), pair(1), pair(2), pair(3), pair(4)]);
            }
            0x24 | 0x25 | 0x2f | 0x30 => {
                f.add("version", b, 4, Kind::Hex).note(version(rd.u32(b)));
                f.add("sdk", b + 4, 4, Kind::Hex).note(version(rd.u32(b + 4)));
                info.push(("Minimum OS".into(), version(rd.u32(b))));
            }
            0x32 => {
                f.add("platform", b, 4, Kind::Enum(PLATFORM));
                f.add("minos", b + 4, 4, Kind::Hex).note(version(rd.u32(b + 4)));
                f.add("sdk", b + 8, 4, Kind::Hex).note(version(rd.u32(b + 8)));
                f.add("ntools", b + 12, 4, Kind::Dec);
                for k in 0..(rd.u32(b + 12) as usize).min(16) {
                    f.add(&format!("tool[{k}]"), b + 16 + k * 8, 4, Kind::Enum(TOOL));
                    f.add(&format!("tool[{k}] version"), b + 20 + k * 8, 4, Kind::Hex).note(version(rd.u32(b + 20 + k * 8)));
                }
                info.push((
                    "Platform".into(),
                    format!("{} {} (SDK {})", lookup(PLATFORM, rd.u32(b) as u64).unwrap_or("?"), version(rd.u32(b + 4)), version(rd.u32(b + 8))),
                ));
            }
            0x2a => {
                f.add("version", b, 8, Kind::Hex);
                let v = rd.u64(b);
                f.note(format!("{}.{}.{}.{}.{}", v >> 40, (v >> 30) & 0x3ff, (v >> 20) & 0x3ff, (v >> 10) & 0x3ff, v & 0x3ff));
            }
            0x8000_0028 => {
                f.seq(b, &[("entryoff", 8, Kind::Hex), ("stacksize", 8, Kind::Hex)]);
                entry_off = Some(rd.u64(b));
            }
            0x21 | 0x2c => {
                f.seq(b, &[("cryptoff", 4, Kind::Hex), ("cryptsize", 4, Kind::Hex), ("cryptid", 4, Kind::Hex)]);
                if rd.u32(b + 8) != 0 {
                    info.push(("Encryption".into(), "encrypted (cryptid is not zero)".into()));
                }
            }
            _ => {
                if cmdsize > 8 {
                    f.add("data", b, (cmdsize - 8).min(256), Kind::Bytes);
                }
            }
        }
        cmd_nodes.push(Node::grid(title, f.finish()).with_span(off, cmdsize));
        off += cmdsize;
    }

    nodes.push(Node::text(format!("Load Commands ({})", cmd_nodes.len()), "Select a load command.").with_span(hdr_end, off - hdr_end).with_children(cmd_nodes));
    nodes.push(Node::grid(format!("Segments ({})", seg_grid.rows.len()), seg_grid));
    nodes.push(Node::grid(format!("Sections ({})", sec_grid.rows.len()), sec_grid));
    if let Some((so, ss)) = sig {
        nodes.push(Node::text("Code Signature", crate::macho_sig::describe(data, base, so, ss)).with_span(base.saturating_add(so), ss));
    }
    if en == Endian::Little {
        dy.dylibs = dylibs.clone();
        nodes.extend(crate::macho_dyld::nodes(&dy));
    }
    if !dylib_grid.rows.is_empty() {
        nodes.push(Node::grid(format!("Libraries ({})", dylib_grid.rows.len()), dylib_grid));
    }

    if let Some((symoff, nsyms, stroff, strsize)) = symtab {
        let ent = if is64 { 16 } else { 12 };
        let mut all = Grid::new(&["#", "Name", "Type", "Kind", "Section", "Desc", "Value"]);
        let mut imports = Grid::new(&["Symbol", "Library"]);
        let mut exports = Grid::new(&["Symbol", "Address"]);
        for i in 0..nsyms.min(MAX_ROWS) {
            let o = base + symoff + i * ent;
            if !rd.has(o, ent) {
                break;
            }
            let strx = rd.u32(o) as usize;
            let ty = rd.u8(o + 4);
            let desc = rd.u16(o + 6);
            let value = rd.uint(o + 8, p);
            let name = if strx < strsize { rd.cstr(base + stroff + strx, 1024) } else { String::new() };
            if ty & 0xe0 == 0 && ty & 0x0e == 0xe && value != 0 {
                symbols.push((value, name.clone()));
            }
            let kind = if ty & 0xe0 != 0 {
                "debug (stab)"
            } else {
                match (ty & 0x0e, ty & 1) {
                    (0x0, 1) => "undefined external",
                    (0x0, _) => "undefined",
                    (0x2, _) => "absolute",
                    (0xe, 1) => "defined external",
                    (0xe, _) => "defined local",
                    (0xa, _) => "indirect",
                    _ => "other",
                }
            };
            if ty & 0xe0 == 0 && ty & 1 != 0 {
                if ty & 0x0e == 0 {
                    let ord = (desc >> 8) as usize;
                    let lib = match ord {
                        0 => "(self)".to_string(),
                        0xfe => "(dynamic lookup)".to_string(),
                        0xff => "(main executable)".to_string(),
                        n => dylibs.get(n - 1).cloned().unwrap_or_else(|| format!("ordinal {n}")),
                    };
                    imports.push(vec![Cell::text(name.clone()), Cell::text(lib)], Some((o, ent)));
                } else if ty & 0x0e == 0xe {
                    exports.push(vec![Cell::text(name.clone()), Cell::text(format!("{value:X}"))], Some((o, ent)));
                }
            }
            all.push(
                vec![Cell::text(i.to_string()), Cell::text(name), hex(o + 4, 1), Cell::text(kind), hex(o + 5, 1), hex(o + 6, 2), hex(o + 8, p)],
                Some((o, ent)),
            );
        }
        let mut sym = Node::grid(format!("Symbols ({})", all.rows.len()), all).with_span(base + symoff, nsyms * ent);
        if !imports.rows.is_empty() {
            sym.children.push(Node::grid(format!("Imported Symbols ({})", imports.rows.len()), imports));
        }
        if !exports.rows.is_empty() {
            sym.children.push(Node::grid(format!("Exported Symbols ({})", exports.rows.len()), exports));
        }
        nodes.push(sym);
    }

    let cpu_name = lookup(CPU, cpu as u64).unwrap_or("unknown CPU");
    let description = format!(
        "Mach-O {} {} for {cpu_name}",
        if is64 { "64-bit" } else { "32-bit" },
        match filetype {
            1 => "object",
            2 => "executable",
            6 => "dynamic library",
            7 => "dynamic linker",
            8 => "bundle",
            10 => "dSYM companion",
            11 => "kernel extension",
            _ => "file",
        }
    );
    let entry = match (entry_off, text_vmaddr) {
        (Some(e), Some(t)) => Some(t.wrapping_add(e)),
        _ => None,
    };
    let mut head = vec![("File Type".to_string(), description.clone())];
    if let Some(e) = entry {
        head.push(("Entry Point".into(), format!("{e:X}")));
    }
    head.push(("Code Signature".into(), if signed { "present (editing the file invalidates it; re-sign with codesign)" } else { "none" }.into()));
    if !dylibs.is_empty() {
        head.push(("Libraries".into(), dylibs.join(", ")));
    }
    if !rpaths.is_empty() {
        head.push(("RPATH".into(), rpaths.join(", ")));
    }
    head.extend(info);

    let arch = match cpu {
        7 => Arch::X86,
        0x0100_0007 => Arch::X64,
        12 => Arch::Arm,
        0x0100_000C | 0x0200_000C => Arch::Arm64,
        _ => Arch::Other,
    };
    Some(Slice { nodes, info: head, description, maps, entry, arch, symbols })
}
