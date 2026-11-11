//! Entry points shared by the libFuzzer targets in `fuzz/` and by the
//! replay tests in `tests/fuzz_replay.rs`. Every function must accept
//! arbitrary bytes without panicking.

use crate::fuzzgen::{self, Expect, Kind};
use crate::model::{Format, Node, View};
use crate::pe::edit::{self, NewImport};
use crate::pe::resources::{self, ResId};
use crate::{analysis, elf, elf_edit, macho, macho_edit, pe, query};

fn walk(node: &Node, data: &[u8]) {
    if let View::Grid(g) | View::Tool(_, g) = &node.view {
        for cell in g.rows.iter().flatten() {
            if let Some(f) = cell.field {
                // Formatting and re-parsing a field must never panic either.
                let text = f.format(data);
                let _ = f.meaning(data);
                let _ = f.parse(&text);
            }
        }
    }
    for c in &node.children {
        walk(c, data);
    }
}

/// Format detection, full parse, text dump and every editable field.
pub fn parse_any(data: &[u8]) {
    let parsed = analysis::parse(data);
    let mut out = String::new();
    analysis::dump(&parsed.root, 0, &mut out);
    walk(&parsed.root, data);
    for m in &parsed.maps {
        let _ = parsed.va_to_offset(m.vaddr);
        let _ = parsed.offset_to_va(m.offset);
    }
    if let Some(e) = parsed.entry
        && let Some((off, _)) = parsed.va_to_offset(e)
        && let Ok(off) = usize::try_from(off)
    {
        let end = data.len().min(off.saturating_add(64));
        if off < end {
            let _ = analysis::disasm(&data[off..end], parsed.arch, e, 16);
        }
    }
    debug_assert!(parsed.format != Format::Unknown || parsed.maps.is_empty());
}

/// The individual parsers, bypassing detection order.
pub fn parse_each(data: &[u8]) {
    let _ = pe::parse(data);
    let _ = elf::parse(data);
    let _ = macho::parse(data);
    let _ = analysis::strings(data, 4);
}

/// Structural PE editing. The first bytes of the input choose the
/// operations, the rest is the file being edited.
pub fn pe_edit(input: &[u8]) {
    let Some((ops, file)) = input.split_first_chunk::<4>() else { return };
    let mut data = file.to_vec();
    if pe::Pe::parse(&data).is_none() {
        return;
    }
    for op in ops {
        let arg = (op >> 4) as usize;
        let before = data.clone();
        let r = match op & 0x0f {
            0 => edit::fix_checksum(&mut data).map(drop),
            1 => edit::fix_size_of_image(&mut data).map(drop),
            2 => edit::fix_size_of_headers(&mut data).map(drop),
            3 => edit::remove_overlay(&mut data).map(drop),
            4 => edit::remove_signature(&mut data).map(drop),
            5 => edit::add_section(&mut data, ".fuzz", &vec![0xCC; arg * 97], (arg * 4096) as u32, 0x6000_0020).map(drop),
            6 => edit::delete_section(&mut data, arg).map(drop),
            7 => imports_round_trip(&mut data, arg),
            8 => resources_round_trip(&mut data, arg),
            9 => edit::rename_import(
                &mut data,
                arg % 4,
                arg.is_multiple_of(2).then_some(arg / 4),
                if arg > 7 { "ALongerNameThanBefore_0123456789" } else { "Ab" },
            )
            .map(drop),
            10 => edit::remove_import_module(&mut data, arg % 4).map(drop),
            11 => edit::unbind_imports(&mut data).map(drop),
            12 => exports_round_trip(&mut data, arg),
            13 => relocs_round_trip(&mut data, arg),
            14 => match arg % 3 {
                0 => edit::remove_tls_callback(&mut data, arg / 3).map(drop),
                _ => {
                    let va = pe::Pe::parse(&data).map_or(0, |p| p.image_base.wrapping_add(p.entry as u64).wrapping_add(arg as u64));
                    edit::add_tls_callback(&mut data, va).map(drop)
                }
            },
            15 => edit::convert_delay_imports(&mut data).map(drop),
            _ => Ok(()),
        };
        // Editors validate first: an error means the buffer is as it was.
        assert!(r.is_ok() || data == before, "editor {} failed and left the buffer changed", op & 0x0f);
        // Whatever an editor produced has to be readable again.
        parse_any(&data);
        if data.len() > (file.len() + 4096) * 8 {
            break;
        }
    }
}

fn imports_round_trip(data: &mut Vec<u8>, arg: usize) -> Result<(), String> {
    let modules = |d: &[u8]| pe::Pe::parse(d).map_or(0, |p| p.imports(d).len());
    let before = modules(data);
    edit::add_imports(data, &[("fuzz.dll".into(), vec![NewImport::Name("Func".into()), NewImport::Ordinal(arg as u16)])])?;
    // The rebuilt directory keeps every module that was there.
    assert!(modules(data) >= before, "imports were lost when the table was rebuilt");
    Ok(())
}

fn resources_round_trip(data: &mut Vec<u8>, arg: usize) -> Result<(), String> {
    let pe = pe::Pe::parse(data).ok_or("not a PE file")?;
    let mut root = resources::parse(data, &pe).unwrap_or_default();
    if arg.is_multiple_of(2) {
        resources::insert(&mut root, &ResId::Id(10), &ResId::Name("FUZZ".into()), &ResId::Id(1033), vec![0x41; arg * 33]);
    } else {
        resources::remove(&mut root, &[arg % 3, 0, 0]);
    }
    resources::apply(data, &root).map(drop)
}

fn exports_round_trip(data: &mut Vec<u8>, arg: usize) -> Result<(), String> {
    let pe = pe::Pe::parse(data).ok_or("not a PE file")?;
    let mut t = edit::parse_exports(data, &pe).unwrap_or_else(|| edit::ExportTable { dll_name: "fuzz.dll".into(), base: 1, ..Default::default() });
    t.funcs.truncate(64);
    t.funcs.push(edit::ExportFn {
        rva: 0x1000 + arg as u32,
        forwarder: arg.is_multiple_of(3).then(|| "KERNEL32.Sleep".to_string()),
        names: vec![format!("Fuzz{arg}")],
    });
    edit::write_exports(data, &t).map(drop)
}

fn relocs_round_trip(data: &mut Vec<u8>, arg: usize) -> Result<(), String> {
    let pe = pe::Pe::parse(data).ok_or("not a PE file")?;
    let mut list = edit::parse_relocs(data, &pe);
    list.truncate(4096);
    if arg.is_multiple_of(2) {
        list.push((0x1000 + arg as u32 * 8, edit::pointer_reloc_type(&pe)));
    } else if !list.is_empty() {
        list.remove(arg % list.len());
    }
    edit::write_relocs(data, &list)?;
    // What was written is what is read back.
    let pe = pe::Pe::parse(data).ok_or("the file became unreadable")?;
    let mut got = edit::parse_relocs(data, &pe);
    list.sort();
    list.dedup();
    got.sort();
    assert_eq!(got, list, "relocations did not survive a write");
    Ok(())
}

/// ELF dynamic section editing. The first bytes choose the operations.
pub fn elf_edit(input: &[u8]) {
    let Some((ops, file)) = input.split_first_chunk::<4>() else { return };
    let mut data = file.to_vec();
    if elf_edit::info(&data).is_err() {
        return;
    }
    for op in ops {
        let arg = (op >> 4) as usize;
        let long = "/a/path/that/is/rather/long/and/will/not/fit/in/place/anywhere:$ORIGIN/../lib";
        let headers = |d: &[u8]| elf_edit::program_headers(d).and_then(|(o, n)| d.get(o..o.saturating_add(n))).map(<[u8]>::to_vec);
        let before = headers(&data);
        // What the sections behind the ELF header hold, as far as it is in the file.
        let contents: Vec<(usize, Vec<u8>)> = elf_edit::sections(&data)
            .unwrap_or_default()
            .iter()
            .filter(|s| !matches!(s.ty, 0 | 8) && s.offset >= 0x40)
            .filter_map(|s| {
                let (off, size) = (usize::try_from(s.offset).ok()?, usize::try_from(s.size).ok()?);
                Some((off, data.get(off..off.checked_add(size)?)?.to_vec()))
            })
            .collect();
        let r = match op & 0x0f {
            0 => elf_edit::add_needed(&mut data, &format!("libfuzz{arg}.so")),
            1 => elf_edit::set_string(&mut data, elf_edit::DT_SONAME, if arg.is_multiple_of(2) { "s" } else { long }),
            2 => elf_edit::set_string(&mut data, elf_edit::DT_RUNPATH, if arg.is_multiple_of(2) { "/r" } else { long }),
            3 => elf_edit::set_string(&mut data, elf_edit::DT_RPATH, long),
            4 => elf_edit::remove_entry(&mut data, arg),
            5 => match elf_edit::info(&data).ok().and_then(|i| i.entries.into_iter().find(|e| e.tag == elf_edit::DT_NEEDED).and_then(|e| e.text)) {
                Some(old) => elf_edit::rename_needed(&mut data, &old, if arg.is_multiple_of(2) { "z" } else { long }),
                None => Ok(String::new()),
            },
            6 => elf_edit::add_section(&mut data, &format!(".fuzz{arg}"), &vec![0x5a; arg * 13]),
            7 => elf_edit::remove_section(&mut data, arg),
            _ => Ok(String::new()),
        };
        // A successful edit must leave a file the editor itself can still read.
        if r.is_ok() {
            assert!(elf_edit::info(&data).is_ok(), "edit produced an unreadable dynamic section");
            // Removing a section is a change to the section headers only.
            assert!(op & 0x0f != 7 || headers(&data) == before, "removing a section changed the program headers");
            // Adding one only appends: what the others hold stays as it was.
            assert!(
                op & 0x0f != 6 || contents.iter().all(|(off, bytes)| data.get(*off..*off + bytes.len()) == Some(&bytes[..])),
                "adding a section changed the content of another one"
            );
        }
        parse_any(&data);
        if data.len() > (file.len() + 4096) * 8 {
            break;
        }
    }
}

/// Mach-O load command editing. The first bytes choose the operations.
pub fn macho_edit(input: &[u8]) {
    let Some((ops, file)) = input.split_first_chunk::<4>() else { return };
    let mut data = file.to_vec();
    if macho_edit::slices(&data).is_empty() {
        return;
    }
    let len = data.len();
    for op in ops {
        let arg = (op >> 4) as usize;
        let path = format!("@rpath/libfuzz{arg}.dylib");
        let _ = match op & 0x0f {
            0 => macho_edit::add_path_command(&mut data, macho_edit::LC_LOAD_DYLIB, &path),
            1 => macho_edit::add_path_command(&mut data, macho_edit::LC_RPATH, "/opt/fuzz/lib"),
            2 => macho_edit::remove_path_command(&mut data, macho_edit::LC_RPATH, "/opt/fuzz/lib"),
            3 => macho_edit::change_path(&mut data, macho_edit::LC_LOAD_DYLIB, &path, "/usr/lib/a/much/longer/library/path/than/before.dylib"),
            4 => macho_edit::remove_signature(&mut data),
            5 => macho_edit::add_path_command(&mut data, macho_edit::LC_LOAD_WEAK_DYLIB, "/w.dylib"),
            _ => Ok(String::new()),
        };
        assert_eq!(data.len(), len, "load command edits never change the file size");
        parse_any(&data);
    }
}

/// The signature and metadata decoders, fed the input directly instead of
/// through a file that would first have to point at it.
pub fn decoders(data: &[u8]) {
    // Authenticode: the input is the PKCS#7 blob of a minimal PE.
    let mut file = vec![0u8; 0x200];
    file[..2].copy_from_slice(b"MZ");
    file[0x3c] = 0x40;
    file[0x40..0x44].copy_from_slice(b"PE\0\0");
    file[0x54] = 0xe0; // SizeOfOptionalHeader
    file[0x58..0x5a].copy_from_slice(&[0x0b, 0x01]);
    file[0xb4] = 16; // NumberOfRvaAndSizes
    if let Some(pe) = pe::Pe::parse(&file) {
        let _ = pe::sig::describe(&file, &pe, data);
    }
    // Mach-O code signature: the input is the signature SuperBlob.
    let _ = crate::macho_sig::describe(data, 0, 0, data.len());
    // .NET metadata: the input is split into the table, string and other heaps.
    let n = data.len();
    let streams: Vec<pe::dotnet::Stream> =
        vec![("#~".into(), 0, n / 2), ("#Strings".into(), n / 2, n / 4), ("#US".into(), n / 2 + n / 4, n / 8), ("#GUID".into(), n - n / 8, n / 8)];
    for node in pe::dotnet::nodes(data, &streams) {
        walk(&node, data);
    }
    // .NET signatures and IL: every method the tables describe, plus raw offsets.
    let streams: Vec<pe::dotnet::Stream> =
        vec![("#~".into(), 0, n / 2), ("#Strings".into(), n / 2, n / 6), ("#Blob".into(), n / 2 + n / 6, n / 6), ("#US".into(), n / 2 + n / 3, n / 6)];
    if let Some(md) = pe::dotnet::Md::parse(data, &streams) {
        for m in md.methods().iter().take(64) {
            let _ = md.il(m.rva as usize % n.max(1), &m.name);
            let _ = md.token_text(m.token);
        }
    }
    for off in [0, n / 5, n / 2] {
        let _ = pe::dotnet::Md::parse(data, &[("#~".into(), 0, 0)]).map(|md| md.il(off, ""));
    }
    // Mach-O dynamic linking data and language metadata: the input stands in
    // for every table, mapped as one segment at the usual image base.
    let range = |a: usize, b: usize| (n * a / 16, n * (b - a) / 16);
    let sect = |name: &str, a: usize, b: usize| crate::macho_dyld::Sect {
        name: name.into(),
        seg: "__DATA".into(),
        addr: 0x1_0000_0000 + (n * a / 16) as u64,
        size: (n * (b - a) / 16) as u64,
        offset: n * a / 16,
    };
    let budget = crate::macho_dyld::Budget::new();
    for chained in [None, Some((0, n))] {
        let ctx = crate::macho_dyld::Ctx {
            data,
            base: 0,
            is64: true,
            segs: vec![crate::macho_dyld::Seg { name: "__TEXT".into(), vmaddr: 0x1_0000_0000, vmsize: n as u64, fileoff: 0, filesize: n as u64 }],
            image_base: 0x1_0000_0000,
            sects: vec![sect("__objc_classlist", 1, 3), sect("__swift5_types", 3, 5)],
            dylibs: vec!["libfuzz.dylib".into()],
            dyld_info: Some([range(0, 3), range(3, 6), range(6, 9), range(9, 12), range(12, 16)]),
            exports_trie: Some((0, n)),
            chained,
            budget: &budget,
        };
        for node in crate::macho_dyld::nodes(&ctx) {
            walk(&node, data);
        }
    }
}

/// Search, offset lookup and comparison over whatever the input parses to.
pub fn queries(data: &[u8]) {
    let parsed = analysis::parse(data);
    let _ = query::search(&parsed.root, "e", 200);
    for off in [0usize, 1, data.len() / 2, data.len().saturating_sub(1)] {
        let _ = query::node_at(&parsed.root, off);
    }
    let mut other = data.to_vec();
    if let Some(b) = other.get_mut(data.len() / 3) {
        *b ^= 0x5a;
    }
    other.truncate(data.len().saturating_sub(data.len() / 7));
    let b = analysis::parse(&other);
    let _ = query::compare(&parsed, data, &b, &other);
}

/// Decoders used by the resource previews.
pub fn resource_previews(data: &[u8]) {
    let _ = resources::version_info(data);
    let _ = resources::string_table(data, 1);
    let _ = resources::group_icon(data);
    let _ = resources::utf16_text(data);
    // Image decoding is bounded so a tiny input cannot demand a huge bitmap.
    if data.len() <= 1 << 16 {
        let _ = resources::decode_image(data, false);
        let _ = resources::decode_image(data, true);
    }
}

/// Structure-aware: the input describes a mostly valid PE, ELF or Mach-O file
/// (see `fuzzgen`). The file is parsed, checked against what was built while
/// it is intact, then edited with the remaining input choosing the edits.
pub fn structured(input: &[u8]) {
    let mut g = fuzzgen::Gen::new(input);
    let (kind, mut file, exp) = fuzzgen::build(&mut g);
    // A few files get damaged, to test the error paths deep inside valid structure.
    let intact = !g.chance(64);
    if !intact && !file.is_empty() {
        for _ in 0..1 + g.below(4) {
            let i = g.below(file.len());
            file[i] ^= g.byte().max(1);
        }
        if g.chance(64) {
            file.truncate(g.below(file.len() + 1));
        }
    }
    parse_any(&file);
    parse_each(&file);
    if intact {
        check_built(&kind, &file, &exp);
    }
    let mut ops = g.bytes(4);
    ops.extend_from_slice(&file);
    match kind {
        Kind::Pe => pe_edit(&ops),
        Kind::Elf => elf_edit(&ops),
        Kind::MachO => macho_edit(&ops),
    }
}

/// The parsers must report exactly what the builder wrote.
fn check_built(kind: &Kind, file: &[u8], exp: &Expect) {
    let parsed = analysis::parse(file);
    assert_eq!(parsed.entry, exp.entry, "entry point");
    match kind {
        Kind::Pe => {
            let pe = pe::Pe::parse(file).expect("a built PE parses");
            let imports: Vec<(String, Vec<Result<String, u16>>)> =
                pe.imports(file).into_iter().map(|m| (m.name, m.funcs.into_iter().map(|f| f.name.ok_or(f.ordinal.unwrap_or(0))).collect())).collect();
            assert_eq!(imports, exp.imports, "imports");
            let mut exports: Vec<String> = edit::parse_exports(file, &pe).map(|t| t.funcs.into_iter().flat_map(|f| f.names).collect()).unwrap_or_default();
            exports.sort();
            assert_eq!(exports, exp.exports, "exports");
            let mut relocs = edit::parse_relocs(file, &pe);
            relocs.sort();
            assert_eq!(relocs, exp.relocs, "relocations");
        }
        Kind::Elf => {
            let info = elf_edit::info(file).expect("a built ELF file has a readable dynamic section");
            let text = |tag: u64| info.entries.iter().filter(|e| e.tag == tag).filter_map(|e| e.text.clone()).collect::<Vec<_>>();
            assert_eq!(text(elf_edit::DT_NEEDED), exp.needed, "DT_NEEDED");
            assert_eq!(text(elf_edit::DT_SONAME).pop(), exp.soname, "DT_SONAME");
            assert_eq!(text(elf_edit::DT_RUNPATH).pop(), exp.runpath, "DT_RUNPATH");
        }
        Kind::MachO => {
            let slices = macho_edit::slices(file);
            assert_eq!(slices.len(), 1, "one slice");
            let s = &slices[0];
            let paths: Vec<(u32, String)> = s.cmds.iter().filter(|c| macho_edit::is_path_cmd(c.cmd)).filter_map(|c| Some((c.cmd, s.path(file, c)?))).collect();
            assert_eq!(paths, exp.paths, "dylib and rpath commands");
        }
    }
}
