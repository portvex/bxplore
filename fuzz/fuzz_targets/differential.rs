//! Differential fuzzing: bxplore and the `object` crate read the same input,
//! and wherever `object` accepts the file completely the two must agree on the
//! format, the entry point, the sections and the PE imports. A disagreement is
//! a wrong answer in one of them, which plain fuzzing for crashes never finds.
//!
//! Inputs are built by the structure-aware generator, so most of them are
//! files both readers accept; raw bytes are tried as well.
#![no_main]

use bxplore::model::Format;
use bxplore::{analysis, elf_edit, fuzzgen, pe};
use libfuzzer_sys::fuzz_target;
use object::read::pe::{ImageNtHeaders, Import, PeFile, PeFile32, PeFile64};
use object::{FileKind, Object, ObjectSection};

fuzz_target!(|input: &[u8]| {
    let (raw, rest) = input.split_first().map_or((false, input), |(b, r)| (b & 7 == 0, r));
    let data = if raw { rest.to_vec() } else { fuzzgen::build(&mut fuzzgen::Gen::new(rest)).1 };
    compare(&data);
});

fn compare(data: &[u8]) {
    let Ok(kind) = FileKind::parse(data) else { return };
    let ours = analysis::parse(data);
    match kind {
        FileKind::Pe32 => {
            if let Ok(f) = PeFile32::parse(data) {
                pe_agrees(data, &ours, &f);
            }
        }
        FileKind::Pe64 => {
            if let Ok(f) = PeFile64::parse(data) {
                pe_agrees(data, &ours, &f);
            }
        }
        FileKind::Elf32 | FileKind::Elf64 => {
            if let Ok(f) = object::File::parse(data) {
                elf_agrees(data, &ours, &f);
            }
        }
        FileKind::MachO32 | FileKind::MachO64 => {
            if object::File::parse(data).is_ok() {
                assert_eq!(ours.format, Format::MachO, "object reads a Mach-O file that bxplore does not recognise");
            }
        }
        _ => {}
    }
}

fn pe_agrees<Pe: ImageNtHeaders>(data: &[u8], ours: &bxplore::model::Parsed, f: &PeFile<'_, Pe>) {
    assert_eq!(ours.format, Format::Pe, "object reads a PE file that bxplore does not recognise");
    let Some(p) = pe::Pe::parse(data) else { panic!("analysis says PE but Pe::parse fails") };
    // object reports image base + AddressOfEntryPoint even when that is 0.
    assert_eq!(ours.entry.unwrap_or(p.image_base), f.entry(), "PE entry point");

    // Sections: same order, names (short ones; long names need the COFF string
    // table, which images do not use), addresses and raw sizes.
    let theirs: Vec<_> = f.sections().collect();
    if theirs.len() == p.sections.len() {
        for (s, o) in p.sections.iter().zip(&theirs) {
            let name = String::from_utf8_lossy(o.name_bytes().unwrap_or_default());
            if !name.starts_with('/') {
                assert_eq!(s.name, name, "PE section name");
            }
            assert_eq!(p.image_base.wrapping_add(s.va as u64), o.address(), "address of PE section {name}");
        }
    }

    // Regular (not delay load) imports, in descriptor order.
    let Ok(Some(table)) = f.import_table() else { return };
    let Ok(mut descs) = table.descriptors() else { return };
    let mut theirs: Vec<(String, Vec<Result<String, u16>>)> = Vec::new();
    while let Ok(Some(d)) = descs.next() {
        let Ok(lib) = table.name(d.name.get(object::LittleEndian)) else { return };
        let mut first = d.original_first_thunk.get(object::LittleEndian);
        if first == 0 {
            first = d.first_thunk.get(object::LittleEndian);
        }
        let Ok(mut thunks) = table.thunks(first) else { return };
        let mut funcs = Vec::new();
        loop {
            match thunks.next::<Pe>() {
                Ok(Some(t)) => match table.import::<Pe>(t) {
                    Ok(Import::Ordinal(o)) => funcs.push(Err(o)),
                    Ok(Import::Name(_, n)) => funcs.push(Ok(String::from_utf8_lossy(n).into_owned())),
                    Err(_) => return,
                },
                Ok(None) => break,
                Err(_) => return,
            }
        }
        theirs.push((String::from_utf8_lossy(lib).into_owned(), funcs));
    }
    // bxplore caps what it reads from a hostile file; compare only below the caps.
    if theirs.len() > 256 || theirs.iter().any(|m| m.1.len() > 4096) {
        return;
    }
    let ours: Vec<(String, Vec<Result<String, u16>>)> =
        p.imports(data).into_iter().map(|m| (m.name, m.funcs.into_iter().map(|f| f.name.ok_or(f.ordinal.unwrap_or(0))).collect())).collect();
    assert_eq!(ours, theirs, "PE imports");
}

fn elf_agrees(data: &[u8], ours: &bxplore::model::Parsed, f: &object::File) {
    assert_eq!(ours.format, Format::Elf, "object reads an ELF file that bxplore does not recognise");
    assert_eq!(ours.entry.unwrap_or(0), f.entry(), "ELF entry point");
    let Ok(sections) = elf_edit::sections(data) else { return };
    let theirs: Vec<_> = f.sections().collect();
    if theirs.len() > 4096 {
        return;
    }
    // object leaves out the null section at index 0 but keeps the real indexes.
    assert_eq!(sections.len().saturating_sub(1), theirs.len(), "number of ELF sections");
    for o in &theirs {
        let i = o.index().0;
        let Some(s) = sections.get(i) else { panic!("ELF section {i} missing in bxplore") };
        if let Ok(name) = o.name_bytes() {
            assert_eq!(s.name, String::from_utf8_lossy(name), "ELF section {i} name");
        }
    }
}
