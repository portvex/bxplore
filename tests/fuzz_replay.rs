//! Runs the libFuzzer entry points as ordinary unit tests on stable Rust:
//! over small synthetic files, over deterministic mutations of them, and over
//! every input saved in `fuzz/regressions` (crashes found by the fuzzers) and
//! `fuzz/artifacts` (crashes not yet triaged).

use bxplore::fuzzing;

fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
    buf[off..off + bytes.len()].copy_from_slice(bytes);
}

/// Smallest useful PE32: headers, one code section, one import-less data directory table.
fn tiny_pe() -> Vec<u8> {
    let mut f = vec![0u8; 0x400];
    put(&mut f, 0, b"MZ");
    put(&mut f, 0x3c, &0x80u32.to_le_bytes());
    put(&mut f, 0x80, b"PE\0\0");
    put(&mut f, 0x84, &0x014cu16.to_le_bytes()); // Machine
    put(&mut f, 0x86, &1u16.to_le_bytes()); // NumberOfSections
    put(&mut f, 0x94, &0xe0u16.to_le_bytes()); // SizeOfOptionalHeader
    put(&mut f, 0x96, &0x0102u16.to_le_bytes()); // Characteristics
    let opt = 0x98;
    put(&mut f, opt, &0x010bu16.to_le_bytes()); // Magic
    put(&mut f, opt + 16, &0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    put(&mut f, opt + 28, &0x40_0000u32.to_le_bytes()); // ImageBase
    put(&mut f, opt + 32, &0x1000u32.to_le_bytes()); // SectionAlignment
    put(&mut f, opt + 36, &0x200u32.to_le_bytes()); // FileAlignment
    put(&mut f, opt + 56, &0x2000u32.to_le_bytes()); // SizeOfImage
    put(&mut f, opt + 60, &0x200u32.to_le_bytes()); // SizeOfHeaders
    put(&mut f, opt + 68, &3u16.to_le_bytes()); // Subsystem
    put(&mut f, opt + 92, &16u32.to_le_bytes()); // NumberOfRvaAndSizes
    let sec = opt + 0xe0;
    put(&mut f, sec, b".text\0\0\0");
    put(&mut f, sec + 8, &0x200u32.to_le_bytes()); // VirtualSize
    put(&mut f, sec + 12, &0x1000u32.to_le_bytes()); // VirtualAddress
    put(&mut f, sec + 16, &0x200u32.to_le_bytes()); // SizeOfRawData
    put(&mut f, sec + 20, &0x200u32.to_le_bytes()); // PointerToRawData
    put(&mut f, sec + 36, &0x6000_0020u32.to_le_bytes()); // Characteristics
    f[0x200] = 0xc3;
    f
}

fn tiny_elf() -> Vec<u8> {
    let mut f = vec![0u8; 0x200];
    put(&mut f, 0, b"\x7fELF\x02\x01\x01");
    put(&mut f, 16, &2u16.to_le_bytes()); // e_type
    put(&mut f, 18, &62u16.to_le_bytes()); // e_machine
    put(&mut f, 20, &1u32.to_le_bytes());
    put(&mut f, 24, &0x40_0100u64.to_le_bytes()); // e_entry
    put(&mut f, 32, &64u64.to_le_bytes()); // e_phoff
    put(&mut f, 52, &64u16.to_le_bytes()); // e_ehsize
    put(&mut f, 54, &56u16.to_le_bytes()); // e_phentsize
    put(&mut f, 56, &1u16.to_le_bytes()); // e_phnum
    put(&mut f, 58, &64u16.to_le_bytes()); // e_shentsize
    put(&mut f, 64, &1u32.to_le_bytes()); // PT_LOAD
    put(&mut f, 68, &5u32.to_le_bytes());
    put(&mut f, 64 + 16, &0x40_0000u64.to_le_bytes());
    put(&mut f, 64 + 32, &0x200u64.to_le_bytes());
    put(&mut f, 64 + 40, &0x200u64.to_le_bytes());
    f[0x100] = 0xc3;
    f
}

fn tiny_macho() -> Vec<u8> {
    let mut f = vec![0u8; 0x200];
    put(&mut f, 0, &0xfeed_facfu32.to_le_bytes());
    put(&mut f, 4, &0x0100_000cu32.to_le_bytes()); // CPU_TYPE_ARM64
    put(&mut f, 12, &2u32.to_le_bytes()); // MH_EXECUTE
    put(&mut f, 16, &2u32.to_le_bytes()); // ncmds
    put(&mut f, 20, &(72u32 + 24).to_le_bytes()); // sizeofcmds
    let seg = 32;
    put(&mut f, seg, &0x19u32.to_le_bytes()); // LC_SEGMENT_64
    put(&mut f, seg + 4, &72u32.to_le_bytes());
    put(&mut f, seg + 8, b"__TEXT");
    put(&mut f, seg + 24, &0x1_0000_0000u64.to_le_bytes());
    put(&mut f, seg + 32, &0x4000u64.to_le_bytes());
    put(&mut f, seg + 48, &0x200u64.to_le_bytes());
    let main = seg + 72;
    put(&mut f, main, &0x8000_0028u32.to_le_bytes()); // LC_MAIN
    put(&mut f, main + 4, &24u32.to_le_bytes());
    put(&mut f, main + 8, &0x100u64.to_le_bytes());
    f
}

/// Small dynamically linked ELF64: one PT_LOAD over the whole file, a
/// PT_DYNAMIC with two spare slots, a PT_NOTE, `.dynstr` and `.dynamic`
/// sections. Enough for the dynamic section editor to work on.
fn tiny_dyn_elf() -> Vec<u8> {
    let mut f = vec![0u8; 0x400];
    put(&mut f, 0, b"\x7fELF\x02\x01\x01");
    put(&mut f, 16, &3u16.to_le_bytes()); // ET_DYN
    put(&mut f, 18, &62u16.to_le_bytes());
    put(&mut f, 20, &1u32.to_le_bytes());
    put(&mut f, 32, &64u64.to_le_bytes()); // e_phoff
    put(&mut f, 40, &0x300u64.to_le_bytes()); // e_shoff
    put(&mut f, 52, &64u16.to_le_bytes());
    put(&mut f, 54, &56u16.to_le_bytes());
    put(&mut f, 56, &3u16.to_le_bytes()); // e_phnum
    put(&mut f, 58, &64u16.to_le_bytes());
    put(&mut f, 60, &4u16.to_le_bytes()); // e_shnum
    put(&mut f, 62, &3u16.to_le_bytes()); // e_shstrndx
    let ph = |f: &mut Vec<u8>, i: usize, ty: u32, flags: u32, off: u64, size: u64, align: u64| {
        let o = 64 + i * 56;
        put(f, o, &ty.to_le_bytes());
        put(f, o + 4, &flags.to_le_bytes());
        for (field, v) in [(8, off), (16, off), (24, off), (32, size), (40, size), (48, align)] {
            put(f, o + field, &v.to_le_bytes());
        }
    };
    ph(&mut f, 0, 1, 6, 0, 0x400, 0x1000); // PT_LOAD
    ph(&mut f, 1, 2, 6, 0x200, 0x80, 8); // PT_DYNAMIC, 8 slots
    ph(&mut f, 2, 4, 4, 0x2c0, 0x20, 4); // PT_NOTE
    let strtab = b"\0libc.so.6\0libfirst.so.1\0/opt/original\0";
    put(&mut f, 0x280, strtab);
    let dynamic: [(u64, u64); 6] = [(1, 1), (14, 11), (29, 25), (5, 0x280), (10, strtab.len() as u64), (0, 0)];
    for (i, (tag, val)) in dynamic.iter().enumerate() {
        put(&mut f, 0x200 + i * 16, &tag.to_le_bytes());
        put(&mut f, 0x200 + i * 16 + 8, &val.to_le_bytes());
    }
    let sh = |f: &mut Vec<u8>, i: usize, ty: u32, off: u64, size: u64| {
        let o = 0x300 + i * 64;
        put(f, o + 4, &ty.to_le_bytes());
        put(f, o + 16, &off.to_le_bytes());
        put(f, o + 24, &off.to_le_bytes());
        put(f, o + 32, &size.to_le_bytes());
    };
    sh(&mut f, 1, 3, 0x280, strtab.len() as u64); // .dynstr
    sh(&mut f, 2, 6, 0x200, 0x80); // .dynamic
    let names = b"\0.dynstr\0.dynamic\0.shstrtab\0";
    put(&mut f, 0x2e0, names);
    sh(&mut f, 3, 3, 0x2e0, names.len() as u64); // .shstrtab
    for (i, name_off) in [(1usize, 1u32), (2, 9), (3, 18)] {
        put(&mut f, 0x300 + i * 64, &name_off.to_le_bytes());
    }
    f
}

fn seeds() -> Vec<Vec<u8>> {
    let mut fat = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1];
    fat.extend_from_slice(&[1, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 2, 0, 0, 0, 0, 0]);
    fat.resize(0x20, 0);
    fat.extend(tiny_macho());
    vec![tiny_pe(), tiny_elf(), tiny_dyn_elf(), tiny_macho(), fat, Vec::new(), b"MZ".to_vec(), b"\x7fELF".to_vec(), vec![0xff; 64]]
}

fn run_all(data: &[u8]) {
    fuzzing::parse_any(data);
    fuzzing::parse_each(data);
    fuzzing::resource_previews(data);
    fuzzing::queries(data);
    fuzzing::decoders(data);
    for ops in [[0u8, 0x11, 0x12, 0x03], [0x05, 0x15, 0x14, 0x24], [0x10, 0x20, 0x30, 0x04], [0x16, 0x26, 0x17, 0x37]] {
        let mut input = ops.to_vec();
        input.extend_from_slice(data);
        fuzzing::elf_edit(&input);
        fuzzing::macho_edit(&input);
    }
    for ops in [
        [5u8, 0x37, 0x18, 0],
        [0x08, 0x16, 6, 2],
        [4, 3, 1, 0x26],
        [0x25, 0x25, 0x06, 0x06],
        [0x1c, 0x2c, 0x09, 0x0a],
        [0x97, 0x89, 0x0b, 0x3c],
        [0x0d, 0x1d, 0x1e, 0x0e],
        [0x0f, 0x2d, 0x3e, 0x1e],
    ] {
        let mut input = ops.to_vec();
        input.extend_from_slice(data);
        fuzzing::pe_edit(&input);
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn seeds_are_recognised() {
    use bxplore::model::Format;
    assert!(matches!(bxplore::analysis::parse(&tiny_pe()).format, Format::Pe));
    assert!(matches!(bxplore::analysis::parse(&tiny_elf()).format, Format::Elf));
    assert!(matches!(bxplore::analysis::parse(&tiny_macho()).format, Format::MachO));
}

#[test]
fn seeds_do_not_panic() {
    for s in seeds() {
        run_all(&s);
    }
}

#[test]
fn truncated_seeds_do_not_panic() {
    for s in seeds() {
        for len in (0..s.len()).step_by(7) {
            run_all(&s[..len]);
        }
    }
}

#[test]
fn mutated_seeds_do_not_panic() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for s in seeds().into_iter().filter(|s| !s.is_empty()) {
        for _ in 0..300 {
            let mut m = s.clone();
            for _ in 0..1 + rng.next() % 6 {
                let at = (rng.next() % m.len() as u64) as usize;
                let interesting = [0u8, 1, 0x7f, 0x80, 0xff, 0x10, 0x40, 0xfe];
                m[at] = if rng.next().is_multiple_of(2) { interesting[(rng.next() % 8) as usize] } else { rng.next() as u8 };
            }
            run_all(&m);
        }
    }
}

/// The structure-aware builder over pseudo-random choices: every built file
/// must parse back to what was written, and editing it must not panic.
#[test]
fn structured_files_read_back_what_was_built() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut kinds = [0usize; 3];
    for _ in 0..3000 {
        let len = (rng.next() % 600) as usize;
        let input: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        kinds[bxplore::fuzzgen::Gen::new(&input).below(3)] += 1;
        fuzzing::structured(&input);
    }
    assert!(kinds.iter().all(|&k| k > 500), "every format is built: {kinds:?}");
}

#[test]
fn saved_fuzzer_inputs_do_not_panic() {
    fn visit(dir: &std::path::Path, n: &mut usize) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                visit(&p, n);
            } else if let Ok(data) = std::fs::read(&p) {
                // An input saved by one target is replayed through all of them.
                run_all(&data);
                fuzzing::pe_edit(&data);
                fuzzing::elf_edit(&data);
                fuzzing::macho_edit(&data);
                fuzzing::structured(&data);
                *n += 1;
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz");
    let mut n = 0;
    visit(&root.join("regressions"), &mut n);
    visit(&root.join("artifacts"), &mut n);
    println!("replayed {n} saved fuzzer input(s)");
}

/// Writes the synthetic files to `fuzz/seeds` as starting corpus for the fuzzers:
/// `cargo test --test fuzz_replay write_seeds -- --ignored`
#[test]
#[ignore = "writes files; run on demand"]
fn write_seeds() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds");
    for (name, data) in [("tiny.exe", tiny_pe()), ("tiny.elf", tiny_elf()), ("tiny.macho", tiny_macho()), ("tiny_dyn.elf", tiny_dyn_elf())] {
        for target in ["parse_any", "parse_each", "queries"] {
            std::fs::create_dir_all(root.join(target)).unwrap();
            std::fs::write(root.join(target).join(name), &data).unwrap();
        }
    }
    for (target, data) in [("elf_edit", tiny_dyn_elf()), ("macho_edit", tiny_macho())] {
        std::fs::create_dir_all(root.join(target)).unwrap();
        for (i, ops) in [[0u8, 0x11, 0x12, 0x03], [0x05, 0x15, 0x14, 0x24]].iter().enumerate() {
            let mut input = ops.to_vec();
            input.extend(&data);
            std::fs::write(root.join(target).join(format!("tiny{i}.bin")), input).unwrap();
        }
    }
    std::fs::write(root.join("parse_any").join("bind_run.macho"), bind_run_macho()).unwrap();
    std::fs::write(root.join("parse_any").join("aliased_versym.elf"), aliased_versym_elf(200, 0x400)).unwrap();
    std::fs::create_dir_all(root.join("pe_edit")).unwrap();
    for (i, ops) in [[5u8, 0x37, 0x18, 0], [0x08, 0x16, 6, 2], [4, 3, 1, 0x26]].iter().enumerate() {
        let mut input = ops.to_vec();
        input.extend(tiny_pe());
        std::fs::write(root.join("pe_edit").join(format!("tiny{i}.bin")), input).unwrap();
    }
}

// --- behaviour tests on the synthetic files -------------------------------

fn dump(data: &[u8]) -> String {
    let mut out = String::new();
    bxplore::analysis::dump(&bxplore::analysis::parse(data).root, 0, &mut out);
    out
}

#[test]
fn elf_dynamic_editing_on_the_synthetic_file() {
    use bxplore::elf_edit::{self, DT_NEEDED, DT_RUNPATH, DT_SONAME};
    let orig = tiny_dyn_elf();
    let strings =
        |d: &[u8], tag: u64| -> Vec<String> { elf_edit::info(d).unwrap().entries.iter().filter(|e| e.tag == tag).filter_map(|e| e.text.clone()).collect() };
    assert_eq!(strings(&orig, DT_NEEDED), ["libc.so.6"]);
    assert_eq!(elf_edit::info(&orig).unwrap().spare_slots, 2);

    // Shorter values are overwritten in place.
    let mut d = orig.clone();
    elf_edit::set_string(&mut d, DT_SONAME, "libx.so").unwrap();
    elf_edit::set_string(&mut d, DT_RUNPATH, "/opt/o").unwrap();
    assert_eq!(d.len(), orig.len());
    assert_eq!((strings(&d, DT_SONAME), strings(&d, DT_RUNPATH)), (vec!["libx.so".to_string()], vec!["/opt/o".to_string()]));

    // A string that already exists in the table is reused through a spare slot.
    let mut d = orig.clone();
    elf_edit::add_needed(&mut d, "libfirst.so.1").unwrap();
    assert_eq!(d.len(), orig.len());
    assert_eq!(strings(&d, DT_NEEDED), ["libc.so.6", "libfirst.so.1"]);

    // New strings need room: the PT_NOTE header becomes a PT_LOAD for the moved table.
    let mut d = orig.clone();
    elf_edit::add_needed(&mut d, "libnew_one.so").unwrap();
    assert!(d.len() > orig.len());
    let loads = |d: &[u8]| dump(d).matches("  LOAD  ").count();
    assert_eq!((loads(&orig), loads(&d)), (1, 2), "the PT_NOTE header became a second PT_LOAD");
    // Later strings extend the moved table; more entries than slots move the dynamic table too.
    for name in ["libnew_two.so", "libnew_three.so", "libnew_four.so"] {
        elf_edit::add_needed(&mut d, name).unwrap();
    }
    assert_eq!(strings(&d, DT_NEEDED), ["libc.so.6", "libnew_one.so", "libnew_two.so", "libnew_three.so", "libnew_four.so"]);
    assert_eq!(strings(&d, DT_SONAME), ["libfirst.so.1"], "untouched entries keep their values");
    assert_eq!(strings(&d, DT_RUNPATH), ["/opt/original"]);

    elf_edit::rename_needed(&mut d, "libnew_two.so", "librenamed_to_something_longer.so").unwrap();
    let i = elf_edit::info(&d).unwrap().entries.iter().position(|e| e.text.as_deref() == Some("libc.so.6")).unwrap();
    elf_edit::remove_entry(&mut d, i).unwrap();
    assert_eq!(strings(&d, DT_NEEDED), ["libnew_one.so", "librenamed_to_something_longer.so", "libnew_three.so", "libnew_four.so"]);
    assert!(elf_edit::add_needed(&mut d, "libnew_one.so").is_err(), "duplicates are refused");
}

#[test]
fn macho_load_command_editing_on_the_synthetic_file() {
    use bxplore::macho_edit::{self, LC_LOAD_DYLIB, LC_RPATH};
    let orig = tiny_macho();
    let paths = |d: &[u8]| -> Vec<String> {
        let s = &macho_edit::slices(d)[0];
        s.cmds.iter().filter_map(|c| s.path(d, c)).collect()
    };
    let mut d = orig.clone();
    macho_edit::add_path_command(&mut d, LC_LOAD_DYLIB, "/usr/lib/libz.1.dylib").unwrap();
    macho_edit::add_path_command(&mut d, LC_RPATH, "@loader_path/../lib").unwrap();
    assert_eq!(d.len(), orig.len());
    assert_eq!(paths(&d), ["/usr/lib/libz.1.dylib", "@loader_path/../lib"]);
    assert!(dump(&d).contains("/usr/lib/libz.1.dylib"), "the viewer sees the new command");
    macho_edit::change_path(&mut d, LC_LOAD_DYLIB, "/usr/lib/libz.1.dylib", "/z").unwrap();
    assert_eq!(paths(&d), ["/z", "@loader_path/../lib"]);
    macho_edit::remove_path_command(&mut d, LC_LOAD_DYLIB, "/z").unwrap();
    macho_edit::remove_path_command(&mut d, LC_RPATH, "@loader_path/../lib").unwrap();
    assert_eq!(d, orig, "removing what was added restores the file");
    // The header padding is finite.
    let long = "x".repeat(600);
    assert!(macho_edit::add_path_command(&mut d, LC_RPATH, &long).unwrap_err().contains("not enough header padding"));
    assert_eq!(d, orig, "a refused edit changes nothing");
}

#[test]
fn search_lookup_and_compare() {
    use bxplore::query;
    let a = tiny_pe();
    let pa = bxplore::analysis::parse(&a);
    let hits = query::search(&pa.root, ".TEXT", 100);
    assert!(hits.iter().any(|h| h.path.last().is_some_and(|t| t == "Section Headers") && h.row == Some(0)), "case insensitive match in the section table");
    assert!(query::search(&pa.root, "no such thing anywhere", 100).is_empty());

    let (path, row) = query::node_at(&pa.root, 0x86).unwrap();
    assert_eq!((path.last().unwrap().as_str(), row), ("File Header", Some(1)));

    // Identical files have no differences; one changed field is reported exactly.
    assert!(query::compare(&pa, &a, &pa, &a).diffs.is_empty());
    let mut b = a.clone();
    put(&mut b, 0x86 + 2, &0x1234_5678u32.to_le_bytes()); // TimeDateStamp
    let pb = bxplore::analysis::parse(&b);
    let cmp = query::compare(&pa, &a, &pb, &b);
    let d = cmp.diffs.iter().find(|d| d.what.contains("TimeDateStamp") && d.what.ends_with("Value")).expect("the changed field is listed");
    assert_eq!((d.left.as_str(), d.right.as_str(), d.row), ("00000000", "12345678", Some(2)));
    assert!(cmp.summary.iter().any(|(k, v)| k == "Bytes" && v.starts_with("4 differing")), "{:?}", cmp.summary);
}

#[test]
fn disassembly_is_annotated_with_symbols_and_targets() {
    use bxplore::model::*;
    // call rel32 to 0x1020; call [rip+disp] through an import slot at 0x2000; lea of a string at 0x2010.
    let mut data = vec![0x90u8; 0x3000];
    put(&mut data, 0x1000, &[0xE8, 0x1B, 0, 0, 0]);
    put(&mut data, 0x1005, &[0xFF, 0x15, 0xF5, 0x0F, 0, 0]);
    put(&mut data, 0x100B, &[0x48, 0x8D, 0x0D, 0xFE, 0x0F, 0, 0]);
    put(&mut data, 0x2010, b"hello world\0");
    let parsed = Parsed {
        format: Format::Unknown,
        description: String::new(),
        root: Node::text("File", ""),
        maps: vec![Map { name: "all".into(), vaddr: 0, vsize: 0x3000, offset: 0, fsize: 0x3000, exec: true }],
        image_base: 0,
        entry: None,
        arch: Arch::X64,
        symbols: vec![(0x1020, "helper".into()), (0x2000, "KERNEL32!Sleep".into())],
        functions: vec![(0x1000, 0x1020), (0x1020, 0x1040)],
    };
    let mut insns = bxplore::analysis::disasm(&data[0x1000..0x1012], Arch::X64, 0x1000, 3).unwrap();
    bxplore::analysis::annotate(&mut insns, &parsed, &data);
    assert_eq!((insns[0].target, insns[0].comment.as_str()), (Some(0x1020), "helper"));
    assert_eq!((insns[1].target, insns[1].comment.as_str()), (None, "KERNEL32!Sleep"), "an indirect call names the import");
    assert_eq!(insns[2].comment, "\"hello world\"");
    assert_eq!(parsed.function_of(0x1025), Some((0x1020, 0x1040)));
    assert_eq!(parsed.function_of(0x1040), None);
}

/// Text dumps of the synthetic files are compared with stored snapshots, so
/// any change in what the parsers report shows up in review.
/// Regenerate with: BXPLORE_UPDATE_SNAPSHOTS=1 cargo test --test fuzz_replay snapshots
#[test]
fn snapshots() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots");
    let update = std::env::var_os("BXPLORE_UPDATE_SNAPSHOTS").is_some();
    let mut stale = Vec::new();
    for (name, data) in [("tiny_pe", tiny_pe()), ("tiny_elf", tiny_elf()), ("tiny_dyn_elf", tiny_dyn_elf()), ("tiny_macho", tiny_macho())] {
        let text = dump(&data);
        let file = dir.join(format!("{name}.txt"));
        if update {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&file, &text).unwrap();
        } else if std::fs::read_to_string(&file).map(|s| s.replace("\r\n", "\n")).ok().as_deref() != Some(text.as_str()) {
            let _ = std::fs::write(dir.join(format!("{name}.new.txt")), &text);
            stale.push(name);
        }
    }
    assert!(
        stale.is_empty(),
        "dump differs from tests/snapshots for {stale:?}; the new output is next to it as .new.txt. If the change is intended, rerun with BXPLORE_UPDATE_SNAPSHOTS=1"
    );
}

#[test]
fn patches_reproduce_the_edit() {
    use bxplore::query;
    let original = tiny_pe();
    // A field edit, then a structural edit that makes the file longer.
    let mut patched = original.clone();
    put(&mut patched, 0x88, &0xDEAD_BEEFu32.to_le_bytes());
    bxplore::pe::edit::add_section(&mut patched, ".new", &[0x41; 700], 0x1000, 0x4000_0040).unwrap();
    assert!(patched.len() > original.len());

    let text = query::patch_text("tiny.exe", &original, &patched);
    assert!(text.contains("00000088: 00000000 -> EFBEADDE"), "{text}");
    assert!(text.contains("bytes appended at 00000400"));

    // The Python script must turn the original into exactly the patched file, and refuse other inputs.
    if !std::process::Command::new("python3").arg("--version").output().is_ok_and(|o| o.status.success()) {
        return;
    }
    let dir = std::env::temp_dir().join(format!("bxplore-patch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n);
    std::fs::write(p("patch.py"), query::patch_python("tiny.exe", &original, &patched)).unwrap();
    std::fs::write(p("orig.bin"), &original).unwrap();
    let run = |input: &str| std::process::Command::new("python3").arg("-I").arg(p("patch.py")).arg(p(input)).arg(p("out.bin")).output().unwrap();
    assert!(run("orig.bin").status.success());
    assert_eq!(std::fs::read(p("out.bin")).unwrap(), patched);
    // A shrinking edit works the same way.
    std::fs::write(p("patch.py"), query::patch_python("tiny.exe", &patched, &original)).unwrap();
    std::fs::write(p("big.bin"), &patched).unwrap();
    assert!(run("big.bin").status.success());
    assert_eq!(std::fs::read(p("out.bin")).unwrap(), original);
    assert!(!run("orig.bin").status.success(), "a file the patch was not made for is refused");
    // The file name is untrusted and must never become code: the script has
    // the same statements whatever the name is, and running it runs only main.
    let hostile = "a\"\"\";print('INJECTED');\"\"\"b\\\nprint('INJECTED')\r\nimport os\u{2028}#'.exe";
    let shape = |name: &str| {
        std::fs::write(p("patch.py"), query::patch_python(name, &original, &patched)).unwrap();
        let o = std::process::Command::new("python3")
            .args(["-I", "-c", "import ast, sys; print([type(n).__name__ for n in ast.parse(open(sys.argv[1], encoding='utf-8').read()).body])"])
            .arg(p("patch.py"))
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    let plain = shape("tiny.exe");
    assert_eq!(shape(hostile), plain);
    let o = run("orig.bin");
    assert!(o.status.success() && !String::from_utf8_lossy(&o.stdout).contains("INJECTED"));
    assert_eq!(std::fs::read(p("out.bin")).unwrap(), patched);
    assert_eq!(query::patch_text(hostile, &original, &patched).lines().filter(|l| !l.starts_with('#') && !l.contains(": ")).count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn settings_and_bookmarks_survive_a_round_trip() {
    use bxplore::store::{self, Bookmark, Settings, ThemeChoice};
    let s = Settings { theme: ThemeChoice::Dark, zoom: 1.25, hex_panel: false, backup_on_save: false, recent_max: 3, strings_min: 8 };
    assert_eq!(Settings::parse(&s.to_text()), s);
    // Garbage falls back to defaults instead of failing, and values are clamped.
    assert_eq!(Settings::parse("nonsense\nzoom=abc\ntheme=purple\nunknown=1\n"), Settings::default());
    assert_eq!(Settings::parse("zoom=99\nstrings_min=0\n").zoom, 2.0);
    assert_eq!(Settings::parse("zoom=NaN").zoom, 1.0);

    let dir = std::env::temp_dir().join(format!("bxplore-store-{}", std::process::id()));
    let file = std::path::Path::new("/some/where/app.exe");
    let list = vec![
        Bookmark { off: 0x40, len: 4, note: "entry\tpoint\nsecond line".into() },
        Bookmark { off: 0x1000, len: 1, note: String::new() },
        Bookmark { off: 0x2000, len: 2, note: r"see C:\new\notes.txt, \\server\n and a trailing \".into() },
    ];
    store::save_bookmarks(&dir, file, &list).unwrap();
    let back = store::load_bookmarks(&dir, file);
    assert_eq!(back[0].note, "entry point\nsecond line", "tabs become spaces, newlines survive");
    assert_eq!((back[1].off, back[1].len), (0x1000, 1));
    assert_eq!(back[2], list[2], "a backslash followed by n is not a line break");
    assert!(store::load_bookmarks(&dir, std::path::Path::new("/other/file")).is_empty(), "bookmarks belong to one file");
    store::save_bookmarks(&dir, file, &[]).unwrap();
    assert!(store::load_bookmarks(&dir, file).is_empty());
    s.save(&dir).unwrap();
    assert_eq!(Settings::load(&dir), s);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn elf_sections_on_the_synthetic_file() {
    use bxplore::elf_edit;
    let orig = tiny_dyn_elf();
    let names = |d: &[u8]| -> Vec<String> { elf_edit::sections(d).unwrap().into_iter().map(|s| s.name).collect() };
    assert_eq!(names(&orig), ["", ".dynstr", ".dynamic", ".shstrtab"]);
    let mut d = orig.clone();
    elf_edit::add_section(&mut d, ".note.extra", b"payload").unwrap();
    assert_eq!(names(&d), ["", ".dynstr", ".dynamic", ".shstrtab", ".note.extra"]);
    let s = &elf_edit::sections(&d).unwrap()[4];
    assert_eq!(&d[s.offset as usize..(s.offset + s.size) as usize], b"payload");
    assert!(elf_edit::add_section(&mut d, ".note.extra", b"again").is_err());
    // The dynamic editor still works on the grown file, and the other way round.
    elf_edit::add_needed(&mut d, "libafter.so").unwrap();
    elf_edit::add_section(&mut d, ".second", &[1, 2, 3]).unwrap();
    assert_eq!(names(&d).last().map(String::as_str), Some(".second"));
    assert!(elf_edit::info(&d).unwrap().entries.iter().any(|e| e.text.as_deref() == Some("libafter.so")));
    elf_edit::remove_section(&mut d, 4).unwrap();
    assert_eq!(names(&d), ["", ".dynstr", ".dynamic", ".shstrtab", ".second"]);
    assert!(elf_edit::remove_section(&mut d, 3).is_err(), "the name table stays");
    assert!(elf_edit::remove_section(&mut d, 0).is_err());
    let before = d.clone();
    assert!(elf_edit::remove_section(&mut d, 99).is_err());
    assert_eq!(d, before, "a refused edit changes nothing");

    // A relocation section names its target in sh_info: the target stays while it exists.
    elf_edit::add_section(&mut d, ".rela.second", &[0; 24]).unwrap();
    let shoff = u64::from_le_bytes(d[0x28..0x30].try_into().unwrap()) as usize;
    put(&mut d, shoff + 5 * 64 + 4, &4u32.to_le_bytes()); // SHT_RELA
    put(&mut d, shoff + 5 * 64 + 44, &4u32.to_le_bytes()); // sh_info: .second
    let before = d.clone();
    let err = elf_edit::remove_section(&mut d, 4).unwrap_err();
    assert!(err.contains(".rela.second applies to .second"), "{err}");
    assert_eq!(d, before);
    // Section groups keep section indexes in their content, which is not rewritten.
    put(&mut d, shoff + 5 * 64 + 4, &17u32.to_le_bytes()); // SHT_GROUP
    assert!(elf_edit::remove_section(&mut d, 4).unwrap_err().contains("section groups"));
    // A symbol defined in the section would silently become undefined.
    put(&mut d, shoff + 5 * 64 + 4, &2u32.to_le_bytes()); // SHT_SYMTAB with one symbol
    let sym = u64::from_le_bytes(d[shoff + 5 * 64 + 24..shoff + 5 * 64 + 32].try_into().unwrap()) as usize;
    put(&mut d, sym + 4, &[0x12]); // STB_GLOBAL, STT_FUNC
    put(&mut d, sym + 6, &4u16.to_le_bytes()); // st_shndx: .second
    let before = d.clone();
    assert!(elf_edit::remove_section(&mut d, 4).unwrap_err().contains("a symbol is defined in .second"));
    assert_eq!(d, before);
    put(&mut d, sym + 4, &[0x03]); // its own STT_SECTION symbol may go
    elf_edit::remove_section(&mut d, 4).unwrap();
    assert_eq!(names(&d), ["", ".dynstr", ".dynamic", ".shstrtab", ".rela.second"]);
    assert_eq!(&d[sym + 6..sym + 8], &[0, 0]);
}

#[test]
fn a_section_table_inside_a_segment_is_not_rewritten() {
    // The saved fuzzer input (4 operation bytes, then the file) has its section
    // header table at 0x101, reaching into the dynamic section at 0x200: closing
    // the gap after a removal used to overwrite the first dynamic entry.
    let input = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/regressions/elf_edit/section_table_in_segment.bin")).unwrap();
    let mut d = input[4..].to_vec();
    let before = d.clone();
    let err = bxplore::elf_edit::remove_section(&mut d, 2).unwrap_err();
    assert!(err.contains("section header table lies inside a loaded segment"), "{err}");
    assert_eq!(d, before, "a refused edit changes nothing");
    assert!(bxplore::elf_edit::info(&d).is_ok());
}

#[test]
fn an_image_that_ends_past_4_gb_is_not_edited() {
    // The saved fuzzer input (4 operation bytes, then the file) has no sections
    // and SizeOfHeaders 0xFFFFFFF2, which is where its first section would go:
    // the RVAs inside the new export table overflowed.
    use bxplore::pe::{Pe, edit};
    let input = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/regressions/pe_edit/huge_size_of_headers.bin")).unwrap();
    fuzzing::pe_edit(&input);
    let mut d = input[4..].to_vec();
    let pe = Pe::parse(&d).unwrap();
    assert_eq!((pe.sections.len(), pe.size_of_headers, pe.section_align), (0, 0xFFFF_FFF2, 1));
    let table = edit::ExportTable { dll_name: "a.dll".into(), ..Default::default() };
    // With a section alignment of 4 KB the image ends at exactly 4 GB, which
    // used to be taken as RVA 0.
    for align in [1u32, 0x1000] {
        put(&mut d, pe.opt + 32, &align.to_le_bytes());
        let before = d.clone();
        for r in [edit::write_exports(&mut d, &table), edit::add_section(&mut d, ".new", &[1, 2, 3], 3, 0x4000_0040).map(|_| String::new())] {
            let err = r.unwrap_err();
            assert!(err.contains("the image does not fit in 4 GB"), "{err}");
            assert_eq!(d, before, "a refused edit changes nothing");
        }
    }
}

// --- hostile inputs: small files that used to demand huge amounts of work ---

#[test]
fn decoder_seeds_do_not_panic() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/decoders");
    let mut n = 0;
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        fuzzing::decoders(&std::fs::read(e.path()).unwrap());
        n += 1;
    }
    // typespec_cycle.bin: a TypeSpec row that names itself nine times per level.
    assert!(n >= 1);
}

#[test]
fn needed_versions_are_capped() {
    // 256 Verneed entries that all share one chain of 4096 Vernaux entries.
    let mut f = tiny_dyn_elf();
    let at = f.len();
    for i in 0..256u32 {
        let mut e = Vec::new();
        e.extend_from_slice(&1u16.to_le_bytes());
        e.extend_from_slice(&4096u16.to_le_bytes()); // vn_cnt
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend_from_slice(&((256 - i) * 16).to_le_bytes()); // vn_aux: the shared chain
        e.extend_from_slice(&if i == 255 { 0u32 } else { 16 }.to_le_bytes());
        f.extend_from_slice(&e);
    }
    for i in 0..4096u32 {
        f.extend_from_slice(&[0; 12]);
        f.extend_from_slice(&if i == 4095 { 0u32 } else { 16 }.to_le_bytes());
    }
    let size = (f.len() - at) as u64;
    put(&mut f, 0x300 + 64 + 4, &0x6fff_fffeu32.to_le_bytes()); // SHT_GNU_verneed
    put(&mut f, 0x300 + 64 + 24, &(at as u64).to_le_bytes());
    put(&mut f, 0x300 + 64 + 32, &size.to_le_bytes());
    assert!(dump(&f).contains("[Needed Versions (200000)]"), "1,048,576 rows without the cap");
    // Aux entries outside the section are not followed.
    put(&mut f, 0x300 + 64 + 32, &4096u64.to_le_bytes());
    assert!(dump(&f).contains("[Needed Versions (0)]"));
}

/// `tiny_dyn_elf` with `headers` more section headers of type SHT_GNU_versym
/// that all name the same `bytes` bytes at the end of the file.
fn aliased_versym_elf(headers: usize, bytes: usize) -> Vec<u8> {
    let mut f = tiny_dyn_elf();
    let at = f.len();
    f.resize(at + bytes, 2);
    let table = f.len();
    f.extend_from_within(0x300..0x400);
    for _ in 0..headers {
        let mut h = [0u8; 64];
        put(&mut h, 4, &0x6fff_ffffu32.to_le_bytes());
        put(&mut h, 24, &(at as u64).to_le_bytes());
        put(&mut h, 32, &(bytes as u64).to_le_bytes());
        put(&mut h, 40, &1u32.to_le_bytes()); // sh_link
        f.extend_from_slice(&h);
    }
    put(&mut f, 40, &(table as u64).to_le_bytes());
    put(&mut f, 60, &(4 + headers as u16).to_le_bytes());
    f
}

#[test]
fn elf_grids_of_aliased_sections_share_one_budget() {
    use bxplore::model::{Node, View};
    fn rows(n: &Node) -> usize {
        let own = match &n.view {
            View::Grid(g) | View::Tool(_, g) => g.rows.len(),
            View::Text(_) => 0,
        };
        own + n.children.iter().map(rows).sum::<usize>()
    }
    // A few headers: every grid is complete and says how many rows it has.
    let small = bxplore::analysis::parse(&aliased_versym_elf(3, 0x400));
    let titles = dump(&aliased_versym_elf(3, 0x400));
    assert_eq!(titles.matches("[Symbol Versions (512)").count(), 3, "three complete grids");
    assert!(rows(&small.root) > 3 * 512);
    // 400 headers over 800 KB: 80 million rows of 2 file bytes each without a budget.
    let f = aliased_versym_elf(400, 800_000);
    assert!(f.len() < 830_000);
    let parsed = bxplore::analysis::parse(&f);
    assert!(matches!(parsed.format, bxplore::model::Format::Elf));
    let total = rows(&parsed.root);
    assert!((200_000..2_000_000).contains(&total), "{total} rows");
    fn titles_of(n: &Node, out: &mut Vec<String>) {
        out.push(n.title.clone());
        n.children.iter().for_each(|c| titles_of(c, out));
    }
    let mut titles = Vec::new();
    titles_of(&parsed.root, &mut titles);
    assert!(titles.iter().any(|t| t.starts_with("Symbol Versions (first 0 shown)")), "a grid that was cut says so");
}

fn dyld_nodes(data: &[u8], dyld_info: Option<[(usize, usize); 5]>, exports_trie: Option<(usize, usize)>) -> Vec<bxplore::model::Node> {
    use bxplore::macho_dyld::{Ctx, Seg, nodes};
    let n = data.len() as u64;
    let ctx = Ctx {
        data,
        base: 0,
        is64: true,
        segs: vec![Seg { name: "__TEXT".into(), vmaddr: 0x1_0000_0000, vmsize: n, fileoff: 0, filesize: n }],
        image_base: 0x1_0000_0000,
        sects: Vec::new(),
        dylibs: Vec::new(),
        dyld_info,
        exports_trie,
        chained: None,
        budget: &bxplore::macho_dyld::Budget::new(),
    };
    nodes(&ctx)
}

fn rows(node: &bxplore::model::Node) -> Vec<Vec<String>> {
    match &node.view {
        bxplore::model::View::Grid(g) => g.rows.iter().map(|r| r.iter().map(|c| c.text.clone()).collect()).collect(),
        _ => Vec::new(),
    }
}

#[test]
fn rebase_and_bind_runs_cost_one_step_per_opcode() {
    // 20,000 times DO_REBASE_ULEB_TIMES 4,000,000: 80 billion rebases in 100 KB.
    let mut stream = vec![0x21, 0x00]; // segment 1 (not in the file), offset 0
    stream.extend([0x60, 0x80, 0x92, 0xF4, 0x01].repeat(20_000));
    let none = (0, 0);
    let n = &dyld_nodes(&stream, Some([(0, stream.len()), none, none, none, none]), None)[0];
    assert_eq!(n.title, "Rebases (80000000000, first 100000 shown)");
    assert_eq!(rows(n)[99_999][..2], ["segment 1", "C34F8"]);

    // 20,000 times DO_BIND_ULEB_TIMES_SKIPPING_ULEB 100,000.
    let mut stream = vec![0x71, 0x00];
    stream.extend([0xC0, 0xA0, 0x8D, 0x06, 0x00].repeat(20_000));
    let n = &dyld_nodes(&stream, Some([none, (0, stream.len()), none, none, none]), None)[0];
    assert_eq!(n.title, "Binds (100000)");
    assert_eq!(rows(n)[99_999][..2], ["segment 1", "C34F8"]);
}

#[test]
fn exports_trie_walk_shares_one_prefix() {
    // root -> "_a" (terminal), "_b" -> "c" (terminal), plus an edge back to the root.
    let mut t = vec![0u8, 3];
    t.extend_from_slice(b"_a\0\x10");
    t.extend_from_slice(b"_b\0\x14");
    t.extend_from_slice(b"loop\0\x00");
    assert_eq!(t.len(), 0x10);
    t.extend_from_slice(&[2, 0, 0x10, 0]); // 0x10: regular symbol at 0x10, no children
    t.extend_from_slice(&[0, 1, b'c', 0, 0x19]); // 0x14: one child
    t.extend_from_slice(&[2, 0, 0x20, 0]); // 0x19
    let n = &dyld_nodes(&t, None, Some((0, t.len())))[0];
    assert_eq!(n.title, "Exports Trie (2)");
    assert_eq!(rows(n).iter().map(|r| r[0].as_str()).collect::<Vec<_>>(), ["_a", "_bc"]);

    // 200 nodes that each have 254 edges back to the root and one to the next node,
    // under a long prefix: every node is visited once and the walk ends.
    let mut t = vec![0u8, 1];
    t.extend(std::iter::repeat_n(b'p', 4000));
    t.extend_from_slice(&[0, 0x80, 0x40]); // child at 0x2000
    t.resize(0x2000, 0);
    for i in 0..200usize {
        let next = t.len() + 771;
        t.extend_from_slice(&[2, 0, 0x10, 255]);
        for _ in 0..254 {
            t.extend_from_slice(&[b'x', 0, 0]);
        }
        t.extend_from_slice(&[if i == 199 { b'x' } else { b'n' }, 0]);
        t.extend_from_slice(&if i == 199 { [0x80, 0x80, 0] } else { [next as u8 | 0x80, (next >> 7) as u8 | 0x80, (next >> 14) as u8] });
    }
    let n = &dyld_nodes(&t, None, Some((0, t.len())))[0];
    assert_eq!(n.title, "Exports Trie (97)", "one symbol per node until the prefix reaches 4096 bytes");
    assert_eq!(rows(n)[96][0].len(), 4096);
}

#[test]
fn a_certificate_table_in_front_of_section_data_fails() {
    // The CMS fixture stands in for an Authenticode blob: it has no image
    // digest, but the placement check does not depend on one.
    let cms = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cms_rsa.der")).unwrap();
    let mut table = ((cms.len() + 8) as u32).to_le_bytes().to_vec();
    table.extend_from_slice(&[0x00, 0x02, 0x02, 0x00]); // revision 2.0, PKCS#7
    table.extend_from_slice(&cms);
    let dir = 0x98 + 96 + 4 * 8;
    let signed = |at: usize, file: &mut Vec<u8>| {
        file.splice(at..at, table.iter().copied());
        put(file, dir, &(at as u32).to_le_bytes());
        put(file, dir + 4, &(table.len() as u32).to_le_bytes());
    };
    let mut good = tiny_pe();
    signed(0x400, &mut good);
    let text = dump(&good);
    assert!(text.contains("Certificate table  OK"), "{text}");
    // Same bytes with the table between the headers and the section: the
    // section header still says 0x200, where the table now is.
    let mut bad = tiny_pe();
    signed(0x200, &mut bad);
    let text = dump(&bad);
    assert!(text.contains("Certificate table  FAILED") && text.contains("not at the end of the file"), "{text}");
    assert!(!text.contains("Result: the signature is cryptographically valid"));
    // The verdict names what failed and stands above the details.
    let verdict = text.find("Result: NOT valid. Failed: Certificate table (Primary signature). Could not be checked: Image digest (Primary signature).");
    assert!(verdict.is_some_and(|at| at < text.find("Certificate table  FAILED").unwrap()), "{text}");
    // A table that claims more bytes than the file has.
    put(&mut good, dir + 4, &(table.len() as u32 + 8).to_le_bytes());
    assert!(dump(&good).contains("Certificate table  FAILED"));
}

/// A thin Mach-O of about 4 KB whose bind, weak bind and lazy bind streams are
/// one blob: a symbol name of 4095 bytes, bound 100,000 times by one opcode.
fn bind_run_macho() -> Vec<u8> {
    let mut f = vec![0u8; 32 + 48];
    put(&mut f, 0, &0xfeed_facfu32.to_le_bytes());
    put(&mut f, 4, &0x0100_000cu32.to_le_bytes()); // CPU_TYPE_ARM64
    put(&mut f, 12, &2u32.to_le_bytes()); // MH_EXECUTE
    put(&mut f, 16, &1u32.to_le_bytes()); // ncmds
    put(&mut f, 20, &48u32.to_le_bytes()); // sizeofcmds
    put(&mut f, 32, &0x8000_0022u32.to_le_bytes()); // LC_DYLD_INFO_ONLY
    put(&mut f, 36, &48u32.to_le_bytes());
    let mut blob = vec![0x40]; // SET_SYMBOL_TRAILING_FLAGS_IMM
    blob.extend(std::iter::repeat_n(b'A', 4095));
    blob.extend_from_slice(&[0, 0xC0, 0xA0, 0x8D, 0x06, 0x00]); // DO_BIND_ULEB_TIMES_SKIPPING_ULEB 100000, 0
    for stream in 1..4 {
        put(&mut f, 40 + stream * 8, &80u32.to_le_bytes());
        put(&mut f, 44 + stream * 8, &(blob.len() as u32).to_le_bytes());
    }
    f.extend(blob);
    f
}

#[test]
fn repeated_bind_rows_stay_within_the_grid_budget() {
    use bxplore::model::{Node, View};
    fn text(n: &Node) -> usize {
        let own = match &n.view {
            View::Grid(g) | View::Tool(_, g) => g.rows.iter().flatten().map(|c| c.text.len()).sum(),
            View::Text(t) => t.len(),
        };
        own + n.children.iter().map(text).sum::<usize>()
    }
    let thin = bind_run_macho();
    assert!(thin.len() < 4200);
    // Without a budget: three grids of 100,000 rows with 4 KB of name each, 1.2 GB.
    let parsed = bxplore::analysis::parse(&thin);
    assert!(text(&parsed.root) <= bxplore::macho_dyld::GRID_BUDGET + 8192, "{} bytes of cell text", text(&parsed.root));
    let titles = dump(&thin);
    assert!(titles.contains("[Binds (first ") && titles.contains("[Lazy Binds (first 0 shown)]"), "a grid that was cut says so");

    // Thirty architectures that all are the same slice share the one budget.
    let mut fat = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 30];
    for _ in 0..30 {
        fat.extend_from_slice(&[1, 0, 0, 12, 0, 0, 0, 0]);
        fat.extend_from_slice(&0x400u32.to_be_bytes());
        fat.extend_from_slice(&(thin.len() as u32).to_be_bytes());
        fat.extend_from_slice(&[0; 4]);
    }
    fat.resize(0x400, 0);
    fat.extend(&thin);
    let parsed = bxplore::analysis::parse(&fat);
    assert!(matches!(parsed.format, bxplore::model::Format::MachO));
    assert!(text(&parsed.root) <= bxplore::macho_dyld::GRID_BUDGET + 8192, "{} bytes of cell text", text(&parsed.root));
}

/// A Mach-O with `nseg` segments, none of them `__TEXT`, and chained fixups
/// whose 64 segment entries all describe the same pages of pointers. Every
/// pointer links to the one 4 bytes on, so a page of 4 KB holds 1025 links.
fn chained_macho(nseg: usize, pages: u16) -> Vec<u8> {
    let mut cmds = Vec::new();
    for i in 0..nseg {
        cmds.extend_from_slice(&0x19u32.to_le_bytes());
        cmds.extend_from_slice(&72u32.to_le_bytes());
        let mut name = [0u8; 16];
        name[..6].copy_from_slice(if i == 300 { b"__LATE" } else { b"__TEXU" });
        cmds.extend_from_slice(&name);
        // vmaddr, vmsize, then fileoff and filesize. Every segment maps the
        // pointers; segment 300 is the one that starts at them.
        let at = if i == 300 { 0x2_0000u64 } else { 0x1_0000 };
        for v in [at, 0x10_0000, at, 0x10_0000] {
            cmds.extend_from_slice(&v.to_le_bytes());
        }
        cmds.extend_from_slice(&[7, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
    let (blob_off, area_off) = (0x1_0000u32, 0x2_0000u64);
    let mut blob = Vec::new();
    for v in [0u32, 28, 0, 0, 0, 1, 0] {
        blob.extend_from_slice(&v.to_le_bytes());
    }
    blob.extend_from_slice(&64u32.to_le_bytes());
    blob.extend_from_slice(&(4 + 64 * 4u32).to_le_bytes().repeat(64));
    blob.extend_from_slice(&(22 + pages as u32 * 2).to_le_bytes());
    blob.extend_from_slice(&0x1000u16.to_le_bytes()); // page_size
    blob.extend_from_slice(&2u16.to_le_bytes()); // DYLD_CHAINED_PTR_64
    blob.extend_from_slice(&area_off.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&pages.to_le_bytes());
    blob.extend_from_slice(&[0, 0].repeat(pages as usize));
    cmds.extend_from_slice(&0x8000_0034u32.to_le_bytes());
    cmds.extend_from_slice(&16u32.to_le_bytes());
    cmds.extend_from_slice(&blob_off.to_le_bytes());
    cmds.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    let mut f = Vec::new();
    for v in [0xFEED_FACFu32, 0x0100_000C, 0, 2, nseg as u32 + 1, cmds.len() as u32, 0, 0] {
        f.extend_from_slice(&v.to_le_bytes());
    }
    f.extend(cmds);
    assert!(f.len() <= blob_off as usize);
    f.resize(blob_off as usize, 0);
    f.extend(blob);
    f.resize(area_off as usize, 0);
    f.extend(0x0008_0000u32.to_le_bytes().repeat(pages as usize * 0x400 + 4));
    f
}

#[test]
fn chained_fixup_links_do_not_scan_the_segments() {
    use bxplore::macho_dyld::{Budget, Ctx, MAX_LINKS, MAX_SEGS, Seg, nodes};
    // 64 segment entries of 2 pages with 1025 links each. The load commands
    // name 400 segments: every link used to search them for __TEXT.
    let f = chained_macho(400, 2);
    let titles = dump(&f);
    assert!(titles.contains("[Fixups (131200, first 100000 shown)]"), "64 * 2 * 1025 links");
    assert!(titles.contains("399: LC_SEGMENT_64 (__TEXU)"), "the load command view shows every segment");
    // Only the first 256 segments are kept for lookups, so the fixups are not
    // attributed to segment 300, which starts at their address.
    let grid = &titles[titles.find("[Fixups").unwrap()..];
    assert!(MAX_SEGS == 256 && grid.contains("__TEXU   20000") && !grid.contains("__LATE"), "{}", &grid[..300]);

    // The links are counted per file: slices that name the same bytes share them.
    let budget = Budget::new();
    let ctx = |budget| Ctx {
        data: &f,
        base: 0,
        is64: true,
        segs: vec![Seg { name: "__TEXT".into(), vmaddr: 0x1_0000_0000, vmsize: 0x10_0000, fileoff: 0, filesize: 0x10_0000 }],
        image_base: 0x1_0000_0000,
        sects: Vec::new(),
        dylibs: Vec::new(),
        dyld_info: None,
        exports_trie: None,
        chained: Some((0x1_0000, 0x200)),
        budget,
    };
    let fixups = |budget| nodes(&ctx(budget))[0].children[1].title.clone();
    assert_eq!(fixups(&budget), "Fixups (131200, first 100000 shown)");
    assert_eq!(budget.links.get(), MAX_LINKS - 131_200);
    budget.links.set(1000);
    assert_eq!(fixups(&budget), "Fixups (more than 1000, first 1000 shown)");
    assert_eq!(fixups(&budget), "Fixups (more than 0, first 0 shown)");
    assert_eq!(budget.links.get(), 0);
}

#[test]
fn chained_fixups_are_found_by_address_after_zero_fill() {
    use bxplore::macho_dyld::{Budget, Ctx, Seg, nodes};
    use bxplore::model::View;
    // __DATA takes 0x3000 of memory and 0x1000 of the file, so __AUTH is at
    // memory offset 0x4000 from the image base and at file offset 0x2000.
    let base = 0x1_0000_0000u64;
    let seg = |name: &str, vm: u64, vmsize: u64, fileoff: u64| Seg { name: name.into(), vmaddr: base + vm, vmsize, fileoff, filesize: 0x1000 };
    let mut f = vec![0u8; 0x4010];
    let mut blob = Vec::new();
    for v in [0u32, 28, 0, 0, 0, 1, 0, 1, 8] {
        blob.extend_from_slice(&v.to_le_bytes());
    }
    blob.extend_from_slice(&24u32.to_le_bytes());
    blob.extend_from_slice(&0x1000u16.to_le_bytes()); // page_size
    blob.extend_from_slice(&2u16.to_le_bytes()); // DYLD_CHAINED_PTR_64
    blob.extend_from_slice(&0x4000u64.to_le_bytes()); // segment_offset, in memory
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&[1, 0, 8, 0]); // one page, first link at 8
    put(&mut f, 0x3000, &blob);
    put(&mut f, 0x2008, &0x1234u64.to_le_bytes()); // rebase to 0x1234, end of chain
    put(&mut f, 0x4008, &(1u64 << 63 | 7).to_le_bytes()); // what a file offset of 0x4008 would find
    let budget = Budget::new();
    let ctx = Ctx {
        data: &f,
        base: 0,
        is64: true,
        segs: vec![seg("__TEXT", 0, 0x1000, 0), seg("__DATA", 0x1000, 0x3000, 0x1000), seg("__AUTH", 0x4000, 0x1000, 0x2000)],
        image_base: base,
        sects: Vec::new(),
        dylibs: Vec::new(),
        dyld_info: None,
        exports_trie: None,
        chained: Some((0x3000, blob.len())),
        budget: &budget,
    };
    let fixups = nodes(&ctx).remove(0).children.remove(1);
    let View::Grid(g) = &fixups.view else { panic!("the fixups are a grid") };
    let row: Vec<&str> = g.rows[0].iter().map(|c| c.text.as_str()).collect();
    assert_eq!((fixups.title.as_str(), row), ("Fixups (1)", vec!["__AUTH", "100004008", "rebase", "1234"]));
    assert_eq!(g.spans[0], Some((0x2008, 8)));
}

/// A relocation block whose size field claims 547 million entries in a 4 KB
/// file: the view lists the entries the directory really holds, not 200 000
/// rows of zeros read past the end (which cost 135 MB of memory).
#[test]
fn a_relocation_block_is_read_only_inside_the_file() {
    let input = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/regressions/parse_any/relocation_block_past_the_file.bin")).unwrap();
    let parsed = bxplore::analysis::parse(&input);
    let relocs = parsed.root.children.iter().find(|n| n.title.starts_with("Relocation Directory")).expect("the file has a relocation directory");
    assert_eq!(relocs.title, "Relocation Directory (1 blocks, 18 entries)");
    let bxplore::model::View::Grid(g) = &relocs.view else { panic!("the relocations are a grid") };
    assert_eq!(g.rows.len(), 18);
    assert!(relocs.children.iter().any(|c| matches!(&c.view, bxplore::model::View::Text(t) if t.contains("claims 547397788 entries"))));
}
