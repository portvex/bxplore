//! PE editors on a file made by a real linker: `tests/fixtures/pe/fixture.c`
//! is compiled with clang for the Windows target and linked with lld-link,
//! giving an image with imports, delay imports, exports, a TLS callback and
//! base relocations. Skipped when clang or lld-link are missing.
//! The results are inspected, not executed: there is no Windows here.

use bxplore::pe::Pe;
use bxplore::pe::edit::{self, NewImport};
use std::path::PathBuf;
use std::process::Command;

fn have(tool: &str) -> bool {
    Command::new("which").arg(tool).output().is_ok_and(|o| o.status.success())
}

fn run(dir: &PathBuf, cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd).current_dir(dir).args(args).output().is_ok_and(|o| o.status.success())
}

/// Build the fixture once per test binary run.
fn fixture() -> Option<Vec<u8>> {
    static BUILT: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            if !have("clang") || !have("lld-link") {
                return None;
            }
            let dir = std::env::temp_dir().join(format!("bxplore-pe-fixture-{}", std::process::id()));
            std::fs::create_dir_all(&dir).ok()?;
            let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pe/fixture.c");
            std::fs::write(dir.join("kernel32.def"), "LIBRARY KERNEL32.dll\nEXPORTS\nSleep\nGetTickCount\n").ok()?;
            std::fs::write(dir.join("user32.def"), "LIBRARY USER32.dll\nEXPORTS\nMessageBeep\nGetSystemMetrics\n").ok()?;
            let ok =
                run(&dir, "clang", &["--target=x86_64-pc-windows-msvc", "-ffreestanding", "-fno-stack-protector", "-O1", "-c", src.to_str()?, "-o", "t.obj"])
                    && run(&dir, "lld-link", &["/lib", "/def:kernel32.def", "/machine:x64", "/out:kernel32.lib"])
                    && run(&dir, "lld-link", &["/lib", "/def:user32.def", "/machine:x64", "/out:user32.lib"])
                    && run(
                        &dir,
                        "lld-link",
                        &[
                            "/nologo",
                            "/entry:entry",
                            "/subsystem:console",
                            "/nodefaultlib",
                            "/machine:x64",
                            "/dynamicbase",
                            "/delayload:USER32.dll",
                            "/out:fixture.exe",
                            "t.obj",
                            "kernel32.lib",
                            "user32.lib",
                        ],
                    );
            // A toolchain without the Windows target simply skips these tests.
            let data = ok.then(|| std::fs::read(dir.join("fixture.exe")).ok()).flatten();
            let _ = std::fs::remove_dir_all(&dir);
            data
        })
        .clone()
}

fn imports(data: &[u8]) -> Vec<(String, Vec<String>)> {
    let pe = Pe::parse(data).unwrap();
    pe.imports(data).into_iter().map(|m| (m.name, m.funcs.into_iter().filter_map(|f| f.name).collect())).collect()
}

fn dump(data: &[u8]) -> String {
    let mut out = String::new();
    bxplore::analysis::dump(&bxplore::analysis::parse(data).root, 0, &mut out);
    out
}

#[test]
fn the_fixture_has_what_the_tests_need() {
    let Some(data) = fixture() else { return };
    let pe = Pe::parse(&data).unwrap();
    assert_eq!(imports(&data), [("KERNEL32.dll".to_string(), vec!["GetTickCount".to_string(), "Sleep".to_string()])]);
    let delay = edit::delay_imports(&data, &pe);
    assert_eq!(delay.len(), 1);
    assert_eq!((delay[0].name.as_str(), delay[0].thunks.len()), ("USER32.dll", 2));
    assert_eq!(edit::tls_callbacks(&data, &pe).unwrap().1.len(), 1);
    assert!(!edit::parse_relocs(&data, &pe).is_empty());
    let exports = edit::parse_exports(&data, &pe).unwrap();
    let names: Vec<&str> = exports.funcs.iter().flat_map(|f| f.names.iter().map(String::as_str)).collect();
    assert_eq!(names, ["fixture_add", "fixture_answer"]);
}

#[test]
fn delay_imports_become_ordinary_imports() {
    let Some(orig) = fixture() else { return };
    let pe = Pe::parse(&orig).unwrap();
    let delay = edit::delay_imports(&orig, &pe);
    let mut data = orig.clone();
    edit::convert_delay_imports(&mut data).unwrap();
    let pe2 = Pe::parse(&data).unwrap();
    let after = pe2.imports(&data);
    assert_eq!(
        imports(&data),
        [
            ("KERNEL32.dll".to_string(), vec!["GetTickCount".to_string(), "Sleep".to_string()]),
            ("USER32.dll".to_string(), vec!["GetSystemMetrics".to_string(), "MessageBeep".to_string()])
        ]
    );
    // The new descriptor fills the very slots the delay-load stubs read.
    assert_eq!(after[1].funcs[0].iat_rva, delay[0].iat_rva);
    assert_eq!(after[1].funcs[1].iat_rva, delay[0].iat_rva + 8);
    assert!(edit::delay_imports(&data, &pe2).is_empty(), "the delay directory is cleared");
    assert!(edit::convert_delay_imports(&mut data).is_err(), "nothing left to convert");
    // Everything else the image had is still there.
    assert_eq!(edit::tls_callbacks(&data, &pe2).unwrap().1, edit::tls_callbacks(&orig, &pe).unwrap().1);
    assert_eq!(edit::parse_relocs(&data, &pe2), edit::parse_relocs(&orig, &pe));
    assert_eq!(edit::parse_exports(&data, &pe2), edit::parse_exports(&orig, &pe));
}

#[test]
fn tls_callbacks_add_and_remove() {
    let Some(orig) = fixture() else { return };
    let pe = Pe::parse(&orig).unwrap();
    let (_, before) = edit::tls_callbacks(&orig, &pe).unwrap();
    let relocs_before = edit::parse_relocs(&orig, &pe);
    let extra = pe.image_base + pe.entry as u64;

    let mut data = orig.clone();
    edit::add_tls_callback(&mut data, extra).unwrap();
    let pe2 = Pe::parse(&data).unwrap();
    let (array, after) = edit::tls_callbacks(&data, &pe2).unwrap();
    assert_eq!(after, [before[0], extra]);
    let slot_rva = |pe: &Pe, off: usize| {
        let s = pe.sections.iter().find(|s| off >= s.roff as usize && off < (s.roff + s.rsize) as usize).unwrap();
        s.va + (off - s.roff as usize) as u32
    };
    let relocs = edit::parse_relocs(&data, &pe2);
    let base = slot_rva(&pe2, array);
    assert!(relocs.contains(&(base, 10)) && relocs.contains(&(base + 8, 10)), "both callbacks are relocated as 64 bit addresses");
    assert!(!relocs.iter().any(|r| r.0 == base + 16), "the terminator is not relocated");
    for r in &relocs_before {
        assert!(relocs.contains(r), "an original relocation was lost");
    }
    assert!(dump(&data).contains("[TLS Callbacks (2)]"), "the viewer sees both callbacks");

    // Removing the first one moves the second up and drops the last slot's relocation.
    edit::remove_tls_callback(&mut data, 0).unwrap();
    let pe3 = Pe::parse(&data).unwrap();
    let (array, list) = edit::tls_callbacks(&data, &pe3).unwrap();
    assert_eq!(list, [extra]);
    let base = slot_rva(&pe3, array);
    let relocs = edit::parse_relocs(&data, &pe3);
    assert!(relocs.contains(&(base, 10)) && !relocs.iter().any(|r| r.0 == base + 8));

    // Removing the linker's own callback in the original array works in place.
    let mut data = orig.clone();
    edit::remove_tls_callback(&mut data, 0).unwrap();
    assert_eq!(data.len(), orig.len());
    let pe4 = Pe::parse(&data).unwrap();
    let (array, list) = edit::tls_callbacks(&data, &pe4).unwrap();
    assert!(list.is_empty());
    assert!(!edit::parse_relocs(&data, &pe4).iter().any(|r| r.0 == slot_rva(&pe4, array)), "an emptied slot must not be rebased into a bogus callback");
}

#[test]
fn relocations_edit_in_place_and_grow() {
    let Some(orig) = fixture() else { return };
    let pe = Pe::parse(&orig).unwrap();
    let list = edit::parse_relocs(&orig, &pe);
    let mut data = orig.clone();
    edit::write_relocs(&mut data, &list).unwrap();
    assert_eq!(data, orig, "writing back the same table reproduces the linker's bytes");

    edit::remove_reloc(&mut data, list[0].0).unwrap();
    assert_eq!(data.len(), orig.len(), "a smaller table stays in place");
    let text = &pe.sections[0];
    let mut want: Vec<(u32, u8)> = list[1..].to_vec();
    let mut grow = |data: &mut Vec<u8>, range: std::ops::Range<u32>| {
        for i in range {
            let rva = text.va + 0x100 + i * 8;
            if !want.iter().any(|r| r.0 == rva) {
                want.push((rva, 10));
            }
        }
        edit::write_relocs(data, &want).unwrap();
        let pe2 = Pe::parse(data).unwrap();
        let mut got = edit::parse_relocs(data, &pe2);
        got.sort();
        want.sort();
        assert_eq!(got, want);
        pe2
    };
    // A longer table takes the unused tail of its section.
    let pe2 = grow(&mut data, 0..20);
    assert_eq!((data.len(), pe2.sections.len()), (orig.len(), pe.sections.len()), "the padding of .reloc holds 20 more entries");
    let (rva, size) = pe2.dir(&data, 5);
    let reloc = pe2.sections.iter().find(|s| s.name == ".reloc").unwrap();
    assert_eq!((rva, size), (reloc.va, reloc.vsize), "the section grew with its table");
    // Many new entries no longer fit and move the table to a new section.
    let pe2 = grow(&mut data, 20..400);
    assert!(pe2.sections.iter().any(|s| s.name == ".reloc2"));
}

#[test]
fn relocations_added_one_by_one_share_a_section() {
    let Some(orig) = fixture() else { return };
    let pe = Pe::parse(&orig).unwrap();
    let mut data = orig.clone();
    // One address per click, as the Relocations view does it: enough of them
    // to outgrow the padding of the linker's table.
    let old = edit::parse_relocs(&orig, &pe);
    let free: Vec<u32> =
        pe.sections[..3].iter().flat_map(|s| (0..s.vsize).step_by(2).map(move |o| s.va + o)).filter(|rva| !old.iter().any(|r| r.0 == *rva)).collect();
    let n = pe.file_align as usize / 2 + 4;
    assert!(free.len() >= n, "the fixture has {} free addresses", free.len());
    for rva in &free[..n] {
        edit::add_reloc(&mut data, *rva, 10).unwrap();
    }
    let pe2 = Pe::parse(&data).unwrap();
    assert_eq!(edit::parse_relocs(&data, &pe2).len(), old.len() + n);
    assert_eq!(pe2.sections.len(), pe.sections.len() + 1, "the table moves once and then grows where it is");
}

#[test]
fn an_oversized_relocation_directory_is_not_rewritten_in_place() {
    let Some(orig) = fixture() else { return };
    let pe = Pe::parse(&orig).unwrap();
    let list = edit::parse_relocs(&orig, &pe);
    let (rva, size) = pe.dir(&orig, 5);
    let table = pe.rva_to_off(rva).unwrap();
    // The directory claims 64 bytes more than its blocks; what lies there is not relocation data.
    let mut data = orig.clone();
    let marker = table + size as usize + 16;
    data[marker..marker + 8].copy_from_slice(b"NOTRELOC");
    data[pe.dirs_off + 5 * 8 + 4..pe.dirs_off + 5 * 8 + 8].copy_from_slice(&(size + 64).to_le_bytes());
    assert_eq!(edit::parse_relocs(&data, &Pe::parse(&data).unwrap()), list, "blocks end where the first empty one starts");
    edit::remove_reloc(&mut data, list[0].0).unwrap();
    assert_eq!(&data[marker..marker + 8], b"NOTRELOC", "bytes after the table were overwritten");
    let pe2 = Pe::parse(&data).unwrap();
    assert!(pe2.sections.iter().any(|s| s.name == ".reloc2"), "the table is rebuilt elsewhere instead");
    assert_eq!(edit::parse_relocs(&data, &pe2), list[1..]);

    // A block size that claims gigabytes is cut at the end of the directory.
    let mut data = orig.clone();
    data[table + 4..table + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    let got = edit::parse_relocs(&data, &Pe::parse(&data).unwrap());
    assert!(got.len() <= size as usize / 2, "{} entries from a {size} byte directory", got.len());
}

#[test]
fn a_failed_tls_edit_leaves_the_file_alone() {
    let Some(orig) = fixture() else { return };
    let pe = Pe::parse(&orig).unwrap();
    // One free section header slot: the callback array gets it, and the
    // relocation table, which no longer fits in place, has nowhere to go.
    let mut data = orig.clone();
    let second = pe.sec_table + (pe.sections.len() + 1) * 40;
    data[second..second + 4].copy_from_slice(b"used");
    // Nor can it grow where it is: the bytes behind it are taken.
    let (rva, size) = pe.dir(&data, 5);
    data[pe.rva_to_off(rva).unwrap() + size as usize + 2] = 0xCC;
    let before = data.clone();
    let err = edit::add_tls_callback(&mut data, pe.image_base + pe.entry as u64).unwrap_err();
    assert!(err.contains("header slack"), "{err}");
    assert!(data == before, "the edit failed half way and was not undone");
}

#[test]
fn imports_exports_and_sections_survive_each_other() {
    let Some(orig) = fixture() else { return };
    let mut data = orig.clone();
    edit::add_imports(&mut data, &[("ADVAPI32.dll".into(), vec![NewImport::Name("RegCloseKey".into()), NewImport::Ordinal(7)])]).unwrap();
    edit::rename_import(&mut data, 0, Some(0), "SleepEx").unwrap();
    let pe = Pe::parse(&data).unwrap();
    let mut table = edit::parse_exports(&data, &pe).unwrap();
    table.funcs[1].names = vec!["renamed_answer".into()];
    table.funcs.push(edit::ExportFn { rva: 0, forwarder: Some("KERNEL32.Sleep".into()), names: vec!["forwarded_sleep".into()] });
    edit::write_exports(&mut data, &table).unwrap();
    edit::add_section(&mut data, ".extra", b"some bytes", 0x1000, 0x4000_0040).unwrap();
    edit::convert_delay_imports(&mut data).unwrap();
    edit::add_tls_callback(&mut data, pe.image_base + pe.entry as u64).unwrap();
    edit::fix_checksum(&mut data).unwrap();

    let pe = Pe::parse(&data).unwrap();
    let names: Vec<String> = imports(&data).into_iter().map(|m| m.0).collect();
    assert_eq!(names, ["KERNEL32.dll", "ADVAPI32.dll", "USER32.dll"]);
    assert_eq!(imports(&data)[0].1, ["SleepEx", "Sleep"], "the linker lists imports alphabetically; the first one was renamed");
    let exports = edit::parse_exports(&data, &pe).unwrap();
    assert_eq!(exports.funcs.len(), 3);
    assert_eq!(exports.funcs[1].names, ["renamed_answer"]);
    assert_eq!(exports.funcs[2].forwarder.as_deref(), Some("KERNEL32.Sleep"));
    assert_eq!(edit::tls_callbacks(&data, &pe).unwrap().1.len(), 2);
    let text = dump(&data);
    assert!(text.contains("(valid)"), "the checksum was recomputed");
    // Section table sanity: ascending, non-overlapping virtual ranges.
    for w in pe.sections.windows(2) {
        assert!(w[0].va + w[0].vsize.max(w[0].rsize) <= w[1].va, "{} overlaps {}", w[0].name, w[1].name);
    }
}
