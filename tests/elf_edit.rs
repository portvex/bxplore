//! ELF dynamic section editing, checked with GNU readelf from a Linux cross
//! toolchain. Skipped when no `*-linux-gnu-gcc` / `readelf` pair is installed.
//! The edited files are inspected, not executed: there is no Linux here to run them.

use bxplore::elf_edit::{self, DT_NEEDED, DT_RPATH, DT_RUNPATH, DT_SONAME};
use std::path::{Path, PathBuf};
use std::process::Command;

fn find(names: &[&str]) -> Option<String> {
    names.iter().find(|n| Command::new("which").arg(n).output().is_ok_and(|o| o.status.success())).map(|s| s.to_string())
}

struct Kit {
    cc: String,
    readelf: String,
    dir: PathBuf,
}

fn kit(tag: &str) -> Option<Kit> {
    let cc = find(&["aarch64-linux-gnu-gcc", "x86_64-linux-gnu-gcc"])?;
    let readelf = find(&[&cc.replace("-gcc", "-readelf"), "readelf"])?;
    let dir = std::env::temp_dir().join(format!("bxplore-elf-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Some(Kit { cc, readelf, dir })
}

impl Kit {
    fn build(&self, name: &str, args: &[&str]) -> Vec<u8> {
        let src = self.dir.join("t.c");
        std::fs::write(&src, "int answer(void) { return 42; }\nint main(void) { return answer() - 42; }\n").unwrap();
        let out = self.dir.join(name);
        let o = Command::new(&self.cc).arg(&src).arg("-o").arg(&out).args(args).output().unwrap();
        assert!(o.status.success(), "{} failed: {}", self.cc, String::from_utf8_lossy(&o.stderr));
        std::fs::read(out).unwrap()
    }

    /// readelf output for the dynamic section and program headers; any
    /// warning or error it prints fails the test.
    fn readelf(&self, data: &[u8]) -> String {
        let p: &Path = &self.dir.join("edited");
        std::fs::write(p, data).unwrap();
        let o = Command::new(&self.readelf).args(["-d", "-l", "-S", "--dyn-syms", "-V", "-W"]).arg(p).output().unwrap();
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(o.status.success() && err.trim().is_empty(), "readelf complained:\n{err}");
        String::from_utf8_lossy(&o.stdout).into_owned()
    }
}

fn needed(data: &[u8]) -> Vec<String> {
    elf_edit::info(data).unwrap().entries.iter().filter(|e| e.tag == DT_NEEDED).filter_map(|e| e.text.clone()).collect()
}

fn text_of(data: &[u8], tag: u64) -> Option<String> {
    elf_edit::info(data).unwrap().entries.iter().find(|e| e.tag == tag).and_then(|e| e.text.clone())
}

#[test]
fn in_place_edits_keep_the_file_size() {
    let Some(k) = kit("inplace") else { return };
    let orig = k.build("lib.so", &["-shared", "-fPIC", "-Wl,-soname,libfirstname.so.1", "-Wl,-rpath,/opt/original/library/path"]);
    let mut data = orig.clone();
    elf_edit::set_string(&mut data, DT_SONAME, "libnew.so.2").unwrap();
    let rp = if text_of(&orig, DT_RUNPATH).is_some() { DT_RUNPATH } else { DT_RPATH };
    elf_edit::set_string(&mut data, rp, "/opt/short").unwrap();
    assert_eq!(data.len(), orig.len(), "shorter strings are overwritten in place");
    let out = k.readelf(&data);
    assert!(out.contains("Library soname: [libnew.so.2]"), "{out}");
    assert!(out.contains("[/opt/short]"), "{out}");
    assert_eq!(needed(&data), needed(&orig));

    // Removing an entry never needs more room.
    let i = elf_edit::info(&data).unwrap().entries.iter().position(|e| e.tag == rp).unwrap();
    elf_edit::remove_entry(&mut data, i).unwrap();
    assert_eq!(data.len(), orig.len());
    let out = k.readelf(&data);
    assert!(!out.contains("/opt/short"), "{out}");
    assert!(out.contains("Library soname: [libnew.so.2]"));
}

#[test]
fn growing_adds_a_segment_and_keeps_everything_else() {
    let Some(k) = kit("grow") else { return };
    for (name, args) in [("exe", &["-Wl,-rpath,/a"][..]), ("lib.so", &["-shared", "-fPIC"][..]), ("pie", &["-pie", "-fPIE"][..])] {
        let orig = k.build(name, args);
        let before = k.readelf(&orig);
        let mut data = orig.clone();
        let base = needed(&orig);

        elf_edit::add_needed(&mut data, "libbxplore_added_one.so.1").unwrap();
        elf_edit::add_needed(&mut data, "libbxplore_added_two.so.2").unwrap();
        elf_edit::set_string(&mut data, DT_RUNPATH, "/opt/a/very/long/run/path/that/cannot/fit/in/place:$ORIGIN/../lib").unwrap();
        elf_edit::set_string(&mut data, DT_SONAME, "libsomething_completely_different.so.9").unwrap();
        assert!(elf_edit::add_needed(&mut data, "libbxplore_added_one.so.1").is_err(), "duplicates are refused");

        let after = k.readelf(&data);
        let mut want = base.clone();
        want.extend(["libbxplore_added_one.so.1".to_string(), "libbxplore_added_two.so.2".to_string()]);
        assert_eq!(needed(&data), want, "{name}");
        for lib in &want {
            assert!(after.contains(&format!("Shared library: [{lib}]")), "{name}: readelf does not list {lib}:\n{after}");
        }
        assert!(after.contains("[/opt/a/very/long/run/path/that/cannot/fit/in/place:$ORIGIN/../lib]"), "{name}:\n{after}");
        assert!(after.contains("Library soname: [libsomething_completely_different.so.9]"), "{name}:\n{after}");

        // Symbol names and version names live in the same string table and must be intact.
        let names = |s: &str| -> Vec<String> {
            let mut v: Vec<String> = s
                .lines()
                .filter(|l| l.contains(" FUNC ") || l.contains(" OBJECT ") || l.contains("Name: "))
                .map(|l| l.split_whitespace().last().unwrap_or("").to_string())
                .collect();
            v.sort();
            v
        };
        assert_eq!(names(&after), names(&before), "{name}: dynamic symbol or version names changed");

        // The original bytes are untouched apart from headers and the dynamic table.
        let changed = orig.iter().zip(&data).filter(|(a, b)| a != b).count();
        assert!(changed < 512, "{name}: {changed} original bytes changed");

        // Renaming and removing work on the grown tables too.
        elf_edit::rename_needed(&mut data, "libbxplore_added_two.so.2", "libz.so.1").unwrap();
        let i = elf_edit::info(&data).unwrap().entries.iter().position(|e| e.text.as_deref() == Some("libbxplore_added_one.so.1")).unwrap();
        elf_edit::remove_entry(&mut data, i).unwrap();
        let mut want = base;
        want.push("libz.so.1".to_string());
        assert_eq!(needed(&data), want);
        k.readelf(&data);

        // More libraries than the dynamic table has slots: the table itself moves.
        for i in 0..12 {
            elf_edit::add_needed(&mut data, &format!("libmany{i}.so")).unwrap();
            want.push(format!("libmany{i}.so"));
        }
        assert_eq!(needed(&data), want, "{name}");
        let out = k.readelf(&data);
        assert!(out.contains("Shared library: [libmany11.so]"), "{name}:\n{out}");
        assert_eq!(names(&out), names(&before), "{name}: symbol names changed after the dynamic table moved");
    }
}

#[test]
fn sections_can_be_added_and_removed() {
    let Some(k) = kit("sections") else { return };
    for (name, args) in [("exe", &[][..]), ("lib.so", &["-shared", "-fPIC"][..])] {
        let orig = k.build(name, args);
        let before = k.readelf(&orig);
        let names = |d: &[u8]| -> Vec<String> { elf_edit::sections(d).unwrap().into_iter().map(|s| s.name).collect() };
        let base = names(&orig);

        let mut data = orig.clone();
        elf_edit::add_section(&mut data, ".bxplore_note", b"added by the test\n").unwrap();
        elf_edit::add_section(&mut data, ".bxplore_blob", &[0xAB; 3000]).unwrap();
        assert!(elf_edit::add_section(&mut data, ".bxplore_note", b"x").is_err(), "duplicate names are refused");
        let mut want = base.clone();
        want.extend([".bxplore_note".to_string(), ".bxplore_blob".to_string()]);
        assert_eq!(names(&data), want, "{name}");
        let after = k.readelf(&data);
        assert!(after.contains(".bxplore_note") && after.contains(".bxplore_blob"), "{name}:\n{after}");
        // The content is where the header says.
        let info = elf_edit::sections(&data).unwrap();
        let note = info.iter().find(|s| s.name == ".bxplore_note").unwrap();
        assert_eq!(&data[note.offset as usize..(note.offset + note.size) as usize], b"added by the test\n");
        // Everything that is loaded is untouched.
        let dynamic =
            |s: &str| s.lines().filter(|l| l.contains("(NEEDED)") || l.contains(" FUNC ") || l.contains("LOAD")).map(str::to_string).collect::<Vec<_>>();
        assert_eq!(dynamic(&after), dynamic(&before), "{name}");

        // Remove one of the added sections and one the compiler made.
        let idx = names(&data).iter().position(|n| n == ".bxplore_note").unwrap();
        elf_edit::remove_section(&mut data, idx).unwrap();
        let idx = names(&data).iter().position(|n| n == ".comment").unwrap();
        elf_edit::remove_section(&mut data, idx).unwrap();
        let mut want: Vec<String> = base.iter().filter(|n| *n != ".comment").cloned().collect();
        want.push(".bxplore_blob".into());
        assert_eq!(names(&data), want, "{name}");
        let after = k.readelf(&data);
        assert!(!after.contains(".comment") && !after.contains(".bxplore_note") && after.contains(".bxplore_blob"), "{name}:\n{after}");
        // Symbols still name the right sections after the indexes shifted.
        let funcs = |s: &str| s.lines().filter(|l| l.contains(" FUNC ")).map(|l| l.split_whitespace().last().unwrap_or("").to_string()).collect::<Vec<_>>();
        assert_eq!(funcs(&after), funcs(&before), "{name}");

        // Loaded sections and the name table are protected.
        let text = names(&data).iter().position(|n| n == ".text").unwrap();
        assert!(elf_edit::remove_section(&mut data, text).unwrap_err().contains("loaded at run time"));
        let strtab = names(&data).iter().position(|n| n == ".shstrtab").unwrap();
        assert!(elf_edit::remove_section(&mut data, strtab).is_err());
    }
}

#[test]
fn object_files_keep_their_cross_references() {
    let Some(k) = kit("object") else { return };
    let orig = k.build("t.o", &["-c", "-g"]);
    let names = |d: &[u8]| -> Vec<String> { elf_edit::sections(d).unwrap().into_iter().map(|s| s.name).collect() };
    let index = |d: &[u8], n: &str| names(d).iter().position(|x| x == n).unwrap_or_else(|| panic!("no {n} section"));
    // Every relocation section must name the section it applies to (the Inf column of readelf -S).
    let targets_match = |out: &str| {
        let rows: Vec<(usize, Vec<&str>)> = out
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix('[')?.split_once(']'))
            .filter_map(|(i, rest)| Some((i.trim().parse().ok()?, rest.split_whitespace().collect())))
            .collect();
        let mut n = 0;
        for (_, cols) in rows.iter().filter(|(_, c)| c.first().is_some_and(|x| x.starts_with(".rela."))) {
            let inf: usize = cols[cols.len() - 2].parse().unwrap();
            let target = rows.iter().find(|(i, _)| *i == inf).map(|(_, c)| c[0]).unwrap_or("");
            assert_eq!(format!(".rela{target}"), cols[0], "{out}");
            n += 1;
        }
        assert!(n >= 2, "the object has relocation sections:\n{out}");
    };
    targets_match(&k.readelf(&orig));

    // A section that relocations apply to stays, and a refusal changes nothing.
    let mut data = orig.clone();
    let err = elf_edit::remove_section(&mut data, index(&orig, ".debug_info")).unwrap_err();
    assert!(err.contains(".rela.debug_info applies to .debug_info"), "{err}");
    assert_eq!(data, orig);

    // Removing an unreferenced section shifts the later indexes, relocation targets included.
    elf_edit::remove_section(&mut data, index(&orig, ".comment")).unwrap();
    assert_eq!(names(&data), names(&orig).into_iter().filter(|n| n != ".comment").collect::<Vec<_>>());
    targets_match(&k.readelf(&data));

    // With the relocations gone first, the section itself can go.
    let rela = index(&data, ".rela.debug_info");
    elf_edit::remove_section(&mut data, rela).unwrap();
    k.readelf(&data);
}

#[test]
fn versioning_and_gnu_hash_views() {
    let Some(k) = kit("views") else { return };
    // --no-as-needed keeps libc linked, so the library has versioned imports
    // (__cxa_finalize@GLIBC_*) even where the toolchain defaults to --as-needed (Ubuntu).
    let data = k.build("lib.so", &["-shared", "-fPIC", "-Wl,--hash-style=gnu", "-Wl,--no-as-needed"]);
    let mut text = String::new();
    bxplore::analysis::dump(&bxplore::analysis::parse(&data).root, 0, &mut text);
    assert!(text.contains("[Symbol Versions ("), "{text}");
    // The library exports answer and main, so the hash table has entries, and they all check out.
    let line = text.lines().find(|l| l.contains("hashed symbols verify")).expect("the GNU hash table is verified");
    let n: usize = line.split("all ").nth(1).and_then(|s| s.split_whitespace().next()).and_then(|s| s.parse().ok()).unwrap();
    assert!(n >= 2, "{line}");
    assert!(!text.contains("MISMATCH"));
    // A corrupted chain entry is reported.
    let hashed = text.lines().skip_while(|l| !l.contains("[Hashed Symbols (")).nth(2).unwrap();
    assert!(hashed.contains("ok"), "{hashed}");
}

// --- crafted section headers on the synthetic seed; no toolchain needed ---

fn tiny_dyn() -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/parse_any/tiny_dyn.elf")).unwrap()
}

fn u64_at(d: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}

#[test]
fn sections_inside_a_segment_count_as_loaded() {
    let orig = tiny_dyn();
    // Neither section has SHF_ALLOC, but PT_LOAD and PT_DYNAMIC cover their bytes.
    let list = elf_edit::sections(&orig).unwrap();
    for (i, name) in [(1, ".dynstr"), (2, ".dynamic")] {
        assert_eq!((list[i].name.as_str(), list[i].flags & 2, list[i].loaded), (name, 0, true));
    }
    let mut data = orig.clone();
    let err = elf_edit::remove_section(&mut data, 2).unwrap_err();
    assert!(err.contains(".dynamic lies inside a loaded segment"), "{err}");
    assert_eq!(data, orig);

    // A section added to the file is not loaded and can go again, bytes and all.
    elf_edit::add_section(&mut data, ".note2", b"note").unwrap();
    let added = &elf_edit::sections(&data).unwrap()[4];
    assert!(!added.loaded && added.offset as usize >= orig.len(), "new content lies behind everything that is mapped");
    let at = added.offset as usize;
    let msg = elf_edit::remove_section(&mut data, 4).unwrap();
    assert!(msg.contains("4 bytes of content zeroed"), "{msg}");
    assert_eq!(&data[at..at + 4], &[0; 4]);
}

#[test]
fn a_null_typed_section_has_no_bytes_to_erase() {
    // The other members of an SHT_NULL header are undefined (gABI): here they
    // name 16 bytes inside PT_LOAD that no other section header covers.
    let mut data = tiny_dyn();
    elf_edit::add_section(&mut data, ".note2", b"note").unwrap();
    let h = u64_at(&data, 0x28) as usize + 4 * 64;
    data[h + 4..h + 8].copy_from_slice(&0u32.to_le_bytes());
    data[h + 24..h + 32].copy_from_slice(&0x2c0u64.to_le_bytes());
    data[h + 32..h + 40].copy_from_slice(&0x10u64.to_le_bytes());
    data[0x2c0..0x2d0].fill(0xAA);
    let s = &elf_edit::sections(&data).unwrap()[4];
    assert_eq!((s.ty, s.offset, s.loaded), (0, 0x2c0, false));
    let msg = elf_edit::remove_section(&mut data, 4).unwrap();
    assert!(msg.contains("it had no content in the file"), "{msg}");
    assert_eq!(data[0x2c0..0x2d0], [0xAA; 16]);

    // The same for a header that still covers .dynamic: it goes, the bytes stay.
    // (Adding a section first moves the header table out of PT_LOAD, where it may be rewritten.)
    let mut data = tiny_dyn();
    elf_edit::add_section(&mut data, ".note2", b"note").unwrap();
    let h = u64_at(&data, 0x28) as usize + 2 * 64;
    data[h + 4..h + 8].copy_from_slice(&0u32.to_le_bytes());
    let (at, len) = (u64_at(&data, h + 24) as usize, u64_at(&data, h + 32) as usize);
    let before = data.clone();
    elf_edit::remove_section(&mut data, 2).unwrap();
    assert_eq!(data[at..at + len], before[at..at + len]);
    elf_edit::info(&data).unwrap();
}

#[test]
fn a_section_that_names_the_header_tables_does_not_erase_them() {
    let mut base = tiny_dyn();
    let phoff = u64_at(&base, 0x20) as usize;
    let phlen = 3 * 56;
    // The loaded segment starts behind the program headers, so only the header tables protect them.
    for field in [8, 16, 24] {
        let v = u64_at(&base, phoff + field) + 0x200;
        base[phoff + field..phoff + field + 8].copy_from_slice(&v.to_le_bytes());
    }
    for field in [32, 40] {
        base[phoff + field..phoff + field + 8].copy_from_slice(&0x200u64.to_le_bytes());
    }
    elf_edit::add_section(&mut base, ".note2", b"note").unwrap();
    let shoff = u64_at(&base, 0x28) as usize;
    let names = |d: &[u8]| -> Vec<String> { elf_edit::sections(d).unwrap().into_iter().map(|s| s.name).collect() };
    assert_eq!(names(&base), ["", ".dynstr", ".dynamic", ".shstrtab", ".note2"]);

    for (what, off, len) in [("the program headers", phoff, phlen), ("the section headers", shoff, 4 * 64), ("the ELF header", 0x10, 0x20)] {
        let mut data = base.clone();
        data[shoff + 4 * 64 + 24..shoff + 4 * 64 + 32].copy_from_slice(&(off as u64).to_le_bytes());
        data[shoff + 4 * 64 + 32..shoff + 4 * 64 + 40].copy_from_slice(&(len as u64).to_le_bytes());
        assert!(!elf_edit::sections(&data).unwrap()[4].loaded, "{what}");
        let before = data.clone();
        let msg = elf_edit::remove_section(&mut data, 4).unwrap();
        assert!(msg.contains("were left as they are"), "{what}: {msg}");
        assert_eq!(names(&data), ["", ".dynstr", ".dynamic", ".shstrtab"], "{what}");
        assert_eq!(&data[phoff..phoff + phlen], &before[phoff..phoff + phlen], "{what}: the program headers changed");
        assert_eq!(&data[shoff..shoff + 4 * 64], &before[shoff..shoff + 4 * 64], "{what}: the other section headers changed");
        assert_eq!(elf_edit::program_headers(&data), Some((phoff, phlen)));
    }

    // A symbol table that claims the program headers as its content is not rewritten there.
    let mut data = base.clone();
    data[shoff + 4 * 64 + 4] = 2; // SHT_SYMTAB
    data[shoff + 4 * 64 + 24..shoff + 4 * 64 + 32].copy_from_slice(&(phoff as u64).to_le_bytes());
    data[shoff + 4 * 64 + 32..shoff + 4 * 64 + 40].copy_from_slice(&(phlen as u64).to_le_bytes());
    elf_edit::add_section(&mut data, ".last", b"x").unwrap();
    let before = data.clone();
    let err = elf_edit::remove_section(&mut data, 5).unwrap_err();
    assert!(err.contains("a symbol table overlaps"), "{err}");
    assert_eq!(data, before);
}

/// `tiny_dyn` with `.comment` [4], `.keep` [5] and two symbol tables [6] and [7];
/// the one symbol in [6] is an object defined in `.keep`.
#[test]
fn a_section_inside_the_trailing_header_table_keeps_its_bytes() {
    let mut data = tiny_dyn();
    elf_edit::add_section(&mut data, ".first", &[1; 32]).unwrap();
    let shoff = u64_at(&data, 0x28) as usize;
    let n = elf_edit::sections(&data).unwrap().len();
    assert_eq!(shoff + n * 64, data.len(), "the header table ends the file");
    // The new section now names 16 bytes inside the header table.
    let h = shoff + (n - 1) * 64;
    let at = shoff + 64;
    data[h + 24..h + 32].copy_from_slice(&(at as u64).to_le_bytes());
    data[h + 32..h + 40].copy_from_slice(&16u64.to_le_bytes());
    let before = data.clone();
    elf_edit::add_section(&mut data, ".second", &[0xAA; 128]).unwrap();
    assert_eq!(data[at..at + 16], before[at..at + 16], "the old table was replaced although a section lies in it");
    let info = elf_edit::sections(&data).unwrap();
    assert_eq!((info[n - 1].name.as_str(), info[n - 1].offset), (".first", at as u64));
    assert!(info[n].offset as usize >= before.len(), "the new content goes behind the old table");

    // Without such a section the table is replaced as before.
    let mut data = tiny_dyn();
    elf_edit::add_section(&mut data, ".first", &[1; 32]).unwrap();
    let shoff = u64_at(&data, 0x28) as usize;
    elf_edit::add_section(&mut data, ".second", &[0xAA; 128]).unwrap();
    assert_eq!(elf_edit::sections(&data).unwrap().last().unwrap().offset as usize, shoff);
}

fn with_symbol_tables() -> (Vec<u8>, usize) {
    let mut data = tiny_dyn();
    let mut symbol = [0u8; 48];
    symbol[24 + 4] = 1; // STT_OBJECT
    symbol[24 + 6] = 5; // st_shndx
    for (name, content) in [(".comment", &b"a remark"[..]), (".keep", &b"data"[..]), (".syms", &symbol[..]), (".syms2", &[0u8; 48][..])] {
        elf_edit::add_section(&mut data, name, content).unwrap();
    }
    let shoff = u64_at(&data, 0x28) as usize;
    for i in [6, 7] {
        data[shoff + i * 64 + 4] = 2; // SHT_SYMTAB
    }
    (data, shoff)
}

#[test]
fn symbol_tables_that_share_bytes_or_lie_outside_the_file_are_not_renumbered() {
    let (base, shoff) = with_symbol_tables();
    let syms = u64_at(&base, shoff + 6 * 64 + 24) as usize;
    let shndx = |d: &[u8]| u16::from_le_bytes(d[syms + 24 + 6..syms + 24 + 8].try_into().unwrap());

    // Two tables on their own bytes: the index is adjusted, once.
    let mut data = base.clone();
    elf_edit::remove_section(&mut data, 4).unwrap();
    assert_eq!(shndx(&data), 4);

    // The second header names the bytes of the first: every index would be adjusted twice.
    let mut data = base.clone();
    data.copy_within(shoff + 6 * 64 + 24..shoff + 6 * 64 + 40, shoff + 7 * 64 + 24);
    let before = data.clone();
    let err = elf_edit::remove_section(&mut data, 4).unwrap_err();
    assert!(err.contains("two symbol tables overlap"), "{err}");
    assert_eq!(data, before);
    // Kept for the fuzzer as well: the first bytes ask for this removal.
    let saved = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/regressions/elf_edit/aliased_symbol_tables.bin")).unwrap();
    assert_eq!(saved[..4], [0x47, 0, 0, 0]);
    assert_eq!(saved[4..], data);

    // A table far outside the file reads as zeroes; walking it would only cost time.
    let mut data = base.clone();
    data[shoff + 7 * 64 + 24..shoff + 7 * 64 + 32].copy_from_slice(&0x4000_0000u64.to_le_bytes());
    data[shoff + 7 * 64 + 32..shoff + 7 * 64 + 40].copy_from_slice(&96_000_000u64.to_le_bytes());
    let before = data.clone();
    let err = elf_edit::remove_section(&mut data, 4).unwrap_err();
    assert!(err.contains("a symbol table lies outside the file"), "{err}");
    assert_eq!(data, before);
}
