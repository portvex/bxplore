//! Round trip tests for the structural editors. They run against a real PE
//! file given in the BXPLORE_TEST_PE environment variable and are skipped when
//! it is not set.

use super::Pe;
use super::edit::{self, NewImport};
use super::resources::{self, ResId, ResNode};

fn sample() -> Option<Vec<u8>> {
    std::fs::read(std::env::var("BXPLORE_TEST_PE").ok()?).ok()
}

fn out(name: &str, data: &[u8]) {
    if let Ok(dir) = std::env::var("BXPLORE_TEST_OUT") {
        std::fs::write(std::path::Path::new(&dir).join(name), data).unwrap();
    }
}

fn import_names(data: &[u8]) -> Vec<(String, Vec<String>)> {
    let pe = Pe::parse(data).unwrap();
    pe.imports(data)
        .into_iter()
        .map(|m| (m.name, m.funcs.into_iter().map(|f| f.name.unwrap_or_else(|| format!("#{}", f.ordinal.unwrap_or(0)))).collect()))
        .collect()
}

fn leaves(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &resources::ResDir, data: &[u8], prefix: String, out: &mut Vec<(String, Vec<u8>)>) {
        for e in &dir.entries {
            let p = format!("{prefix}/{}", e.id.label());
            match &e.node {
                ResNode::Dir(d) => walk(d, data, p, out),
                ResNode::Data(d) => out.push((p, d.bytes(data).to_vec())),
            }
        }
    }
    let pe = Pe::parse(data).unwrap();
    let mut v = Vec::new();
    if let Some(root) = resources::parse(data, &pe) {
        walk(&root, data, String::new(), &mut v);
    }
    v
}

#[test]
fn add_and_delete_section() {
    let Some(orig) = sample() else { return };
    let mut data = orig.clone();
    let before = Pe::parse(&data).unwrap();
    let overlay = orig[before.raw_end()..].to_vec();
    let payload = vec![0xAB; 0x1234];
    let va = edit::add_section(&mut data, ".test", &payload, payload.len() as u32, 0x4000_0040).unwrap();
    let pe = Pe::parse(&data).unwrap();
    assert_eq!(pe.sections.len(), before.sections.len() + 1);
    let s = pe.sections.last().unwrap();
    assert_eq!((s.name.as_str(), s.va), (".test", va));
    assert_eq!(&data[s.roff as usize..s.roff as usize + payload.len()], &payload[..]);
    assert_eq!(pe.rva_to_off(va), Some(s.roff as usize));
    // The overlay (and with it the certificate table) must follow the new data untouched.
    assert_eq!(&data[pe.raw_end()..], &overlay[..]);
    if before.dir(&orig, 4).0 != 0 {
        assert_eq!(pe.dir(&data, 4).0 as usize, pe.raw_end());
    }
    let mut fixed = data.clone();
    edit::fix_checksum(&mut fixed).unwrap();
    let pe_fixed = Pe::parse(&fixed).unwrap();
    assert_eq!(edit::checksum(&fixed, &pe_fixed), u32::from_le_bytes(fixed[pe.opt + 64..pe.opt + 68].try_into().unwrap()));
    out("added_section.exe", &fixed);

    edit::delete_section(&mut data, pe.sections.len() - 1).unwrap();
    if Pe::parse(&data).unwrap().size_of_headers == before.size_of_headers {
        assert_eq!(data, orig, "deleting the added section restores the original file");
    }
}

#[test]
fn add_imports_keeps_existing() {
    let Some(orig) = sample() else { return };
    let mut data = orig.clone();
    let before = import_names(&data);
    let new = vec![
        ("extra.dll".to_string(), vec![NewImport::Name("DoSomething".into()), NewImport::Ordinal(7)]),
        ("other.dll".to_string(), vec![NewImport::Name("X".into())]),
    ];
    edit::add_imports(&mut data, &new).unwrap();
    edit::fix_checksum(&mut data).unwrap();
    let after = import_names(&data);
    assert_eq!(&after[..before.len()], &before[..]);
    assert_eq!(after[before.len()], ("extra.dll".to_string(), vec!["DoSomething".to_string(), "#7".to_string()]));
    assert_eq!(after[before.len() + 1], ("other.dll".to_string(), vec!["X".to_string()]));
    out("added_imports.exe", &data);
}

#[test]
fn resources_round_trip() {
    let Some(orig) = sample() else { return };
    let before = leaves(&orig);
    if before.is_empty() {
        return;
    }
    let pe = Pe::parse(&orig).unwrap();
    let root = resources::parse(&orig, &pe).unwrap();

    // Rebuilding an unchanged tree keeps every resource byte for byte.
    let mut data = orig.clone();
    resources::apply(&mut data, &root).unwrap();
    assert_eq!(leaves(&data), before);

    // Add a large resource, replace the first one and delete the last one.
    let mut tree = root.clone();
    let big = vec![0x5A; 300_000];
    resources::insert(&mut tree, &ResId::Id(10), &ResId::Name("PAYLOAD".into()), &ResId::Id(1033), big.clone());
    let mut data = orig.clone();
    resources::apply(&mut data, &tree).unwrap();
    edit::fix_checksum(&mut data).unwrap();
    let after = leaves(&data);
    assert_eq!(after.len(), before.len() + 1);
    assert!(after.iter().any(|(p, b)| p.contains("PAYLOAD") && *b == big));
    for item in &before {
        assert!(after.contains(item), "{} survived", item.0);
    }
    let pe2 = Pe::parse(&data).unwrap();
    assert_eq!(&data[pe2.raw_end()..], &orig[pe.raw_end()..], "overlay preserved");
    out("added_resource.exe", &data);
}

#[test]
fn exports_round_trip_and_edit() {
    let Some(orig) = sample() else { return };
    let pe = Pe::parse(&orig).unwrap();
    let mut table = edit::parse_exports(&orig, &pe).unwrap_or_else(|| edit::ExportTable { dll_name: "test.dll".into(), base: 1, ..Default::default() });
    let before = table.clone();
    table.funcs.push(edit::ExportFn { rva: pe.entry, forwarder: None, names: vec!["ZzAdded".into(), "AaAlias".into()] });
    table.funcs.push(edit::ExportFn { rva: 0, forwarder: Some("KERNEL32.Sleep".into()), names: vec!["Nap".into()] });
    let mut data = orig.clone();
    edit::write_exports(&mut data, &table).unwrap();
    out("added_exports.exe", &data);
    let pe2 = Pe::parse(&data).unwrap();
    let after = edit::parse_exports(&data, &pe2).unwrap();
    assert_eq!(after.funcs.len(), before.funcs.len() + 2);
    assert_eq!(&after.funcs[..before.funcs.len()], &before.funcs[..], "existing exports must survive");
    let added = &after.funcs[before.funcs.len()];
    assert_eq!(added.rva, pe.entry);
    let mut names = added.names.clone();
    names.sort();
    assert_eq!(names, ["AaAlias", "ZzAdded"]);
    assert_eq!(after.funcs.last().unwrap().forwarder.as_deref(), Some("KERNEL32.Sleep"));
}

#[test]
fn rename_and_remove_imports() {
    let Some(orig) = sample() else { return };
    let before = import_names(&orig);
    let Some(mi) = before.iter().position(|(_, f)| f.iter().any(|n| !n.starts_with('#'))) else { return };
    let fi = before[mi].1.iter().position(|n| !n.starts_with('#')).unwrap();

    // Shorter name: in place, file size unchanged.
    let mut data = orig.clone();
    edit::rename_import(&mut data, mi, Some(fi), "Ab").unwrap();
    assert_eq!(data.len(), orig.len());
    assert_eq!(import_names(&data)[mi].1[fi], "Ab");

    // Longer names go to a new section; everything else stays.
    let mut data = orig.clone();
    let long = "ThisNameIsMuchLongerThanAnythingTheLinkerWroteIntoTheImportTable_0123456789";
    edit::rename_import(&mut data, mi, Some(fi), long).unwrap();
    edit::rename_import(&mut data, mi, None, "a_considerably_longer_module_name.dll").unwrap();
    out("renamed_imports.exe", &data);
    let after = import_names(&data);
    assert_eq!(after.len(), before.len());
    assert_eq!(after[mi].0, "a_considerably_longer_module_name.dll");
    assert_eq!(after[mi].1[fi], long);
    for (i, (b, a)) in before.iter().zip(&after).enumerate() {
        for (j, (bn, an)) in b.1.iter().zip(&a.1).enumerate() {
            assert!(bn == an || (i == mi && j == fi), "import {i}/{j} changed unexpectedly");
        }
    }

    let mut data = orig.clone();
    edit::remove_import_module(&mut data, mi).unwrap();
    let after = import_names(&data);
    assert_eq!(after.len(), before.len() - 1);
    let mut expect = before.clone();
    expect.remove(mi);
    assert_eq!(after, expect);

    let mut data = orig.clone();
    edit::unbind_imports(&mut data).unwrap();
    assert_eq!(import_names(&data), before);
}

#[test]
fn authenticode_verifies_and_detects_tampering() {
    let Some(orig) = sample() else { return };
    let text = |d: &[u8]| {
        let mut out = String::new();
        crate::analysis::dump(&crate::analysis::parse(d).root, 0, &mut out);
        out
    };
    let before = text(&orig);
    if !before.contains("[Authenticode Signature]") {
        return;
    }
    assert!(before.contains("Result: the signature is cryptographically valid"), "a signed, unmodified file must verify");
    assert!(before.contains("Certificate chain  OK"));
    // One changed byte in the code breaks the image digest but not the signature over it.
    let pe = Pe::parse(&orig).unwrap();
    let mut bad = orig.clone();
    let off = pe.sections[0].roff as usize + 16;
    bad[off] ^= 0xff;
    let after = text(&bad);
    assert!(after.contains("Image digest       FAILED"));
    assert!(after.contains("Signature          OK"));
    // Changing the digest stored in the signed content is caught by the
    // messageDigest attribute, which the signature covers.
    let (sec_off, sec_size) = pe.dir(&orig, 4);
    let blob = sec_off as usize..(sec_off as usize + sec_size as usize).min(orig.len());
    let hex = |label: &str| -> Vec<u8> {
        let line = before.lines().find(|l| l.contains(label)).unwrap();
        let h = line.rsplit(' ').next().unwrap();
        (0..h.len() / 2).map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap()).collect()
    };
    let digest = [hex("Authenticode SHA-1:"), hex("Authenticode SHA-256:")];
    let at =
        digest.iter().find_map(|d| orig[blob.clone()].windows(d.len()).position(|w| w == &d[..])).expect("the image digest is in the signature") + blob.start;
    let mut bad = orig.clone();
    bad[at] ^= 0x01;
    let after = text(&bad);
    assert!(after.contains("Signed attributes  FAILED"), "a forged digest must not pass");
    assert!(!after.contains("Result: the signature is cryptographically valid"));
    // The certificate table moved in front of the last section: the digest
    // still matches (it skips the table wherever the directory says it is),
    // but that section now maps other bytes, so the file must not verify.
    let last = pe.sections.iter().filter(|s| s.rsize > 0).max_by_key(|s| s.roff).unwrap().roff as usize;
    let mut moved = orig[..last].to_vec();
    moved.extend_from_slice(&orig[blob.start..]);
    moved.extend_from_slice(&orig[last..blob.start]);
    moved[pe.dirs_off + 32..pe.dirs_off + 36].copy_from_slice(&(last as u32).to_le_bytes());
    let after = text(&moved);
    assert!(before.contains("Certificate table  OK") && after.contains("Certificate table  FAILED"), "{after}");
    assert!(!after.contains("Result: the signature is cryptographically valid"));
}

#[test]
fn dotnet_tables_are_decoded() {
    let Some(orig) = sample() else { return };
    let pe = Pe::parse(&orig).unwrap();
    if pe.dir(&orig, 14).0 == 0 {
        return;
    }
    let mut out = String::new();
    crate::analysis::dump(&crate::analysis::parse(&orig).root, 0, &mut out);
    for table in ["[Module (1)]", "[TypeDef (", "[MethodDef (", "[Assembly (1)]", "[AssemblyRef ("] {
        assert!(out.contains(table), "missing {table}");
    }
    assert!(out.contains("TypeName=<Module>"), "the first TypeDef is always <Module>");
    assert!(out.contains("[User Strings ("));
    // Signatures and IL: every method with a body must disassemble to the end
    // without unknown opcodes, and bodies end in ret, throw, a branch or jmp.
    let md = super::metadata(&orig, &pe).unwrap();
    let methods = md.methods();
    assert!(methods.iter().any(|m| m.name.ends_with("::.ctor") && m.signature.starts_with("instance void (")), "constructors decode as instance void");
    let mut bodies = 0;
    for (i, m) in methods.iter().enumerate() {
        if m.rva == 0 {
            continue;
        }
        let il = super::method_il(&orig, &pe, i + 1).unwrap();
        assert!(!il.contains("<unknown opcode") && !il.contains("<truncated>"), "{}:\n{il}", m.name);
        let last = il.lines().rev().find(|l| l.starts_with("IL_")).unwrap_or("");
        let end = last.split_whitespace().nth(1).unwrap_or("");
        assert!(
            ["ret", "throw", "rethrow", "br", "br.s", "leave", "leave.s", "endfinally", "jmp", "endfilter"].contains(&end),
            "{} ends with {last:?}",
            m.name
        );
        bodies += 1;
    }
    assert!(bodies > 0);
    if let Ok(dir) = std::env::var("BXPLORE_TEST_OUT") {
        let sample: String = (1..=methods.len()).step_by(methods.len() / 12 + 1).filter_map(|r| super::method_il(&orig, &pe, r)).collect::<Vec<_>>().join("\n");
        std::fs::write(std::path::Path::new(&dir).join("il_sample.txt"), sample).unwrap();
    }
}

#[test]
fn relocations_round_trip_and_edit() {
    let Some(orig) = sample() else { return };
    let pe = Pe::parse(&orig).unwrap();
    let list = edit::parse_relocs(&orig, &pe);
    if list.is_empty() {
        return;
    }
    // Writing back what was read must not change what is read.
    let mut data = orig.clone();
    edit::write_relocs(&mut data, &list).unwrap();
    assert_eq!(data.len(), orig.len(), "an unchanged table fits in place");
    assert_eq!(edit::parse_relocs(&data, &Pe::parse(&data).unwrap()), list);

    // Remove one, add one elsewhere.
    let victim = list[list.len() / 2].0;
    edit::remove_reloc(&mut data, victim).unwrap();
    let free = (pe.sections[0].va..).step_by(4).find(|r| !list.iter().any(|x| x.0 == *r)).unwrap();
    edit::add_reloc(&mut data, free, edit::pointer_reloc_type(&pe)).unwrap();
    let mut want: Vec<(u32, u8)> = list.iter().copied().filter(|r| r.0 != victim).collect();
    want.push((free, edit::pointer_reloc_type(&pe)));
    want.sort();
    let mut got = edit::parse_relocs(&data, &Pe::parse(&data).unwrap());
    got.sort();
    assert_eq!(got, want);
    assert!(edit::add_reloc(&mut data, free, 3).is_err(), "duplicates are refused");
    out("edited_relocs.exe", &data);
}

#[test]
fn tls_callbacks_add_and_remove() {
    let Some(orig) = sample() else { return };
    let pe = Pe::parse(&orig).unwrap();
    let Some((_, before)) = edit::tls_callbacks(&orig, &pe) else { return };
    let target = pe.image_base + pe.entry as u64;
    let mut data = orig.clone();
    edit::add_tls_callback(&mut data, target).unwrap();
    out("added_tls_callback.exe", &data);
    let pe2 = Pe::parse(&data).unwrap();
    let (array, after) = edit::tls_callbacks(&data, &pe2).unwrap();
    let mut want = before.clone();
    want.push(target);
    assert_eq!(after, want);
    // Every slot of the new array is relocated when the image has relocations.
    let relocs = edit::parse_relocs(&data, &pe2);
    if !edit::parse_relocs(&orig, &pe).is_empty() {
        let s = pe2.sections.iter().find(|s| array >= s.roff as usize && array < (s.roff + s.rsize) as usize).unwrap();
        let rva = s.va + (array - s.roff as usize) as u32;
        for i in 0..after.len() {
            assert!(relocs.iter().any(|r| r.0 == rva + (i * pe2.ptr_size()) as u32), "slot {i} has no relocation");
        }
        assert!(!relocs.iter().any(|r| r.0 == rva + (after.len() * pe2.ptr_size()) as u32), "the terminator must not be relocated");
    }
    assert!(edit::add_tls_callback(&mut data, target).is_err());

    edit::remove_tls_callback(&mut data, after.len() - 1).unwrap();
    let pe3 = Pe::parse(&data).unwrap();
    let (array, list) = edit::tls_callbacks(&data, &pe3).unwrap();
    assert_eq!(list, before);
    let s = pe3.sections.iter().find(|s| array >= s.roff as usize && array < (s.roff + s.rsize) as usize).unwrap();
    let term = s.va + (array - s.roff as usize + list.len() * pe3.ptr_size()) as u32;
    assert!(!edit::parse_relocs(&data, &pe3).iter().any(|r| r.0 == term), "the new terminator lost its relocation");
}

#[test]
fn delay_imports_become_ordinary_imports() {
    let Some(orig) = sample() else { return };
    let pe = Pe::parse(&orig).unwrap();
    let delay = edit::delay_imports(&orig, &pe);
    if delay.is_empty() {
        return;
    }
    let before = import_names(&orig);
    let mut data = orig.clone();
    edit::convert_delay_imports(&mut data).unwrap();
    out("converted_delay_imports.exe", &data);
    let pe2 = Pe::parse(&data).unwrap();
    let after = import_names(&data);
    assert_eq!(&after[..before.len()], &before[..], "existing imports are untouched");
    assert_eq!(after.len(), before.len() + delay.len());
    for (m, d) in pe2.imports(&data)[before.len()..].iter().zip(&delay) {
        assert_eq!(m.name, d.name);
        assert_eq!(m.funcs.len(), d.thunks.len());
        assert_eq!(m.funcs[0].iat_rva, d.iat_rva, "the loader fills the delay IAT");
    }
    assert!(edit::delay_imports(&data, &pe2).is_empty());
}

// --- tests on the files checked in as fuzzer seeds; these always run ---

fn seed(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/parse_any").join(name)).unwrap()
}

/// `linked.exe` with headers that end 20 bytes into the next section header
/// slot and a byte in use behind them: the headers can be enlarged, but the
/// slot is still occupied afterwards.
fn occupied_slack() -> Vec<u8> {
    let mut data = seed("linked.exe");
    let pe = Pe::parse(&data).unwrap();
    let slot = pe.sec_table + pe.sections.len() * 40;
    edit::w32(&mut data, pe.opt + 60, slot as u32 + 20);
    data[slot + 30] = 0x55;
    data
}

#[test]
fn a_refused_section_leaves_the_headers_as_they_were() {
    type Editor = fn(&mut Vec<u8>) -> Result<String, String>;
    let editors: [(&str, Editor); 4] = [
        ("add_section", |d| edit::add_section(d, ".new", &[1, 2, 3], 3, 0x4000_0040).map(|_| String::new())),
        ("write_relocs", |d| edit::write_relocs(d, &(0..600).map(|i| (0x1000 + i * 2, 10)).collect::<Vec<_>>())),
        ("add_tls_callback", |d| edit::add_tls_callback(d, 0x1_4000_1040)),
        ("convert_delay_imports", edit::convert_delay_imports),
    ];
    for (name, editor) in editors {
        let mut data = occupied_slack();
        let before = data.clone();
        let err = editor(&mut data).unwrap_err();
        assert!(err.contains("header slack"), "{name}: {err}");
        assert!(data == before, "{name} failed after the headers were enlarged and left them that way");
    }
    // The same on the synthetic file: three headers fill the table up to the raw data.
    let mut data = seed("tiny.exe");
    edit::add_section(&mut data, ".a", &[1], 1, 0x4000_0040).unwrap();
    edit::add_section(&mut data, ".b", &[2], 1, 0x4000_0040).unwrap();
    let pe = Pe::parse(&data).unwrap();
    let slot = pe.sec_table + pe.sections.len() * 40;
    let first_raw = pe.sections.iter().map(|s| s.roff as usize).min().unwrap();
    assert!(first_raw - slot < 40, "the next header does not fit without enlarging the headers");
    data[slot..first_raw].fill(0x55);
    let before = data.clone();
    assert!(edit::add_section(&mut data, ".c", &[3], 1, 0x4000_0040).is_err());
    assert!(data == before);
    assert!(edit::write_relocs(&mut data, &[(0x1000, 3), (0x1004, 3)]).is_err());
    assert!(data == before);
    assert!(edit::add_reloc(&mut data, 0x1000, 3).is_err());
    assert!(data == before);
}

#[test]
fn a_relocation_table_beyond_the_cap_is_not_edited() {
    let mut data = seed("tiny.exe");
    let list: Vec<(u32, u8)> = (0..4_100_000).map(|i| (0x1000 + i, 3)).collect();
    edit::write_relocs(&mut data, &list).unwrap();
    let pe = Pe::parse(&data).unwrap();
    let shown = edit::parse_relocs(&data, &pe).len();
    assert!((4_000_000..list.len()).contains(&shown), "the viewer shows {shown} entries");
    // Writing back what the viewer shows would drop the rest.
    let before = data.clone();
    for r in [edit::add_reloc(&mut data, 0x0FF0, 3), edit::remove_reloc(&mut data, 0x1000)] {
        assert!(r.unwrap_err().contains("too large to edit"));
        assert!(data == before);
    }
}

#[test]
fn a_relocation_table_with_highadj_entries_is_not_rewritten() {
    let mut data = seed("tiny.exe");
    edit::write_relocs(&mut data, &[(0x1010, 3), (0x1234, 3), (0x1300, 3), (0x1400, 3)]).unwrap();
    let pe = Pe::parse(&data).unwrap();
    let block = pe.rva_to_off(pe.dir(&data, 5).0).unwrap();
    // The first two slots become a HIGHADJ entry and its parameter, which
    // would read as a HIGHLOW relocation of 0x1234.
    data[block + 8..block + 12].copy_from_slice(&[0x10, 0x40, 0x34, 0x32]);
    assert_eq!(edit::parse_relocs(&data, &pe), [(0x1010, 4), (0x1300, 3), (0x1400, 3)], "the parameter is not an entry");
    let before = data.clone();
    for r in [edit::add_reloc(&mut data, 0x1004, 3), edit::remove_reloc(&mut data, 0x1300), edit::write_relocs(&mut data, &[(0x1300, 3)])] {
        let err = r.unwrap_err();
        assert!(err.contains("HIGHADJ"), "{err}");
        assert!(data == before);
    }
    // A new entry of that type is refused as well.
    let mut data = seed("tiny.exe");
    let before = data.clone();
    assert!(edit::write_relocs(&mut data, &[(0x1010, 4)]).unwrap_err().contains("HIGHADJ"));
    assert!(edit::add_reloc(&mut data, 0x1004, 4).unwrap_err().contains("HIGHADJ"));
    assert!(data == before);
}

#[test]
fn a_read_only_delay_iat_becomes_writable_when_converted() {
    let orig = seed("linked.exe");
    let pe = Pe::parse(&orig).unwrap();
    let delay = edit::delay_imports(&orig, &pe);
    let i = pe.section_of_rva(delay[0].iat_rva).unwrap();
    let chars = pe.sections[i].hdr_off + 36;
    // As linked: the loader can write to the table, and the flags stay.
    let mut data = orig.clone();
    let text = edit::convert_delay_imports(&mut data).unwrap();
    assert!(pe.sections[i].chars & 0x8000_0000 != 0 && !text.contains("writable"), "{text}");
    assert_eq!(data[chars..chars + 4], orig[chars..chars + 4]);
    // A protected delay IAT lies in a read-only section, where the loader
    // would fault on the first slot.
    let mut data = orig.clone();
    edit::w32(&mut data, chars, pe.sections[i].chars & !0x8000_0000);
    let text = edit::convert_delay_imports(&mut data).unwrap();
    assert!(text.contains(&format!("section {} holds a delay import address table and was made writable", pe.sections[i].name)), "{text}");
    assert_eq!(Pe::parse(&data).unwrap().sections[i].chars, pe.sections[i].chars);
    // A table outside every section cannot be filled at all.
    let mut data = orig.clone();
    let desc = pe.rva_to_off(pe.dir(&orig, 13).0).unwrap();
    edit::w32(&mut data, desc + 12, pe.next_section_rva() + 0x10_0000);
    let before = data.clone();
    let err = edit::convert_delay_imports(&mut data).unwrap_err();
    assert!(err.contains("is not inside a section"), "{err}");
    assert!(data == before);
}

#[test]
fn a_tls_callback_array_needs_room_above_the_image_base() {
    let mut data = seed("linked.exe");
    let pe = Pe::parse(&data).unwrap();
    // The array would lie at ImageBase + 0x8000, past the end of the address space.
    data[pe.opt + 24..pe.opt + 32].copy_from_slice(&0xFFFF_FFFF_FFFF_F000u64.to_le_bytes());
    let before = data.clone();
    let err = edit::add_tls_callback(&mut data, 0xFFFF_FFFF_FFFF_F200).unwrap_err();
    assert!(err.contains("leaves no room"), "{err}");
    assert!(data == before);
}

#[test]
fn relocations_grow_into_the_tail_of_their_section() {
    let orig = seed("linked.exe");
    let pe = Pe::parse(&orig).unwrap();
    let mut data = orig.clone();
    // Six blocks of 12 bytes on pages of their own: more than the old Size, less than the padding.
    for i in 0..6 {
        edit::add_reloc(&mut data, pe.sections[i].va + 0x10 * i as u32 + 1, 10).unwrap();
    }
    let pe2 = Pe::parse(&data).unwrap();
    assert_eq!((pe2.sections.len(), data.len()), (pe.sections.len(), orig.len()), "no new section, no new bytes");
    assert_eq!(edit::parse_relocs(&data, &pe2).len(), edit::parse_relocs(&orig, &pe).len() + 6);
    let reloc = pe2.sections.last().unwrap();
    assert_eq!(pe2.dir(&data, 5), (reloc.va, reloc.vsize), "VirtualSize follows the table");
    assert_eq!(pe2.next_section_rva(), pe.next_section_rva());

    // Bytes in use behind the table are not taken: the table moves instead.
    let mut data = orig.clone();
    let (rva, size) = pe.dir(&data, 5);
    data[pe.rva_to_off(rva).unwrap() + size as usize + 9] = 1;
    edit::add_reloc(&mut data, pe.sections[0].va + 1, 10).unwrap();
    edit::add_reloc(&mut data, pe.sections[1].va + 1, 10).unwrap();
    let pe2 = Pe::parse(&data).unwrap();
    assert_eq!(pe2.sections.last().unwrap().name, ".reloc2");
    assert_eq!(data[pe.rva_to_off(rva).unwrap() + size as usize + 9], 1);
}

#[test]
fn a_tls_directory_across_the_end_of_its_section_is_not_edited() {
    let mut data = seed("linked.exe");
    let pe = Pe::parse(&data).unwrap();
    let i = pe.section_of_rva(pe.dir(&data, 9).0).unwrap();
    let s = &pe.sections[i];
    assert!(pe.sections.iter().any(|t| t.roff > s.roff), "another section follows in the file");
    // The directory starts eight bytes before the end of the raw data, so
    // its AddressOfCallBacks field would be in the next section's bytes.
    let rva = s.va + s.rsize - 8;
    data[pe.dirs_off + 9 * 8..pe.dirs_off + 9 * 8 + 4].copy_from_slice(&rva.to_le_bytes());
    let before = data.clone();
    let err = edit::add_tls_callback(&mut data, pe.image_base + pe.entry as u64).unwrap_err();
    assert!(err.contains("not fully inside"), "{err}");
    assert!(data == before);
    assert!(edit::remove_tls_callback(&mut data, 0).is_err());
    assert!(data == before);
}

#[test]
fn a_tls_directory_mapped_through_the_headers_into_section_data_is_not_edited() {
    let orig = seed("linked.exe");
    let pe = Pe::parse(&orig).unwrap();
    let first_raw = pe.sections.iter().filter(|s| s.rsize > 0).map(|s| s.roff).min().unwrap();
    let first_va = pe.sections.iter().map(|s| s.va).min().unwrap();
    assert_eq!(first_raw, pe.size_of_headers);
    // Below the first section an RVA is its own file offset: the directory
    // would end in, or lie in, the raw data of the first section.
    for rva in [pe.size_of_headers - 0x10, pe.size_of_headers + 0x100] {
        assert!(rva < first_va && pe.rva_to_off(rva) == Some(rva as usize));
        let mut data = orig.clone();
        data[pe.dirs_off + 9 * 8..pe.dirs_off + 9 * 8 + 4].copy_from_slice(&rva.to_le_bytes());
        let before = data.clone();
        let err = edit::add_tls_callback(&mut data, pe.image_base + pe.entry as u64).unwrap_err();
        assert!(err.contains("does not edit TLS data there"), "{rva:X}: {err}");
        assert!(data == before);
        assert!(edit::remove_tls_callback(&mut data, 0).is_err());
        assert!(data == before);
    }
}

#[test]
fn the_terminator_of_a_shortened_tls_array_loses_its_relocation_by_rva() {
    let mut data = seed("linked.exe");
    let pe = Pe::parse(&data).unwrap();
    let ps = pe.ptr_size();
    edit::add_tls_callback(&mut data, pe.image_base + pe.entry as u64).unwrap();
    edit::add_tls_callback(&mut data, pe.image_base + pe.entry as u64 + 1).unwrap();
    let pe = Pe::parse(&data).unwrap();
    let array = pe.sections.last().unwrap().clone();
    assert_eq!(array.name, ".tlscb");
    let n = edit::tls_callbacks(&data, &pe).unwrap().1.len();
    let last = array.va + ((n - 1) * ps) as u32;
    assert!(edit::parse_relocs(&data, &pe).iter().any(|r| r.0 == last), "the last callback is relocated");
    // The first section shares the raw data of the array, so the file offset
    // of the array belongs to two sections.
    let first = pe.sections[0].hdr_off;
    edit::w32(&mut data, first + 16, array.rsize);
    edit::w32(&mut data, first + 20, array.roff);
    edit::remove_tls_callback(&mut data, n - 1).unwrap();
    let pe = Pe::parse(&data).unwrap();
    assert_eq!(edit::tls_callbacks(&data, &pe).unwrap().1.len(), n - 1);
    let relocs = edit::parse_relocs(&data, &pe);
    assert!(!relocs.iter().any(|r| r.0 == last), "the terminator is still relocated");
    assert!(relocs.iter().any(|r| r.0 == last - ps as u32), "the callback before it keeps its relocation");
}

#[test]
fn a_tls_callback_array_across_the_end_of_its_section_is_not_edited() {
    let mut data = seed("linked.exe");
    let pe = Pe::parse(&data).unwrap();
    let dir = edit::tls_directory(&data, &pe).unwrap();
    let ps = pe.ptr_size();
    let s = pe.sections.iter().find(|s| s.rsize as usize >= 2 * ps && pe.sections.iter().any(|t| t.roff > s.roff)).unwrap();
    // One callback in the last slot of the section; the terminator would be
    // read from, and rewritten in, the bytes that follow.
    let slot = s.roff as usize + s.rsize as usize - ps;
    data[slot..slot + ps].copy_from_slice(&(pe.image_base + pe.entry as u64).to_le_bytes()[..ps]);
    let va = pe.image_base + (s.va + s.rsize) as u64 - ps as u64;
    data[dir + 3 * ps..dir + 4 * ps].copy_from_slice(&va.to_le_bytes()[..ps]);
    let before = data.clone();
    let err = edit::remove_tls_callback(&mut data, 0).unwrap_err();
    assert!(err.contains("not fully inside"), "{err}");
    assert!(data == before);
}

#[test]
fn the_first_tls_callback_creates_the_array() {
    let mut data = seed("linked.exe");
    let pe = Pe::parse(&data).unwrap();
    let dir = edit::tls_directory(&data, &pe).unwrap();
    let ps = pe.ptr_size();
    // Thread local data without callbacks: the directory is there, the array is not.
    data[dir + 3 * ps..dir + 4 * ps].fill(0);
    assert!(edit::tls_callbacks(&data, &pe).is_none());
    assert!(edit::tls_directory(&data, &pe).is_some());
    let target = pe.image_base + pe.entry as u64;
    edit::add_tls_callback(&mut data, target).unwrap();

    let pe2 = Pe::parse(&data).unwrap();
    let (array, list) = edit::tls_callbacks(&data, &pe2).unwrap();
    assert_eq!(list, [target]);
    let s = pe2.sections.last().unwrap();
    assert_eq!((s.name.as_str(), array), (".tlscb", s.roff as usize));
    let dir = edit::tls_directory(&data, &pe2).unwrap();
    assert_eq!(u64::from_le_bytes(data[dir + 3 * ps..dir + 4 * ps].try_into().unwrap()), pe2.image_base + s.va as u64);
    let relocs = edit::parse_relocs(&data, &pe2);
    assert!(!edit::parse_relocs(&seed("linked.exe"), &pe).is_empty(), "the fixture has relocations");
    let field = pe2.dir(&data, 9).0 + (3 * ps) as u32;
    assert!(relocs.iter().any(|r| r.0 == field), "the directory field is relocated");
    assert!(relocs.iter().any(|r| r.0 == s.va), "the callback slot is relocated");
    assert!(!relocs.iter().any(|r| r.0 == s.va + ps as u32), "the terminator is not");
}

/// A PE32 without sections whose headers end at `size_of_headers`, with the
/// TLS directory at RVA `tls` (mapped through the headers).
fn sectionless(size_of_headers: u32, tls: u32) -> Vec<u8> {
    let mut f = vec![0u8; 0x400];
    f[..2].copy_from_slice(b"MZ");
    edit::w32(&mut f, 0x3c, 0x80);
    f[0x80..0x84].copy_from_slice(b"PE\0\0");
    f[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // Machine
    f[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // SizeOfOptionalHeader
    let opt = 0x98;
    f[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes()); // Magic
    edit::w32(&mut f, opt + 16, 0x10); // AddressOfEntryPoint
    edit::w32(&mut f, opt + 28, 0x40_0000); // ImageBase
    edit::w32(&mut f, opt + 32, 0x200); // SectionAlignment
    edit::w32(&mut f, opt + 36, 0x200); // FileAlignment
    edit::w32(&mut f, opt + 60, size_of_headers);
    edit::w32(&mut f, opt + 92, 16); // NumberOfRvaAndSizes
    edit::w32(&mut f, opt + 96 + 9 * 8, tls);
    edit::w32(&mut f, opt + 96 + 9 * 8 + 4, 24);
    f
}

#[test]
fn a_section_that_lands_elsewhere_is_refused() {
    type Editor = fn(&mut Vec<u8>) -> Result<String, String>;
    let editors: [(&str, Editor); 3] = [
        ("add_tls_callback", |d| edit::add_tls_callback(d, 0x40_0010)),
        ("add_imports", |d| edit::add_imports(d, &[("a.dll".into(), vec![NewImport::Name("F".into())])])),
        ("write_exports", |d| edit::write_exports(d, &edit::ExportTable { dll_name: "a.dll".into(), ..Default::default() })),
    ];
    // The headers end at 0x180 and have to grow for the first section header:
    // a directory behind them would move away from its RVA. (The TLS editor
    // does not get that far: it refuses a directory behind the headers.)
    let mut data = sectionless(0x180, 0x300);
    let before = data.clone();
    let err = editors[1].1(&mut data).unwrap_err();
    assert!(err.contains("mapped through the headers"), "{err}");
    assert!(data == before);
    let err = edit::add_tls_callback(&mut data, 0x40_0010).unwrap_err();
    assert!(err.contains("does not edit TLS data there"), "{err}");
    assert!(data == before);
    // With the directory in front of the insertion, growing the headers still
    // moves the section from the predicted RVA 0x200 to 0x400. (Again the TLS
    // editor stops earlier: in front of the insertion means in the headers.)
    for (name, editor) in editors {
        let mut data = sectionless(0x180, 0x100);
        let before = data.clone();
        let err = editor(&mut data).unwrap_err();
        let expected = if name == "add_tls_callback" { "does not edit TLS data there" } else { "instead of 00000200" };
        assert!(err.contains(expected), "{name}: {err}");
        assert!(data == before, "{name} left the buffer changed");
    }
    // Headers with room for the section header: the prediction holds.
    let mut data = sectionless(0x200, 0x1c0);
    edit::add_imports(&mut data, &[("a.dll".into(), vec![NewImport::Name("F".into())])]).unwrap();
    assert_eq!(Pe::parse(&data).unwrap().sections[0].va, 0x200);
}

#[test]
fn a_directory_behind_the_headers_of_a_sectionless_file_is_not_left_behind() {
    // The headers have room for the section header, so nothing grows; the new
    // section still takes RVA 0x200 and file offset 0x200, where the
    // directory is found as long as there is no section.
    for tls in [0x300, 0x600] {
        let mut data = sectionless(0x200, tls);
        data.resize(0x800, 0);
        edit::w32(&mut data, tls as usize, 0x40_0020);
        let pe = Pe::parse(&data).unwrap();
        assert_eq!(edit::tls_directory(&data, &pe), Some(tls as usize));
        let before = data.clone();
        let err = edit::add_tls_callback(&mut data, 0x40_0010).unwrap_err();
        assert!(err.contains("does not edit TLS data there"), "{tls:X}: {err}");
        assert!(data == before);
        assert!(edit::remove_tls_callback(&mut data, 0).is_err());
        assert!(data == before);
    }
    // The same for a directory the editor does not own: the import directory
    // would be hidden by the new section, or move down the file with it.
    type Editor = fn(&mut Vec<u8>) -> Result<String, String>;
    let editors: [(&str, Editor); 4] = [
        ("add_section", |d| edit::add_section(d, ".new", &[1, 2, 3], 3, 0x4000_0040).map(|_| String::new())),
        ("add_tls_callback", |d| edit::add_tls_callback(d, 0x40_0010)),
        ("write_exports", |d| edit::write_exports(d, &edit::ExportTable { dll_name: "a.dll".into(), ..Default::default() })),
        ("write_relocs", |d| edit::write_relocs(d, &[(0x10, 3)])),
    ];
    for imports in [0x300, 0x600] {
        for (name, editor) in editors {
            let mut data = sectionless(0x200, 0x1c0);
            data.resize(0x800, 0);
            edit::w32(&mut data, 0x98 + 96 + 8, imports);
            edit::w32(&mut data, 0x98 + 96 + 12, 40);
            let before = data.clone();
            let err = editor(&mut data).unwrap_err();
            let expected = if name == "add_tls_callback" { "does not edit TLS data there" } else { "mapped through the headers" };
            assert!(err.contains(expected), "{name} {imports:X}: {err}");
            assert!(data == before, "{name} left the buffer changed");
        }
    }
    // An import directory there is not rebuilt by add_imports either, while
    // one inside the headers is.
    let add: Editor = |d| edit::add_imports(d, &[("a.dll".into(), vec![NewImport::Name("F".into())])]);
    let mut data = sectionless(0x200, 0x300);
    edit::w32(&mut data, 0x98 + 96 + 9 * 8, 0);
    edit::w32(&mut data, 0x98 + 96 + 8, 0x300);
    edit::w32(&mut data, 0x98 + 96 + 12, 40);
    let before = data.clone();
    let err = add(&mut data).unwrap_err();
    assert!(err.contains("mapped through the headers"), "{err}");
    assert!(data == before);
    let mut data = sectionless(0x200, 0x1c0);
    add(&mut data).unwrap();
    let pe = Pe::parse(&data).unwrap();
    assert_eq!(edit::tls_directory(&data, &pe), Some(0x1c0));
    assert_eq!(import_names(&data), [("a.dll".to_string(), vec!["F".to_string()])]);
}

#[test]
fn a_tls_directory_over_the_header_structures_is_not_edited() {
    // The data directories, the slot of the next section header (0x178 to
    // 0x1a0; the directory starts before, at or inside it): the array address
    // would be written into a header field, and the edit reported as done.
    // Behind that slot (0x1c0) the header of a second section, for the
    // rewritten relocation table, would land on the directory.
    for tls in [0x100, 0x170, 0x178, 0x190, 0x1c0] {
        let mut data = sectionless(0x200, tls);
        let before = data.clone();
        let err = edit::add_tls_callback(&mut data, 0x40_0010).unwrap_err();
        assert!(err.contains("does not edit TLS data there"), "{tls:X}: {err}");
        assert!(data == before, "{tls:X}");
    }
    // The saved fuzzer input is the 0x178 case with an add_tls_callback first.
    let input =
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/regressions/pe_edit/sectionless_tls_over_section_header.bin")).unwrap();
    assert_eq!(input[0] & 0x0f, 14);
    assert!(input[4..] == sectionless(0x200, 0x178));
    // A section with its raw data over the headers maps the directory there too.
    let mut data = seed("linked.exe");
    let pe = Pe::parse(&data).unwrap();
    let s = &pe.sections[pe.section_of_rva(pe.dir(&data, 9).0).unwrap()];
    edit::w32(&mut data, s.hdr_off + 20, 0);
    let before = data.clone();
    for r in [edit::add_tls_callback(&mut data, pe.image_base + pe.entry as u64), edit::remove_tls_callback(&mut data, 0)] {
        let err = r.unwrap_err();
        assert!(err.contains("does not edit TLS data there"), "{err}");
        assert!(data == before);
    }
}

#[test]
fn a_section_header_is_not_written_over_a_directory_in_the_header_slack() {
    // The TLS directory sits in the slot of the second section header, and
    // its first two fields are zero, so the slot looks free.
    let mut data = sectionless(0x200, 0x1a8);
    edit::w32(&mut data, 0x1a8 + 8, 0x40_0020);
    edit::add_section(&mut data, ".one", &[1, 2, 3], 3, 0x4000_0040).unwrap();
    let before = data.clone();
    let err = edit::add_section(&mut data, ".two", &[1, 2, 3], 3, 0x4000_0040).unwrap_err();
    assert!(err.contains("occupied"), "{err}");
    assert!(data == before);
}

#[test]
fn a_tls_callback_array_over_the_header_structures_is_not_shortened() {
    // AddressOfCallBacks is the VA of the PE signature: the list reads as the
    // signature and the two fields after it, and removing an entry would
    // shift them up.
    let mut data = sectionless(0x200, 0x1c0);
    edit::w32(&mut data, 0x1c0 + 12, 0x40_0080);
    let pe = Pe::parse(&data).unwrap();
    assert_eq!(edit::tls_callbacks(&data, &pe).unwrap().1, [0x4550, 0x14c]);
    let before = data.clone();
    let err = edit::remove_tls_callback(&mut data, 0).unwrap_err();
    assert!(err.contains("does not edit TLS data there"), "{err}");
    assert!(data == before);
    assert!(Pe::parse(&data).is_some());
}

#[test]
fn a_resource_section_mapped_over_the_headers_is_not_rebuilt_in_place() {
    // Found by the pe_edit fuzzer: the last section has PointerToRawData 0, so
    // its raw data is the headers, and the resource directory starts it.
    let input = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/regressions/pe_edit/resource_section_over_headers.bin")).unwrap();
    let mut data = input[4..].to_vec();
    // The operations the fuzzer ran before the failing one.
    let _ = edit::add_section(&mut data, ".fuzz", &[], 0, 0x6000_0020);
    let _ = edit::add_imports(&mut data, &[("fuzz.dll".into(), vec![NewImport::Name("Func".into()), NewImport::Ordinal(3)])]);
    let pe = Pe::parse(&data).unwrap();
    let (rva, _) = pe.dir(&data, 2);
    let s = &pe.sections[pe.section_of_rva(rva).unwrap()];
    assert_eq!((s.va, s.roff), (rva, 0), "the resource section starts the file");
    let mut root = resources::parse(&data, &pe).unwrap_or_default();
    resources::remove(&mut root, &[1, 0, 0]);
    let before = data.clone();
    let err = resources::apply(&mut data, &root).unwrap_err();
    assert!(err.contains("overlaps the headers"), "{err}");
    assert!(data == before, "a refused edit leaves the file as it was");
    // The low level editor refuses on its own, too.
    assert!(edit::resize_last_section(&mut data, 0, &[0; 64]).is_err());
    assert!(data == before);
}

#[test]
fn a_tls_callback_array_past_the_viewer_cap_is_not_edited() {
    let mut data = seed("linked.exe");
    let pe = Pe::parse(&data).unwrap();
    let ps = pe.ptr_size();
    let target = pe.image_base + pe.entry as u64;
    // 1100 callbacks and a terminator in a section of their own; the viewer lists 1024.
    let array = |n: usize| -> Vec<u8> { (0..n as u64).flat_map(|i| (target + i).to_le_bytes()).chain([0; 8]).collect() };
    let va = edit::add_section(&mut data, ".cb", &array(1100), 0, 0x4000_0040).unwrap();
    let pe = Pe::parse(&data).unwrap();
    let dir = edit::tls_directory(&data, &pe).unwrap();
    data[dir + 3 * ps..dir + 4 * ps].copy_from_slice(&(pe.image_base + va as u64).to_le_bytes());
    assert_eq!(edit::tls_callbacks(&data, &pe).unwrap().1.len(), 1024);
    let before = data.clone();
    for err in [edit::remove_tls_callback(&mut data, 0).unwrap_err(), edit::add_tls_callback(&mut data, target).unwrap_err()] {
        assert!(err.contains("more than 1024 entries"), "{err}");
        assert!(data == before, "a refused edit leaves the file as it was");
    }
    // Exactly as many as the cap is still the whole list.
    let at = pe.rva_to_off(va).unwrap();
    data[at + 1024 * ps..at + 1025 * ps].fill(0);
    let text = edit::remove_tls_callback(&mut data, 0).unwrap();
    assert!(text.contains("1023 left"), "{text}");
    assert_eq!(edit::tls_callbacks(&data, &pe).unwrap().1.len(), 1023);
}

#[test]
fn a_truncated_section_table_is_not_edited() {
    // The file ends 12 bytes into its only section header. Enlarging the
    // headers for a new section used to bring the cut-off header back as a
    // section at RVA 0 and put the new one there as well.
    let input = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/regressions/pe_edit/truncated_section_table.bin")).unwrap();
    let orig = input[4..].to_vec();
    let pe = Pe::parse(&orig).unwrap();
    assert_eq!((u16::from_le_bytes([orig[pe.file_hdr + 2], orig[pe.file_hdr + 3]]), pe.sections.len()), (1, 0));
    assert!(pe.sec_table < orig.len() && orig.len() < pe.sec_table + 40);
    type Editor = fn(&mut Vec<u8>) -> Result<String, String>;
    let editors: [(&str, Editor); 4] = [
        ("add_section", |d| edit::add_section(d, ".new", &[0xCC; 300], 300, 0x4000_0040).map(|_| String::new())),
        ("add_section (no raw data)", |d| edit::add_section(d, ".new", &[], 0x3000, 0x4000_0040).map(|_| String::new())),
        ("add_imports", |d| edit::add_imports(d, &[("a.dll".into(), vec![NewImport::Name("F".into())])])),
        ("add_tls_callback", |d| edit::add_tls_callback(d, 0x40_0010)),
    ];
    for (name, editor) in editors {
        let mut data = orig.clone();
        let err = editor(&mut data).unwrap_err();
        assert!(err.contains("the section table is truncated"), "{name}: {err}");
        assert!(data == orig, "{name} left the buffer changed");
    }
}

#[test]
fn a_new_section_goes_behind_an_empty_last_section() {
    let mut data = seed("linked.exe");
    let pe = Pe::parse(&data).unwrap();
    let last = pe.sections.iter().max_by_key(|s| s.va).unwrap().clone();
    assert_eq!(last.va % pe.section_align, 0);
    // An empty section still answers for its first RVA, so a section placed
    // there could not be read: the imports moved into it were lost.
    edit::w32(&mut data, last.hdr_off + 8, 0);
    edit::w32(&mut data, last.hdr_off + 16, 0);
    let before = import_names(&data);
    assert!(!before.is_empty());
    edit::add_imports(&mut data, &[("a.dll".into(), vec![NewImport::Name("F".into())])]).unwrap();
    let pe2 = Pe::parse(&data).unwrap();
    let new = pe2.sections.last().unwrap();
    assert_eq!((new.name.as_str(), new.va), (".idata2", last.va + pe.section_align));
    assert_eq!(pe2.rva_to_off(new.va), Some(new.roff as usize));
    let after = import_names(&data);
    assert_eq!(after.len(), before.len() + 1);
    assert_eq!(&after[..before.len()], &before[..]);

    // Found by the pe_edit fuzzer: seven section headers, all at RVA 0 and
    // empty. The rewritten relocation table went to "RVA 00000000", which a
    // data directory reads as no table at all.
    let input = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/regressions/pe_edit/empty_sections_at_rva_0.bin")).unwrap();
    let mut data = input[4..].to_vec();
    let pe = Pe::parse(&data).unwrap();
    assert!(!pe.sections.is_empty() && pe.sections.iter().all(|s| s.va == 0 && s.vsize.max(s.rsize) == 0));
    let list = [(0x1000, edit::pointer_reloc_type(&pe))];
    let before = data.clone();
    match edit::write_relocs(&mut data, &list) {
        Ok(_) => assert_eq!(edit::parse_relocs(&data, &Pe::parse(&data).unwrap()), list),
        Err(_) => assert!(data == before),
    }
}

#[test]
fn a_new_section_is_not_placed_inside_the_headers() {
    // One empty section at RVA 0 and no section alignment: the next free RVA
    // is 1, in the middle of the DOS header.
    let mut data = seed("tiny.exe");
    let pe = Pe::parse(&data).unwrap();
    edit::w32(&mut data, pe.opt + 32, 1);
    for field in [8, 12, 16] {
        edit::w32(&mut data, pe.sections[0].hdr_off + field, 0);
    }
    assert_eq!(Pe::parse(&data).unwrap().next_section_rva(), 1);
    let before = data.clone();
    let err = edit::add_section(&mut data, ".new", &[1, 2, 3], 3, 0x4000_0040).unwrap_err();
    assert!(err.contains("at RVA 00000001, inside the headers"), "{err}");
    assert!(data == before);
    let err = edit::add_imports(&mut data, &[("a.dll".into(), vec![NewImport::Name("F".into())])]).unwrap_err();
    assert!(err.contains("inside the headers"), "{err}");
    assert!(data == before);
}
