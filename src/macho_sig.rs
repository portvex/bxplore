//! Mach-O code signature: the embedded signature SuperBlob with its code
//! directory, requirements, entitlements and CMS signature. The page hashes
//! of the code directory are recomputed and compared.

use crate::model::{Endian, Rd, hex_bytes, printable};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

const CS_FLAGS: &[(u32, &str)] = &[
    (0x1, "valid"),
    (0x2, "adhoc"),
    (0x4, "get-task-allow"),
    (0x8, "installer"),
    (0x10, "forced-lv"),
    (0x100, "hard"),
    (0x200, "kill"),
    (0x400, "check-expiration"),
    (0x800, "restrict"),
    (0x1000, "enforcement"),
    (0x2000, "library-validation"),
    (0x10000, "runtime (hardened)"),
    (0x20000, "linker-signed"),
];

fn slot_name(ty: u32) -> String {
    match ty {
        0 => "CodeDirectory".into(),
        1 => "Info.plist".into(),
        2 => "Requirements".into(),
        3 => "ResourceDirectory".into(),
        4 => "Application".into(),
        5 => "Entitlements".into(),
        7 => "DER Entitlements".into(),
        0x1000..=0x1005 => format!("Alternate CodeDirectory {}", ty - 0x1000),
        0x10000 => "CMS Signature".into(),
        _ => format!("slot {ty:X}"),
    }
}

fn hash(ty: u8, data: &[u8]) -> Option<Vec<u8>> {
    Some(match ty {
        1 => Sha1::digest(data).to_vec(),
        2 => Sha256::digest(data).to_vec(),
        3 => Sha256::digest(data)[..20].to_vec(),
        4 => Sha384::digest(data).to_vec(),
        _ => return None,
    })
}

/// `base` is the start of the architecture slice; offsets in the load
/// command and the code limit are relative to it.
pub fn describe(data: &[u8], base: usize, sig_off: usize, sig_size: usize) -> String {
    let rd = Rd::new(data, Endian::Big);
    let start = base.saturating_add(sig_off);
    let mut out = String::new();
    if !rd.has(start, 12) || rd.u32(start) != 0xfade_0cc0 {
        return "The signature data is not an embedded signature SuperBlob.\n".into();
    }
    let count = (rd.u32(start + 8) as usize).min(64);
    out.push_str(&format!("Embedded signature at {start:08X}, {} of {sig_size} bytes used, {count} blob(s)\n\n", rd.u32(start + 4)));
    let mut entitlements = String::new();
    for i in 0..count {
        let ty = rd.u32(start + 12 + i * 8);
        let b = start.saturating_add(rd.u32(start + 16 + i * 8) as usize);
        if !rd.has(b, 8) {
            continue;
        }
        let magic = rd.u32(b);
        let len = rd.u32(b + 4) as usize;
        out.push_str(&format!("{} (magic {magic:08X}, {len} bytes at {b:08X})\n", slot_name(ty)));
        match magic {
            0xfade_0c02 => code_directory(data, base, b, len, &mut out),
            0xfade_0c01 => out.push_str(&format!("  {} requirement(s)\n", rd.u32(b + 8))),
            0xfade_7171 => entitlements = String::from_utf8_lossy(rd.bytes(b + 8, len.saturating_sub(8).min(1 << 20))).into_owned(),
            0xfade_0b01 => out.push_str(if len <= 8 {
                "  empty: ad hoc signature, no certificate chain\n"
            } else {
                "  CMS (PKCS#7) signature with the signing certificate chain; not verified here\n"
            }),
            _ => {}
        }
        out.push('\n');
    }
    if !entitlements.is_empty() {
        out.push_str("Entitlements\n");
        for l in entitlements.lines() {
            out.push_str(&format!("  {l}\n"));
        }
    }
    out
}

fn code_directory(data: &[u8], base: usize, b: usize, len: usize, out: &mut String) {
    let rd = Rd::new(data, Endian::Big);
    let version = rd.u32(b + 8);
    let flags = rd.u32(b + 12);
    let hash_off = rd.u32(b + 16) as usize;
    let ident_off = rd.u32(b + 20) as usize;
    let n_special = rd.u32(b + 24) as usize;
    let n_code = rd.u32(b + 28) as usize;
    let code_limit = rd.u32(b + 32) as usize;
    let hash_size = rd.u8(b + 36) as usize;
    let hash_type = rd.u8(b + 37);
    let page_shift = rd.u8(b + 39) as u32;
    let names: Vec<&str> = CS_FLAGS.iter().filter(|(bit, _)| flags & bit != 0).map(|(_, n)| *n).collect();
    out.push_str(&format!("  Version:     {version:X}\n  Identifier:  {}\n", rd.cstr(b + ident_off, 256)));
    if version >= 0x20200 {
        let team = rd.u32(b + 48) as usize;
        if team != 0 {
            out.push_str(&format!("  Team ID:     {}\n", rd.cstr(b + team, 64)));
        }
    }
    out.push_str(&format!("  Flags:       {flags:08X} {}\n", if names.is_empty() { String::new() } else { format!("({})", names.join(", ")) }));
    let hash_name = match hash_type {
        1 => "SHA-1",
        2 => "SHA-256",
        3 => "SHA-256 truncated to 20 bytes",
        4 => "SHA-384",
        _ => "unknown",
    };
    out.push_str(&format!("  Hash:        {hash_name}, {hash_size} bytes\n"));
    out.push_str(&format!("  Code limit:  {code_limit:X}\n  Slots:       {n_code} code, {n_special} special\n"));
    if let Some(cd) = data.get(b..b.saturating_add(len))
        && let Some(h) = hash(hash_type, cd)
    {
        out.push_str(&format!("  CDHash:      {}\n", hex_bytes(&h[..h.len().min(20)]).to_lowercase()));
    }
    // Recompute the hash of every code page.
    if page_shift == 0 || page_shift > 24 || hash_size == 0 || hash_size > 64 || n_code > 1 << 20 {
        out.push_str("  Page hashes: not checked (single page or unusual parameters)\n");
        return;
    }
    let page = 1usize << page_shift;
    let mut bad = Vec::new();
    let mut checked = 0;
    for i in 0..n_code {
        let from = i * page;
        let to = ((i + 1) * page).min(code_limit);
        let (Some(bytes), true) = (data.get(base.saturating_add(from)..base.saturating_add(to)), from < to) else { break };
        let Some(h) = hash(hash_type, bytes) else {
            out.push_str("  Page hashes: not checked (unknown hash type)\n");
            return;
        };
        if rd.bytes(b + hash_off + i * hash_size, hash_size) != &h[..hash_size.min(h.len())] {
            bad.push(i);
        }
        checked += 1;
    }
    if bad.is_empty() && checked == n_code {
        out.push_str(&format!("  Page hashes: OK, all {checked} pages of {page} bytes match; the code is unchanged since signing\n"));
    } else {
        let list: Vec<String> = bad.iter().take(8).map(|i| format!("{:X}", i * page)).collect();
        out.push_str(&format!(
            "  Page hashes: MISMATCH, {} of {n_code} pages differ{}{}; the file was modified after signing\n",
            bad.len() + (n_code - checked),
            if list.is_empty() { String::new() } else { format!(" (first at offsets {})", list.join(", ")) },
            if checked < n_code { ", some pages are missing" } else { "" },
        ));
    }
    let _ = printable;
}
