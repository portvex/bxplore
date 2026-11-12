//! Resource directory: parsing into an owned tree, rebuilding the tree back
//! into bytes, and decoders used for previews.

use super::consts::RES_TYPES;
use super::{Pe, edit};
use crate::model::*;

const LE: Endian = Endian::Little;

#[derive(Clone, Debug, PartialEq)]
pub enum ResId {
    Id(u32),
    Name(String),
}

impl ResId {
    pub fn parse(text: &str) -> ResId {
        let t = text.trim();
        match t.parse::<u32>() {
            Ok(v) if v <= 0xFFFF => ResId::Id(v),
            _ => ResId::Name(t.to_uppercase()),
        }
    }
    pub fn label(&self) -> String {
        match self {
            ResId::Id(v) => v.to_string(),
            ResId::Name(n) => format!("\"{n}\""),
        }
    }
    pub fn type_label(&self) -> String {
        match self {
            ResId::Id(v) => match RES_TYPES.iter().find(|(k, _)| k == v) {
                Some((_, n)) => format!("{n} ({v})"),
                None => v.to_string(),
            },
            ResId::Name(n) => format!("\"{n}\""),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Src {
    File { off: usize, size: usize },
    Mem(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct ResData {
    pub src: Src,
    pub codepage: u32,
    pub rva: u32,
}

impl ResData {
    pub fn bytes<'a>(&'a self, data: &'a [u8]) -> &'a [u8] {
        match &self.src {
            Src::File { off, size } => Rd::new(data, LE).bytes(*off, *size),
            Src::Mem(v) => v,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn len(&self) -> usize {
        match &self.src {
            Src::File { size, .. } => *size,
            Src::Mem(v) => v.len(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ResDir {
    pub chars: u32,
    pub time: u32,
    pub major: u16,
    pub minor: u16,
    pub entries: Vec<ResEntry>,
}

#[derive(Clone, Debug)]
pub struct ResEntry {
    pub id: ResId,
    pub node: ResNode,
}

#[derive(Clone, Debug)]
pub enum ResNode {
    Dir(ResDir),
    Data(ResData),
}

pub fn parse(data: &[u8], pe: &Pe) -> Option<ResDir> {
    let (rva, _) = pe.dir(data, 2);
    let base = (rva != 0).then(|| pe.rva_to_off(rva)).flatten()?;
    let mut budget = 100_000usize;
    Some(parse_dir(data, pe, base, 0, 0, &mut budget))
}

fn parse_dir(data: &[u8], pe: &Pe, base: usize, rel: usize, depth: usize, budget: &mut usize) -> ResDir {
    let rd = Rd::new(data, LE);
    let off = base + rel;
    let mut dir = ResDir { chars: rd.u32(off), time: rd.u32(off + 4), major: rd.u16(off + 8), minor: rd.u16(off + 10), entries: Vec::new() };
    if !rd.has(off, 16) || depth > 6 {
        return dir;
    }
    let count = rd.u16(off + 12) as usize + rd.u16(off + 14) as usize;
    for i in 0..count {
        let e = off + 16 + i * 8;
        if !rd.has(e, 8) || *budget == 0 {
            break;
        }
        *budget -= 1;
        let name = rd.u32(e);
        let target = rd.u32(e + 4);
        let id = if name & 0x8000_0000 != 0 {
            let s = base + (name & 0x7FFF_FFFF) as usize;
            let len = rd.u16(s) as usize;
            let units: Vec<u16> = (0..len).map(|k| rd.u16(s + 2 + k * 2)).collect();
            ResId::Name(String::from_utf16_lossy(&units))
        } else {
            ResId::Id(name)
        };
        let node = if target & 0x8000_0000 != 0 {
            ResNode::Dir(parse_dir(data, pe, base, (target & 0x7FFF_FFFF) as usize, depth + 1, budget))
        } else {
            let d = base + target as usize;
            let drva = rd.u32(d);
            let size = rd.u32(d + 4) as usize;
            let foff = pe.rva_to_off(drva).unwrap_or(usize::MAX);
            let size = if foff == usize::MAX { 0 } else { size.min(data.len().saturating_sub(foff)) };
            ResNode::Data(ResData { src: Src::File { off: foff, size }, codepage: rd.u32(d + 8), rva: drva })
        };
        dir.entries.push(ResEntry { id, node });
    }
    dir
}

pub fn node(data: &[u8], pe: &Pe) -> Option<Node> {
    let (rva, size) = pe.dir(data, 2);
    let off = (rva != 0).then(|| pe.rva_to_off(rva)).flatten()?;
    let mut f = Fields::new(data, LE);
    f.seq(
        off,
        &[
            ("Characteristics", 4, Kind::Hex),
            ("TimeDateStamp", 4, Kind::Time),
            ("MajorVersion", 2, Kind::Hex),
            ("MinorVersion", 2, Kind::Hex),
            ("NumberOfNamedEntries", 2, Kind::Hex),
            ("NumberOfIdEntries", 2, Kind::Hex),
        ],
    );
    Some(Node::tool("Resource Directory", Tool::PeResources, f.finish()).with_span(off, size as usize))
}

// ---------------------------------------------------------------------------
// Tree editing

pub fn leaf<'a>(root: &'a ResDir, path: &[usize]) -> Option<&'a ResData> {
    let mut dir = root;
    for (i, idx) in path.iter().enumerate() {
        match &dir.entries.get(*idx)?.node {
            ResNode::Dir(d) => dir = d,
            ResNode::Data(d) => return (i + 1 == path.len()).then_some(d),
        }
    }
    None
}

pub fn leaf_mut<'a>(root: &'a mut ResDir, path: &[usize]) -> Option<&'a mut ResData> {
    let mut dir = root;
    for (i, idx) in path.iter().enumerate() {
        match &mut dir.entries.get_mut(*idx)?.node {
            ResNode::Dir(d) => dir = d,
            ResNode::Data(d) => return (i + 1 == path.len()).then_some(d),
        }
    }
    None
}

pub fn remove(root: &mut ResDir, path: &[usize]) -> bool {
    let Some((last, parents)) = path.split_last() else { return false };
    let mut dir = root;
    for idx in parents {
        match dir.entries.get_mut(*idx).map(|e| &mut e.node) {
            Some(ResNode::Dir(d)) => dir = d,
            _ => return false,
        }
    }
    if *last < dir.entries.len() {
        dir.entries.remove(*last);
        true
    } else {
        false
    }
}

fn subdir<'a>(dir: &'a mut ResDir, id: &ResId) -> &'a mut ResDir {
    let pos = dir.entries.iter().position(|e| &e.id == id && matches!(e.node, ResNode::Dir(_)));
    let pos = pos.unwrap_or_else(|| {
        dir.entries.push(ResEntry { id: id.clone(), node: ResNode::Dir(ResDir::default()) });
        dir.entries.len() - 1
    });
    match &mut dir.entries[pos].node {
        ResNode::Dir(d) => d,
        ResNode::Data(_) => unreachable!(),
    }
}

/// Add (or replace) the resource identified by type / name / language.
pub fn insert(root: &mut ResDir, ty: &ResId, name: &ResId, lang: &ResId, bytes: Vec<u8>) {
    let langs = subdir(subdir(root, ty), name);
    langs.entries.retain(|e| &e.id != lang);
    langs.entries.push(ResEntry { id: lang.clone(), node: ResNode::Data(ResData { src: Src::Mem(bytes), codepage: 0, rva: 0 }) });
}

// ---------------------------------------------------------------------------
// Rebuilding

fn sort_key(id: &ResId) -> (u8, String, u32) {
    match id {
        ResId::Name(n) => (0, n.to_uppercase(), 0),
        ResId::Id(v) => (1, String::new(), *v),
    }
}

pub fn normalize(dir: &mut ResDir) {
    // Drop empty directories, then order entries the way the loader expects.
    for e in &mut dir.entries {
        if let ResNode::Dir(d) = &mut e.node {
            normalize(d);
        }
    }
    dir.entries.retain(|e| !matches!(&e.node, ResNode::Dir(d) if d.entries.is_empty()));
    dir.entries.sort_by_key(|e| sort_key(&e.id));
}

fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Serialize the tree for placement at `base_rva`.
pub fn serialize(root: &ResDir, data: &[u8], base_rva: u32) -> Vec<u8> {
    // Breadth first layout of the directory tables.
    let mut dirs: Vec<(&ResDir, usize)> = vec![(root, 0)];
    let mut children: Vec<Vec<usize>> = Vec::new();
    let mut datas: Vec<&ResData> = Vec::new();
    let mut next = 16 + 8 * root.entries.len();
    let mut i = 0;
    while i < dirs.len() {
        let d = dirs[i].0;
        let mut ch = Vec::new();
        for e in &d.entries {
            match &e.node {
                ResNode::Dir(sd) => {
                    ch.push(dirs.len());
                    dirs.push((sd, next));
                    next += 16 + 8 * sd.entries.len();
                }
                ResNode::Data(dt) => {
                    ch.push(datas.len());
                    datas.push(dt);
                }
            }
        }
        children.push(ch);
        i += 1;
    }
    let data_entries = next;
    let mut out = vec![0u8; data_entries + datas.len() * 16];

    // Name strings go after the data entries.
    let mut name_offs: Vec<Vec<Option<usize>>> = Vec::new();
    for (d, _) in &dirs {
        let mut v = Vec::new();
        for e in &d.entries {
            v.push(match &e.id {
                ResId::Name(n) => {
                    let off = out.len();
                    let units: Vec<u16> = n.encode_utf16().collect();
                    out.extend_from_slice(&(units.len() as u16).to_le_bytes());
                    for u in units {
                        out.extend_from_slice(&u.to_le_bytes());
                    }
                    Some(off)
                }
                ResId::Id(_) => None,
            });
        }
        name_offs.push(v);
    }

    // Raw data, each blob aligned to 8 bytes.
    for (k, dt) in datas.iter().enumerate() {
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
        let off = out.len();
        let bytes = dt.bytes(data);
        out.extend_from_slice(bytes);
        let e = data_entries + k * 16;
        put32(&mut out, e, base_rva.wrapping_add(off as u32));
        put32(&mut out, e + 4, bytes.len() as u32);
        put32(&mut out, e + 8, dt.codepage);
    }
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }

    for (di, (d, off)) in dirs.iter().enumerate() {
        let named = d.entries.iter().filter(|e| matches!(e.id, ResId::Name(_))).count();
        put32(&mut out, *off, d.chars);
        put32(&mut out, off + 4, d.time);
        put16(&mut out, off + 8, d.major);
        put16(&mut out, off + 10, d.minor);
        put16(&mut out, off + 12, named as u16);
        put16(&mut out, off + 14, (d.entries.len() - named) as u16);
        for (ei, e) in d.entries.iter().enumerate() {
            let eo = off + 16 + ei * 8;
            let name = match (&e.id, name_offs[di][ei]) {
                (_, Some(s)) => 0x8000_0000 | s as u32,
                (ResId::Id(v), _) => *v,
                _ => 0,
            };
            let target = match &e.node {
                ResNode::Dir(_) => 0x8000_0000 | dirs[children[di][ei]].1 as u32,
                ResNode::Data(_) => (data_entries + children[di][ei] * 16) as u32,
            };
            put32(&mut out, eo, name);
            put32(&mut out, eo + 4, target);
        }
    }
    out
}

/// Write a modified resource tree back into the file. The existing resource
/// section is rewritten in place when it is the last section and holds only
/// resources; otherwise a new `.rsrc` section is appended.
pub fn apply(data: &mut Vec<u8>, root: &ResDir) -> Result<String, String> {
    let pe = Pe::parse(data).ok_or("not a valid PE file")?;
    if pe.num_dirs < 3 {
        return Err("the optional header has no resource data directory".into());
    }
    let mut root = root.clone();
    normalize(&mut root);
    let (rva, _) = pe.dir(data, 2);
    let in_place = pe.section_of_rva(rva).filter(|_| rva != 0).filter(|i| {
        let s = &pe.sections[*i];
        let last_va = pe.sections.iter().all(|o| o.va <= s.va);
        let last_raw = pe.sections.iter().all(|o| o.rsize == 0 || o.roff <= s.roff);
        s.va == rva && last_va && last_raw && s.rsize > 0
    });
    match in_place {
        Some(idx) => {
            let blob = serialize(&root, data, rva);
            edit::resize_last_section(data, idx, &blob)?;
            edit::w32(data, pe.dirs_off + 20, blob.len() as u32);
            Ok(format!("Resource section rebuilt in place ({} bytes)", blob.len()))
        }
        None => {
            let base = pe.next_section_rva();
            let blob = serialize(&root, data, base);
            let va = edit::add_section(data, ".rsrc", &blob, blob.len() as u32, 0x4000_0040)?;
            edit::w32(data, pe.dirs_off + 16, va);
            edit::w32(data, pe.dirs_off + 20, blob.len() as u32);
            Ok(format!("Resources rebuilt into a new .rsrc section at RVA {va:08X} ({} bytes)", blob.len()))
        }
    }
}

// ---------------------------------------------------------------------------
// Decoders for previews

fn utf16_at(rd: &Rd, off: usize, max_units: usize) -> (String, usize) {
    let mut units = Vec::new();
    let mut o = off;
    while units.len() < max_units && rd.has(o, 2) {
        let u = rd.u16(o);
        o += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    (String::from_utf16_lossy(&units), o)
}

pub fn utf16_text(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

pub fn version_info(bytes: &[u8]) -> String {
    let rd = Rd::new(bytes, LE);
    let mut out = String::new();
    version_node(&rd, 0, 0, &mut out);
    out
}

fn version_node(rd: &Rd, off: usize, depth: usize, out: &mut String) -> usize {
    let len = rd.u16(off) as usize;
    let vlen = rd.u16(off + 2) as usize;
    let ty = rd.u16(off + 4);
    if len < 6 || depth > 5 || !rd.has(off, 6) {
        return off + len.max(6);
    }
    let (key, after_key) = utf16_at(rd, off + 6, 256);
    let value = after_key.div_ceil(4) * 4;
    let end = off + len;
    let indent = "  ".repeat(depth);
    let mut child = value;
    if key == "VS_VERSION_INFO" {
        out.push_str("VS_VERSION_INFO\n");
        if vlen >= 52 && rd.u32(value) == 0xFEEF_04BD {
            let v = |o: usize| {
                let ms = rd.u32(value + o);
                let ls = rd.u32(value + o + 4);
                format!("{}.{}.{}.{}", ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
            };
            out.push_str(&format!("  FileVersion:    {}\n", v(8)));
            out.push_str(&format!("  ProductVersion: {}\n", v(16)));
            out.push_str(&format!("  FileFlags:      {:08X} (mask {:08X})\n", rd.u32(value + 28), rd.u32(value + 24)));
            out.push_str(&format!("  FileOS:         {:08X}\n", rd.u32(value + 32)));
            out.push_str(&format!("  FileType:       {:08X}\n", rd.u32(value + 36)));
        }
        child = (value + vlen).div_ceil(4) * 4;
    } else if key == "Translation" {
        let pairs: Vec<String> = (0..vlen / 4).map(|i| format!("{:04X}-{:04X}", rd.u16(value + i * 4), rd.u16(value + i * 4 + 2))).collect();
        out.push_str(&format!("{indent}Translation: {}\n", pairs.join(", ")));
        return end;
    } else if vlen > 0 && ty == 1 {
        let (text, _) = utf16_at(rd, value, vlen);
        out.push_str(&format!("{indent}{key}: {text}\n"));
        return end;
    } else {
        out.push_str(&format!("{indent}{key}\n"));
        if vlen > 0 {
            child = (value + vlen).div_ceil(4) * 4;
        }
    }
    let mut guard = 0;
    while child + 6 <= end && rd.has(child, 6) && guard < 512 {
        let next = version_node(rd, child, depth + 1, out);
        if next <= child {
            break;
        }
        child = next.div_ceil(4) * 4;
        guard += 1;
    }
    end
}

pub fn string_table(bytes: &[u8], block_id: u32) -> String {
    let rd = Rd::new(bytes, LE);
    let mut out = String::new();
    let mut off = 0;
    for i in 0..16u32 {
        if !rd.has(off, 2) {
            break;
        }
        let len = rd.u16(off) as usize;
        off += 2;
        if len > 0 {
            let text = utf16_text(rd.bytes(off, len * 2));
            out.push_str(&format!("{:5}: {}\n", block_id.saturating_sub(1) * 16 + i, text.replace('\n', "\\n")));
            off += len * 2;
        }
    }
    out
}

pub fn group_icon(bytes: &[u8]) -> String {
    let rd = Rd::new(bytes, LE);
    let count = rd.u16(4) as usize;
    let mut out = format!("Type: {}, {} image(s)\n\n", if rd.u16(2) == 2 { "cursor" } else { "icon" }, count);
    for i in 0..count.min(256) {
        let e = 6 + i * 14;
        if !rd.has(e, 14) {
            break;
        }
        let dim = |v: u8| if v == 0 { 256 } else { v as u32 };
        out.push_str(&format!(
            "  {:3}x{:<3} {:2} bpp  {:7} bytes  icon id {}\n",
            dim(rd.u8(e)),
            dim(rd.u8(e + 1)),
            rd.u16(e + 6),
            rd.u32(e + 8),
            rd.u16(e + 12)
        ));
    }
    out
}

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Memory a resource preview may decode into. A few header bytes can claim
/// any size: a 368-byte RLE bitmap claimed 65282x2619 pixels (684 MB).
pub const MAX_IMAGE_BYTES: u64 = 64 << 20;

/// Decode with the memory limit; an image claiming more fails to decode.
fn load(bytes: &[u8], format: image::ImageFormat) -> Option<image::DynamicImage> {
    let mut reader = image::ImageReader::with_format(std::io::Cursor::new(bytes), format);
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(MAX_IMAGE_BYTES);
    reader.limits(limits);
    reader.decode().ok()
}

/// Decode an RT_ICON or RT_BITMAP resource to RGBA pixels, scaled down to fit
/// `max_side` (the largest texture the graphics card takes). The last item is
/// the image's own width and height, before any scaling.
pub fn decode_image(bytes: &[u8], is_icon: bool, max_side: usize) -> Option<(usize, usize, Vec<u8>, (u32, u32))> {
    let rd = Rd::new(bytes, LE);
    let img = if bytes.starts_with(PNG_MAGIC) {
        load(bytes, image::ImageFormat::Png)?
    } else if is_icon {
        let w = rd.u32(4);
        let h = rd.u32(8) / 2;
        let mut ico = vec![0, 0, 1, 0, 1, 0];
        ico.push(if w >= 256 { 0 } else { w as u8 });
        ico.push(if h >= 256 { 0 } else { h as u8 });
        ico.extend_from_slice(&[0, 0]);
        ico.extend_from_slice(&rd.u16(12).to_le_bytes());
        ico.extend_from_slice(&rd.u16(14).to_le_bytes());
        ico.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        ico.extend_from_slice(&22u32.to_le_bytes());
        ico.extend_from_slice(bytes);
        load(&ico, image::ImageFormat::Ico)?
    } else {
        let hdr = rd.u32(0) as usize;
        let bpp = rd.u16(14) as u32;
        let used = rd.u32(32) as usize;
        let palette = if used != 0 {
            used
        } else if bpp <= 8 {
            1usize << bpp
        } else {
            0
        };
        let masks = if hdr == 40 && rd.u32(16) == 3 { 12 } else { 0 };
        let offbits = 14 + hdr + palette * 4 + masks;
        let mut bmp = b"BM".to_vec();
        bmp.extend_from_slice(&((bytes.len() + 14) as u32).to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&(offbits as u32).to_le_bytes());
        bmp.extend_from_slice(bytes);
        load(&bmp, image::ImageFormat::Bmp)?
    };
    let original = (img.width(), img.height());
    let side = u32::try_from(max_side).unwrap_or(u32::MAX).max(1);
    let img = if img.width() > side || img.height() > side { img.thumbnail(side, side) } else { img };
    let rgba = img.to_rgba8();
    Some((rgba.width() as usize, rgba.height() as usize, rgba.into_raw(), original))
}
