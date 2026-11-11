//! Format independent data model shared by all parsers and the GUI.
//!
//! Every parser turns a raw byte buffer into a tree of `Node`s. Leaf values
//! that live at a fixed place in the file carry a `FieldRef`, which lets the
//! GUI edit them in place without knowing anything about the format.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Endian {
    Little,
    Big,
}

pub type Names = &'static [(u64, &'static str)];

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Hex,
    Dec,
    /// Fixed size, NUL padded ASCII string.
    Str,
    /// Raw bytes shown as a hex string.
    Bytes,
    /// 32 bit unix timestamp.
    Time,
    Flags(Names),
    Enum(Names),
}

#[derive(Clone, Copy, Debug)]
pub struct FieldRef {
    pub offset: usize,
    pub size: usize,
    pub kind: Kind,
    pub endian: Endian,
}

#[derive(Clone, Debug, Default)]
pub struct Cell {
    pub text: String,
    pub field: Option<FieldRef>,
}

impl Cell {
    pub fn text(s: impl Into<String>) -> Cell {
        Cell { text: s.into(), field: None }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Grid {
    pub columns: Vec<&'static str>,
    pub rows: Vec<Vec<Cell>>,
    /// File range each row covers (offset, length), used for hex highlighting.
    pub spans: Vec<Option<(usize, usize)>>,
}

impl Grid {
    pub fn new(columns: &[&'static str]) -> Grid {
        Grid { columns: columns.to_vec(), rows: Vec::new(), spans: Vec::new() }
    }
    pub fn push(&mut self, row: Vec<Cell>, span: Option<(usize, usize)>) {
        self.rows.push(row);
        self.spans.push(span);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tool {
    FileInfo,
    HexEditor,
    AddressConverter,
    Disassembler,
    Strings,
    PeSections,
    PeImportAdder,
    PeRebuilder,
    PeResources,
    PeExports,
    DotnetIl,
    MachoEdit,
    ElfDynamic,
    Compare,
    Search,
    Bookmarks,
    PeRelocs,
    ElfSections,
}

#[derive(Clone, Debug)]
pub enum View {
    Grid(Grid),
    Text(String),
    /// Grid plus an interactive tool rendered by the GUI.
    Tool(Tool, Grid),
}

#[derive(Clone, Debug)]
pub struct Node {
    pub title: String,
    pub view: View,
    pub children: Vec<Node>,
    pub span: Option<(usize, usize)>,
}

impl Node {
    pub fn grid(title: impl Into<String>, grid: Grid) -> Node {
        Node { title: title.into(), view: View::Grid(grid), children: Vec::new(), span: None }
    }
    pub fn text(title: impl Into<String>, text: impl Into<String>) -> Node {
        Node { title: title.into(), view: View::Text(text.into()), children: Vec::new(), span: None }
    }
    pub fn tool(title: impl Into<String>, tool: Tool, grid: Grid) -> Node {
        Node { title: title.into(), view: View::Tool(tool, grid), children: Vec::new(), span: None }
    }
    pub fn with_span(mut self, off: usize, len: usize) -> Node {
        self.span = Some((off, len));
        self
    }
    pub fn with_children(mut self, children: Vec<Node>) -> Node {
        self.children = children;
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arch {
    X86,
    X64,
    Arm,
    Arm64,
    Other,
}

/// A mapping between a virtual address range and a file range.
#[derive(Clone, Debug)]
pub struct Map {
    pub name: String,
    pub vaddr: u64,
    pub vsize: u64,
    pub offset: u64,
    pub fsize: u64,
    pub exec: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Pe,
    Elf,
    MachO,
    Unknown,
}

pub struct Parsed {
    pub format: Format,
    pub description: String,
    pub root: Node,
    pub maps: Vec<Map>,
    /// Preferred load address. RVA = VA - image_base.
    pub image_base: u64,
    pub entry: Option<u64>,
    pub arch: Arch,
    /// Named addresses (imports, exports, symbol tables), sorted by address.
    pub symbols: Vec<(u64, String)>,
    /// Function ranges (start, end) where the format records them, sorted.
    pub functions: Vec<(u64, u64)>,
}

impl Parsed {
    pub fn symbol_at(&self, va: u64) -> Option<&str> {
        let i = self.symbols.partition_point(|s| s.0 < va);
        self.symbols.get(i).filter(|s| s.0 == va).map(|s| s.1.as_str())
    }

    /// The recorded function containing `va`.
    pub fn function_of(&self, va: u64) -> Option<(u64, u64)> {
        let i = self.functions.partition_point(|f| f.0 <= va);
        i.checked_sub(1).map(|i| self.functions[i]).filter(|f| va < f.1)
    }

    pub fn va_to_offset(&self, va: u64) -> Option<(u64, &Map)> {
        self.maps.iter().find(|m| va >= m.vaddr && va - m.vaddr < m.fsize).map(|m| (m.offset.wrapping_add(va - m.vaddr), m))
    }
    pub fn offset_to_va(&self, off: u64) -> Option<(u64, &Map)> {
        self.maps.iter().find(|m| off >= m.offset && off - m.offset < m.fsize).map(|m| (m.vaddr.wrapping_add(off - m.offset), m))
    }
}

// ---------------------------------------------------------------------------
// Byte access helpers

pub fn read_uint(data: &[u8], off: usize, size: usize, endian: Endian) -> Option<u64> {
    let b = data.get(off..off.checked_add(size)?)?;
    if size == 0 || size > 8 {
        return None;
    }
    let mut v = 0u64;
    match endian {
        Endian::Little => {
            for (i, x) in b.iter().enumerate() {
                v |= (*x as u64) << (8 * i);
            }
        }
        Endian::Big => {
            for x in b {
                v = (v << 8) | *x as u64;
            }
        }
    }
    Some(v)
}

/// Turns an offset or size read from a file into a `usize` that is safe to do
/// arithmetic with: values far beyond any real file are clamped, so adding a
/// few of them cannot overflow, and reads at the result simply find nothing.
pub fn clamp_off(v: u64) -> usize {
    v.min((usize::MAX >> 4) as u64) as usize
}

pub fn uint_bytes(v: u64, size: usize, endian: Endian) -> Vec<u8> {
    let le = v.to_le_bytes();
    let mut out = le[..size.min(8)].to_vec();
    if endian == Endian::Big {
        out.reverse();
    }
    out
}

/// Bounds checked reader with a fixed endianness. Out of range reads give 0,
/// which keeps parsers of truncated or malformed files simple and panic free.
#[derive(Clone, Copy)]
pub struct Rd<'a> {
    pub data: &'a [u8],
    pub endian: Endian,
}

impl<'a> Rd<'a> {
    pub fn new(data: &'a [u8], endian: Endian) -> Rd<'a> {
        Rd { data, endian }
    }
    pub fn has(&self, off: usize, len: usize) -> bool {
        off.checked_add(len).is_some_and(|e| e <= self.data.len())
    }
    pub fn uint(&self, off: usize, size: usize) -> u64 {
        read_uint(self.data, off, size, self.endian).unwrap_or(0)
    }
    pub fn u8(&self, off: usize) -> u8 {
        self.data.get(off).copied().unwrap_or(0)
    }
    pub fn u16(&self, off: usize) -> u16 {
        self.uint(off, 2) as u16
    }
    pub fn u32(&self, off: usize) -> u32 {
        self.uint(off, 4) as u32
    }
    pub fn u64(&self, off: usize) -> u64 {
        self.uint(off, 8)
    }
    pub fn bytes(&self, off: usize, len: usize) -> &'a [u8] {
        let end = off.saturating_add(len).min(self.data.len());
        self.data.get(off..end).unwrap_or(&[])
    }
    /// NUL terminated string, at most `max` bytes.
    pub fn cstr(&self, off: usize, max: usize) -> String {
        let b = self.bytes(off, max);
        let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
        printable(&b[..end])
    }
}

pub fn printable(b: &[u8]) -> String {
    b.iter().map(|c| if (0x20..0x7f).contains(c) { *c as char } else { '.' }).collect()
}

// ---------------------------------------------------------------------------
// Formatting and parsing of field values

pub fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02X}"));
    }
    s
}

pub fn lookup(names: Names, v: u64) -> Option<&'static str> {
    names.iter().find(|(k, _)| *k == v).map(|(_, n)| *n)
}

pub fn flags_text(names: Names, v: u64) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut rest = v;
    for (bit, name) in names {
        if *bit != 0 && v & bit == *bit {
            parts.push((*name).to_string());
            rest &= !bit;
        }
    }
    if rest != 0 {
        parts.push(format!("0x{rest:X}"));
    }
    parts.join(" | ")
}

pub fn time_text(t: u64) -> String {
    if t == 0 || t == 0xFFFF_FFFF {
        return String::new();
    }
    let days = (t / 86400) as i64;
    let secs = t % 86400;
    // Civil date from days since the unix epoch (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", secs / 3600, secs % 3600 / 60, secs % 60)
}

impl FieldRef {
    pub fn value(&self, data: &[u8]) -> u64 {
        read_uint(data, self.offset, self.size.min(8), self.endian).unwrap_or(0)
    }

    pub fn format(&self, data: &[u8]) -> String {
        let Some(b) = data.get(self.offset..self.offset.saturating_add(self.size)) else {
            return "<out of file>".into();
        };
        match self.kind {
            Kind::Str => {
                let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
                printable(&b[..end])
            }
            Kind::Bytes => hex_bytes(b),
            Kind::Dec => self.value(data).to_string(),
            _ => format!("{:0w$X}", self.value(data), w = self.size * 2),
        }
    }

    pub fn meaning(&self, data: &[u8]) -> String {
        let v = self.value(data);
        match self.kind {
            Kind::Time => time_text(v),
            Kind::Flags(n) => flags_text(n, v),
            Kind::Enum(n) => lookup(n, v).unwrap_or("").to_string(),
            _ => String::new(),
        }
    }

    /// Turn user input into the bytes to store for this field.
    pub fn parse(&self, text: &str) -> Result<Vec<u8>, String> {
        let t = text.trim();
        match self.kind {
            Kind::Str => {
                if t.len() > self.size {
                    return Err(format!("string is longer than {} bytes", self.size));
                }
                let mut out = t.as_bytes().to_vec();
                out.resize(self.size, 0);
                Ok(out)
            }
            Kind::Bytes => {
                let out = parse_hex_bytes(t)?;
                if out.len() != self.size {
                    return Err(format!("expected exactly {} bytes", self.size));
                }
                Ok(out)
            }
            Kind::Dec => {
                let v = parse_number(t, 10)?;
                self.check(v)
            }
            _ => {
                let v = parse_number(t, 16)?;
                self.check(v)
            }
        }
    }

    fn check(&self, v: u64) -> Result<Vec<u8>, String> {
        if self.size < 8 && v >> (self.size * 8) != 0 {
            return Err(format!("value does not fit in {} bytes", self.size));
        }
        Ok(uint_bytes(v, self.size, self.endian))
    }
}

pub fn parse_number(t: &str, default_radix: u32) -> Result<u64, String> {
    let t = t.trim().replace('_', "");
    let (s, radix) = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        (h.to_string(), 16)
    } else if let Some(h) = t.strip_suffix('h').or_else(|| t.strip_suffix('H')) {
        (h.to_string(), 16)
    } else {
        (t.clone(), default_radix)
    };
    u64::from_str_radix(&s, radix).map_err(|_| format!("'{t}' is not a valid number"))
}

pub fn parse_hex_bytes(t: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = t.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b',').collect();
    if !digits.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    digits.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap_or("zz"), 16).map_err(|_| "invalid hex digit".to_string())).collect()
}

// ---------------------------------------------------------------------------
// Builder for the classic "Member / Offset / Size / Value / Meaning" table

pub struct Fields<'a> {
    pub rd: Rd<'a>,
    pub grid: Grid,
}

impl<'a> Fields<'a> {
    pub fn new(data: &'a [u8], endian: Endian) -> Fields<'a> {
        Fields { rd: Rd::new(data, endian), grid: Grid::new(&["Member", "Offset", "Size", "Value", "Meaning"]) }
    }

    pub fn add(&mut self, name: &str, offset: usize, size: usize, kind: Kind) -> &mut Self {
        let f = FieldRef { offset, size, kind, endian: self.rd.endian };
        let size_text = match size {
            1 => "Byte".to_string(),
            2 => "Word".to_string(),
            4 => "Dword".to_string(),
            8 => "Qword".to_string(),
            n => format!("{n} bytes"),
        };
        self.grid.push(
            vec![
                Cell::text(name),
                Cell::text(format!("{offset:08X}")),
                Cell::text(size_text),
                Cell { text: f.format(self.rd.data), field: Some(f) },
                Cell::text(f.meaning(self.rd.data)),
            ],
            Some((offset, size)),
        );
        self
    }

    /// Add consecutive fields starting at `base`; returns the offset after the last one.
    pub fn seq(&mut self, base: usize, fields: &[(&str, usize, Kind)]) -> usize {
        let mut off = base;
        for (name, size, kind) in fields {
            self.add(name, off, *size, *kind);
            off += size;
        }
        off
    }

    /// Overwrite the meaning column of the most recently added row.
    pub fn note(&mut self, text: impl Into<String>) -> &mut Self {
        if let Some(row) = self.grid.rows.last_mut() {
            row[4].text = text.into();
        }
        self
    }

    pub fn finish(self) -> Grid {
        self.grid
    }
}

/// Editable cell for use in free form grids.
pub fn cell(data: &[u8], offset: usize, size: usize, kind: Kind, endian: Endian) -> Cell {
    let f = FieldRef { offset, size, kind, endian };
    Cell { text: f.format(data), field: Some(f) }
}

pub fn kv_grid(pairs: Vec<(String, String)>) -> Grid {
    let mut g = Grid::new(&["Property", "Value"]);
    for (k, v) in pairs {
        g.push(vec![Cell::text(k), Cell::text(v)], None);
    }
    g
}

pub fn size_text(n: u64) -> String {
    if n < 1024 {
        format!("{n} bytes")
    } else if n < 1024 * 1024 {
        format!("{:.2} KB ({n} bytes)", n as f64 / 1024.0)
    } else {
        format!("{:.2} MB ({n} bytes)", n as f64 / 1048576.0)
    }
}

pub fn entropy(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for x in b {
        counts[*x as usize] += 1;
    }
    let n = b.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / n;
            -p * p.log2()
        })
        .sum::<f64>()
        .abs()
}
