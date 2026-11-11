//! .NET metadata: the `#~` table stream (ECMA-335 II.22 and II.24), signature
//! blobs (II.23.2), IL method bodies (II.25.4 and Partition III), plus the
//! user string and GUID heaps. Every table cell is an editable field.

use crate::model::*;
use std::cell::RefCell;

const LE: Endian = Endian::Little;
const MAX_ROWS: usize = 100_000;
const MAX_HEAP_ROWS: usize = 50_000;

#[derive(Clone, Copy)]
enum Col {
    U2,
    U4,
    Str,
    Guid,
    Blob,
    /// Row index into one table.
    Table(u8),
    /// Coded index: low bits select one of several tables.
    Coded(&'static Coded),
}

struct Coded {
    bits: u32,
    /// 0xFF marks an unused tag value.
    tables: &'static [u8],
}

const TYPE_DEF_OR_REF: Coded = Coded { bits: 2, tables: &[0x02, 0x01, 0x1B] };
const HAS_CONSTANT: Coded = Coded { bits: 2, tables: &[0x04, 0x08, 0x17] };
const HAS_CUSTOM_ATTRIBUTE: Coded = Coded {
    bits: 5,
    tables: &[0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B],
};
const HAS_FIELD_MARSHAL: Coded = Coded { bits: 1, tables: &[0x04, 0x08] };
const HAS_DECL_SECURITY: Coded = Coded { bits: 2, tables: &[0x02, 0x06, 0x20] };
const MEMBER_REF_PARENT: Coded = Coded { bits: 3, tables: &[0x02, 0x01, 0x1A, 0x06, 0x1B] };
const HAS_SEMANTICS: Coded = Coded { bits: 1, tables: &[0x14, 0x17] };
const METHOD_DEF_OR_REF: Coded = Coded { bits: 1, tables: &[0x06, 0x0A] };
const MEMBER_FORWARDED: Coded = Coded { bits: 1, tables: &[0x04, 0x06] };
const IMPLEMENTATION: Coded = Coded { bits: 2, tables: &[0x26, 0x23, 0x27] };
const CUSTOM_ATTRIBUTE_TYPE: Coded = Coded { bits: 3, tables: &[0xFF, 0xFF, 0x06, 0x0A, 0xFF] };
const RESOLUTION_SCOPE: Coded = Coded { bits: 2, tables: &[0x00, 0x1A, 0x23, 0x01] };
const TYPE_OR_METHOD_DEF: Coded = Coded { bits: 1, tables: &[0x02, 0x06] };

struct Schema {
    name: &'static str,
    cols: &'static [(&'static str, Col)],
}

use Col::*;

/// Indexed by table number. Tables above 0x2C (portable PDB) are not decoded.
const TABLES: [Schema; 0x2D] = [
    Schema { name: "Module", cols: &[("Generation", U2), ("Name", Str), ("Mvid", Guid), ("EncId", Guid), ("EncBaseId", Guid)] },
    Schema { name: "TypeRef", cols: &[("ResolutionScope", Coded(&RESOLUTION_SCOPE)), ("TypeName", Str), ("TypeNamespace", Str)] },
    Schema {
        name: "TypeDef",
        cols: &[
            ("Flags", U4),
            ("TypeName", Str),
            ("TypeNamespace", Str),
            ("Extends", Coded(&TYPE_DEF_OR_REF)),
            ("FieldList", Table(0x04)),
            ("MethodList", Table(0x06)),
        ],
    },
    Schema { name: "FieldPtr", cols: &[("Field", Table(0x04))] },
    Schema { name: "Field", cols: &[("Flags", U2), ("Name", Str), ("Signature", Blob)] },
    Schema { name: "MethodPtr", cols: &[("Method", Table(0x06))] },
    Schema { name: "MethodDef", cols: &[("RVA", U4), ("ImplFlags", U2), ("Flags", U2), ("Name", Str), ("Signature", Blob), ("ParamList", Table(0x08))] },
    Schema { name: "ParamPtr", cols: &[("Param", Table(0x08))] },
    Schema { name: "Param", cols: &[("Flags", U2), ("Sequence", U2), ("Name", Str)] },
    Schema { name: "InterfaceImpl", cols: &[("Class", Table(0x02)), ("Interface", Coded(&TYPE_DEF_OR_REF))] },
    Schema { name: "MemberRef", cols: &[("Class", Coded(&MEMBER_REF_PARENT)), ("Name", Str), ("Signature", Blob)] },
    Schema { name: "Constant", cols: &[("Type", U2), ("Parent", Coded(&HAS_CONSTANT)), ("Value", Blob)] },
    Schema { name: "CustomAttribute", cols: &[("Parent", Coded(&HAS_CUSTOM_ATTRIBUTE)), ("Type", Coded(&CUSTOM_ATTRIBUTE_TYPE)), ("Value", Blob)] },
    Schema { name: "FieldMarshal", cols: &[("Parent", Coded(&HAS_FIELD_MARSHAL)), ("NativeType", Blob)] },
    Schema { name: "DeclSecurity", cols: &[("Action", U2), ("Parent", Coded(&HAS_DECL_SECURITY)), ("PermissionSet", Blob)] },
    Schema { name: "ClassLayout", cols: &[("PackingSize", U2), ("ClassSize", U4), ("Parent", Table(0x02))] },
    Schema { name: "FieldLayout", cols: &[("Offset", U4), ("Field", Table(0x04))] },
    Schema { name: "StandAloneSig", cols: &[("Signature", Blob)] },
    Schema { name: "EventMap", cols: &[("Parent", Table(0x02)), ("EventList", Table(0x14))] },
    Schema { name: "EventPtr", cols: &[("Event", Table(0x14))] },
    Schema { name: "Event", cols: &[("EventFlags", U2), ("Name", Str), ("EventType", Coded(&TYPE_DEF_OR_REF))] },
    Schema { name: "PropertyMap", cols: &[("Parent", Table(0x02)), ("PropertyList", Table(0x17))] },
    Schema { name: "PropertyPtr", cols: &[("Property", Table(0x17))] },
    Schema { name: "Property", cols: &[("Flags", U2), ("Name", Str), ("Type", Blob)] },
    Schema { name: "MethodSemantics", cols: &[("Semantics", U2), ("Method", Table(0x06)), ("Association", Coded(&HAS_SEMANTICS))] },
    Schema { name: "MethodImpl", cols: &[("Class", Table(0x02)), ("MethodBody", Coded(&METHOD_DEF_OR_REF)), ("MethodDeclaration", Coded(&METHOD_DEF_OR_REF))] },
    Schema { name: "ModuleRef", cols: &[("Name", Str)] },
    Schema { name: "TypeSpec", cols: &[("Signature", Blob)] },
    Schema { name: "ImplMap", cols: &[("MappingFlags", U2), ("MemberForwarded", Coded(&MEMBER_FORWARDED)), ("ImportName", Str), ("ImportScope", Table(0x1A))] },
    Schema { name: "FieldRVA", cols: &[("RVA", U4), ("Field", Table(0x04))] },
    Schema { name: "EncLog", cols: &[("Token", U4), ("FuncCode", U4)] },
    Schema { name: "EncMap", cols: &[("Token", U4)] },
    Schema {
        name: "Assembly",
        cols: &[
            ("HashAlgId", U4),
            ("MajorVersion", U2),
            ("MinorVersion", U2),
            ("BuildNumber", U2),
            ("RevisionNumber", U2),
            ("Flags", U4),
            ("PublicKey", Blob),
            ("Name", Str),
            ("Culture", Str),
        ],
    },
    Schema { name: "AssemblyProcessor", cols: &[("Processor", U4)] },
    Schema { name: "AssemblyOS", cols: &[("OSPlatformID", U4), ("OSMajorVersion", U4), ("OSMinorVersion", U4)] },
    Schema {
        name: "AssemblyRef",
        cols: &[
            ("MajorVersion", U2),
            ("MinorVersion", U2),
            ("BuildNumber", U2),
            ("RevisionNumber", U2),
            ("Flags", U4),
            ("PublicKeyOrToken", Blob),
            ("Name", Str),
            ("Culture", Str),
            ("HashValue", Blob),
        ],
    },
    Schema { name: "AssemblyRefProcessor", cols: &[("Processor", U4), ("AssemblyRef", Table(0x23))] },
    Schema { name: "AssemblyRefOS", cols: &[("OSPlatformID", U4), ("OSMajorVersion", U4), ("OSMinorVersion", U4), ("AssemblyRef", Table(0x23))] },
    Schema { name: "File", cols: &[("Flags", U4), ("Name", Str), ("HashValue", Blob)] },
    Schema {
        name: "ExportedType",
        cols: &[("Flags", U4), ("TypeDefId", U4), ("TypeName", Str), ("TypeNamespace", Str), ("Implementation", Coded(&IMPLEMENTATION))],
    },
    Schema { name: "ManifestResource", cols: &[("Offset", U4), ("Flags", U4), ("Name", Str), ("Implementation", Coded(&IMPLEMENTATION))] },
    Schema { name: "NestedClass", cols: &[("NestedClass", Table(0x02)), ("EnclosingClass", Table(0x02))] },
    Schema { name: "GenericParam", cols: &[("Number", U2), ("Flags", U2), ("Owner", Coded(&TYPE_OR_METHOD_DEF)), ("Name", Str)] },
    Schema { name: "MethodSpec", cols: &[("Method", Coded(&METHOD_DEF_OR_REF)), ("Instantiation", Blob)] },
    Schema { name: "GenericParamConstraint", cols: &[("Owner", Table(0x2A)), ("Constraint", Coded(&TYPE_DEF_OR_REF))] },
];

/// A metadata stream: name, file offset, size.
pub type Stream = (String, usize, usize);

type Range = Option<(usize, usize)>;

/// The parsed layout of a metadata root: heaps, table positions and column widths.
pub struct Md<'a> {
    data: &'a [u8],
    rd: Rd<'a>,
    strings: Range,
    blob: Range,
    us: Range,
    guids: Range,
    /// The `#~` stream.
    tables: (usize, usize),
    heap_sizes: u8,
    valid: u64,
    rows: [usize; 64],
    /// File offset of each decoded table.
    start: [usize; 0x2D],
    col_sizes: Vec<Vec<usize>>,
    /// Tables from this number on could not be located.
    decoded: usize,
    /// Type nodes one resolution may still decode; see `SIG_BUDGET`.
    budget: std::cell::Cell<usize>,
    /// Bytes of type names one resolution may still add; see `SIG_TEXT_BUDGET`.
    text: std::cell::Cell<usize>,
    /// Type nodes left for a whole batch of resolutions; see `WORK_BUDGET`.
    work: std::cell::Cell<usize>,
    /// Bytes of resolved text the grids may still take; see `RESOLVED_BUDGET`.
    resolved: std::cell::Cell<usize>,
    /// TypeSpec rows being resolved, so a row that refers to itself stops.
    path: RefCell<Vec<usize>>,
}

pub fn guid_text(b: &[u8]) -> String {
    if b.len() < 16 {
        return String::new();
    }
    format!(
        "{{{:08X}-{:04X}-{:04X}-{}-{}}}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        hex_bytes(&b[8..10]),
        hex_bytes(&b[10..16])
    )
}

/// Reader for the compressed integers and type encodings of a signature blob.
struct Sig<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Sig<'_> {
    fn byte(&mut self) -> Option<u8> {
        let v = *self.b.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    /// ECMA-335 II.23.2 compressed unsigned integer.
    fn uint(&mut self) -> Option<u32> {
        let b0 = self.byte()? as u32;
        if b0 & 0x80 == 0 {
            Some(b0)
        } else if b0 & 0xC0 == 0x80 {
            Some(((b0 & 0x3F) << 8) | self.byte()? as u32)
        } else {
            let (b1, b2, b3) = (self.byte()? as u32, self.byte()? as u32, self.byte()? as u32);
            Some(((b0 & 0x1F) << 24) | (b1 << 16) | (b2 << 8) | b3)
        }
    }
}

pub struct Method {
    pub token: u32,
    pub rva: u32,
    /// `Namespace.Type::Name`
    pub name: String,
    pub signature: String,
}

const MAX_SIG_DEPTH: usize = 16;
/// Type nodes decoded for one resolved text. TypeSpec rows can refer to each
/// other, so depth alone does not bound the work: fan-out multiplies per level.
const SIG_BUDGET: usize = 1024;
/// Longest resolved type or signature text, in bytes.
const MAX_SIG_TEXT: usize = 1024;
/// Bytes of type names gathered for one resolved text. A name can be 1 KB and
/// every node can carry one, so the text is bounded while it is built; twice
/// the visible length keeps `clip` working for texts that are a little long.
const SIG_TEXT_BUDGET: usize = 2 * MAX_SIG_TEXT;
/// Type nodes decoded for one batch of resolutions: all rows of one table,
/// the method list, or one method body. A table holds up to `MAX_ROWS` rows,
/// so the budget per text alone still allows 100 million nodes. Texts past
/// the budget read "?".
const WORK_BUDGET: usize = 1 << 21;
/// Longest name shown for a row another row points at. The row itself has
/// the full text.
const MAX_NAME: usize = 256;
/// Resolved text in all table grids and the method list of one file. A row
/// of 6 bytes can name rows whose text is hundreds of bytes, and a table
/// holds up to `MAX_ROWS` rows. Rows past the budget show plain row numbers.
const RESOLVED_BUDGET: usize = 64 << 20;

/// Cut a resolved text to `MAX_SIG_TEXT` bytes on a character boundary.
/// Text of one IL listing. A `call` of 5 bytes can name a method whose text
/// is 2 KB, so the instruction cap alone allows hundreds of megabytes.
const MAX_IL_TEXT: usize = 2 << 20;

fn clip(s: String) -> String {
    clip_to(s, MAX_SIG_TEXT)
}

fn clip_to(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push_str("...");
    }
    s
}

impl<'a> Md<'a> {
    pub fn parse(data: &'a [u8], streams: &[Stream]) -> Option<Md<'a>> {
        let find = |names: &[&str]| streams.iter().find(|s| names.contains(&s.0.as_str())).map(|s| (s.1, s.2.min(data.len().saturating_sub(s.1))));
        let (off, size) = find(&["#~", "#-"])?;
        let rd = Rd::new(data, LE);
        if size < 24 || !rd.has(off, 24) {
            return None;
        }
        let heap_sizes = rd.u8(off + 6);
        let valid = rd.u64(off + 8);
        let mut rows = [0usize; 64];
        let mut p = off + 24;
        for (t, r) in rows.iter_mut().enumerate() {
            if valid >> t & 1 != 0 {
                *r = rd.u32(p) as usize;
                p += 4;
            }
        }
        if heap_sizes & 0x40 != 0 {
            p += 4;
        }
        let heap = |bit: u8| if heap_sizes & bit != 0 { 4 } else { 2 };
        let col_size = |c: &Col| match c {
            U2 => 2,
            U4 => 4,
            Str => heap(1),
            Guid => heap(2),
            Blob => heap(4),
            Table(t) => {
                if rows[*t as usize] < 0x1_0000 {
                    2
                } else {
                    4
                }
            }
            Coded(c) => {
                let max = c.tables.iter().filter(|t| **t != 0xFF).map(|t| rows[*t as usize]).max().unwrap_or(0);
                if max < 1 << (16 - c.bits) { 2 } else { 4 }
            }
        };
        let col_sizes: Vec<Vec<usize>> = TABLES.iter().map(|s| s.cols.iter().map(|(_, c)| col_size(c)).collect()).collect();
        let mut start = [0usize; 0x2D];
        let mut decoded = 0;
        let end = off + size;
        for t in 0..64 {
            if valid >> t & 1 == 0 {
                if t < 0x2D {
                    decoded = t + 1;
                }
                continue;
            }
            // A table this code has no schema for hides everything after it.
            if t >= 0x2D || p > end {
                break;
            }
            start[t] = p;
            decoded = t + 1;
            p = p.saturating_add(rows[t].saturating_mul(col_sizes[t].iter().sum()));
        }
        Some(Md {
            data,
            rd,
            strings: find(&["#Strings"]),
            blob: find(&["#Blob"]),
            us: find(&["#US"]),
            guids: find(&["#GUID"]),
            tables: (off, size),
            heap_sizes,
            valid,
            rows,
            start,
            col_sizes,
            decoded,
            budget: std::cell::Cell::new(SIG_BUDGET),
            text: std::cell::Cell::new(SIG_TEXT_BUDGET),
            work: std::cell::Cell::new(WORK_BUDGET),
            resolved: std::cell::Cell::new(RESOLVED_BUDGET),
            path: RefCell::new(Vec::new()),
        })
    }

    fn present(&self, t: usize) -> bool {
        t < self.decoded && self.valid >> t & 1 != 0
    }

    fn row_size(&self, t: usize) -> usize {
        self.col_sizes[t].iter().sum()
    }

    /// Number of rows that can actually be read for table `t`.
    pub fn row_count(&self, t: usize) -> usize {
        if !self.present(t) {
            return 0;
        }
        let end = self.tables.0 + self.tables.1;
        let fit = end.saturating_sub(self.start[t]) / self.row_size(t).max(1);
        self.rows[t].min(fit)
    }

    /// Value of one cell; `rid` counts from 1. Zero when out of range.
    fn cell(&self, t: usize, rid: usize, col: usize) -> usize {
        if rid == 0 || rid > self.row_count(t) || col >= self.col_sizes[t].len() {
            return 0;
        }
        let off = self.start[t] + (rid - 1) * self.row_size(t) + self.col_sizes[t][..col].iter().sum::<usize>();
        self.rd.uint(off, self.col_sizes[t][col]) as usize
    }

    fn string(&self, idx: usize) -> String {
        match self.strings {
            Some((off, size)) if idx < size => self.rd.cstr(off + idx, (size - idx).min(512)),
            _ => String::new(),
        }
    }

    fn guid(&self, idx: usize) -> String {
        match self.guids {
            Some((off, size)) if idx >= 1 && idx * 16 <= size => guid_text(self.rd.bytes(off + (idx - 1) * 16, 16)),
            _ => String::new(),
        }
    }

    /// A length prefixed entry of the blob or user string heap.
    fn heap_entry(&self, heap: Range, idx: usize) -> &'a [u8] {
        let Some((off, size)) = heap else { return &[] };
        if idx >= size {
            return &[];
        }
        let bytes = self.rd.bytes(off + idx, size - idx);
        let mut s = Sig { b: bytes, pos: 0 };
        match s.uint() {
            Some(len) => bytes.get(s.pos..s.pos.saturating_add(len as usize)).unwrap_or(&[]),
            None => &[],
        }
    }

    fn user_string(&self, idx: usize) -> String {
        let b = self.heap_entry(self.us, idx);
        let units: Vec<u16> = b[..b.len().saturating_sub(1)].as_chunks::<2>().0.iter().take(256).map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16_lossy(&units).chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
    }

    // --- names ------------------------------------------------------------

    fn full_name(&self, ns: usize, name: usize) -> String {
        let (ns, name) = (self.string(ns), self.string(name));
        if ns.is_empty() { name } else { format!("{ns}.{name}") }
    }

    /// Name of a TypeDef (2), TypeRef (1) or TypeSpec (0x1B) row.
    fn type_name(&self, table: usize, rid: usize, depth: usize) -> String {
        match table {
            0x02 if rid <= self.row_count(2) && rid > 0 => self.full_name(self.cell(2, rid, 2), self.cell(2, rid, 1)),
            0x01 if rid <= self.row_count(1) && rid > 0 => self.full_name(self.cell(1, rid, 2), self.cell(1, rid, 1)),
            0x1B if rid <= self.row_count(0x1B) && rid > 0 && depth < MAX_SIG_DEPTH && !self.path.borrow().contains(&rid) => {
                if depth == 0 {
                    self.start_text();
                }
                let mut s = Sig { b: self.heap_entry(self.blob, self.cell(0x1B, rid, 0)), pos: 0 };
                self.path.borrow_mut().push(rid);
                let text = self.sig_type(&mut s, depth + 1);
                self.path.borrow_mut().pop();
                let text = text.unwrap_or_else(|| "?".into());
                if depth == 0 { clip(text) } else { text }
            }
            _ => format!("{}[{rid}]", TABLES.get(table).map_or("?", |t| t.name)),
        }
    }

    fn coded(&self, c: &Coded, v: usize) -> Option<(usize, usize)> {
        let tag = v & ((1 << c.bits) - 1);
        let rid = v >> c.bits;
        c.tables.get(tag).filter(|t| **t != 0xFF && rid != 0).map(|t| (*t as usize, rid))
    }

    /// The TypeDef that owns row `rid` of the Field (col 4) or MethodDef (col 5) list.
    fn owner(&self, list_col: usize, rid: usize) -> usize {
        let n = self.row_count(2);
        // FieldList and MethodList are ascending, so the owner is the last
        // type whose list starts at or before the row.
        let (mut lo, mut hi) = (1usize, n + 1);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.cell(2, mid, list_col) <= rid {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo - 1
    }

    fn method_name(&self, rid: usize) -> String {
        let owner = self.owner(5, rid);
        format!("{}::{}", if owner == 0 { String::new() } else { self.type_name(2, owner, 0) }, self.string(self.cell(6, rid, 3)))
    }

    fn member_ref_name(&self, rid: usize) -> String {
        let class = match self.coded(&MEMBER_REF_PARENT, self.cell(0x0A, rid, 0)) {
            Some((0x06, r)) => self.method_name(r),
            Some((0x1A, r)) => self.string(self.cell(0x1A, r, 0)),
            Some((t, r)) => self.type_name(t, r, 0),
            None => String::new(),
        };
        format!("{class}::{}", self.string(self.cell(0x0A, rid, 1)))
    }

    /// Readable form of a metadata token as it appears in IL operands.
    pub fn token_text(&self, token: u32) -> String {
        let (t, rid) = ((token >> 24) as usize, (token & 0xFF_FFFF) as usize);
        match t {
            0x01 | 0x02 | 0x1B => self.type_name(t, rid, 0),
            0x04 => {
                let owner = self.owner(4, rid);
                format!(
                    "{} {}::{}",
                    self.sig_text(self.heap_entry(self.blob, self.cell(4, rid, 2))),
                    self.type_name(2, owner, 0),
                    self.string(self.cell(4, rid, 1))
                )
            }
            0x06 => self.method_sig(&self.method_name(rid), self.heap_entry(self.blob, self.cell(6, rid, 4))),
            0x0A => {
                let sig = self.heap_entry(self.blob, self.cell(0x0A, rid, 2));
                let name = self.member_ref_name(rid);
                if sig.first() == Some(&0x06) { format!("{} {name}", self.sig_text(sig)) } else { self.method_sig(&name, sig) }
            }
            0x2B => {
                let method = match self.coded(&METHOD_DEF_OR_REF, self.cell(0x2B, rid, 0)) {
                    Some((0x06, r)) => self.token_text(0x0600_0000 | r as u32),
                    Some((_, r)) => self.token_text(0x0A00_0000 | r as u32),
                    None => "?".into(),
                };
                format!("{method} {}", self.sig_text(self.heap_entry(self.blob, self.cell(0x2B, rid, 1))))
            }
            0x11 => self.sig_text(self.heap_entry(self.blob, self.cell(0x11, rid, 0))),
            0x70 => format!("\"{}\"", self.user_string(rid)),
            _ => format!("token {token:08X}"),
        }
    }

    // --- signatures -------------------------------------------------------

    /// Start one resolved text: full node and text budgets.
    fn start_text(&self) {
        self.budget.set(SIG_BUDGET);
        self.text.set(SIG_TEXT_BUDGET);
    }

    fn type_def_or_ref(&self, s: &mut Sig, depth: usize) -> Option<String> {
        let v = s.uint()? as usize;
        let table = [0x02, 0x01, 0x1B, 0xFF][v & 3];
        let name = self.type_name(table, v >> 2, depth);
        // A TypeSpec was charged while its own text was built. Any other name
        // counts here; once the text budget is spent nothing more is gathered.
        if table != 0x1B {
            let left = self.text.get().checked_sub(name.len());
            self.text.set(left.unwrap_or(0));
            left?;
        }
        Some(name)
    }

    fn sig_type(&self, s: &mut Sig, depth: usize) -> Option<String> {
        if depth > MAX_SIG_DEPTH {
            return None;
        }
        // Out of budget: the whole text becomes "?" instead of growing further.
        self.budget.set(self.budget.get().checked_sub(1)?);
        self.work.set(self.work.get().checked_sub(1)?);
        let d = depth + 1;
        Some(match s.byte()? {
            0x01 => "void".into(),
            0x02 => "bool".into(),
            0x03 => "char".into(),
            0x04 => "int8".into(),
            0x05 => "uint8".into(),
            0x06 => "int16".into(),
            0x07 => "uint16".into(),
            0x08 => "int32".into(),
            0x09 => "uint32".into(),
            0x0A => "int64".into(),
            0x0B => "uint64".into(),
            0x0C => "float32".into(),
            0x0D => "float64".into(),
            0x0E => "string".into(),
            0x0F => format!("{}*", self.sig_type(s, d)?),
            0x10 => format!("{}&", self.sig_type(s, d)?),
            0x11 | 0x12 => self.type_def_or_ref(s, d)?,
            0x13 => format!("!{}", s.uint()?),
            0x14 => {
                let elem = self.sig_type(s, d)?;
                let rank = s.uint()?;
                for _ in 0..s.uint()?.min(32) {
                    s.uint()?;
                }
                for _ in 0..s.uint()?.min(32) {
                    s.uint()?;
                }
                format!("{elem}[{}]", ",".repeat(rank.saturating_sub(1).min(31) as usize))
            }
            0x15 => {
                s.byte()?;
                let base = self.type_def_or_ref(s, d)?;
                let n = s.uint()?.min(64);
                let args: Option<Vec<String>> = (0..n).map(|_| self.sig_type(s, d)).collect();
                format!("{base}<{}>", args?.join(", "))
            }
            0x16 => "typedref".into(),
            0x18 => "native int".into(),
            0x19 => "native uint".into(),
            0x1B => format!("method {}", self.method_sig_at(s, "*", d)?),
            0x1C => "object".into(),
            0x1D => format!("{}[]", self.sig_type(s, d)?),
            0x1E => format!("!!{}", s.uint()?),
            0x1F | 0x20 => {
                // Custom modifier: skip it and describe the modified type.
                self.type_def_or_ref(s, d)?;
                self.sig_type(s, d)?
            }
            0x41 => format!("..., {}", self.sig_type(s, d)?),
            0x45 => format!("{} pinned", self.sig_type(s, d)?),
            other => format!("<type {other:02X}>"),
        })
    }

    fn method_sig_at(&self, s: &mut Sig, name: &str, depth: usize) -> Option<String> {
        let conv = s.byte()?;
        if conv & 0x10 != 0 {
            s.uint()?;
        }
        let n = s.uint()?.min(256);
        let ret = self.sig_type(s, depth)?;
        let params: Option<Vec<String>> = (0..n).map(|_| self.sig_type(s, depth)).collect();
        let instance = if conv & 0x20 != 0 { "instance " } else { "" };
        Some(format!("{instance}{ret} {name}({})", params?.join(", ")))
    }

    fn method_sig(&self, name: &str, blob: &[u8]) -> String {
        self.start_text();
        clip(self.method_sig_at(&mut Sig { b: blob, pos: 0 }, name, 0).unwrap_or_else(|| format!("{name}(?)")))
    }

    /// Text for a TypeSpec blob (ECMA-335 II.23.2.14): a type with no leading
    /// calling convention byte, so it cannot go through `sig_text`.
    pub fn type_spec_text(&self, blob: &[u8]) -> String {
        self.start_text();
        clip(self.sig_type(&mut Sig { b: blob, pos: 0 }, 0).unwrap_or_else(|| "?".into()))
    }

    /// Text for a signature blob that starts with a calling convention byte:
    /// field, method, property, locals, generic instantiation.
    pub fn sig_text(&self, blob: &[u8]) -> String {
        self.start_text();
        let mut s = Sig { b: blob, pos: 0 };
        let text = match s.peek() {
            None => return String::new(),
            Some(0x06) => {
                s.pos = 1;
                self.sig_type(&mut s, 0)
            }
            Some(0x07) | Some(0x0A) => {
                let open = if s.peek() == Some(0x07) { ("(", ")") } else { ("<", ">") };
                s.pos = 1;
                s.uint()
                    .and_then(|n| (0..n.min(256)).map(|_| self.sig_type(&mut s, 0)).collect::<Option<Vec<_>>>())
                    .map(|v| format!("{}{}{}", open.0, v.join(", "), open.1))
            }
            Some(c) if c & 0x0F == 0x08 => {
                s.pos = 1;
                s.uint().and_then(|n| {
                    let ty = self.sig_type(&mut s, 0)?;
                    let idx: Option<Vec<String>> = (0..n.min(64)).map(|_| self.sig_type(&mut s, 0)).collect();
                    let idx = idx?;
                    Some(if idx.is_empty() { ty } else { format!("{ty} [{}]", idx.join(", ")) })
                })
            }
            Some(c) if c & 0x0F <= 5 => self.method_sig_at(&mut s, "", 0),
            Some(_) => self.sig_type(&mut s, 0),
        };
        clip(text.unwrap_or_else(|| "?".into()))
    }

    // --- methods and IL -----------------------------------------------------

    pub fn methods(&self) -> Vec<Method> {
        self.work.set(WORK_BUDGET);
        (1..=self.row_count(6).min(MAX_ROWS))
            .map(|rid| {
                let (token, rva) = (0x0600_0000 | rid as u32, self.cell(6, rid, 0) as u32);
                if self.resolved_spent() {
                    return Method { token, rva, name: format!("MethodDef[{rid}]"), signature: String::new() };
                }
                let name = clip_to(self.method_name(rid), MAX_NAME);
                let signature = self.method_sig("", self.heap_entry(self.blob, self.cell(6, rid, 4)));
                self.charge(name.len() + signature.len());
                Method { token, rva, name, signature }
            })
            .collect()
    }

    /// The budget for resolved text is used up: the grids show row numbers
    /// in place of names from here on.
    pub fn resolved_spent(&self) -> bool {
        self.resolved.get() == 0
    }

    fn charge(&self, bytes: usize) {
        self.resolved.set(self.resolved.get().saturating_sub(bytes));
    }

    /// RVA and full title (`instance void Type::Name(args)`) of one method.
    pub fn method(&self, rid: usize) -> Option<(u32, String)> {
        (rid >= 1 && rid <= self.row_count(6))
            .then(|| (self.cell(6, rid, 0) as u32, self.method_sig(&self.method_name(rid), self.heap_entry(self.blob, self.cell(6, rid, 4)))))
    }

    /// Disassemble the body of the method at file offset `off`.
    pub fn il(&self, off: usize, title: &str) -> String {
        self.work.set(WORK_BUDGET);
        let rd = &self.rd;
        let mut out = format!(".method {title}\n");
        let b0 = rd.u8(off);
        let (code, size, more) = match b0 & 3 {
            2 => {
                out.push_str(&format!("// tiny header, code size {}\n", b0 >> 2));
                (off + 1, (b0 >> 2) as usize, false)
            }
            3 => {
                let flags = rd.u16(off);
                let hdr = ((flags >> 12) as usize * 4).max(12);
                let size = rd.u32(off + 4) as usize;
                let locals = rd.u32(off + 8);
                out.push_str(&format!(
                    "// fat header, code size {size}, maxstack {}{}\n",
                    rd.u16(off + 2),
                    if flags & 0x10 != 0 { ", init locals" } else { "" }
                ));
                if locals != 0 {
                    out.push_str(&format!(".locals {}\n", self.token_text(locals)));
                }
                (off + hdr, size, flags & 0x8 != 0)
            }
            _ => return format!("{out}// no IL body at this address\n"),
        };
        let Some(il) = self.data.get(code..code.saturating_add(size)) else { return format!("{out}// the method body is outside the file\n") };
        let mut p = 0usize;
        let mut lines = 0;
        while p < il.len() && lines < 100_000 && out.len() < MAX_IL_TEXT {
            let at = p;
            let (op, len) = if il[p] == 0xFE {
                (il.get(p + 1).and_then(|b| OPS2.get(*b as usize)).copied().flatten(), 2)
            } else {
                (OPS1.get(il[p] as usize).copied().flatten(), 1)
            };
            p += len;
            let Some((name, kind)) = op else {
                out.push_str(&format!("IL_{at:04X}: <unknown opcode {:02X}>\n", il[at]));
                lines += 1;
                continue;
            };
            let int = |n: usize| -> Option<u64> { read_uint(il, p, n, LE) };
            let (text, used) = match kind {
                Op::None => (String::new(), 0),
                Op::I1 => (int(1).map(|v| (v as i8).to_string()), 1).into_text(),
                Op::U1 => (int(1).map(|v| v.to_string()), 1).into_text(),
                Op::U2 => (int(2).map(|v| v.to_string()), 2).into_text(),
                Op::I4 => (int(4).map(|v| format!("{} (0x{v:X})", v as i32)), 4).into_text(),
                Op::I8 => (int(8).map(|v| format!("{} (0x{v:X})", v as i64)), 8).into_text(),
                Op::R4 => (int(4).map(|v| f32::from_bits(v as u32).to_string()), 4).into_text(),
                Op::R8 => (int(8).map(f64::from_bits).map(|v| v.to_string()), 8).into_text(),
                Op::BrS => (int(1).map(|v| format!("IL_{:04X}", (p as i64 + 1 + v as i8 as i64) as u32)), 1).into_text(),
                Op::Br => (int(4).map(|v| format!("IL_{:04X}", (p as i64 + 4 + v as i32 as i64) as u32)), 4).into_text(),
                Op::Tok | Op::Str => (int(4).map(|v| self.token_text(v as u32)), 4).into_text(),
                Op::Switch => match int(4) {
                    Some(n) => {
                        let n = (n as usize).min(il.len() / 4);
                        let base = p + 4 + n * 4;
                        let targets: Vec<String> = (0..n)
                            .filter_map(|i| read_uint(il, p + 4 + i * 4, 4, LE))
                            .map(|v| format!("IL_{:04X}", (base as i64 + v as i32 as i64) as u32))
                            .collect();
                        (format!("({})", targets.join(", ")), 4 + n * 4)
                    }
                    None => ("<truncated>".into(), il.len()),
                },
            };
            p = p.saturating_add(used);
            out.push_str(&format!("IL_{at:04X}: {name}{}{text}\n", if text.is_empty() { "" } else { " " }));
            lines += 1;
        }
        if p < il.len() {
            // A listing that just ended would read as the end of the method.
            out.push_str(&format!("// listing stopped after {lines} instructions; {} bytes of code not shown\n", il.len() - p));
        }
        if more {
            self.eh_sections(code + size, &mut out);
        }
        out
    }

    /// Exception handling clauses that follow a fat method body.
    fn eh_sections(&self, after_code: usize, out: &mut String) {
        let rd = &self.rd;
        let mut s = after_code.div_ceil(4) * 4;
        // A catch clause of 12 bytes names a type of up to 1 KB.
        let limit = out.len() + (256 << 10);
        for _ in 0..16 {
            if !rd.has(s, 4) {
                break;
            }
            let kind = rd.u8(s);
            let fat = kind & 0x40 != 0;
            let size = if fat { (rd.u32(s) >> 8) as usize } else { rd.u8(s + 1) as usize };
            if kind & 0x01 != 0 {
                let (clause, n) = if fat { (24, size.saturating_sub(4) / 24) } else { (12, size.saturating_sub(4) / 12) };
                for i in 0..n.min(1024) {
                    let c = s + 4 + i * clause;
                    if !rd.has(c, clause) {
                        break;
                    }
                    if out.len() >= limit {
                        out.push_str("// further exception handling clauses not shown\n");
                        return;
                    }
                    let (flags, try_off, try_len, h_off, h_len, extra) = if fat {
                        (rd.u32(c), rd.u32(c + 4), rd.u32(c + 8), rd.u32(c + 12), rd.u32(c + 16), rd.u32(c + 20))
                    } else {
                        (rd.u16(c) as u32, rd.u16(c + 2) as u32, rd.u8(c + 4) as u32, rd.u16(c + 5) as u32, rd.u8(c + 7) as u32, rd.u32(c + 8))
                    };
                    let what = match flags {
                        0 => format!("catch {}", self.token_text(extra)),
                        1 => format!("filter IL_{extra:04X}"),
                        2 => "finally".into(),
                        4 => "fault".into(),
                        _ => format!("clause {flags:X}"),
                    };
                    out.push_str(&format!(
                        ".try IL_{try_off:04X} to IL_{:04X} {what} handler IL_{h_off:04X} to IL_{:04X}\n",
                        try_off.wrapping_add(try_len),
                        h_off.wrapping_add(h_len)
                    ));
                }
            }
            if kind & 0x80 == 0 || size == 0 {
                break;
            }
            s = (s + size).div_ceil(4) * 4;
        }
    }

    // --- nodes --------------------------------------------------------------

    fn tables_node(&self) -> Node {
        let (off, size) = self.tables;
        let mut f = Fields::new(self.data, LE);
        f.seq(
            off,
            &[
                ("Reserved", 4, Kind::Hex),
                ("MajorVersion", 1, Kind::Hex),
                ("MinorVersion", 1, Kind::Hex),
                ("HeapSizes", 1, Kind::Hex),
                ("Reserved2", 1, Kind::Hex),
                ("Valid", 8, Kind::Hex),
                ("Sorted", 8, Kind::Hex),
            ],
        );
        let wide: Vec<&str> = [(1u8, "#Strings"), (2, "#GUID"), (4, "#Blob")].iter().filter(|(b, _)| self.heap_sizes & b != 0).map(|(_, n)| *n).collect();
        f.grid.rows[3][4].text = if wide.is_empty() { "all heap indexes are 2 bytes".into() } else { format!("4 byte indexes into {}", wide.join(", ")) };
        f.grid.rows[5][4].text = format!("{} tables present", self.valid.count_ones());

        let mut summary = Grid::new(&["Table", "Name", "Rows", "Row Size", "Offset"]);
        let mut children = vec![Node::grid("Header", f.finish()).with_span(off, 24)];
        let end = off + size;
        #[allow(clippy::needless_range_loop)] // t is the table number, used well beyond indexing
        for t in 0..64 {
            if self.valid >> t & 1 == 0 {
                continue;
            }
            if !self.present(t) {
                summary.push(
                    vec![Cell::text(format!("{t:02X}")), Cell::text("(not decoded)"), Cell::text(self.rows[t].to_string()), Cell::text("?"), Cell::text("?")],
                    None,
                );
                continue;
            }
            let p = self.start[t];
            let span = (p, self.rows[t].saturating_mul(self.row_size(t)).min(end.saturating_sub(p)));
            summary.push(
                vec![
                    Cell::text(format!("{t:02X}")),
                    Cell::text(TABLES[t].name),
                    Cell::text(self.rows[t].to_string()),
                    Cell::text(self.row_size(t).to_string()),
                    Cell::text(format!("{p:08X}")),
                ],
                Some(span),
            );
            if self.row_count(t) > 0 {
                children.push(self.table_node(t).with_span(span.0, span.1));
            }
        }
        Node::grid("Tables", summary).with_span(off, size).with_children(children)
    }

    fn table_node(&self, t: usize) -> Node {
        let schema = &TABLES[t];
        let sizes = &self.col_sizes[t];
        let n = self.row_count(t).min(MAX_ROWS);
        self.work.set(WORK_BUDGET);
        let mut columns = vec!["Token"];
        columns.extend(schema.cols.iter().map(|(name, _)| *name));
        columns.push("Resolved");
        let row_size = self.row_size(t);
        let mut g = Grid { columns, rows: Vec::with_capacity(n), spans: Vec::with_capacity(n) };
        // Rows whose names were resolved; the rest came after the text budget.
        let mut named = n;
        for i in 0..n {
            let plain = self.resolved_spent();
            if plain {
                named = named.min(i);
            }
            let base = self.start[t] + i * row_size;
            let mut row = Vec::with_capacity(schema.cols.len() + 2);
            row.push(Cell::text(format!("{:08X}", (t << 24) | (i + 1))));
            let mut resolved: Vec<String> = Vec::new();
            let mut o = base;
            for ((name, col), size) in schema.cols.iter().zip(sizes) {
                let v = self.rd.uint(o, *size) as usize;
                row.push(cell(self.data, o, *size, Kind::Hex, LE));
                match col {
                    Str if !plain => {
                        let s = self.string(v);
                        if !s.is_empty() {
                            resolved.push(format!("{name}={s}"));
                        }
                    }
                    Guid if v != 0 => resolved.push(format!("{name}={}", self.guid(v))),
                    Table(target) if v != 0 => resolved.push(format!("{name}={}[{v}]", TABLES[*target as usize].name)),
                    Coded(c) => {
                        if let Some((target, rid)) = self.coded(c, v) {
                            let text = match target {
                                0x01 | 0x02 | 0x1B if !plain => self.type_name(target, rid, 0),
                                0x06 if !plain => self.method_name(rid),
                                0x0A if !plain => self.member_ref_name(rid),
                                _ => format!("{}[{rid}]", TABLES[target].name),
                            };
                            resolved.push(format!("{name}={}", clip_to(text, MAX_NAME)));
                        }
                    }
                    // Signature blobs are worth decoding; other blobs are opaque data.
                    Blob if !plain && v != 0 && matches!(*name, "Signature" | "Type" | "Instantiation") => {
                        let blob = self.heap_entry(self.blob, v);
                        resolved.push(format!("{name}={}", if t == 0x1B { self.type_spec_text(blob) } else { self.sig_text(blob) }));
                    }
                    _ => {}
                }
                o += size;
            }
            let resolved = resolved.join(", ");
            self.charge(resolved.len());
            row.push(Cell::text(resolved));
            g.push(row, Some((base, row_size)));
        }
        let cut = if named < n { format!(", names resolved for the first {named}") } else { String::new() };
        Node::grid(format!("{} ({n}{cut})", schema.name), g)
    }

    /// The `#US` heap: length prefixed UTF-16 strings used by `ldstr`.
    fn user_strings_node(&self, off: usize, size: usize) -> Node {
        let rd = &self.rd;
        let mut g = Grid::new(&["Index", "Offset", "Length", "String"]);
        let mut p = 1usize;
        while p < size && g.rows.len() < MAX_HEAP_ROWS {
            let mut s = Sig { b: rd.bytes(off + p, 4), pos: 0 };
            let Some(len) = s.uint().map(|l| l as usize) else { break };
            let hdr = s.pos;
            if len == 0 {
                p += hdr;
                continue;
            }
            if p + hdr + len > size {
                break;
            }
            g.push(
                vec![Cell::text(format!("{p:X}")), Cell::text(format!("{:08X}", off + p)), Cell::text((len / 2).to_string()), Cell::text(self.user_string(p))],
                Some((off + p, hdr + len)),
            );
            p += hdr + len;
        }
        Node::grid(format!("User Strings ({})", g.rows.len()), g).with_span(off, size)
    }

    /// Nodes for the metadata streams: tables, user strings, GUIDs.
    pub fn nodes(&self) -> Vec<Node> {
        let mut out = vec![self.tables_node()];
        if let Some((off, size)) = self.us {
            out.push(self.user_strings_node(off, size));
        }
        if let Some((off, size)) = self.guids {
            let mut g = Grid::new(&["Index", "Offset", "GUID"]);
            for i in 0..(size / 16).min(MAX_HEAP_ROWS) {
                let o = off + i * 16;
                g.push(vec![Cell::text((i + 1).to_string()), Cell::text(format!("{o:08X}")), Cell::text(guid_text(self.rd.bytes(o, 16)))], Some((o, 16)));
            }
            out.push(Node::grid(format!("GUIDs ({})", g.rows.len()), g).with_span(off, size));
        }
        out
    }
}

/// Nodes for the metadata streams, or nothing when there is no table stream.
pub fn nodes(data: &[u8], streams: &[Stream]) -> Vec<Node> {
    Md::parse(data, streams).map(|md| md.nodes()).unwrap_or_default()
}

// --- IL opcodes ---------------------------------------------------------------

#[derive(Clone, Copy)]
enum Op {
    None,
    I1,
    U1,
    U2,
    I4,
    I8,
    R4,
    R8,
    BrS,
    Br,
    Tok,
    Str,
    Switch,
}

trait IntoText {
    fn into_text(self) -> (String, usize);
}

impl IntoText for (Option<String>, usize) {
    /// A missing operand means the method body ends inside the instruction.
    fn into_text(self) -> (String, usize) {
        (self.0.unwrap_or_else(|| "<truncated>".into()), self.1)
    }
}

type OpInfo = Option<(&'static str, Op)>;

const fn op(name: &'static str, kind: Op) -> OpInfo {
    Some((name, kind))
}

const fn n(name: &'static str) -> OpInfo {
    Some((name, Op::None))
}

#[rustfmt::skip]
const OPS1: [OpInfo; 0xE1] = [
    n("nop"), n("break"), n("ldarg.0"), n("ldarg.1"), n("ldarg.2"), n("ldarg.3"), n("ldloc.0"), n("ldloc.1"),
    n("ldloc.2"), n("ldloc.3"), n("stloc.0"), n("stloc.1"), n("stloc.2"), n("stloc.3"), op("ldarg.s", Op::U1), op("ldarga.s", Op::U1),
    op("starg.s", Op::U1), op("ldloc.s", Op::U1), op("ldloca.s", Op::U1), op("stloc.s", Op::U1), n("ldnull"), n("ldc.i4.m1"), n("ldc.i4.0"), n("ldc.i4.1"),
    n("ldc.i4.2"), n("ldc.i4.3"), n("ldc.i4.4"), n("ldc.i4.5"), n("ldc.i4.6"), n("ldc.i4.7"), n("ldc.i4.8"), op("ldc.i4.s", Op::I1),
    op("ldc.i4", Op::I4), op("ldc.i8", Op::I8), op("ldc.r4", Op::R4), op("ldc.r8", Op::R8), None, n("dup"), n("pop"), op("jmp", Op::Tok),
    op("call", Op::Tok), op("calli", Op::Tok), n("ret"), op("br.s", Op::BrS), op("brfalse.s", Op::BrS), op("brtrue.s", Op::BrS), op("beq.s", Op::BrS), op("bge.s", Op::BrS),
    op("bgt.s", Op::BrS), op("ble.s", Op::BrS), op("blt.s", Op::BrS), op("bne.un.s", Op::BrS), op("bge.un.s", Op::BrS), op("bgt.un.s", Op::BrS), op("ble.un.s", Op::BrS), op("blt.un.s", Op::BrS),
    op("br", Op::Br), op("brfalse", Op::Br), op("brtrue", Op::Br), op("beq", Op::Br), op("bge", Op::Br), op("bgt", Op::Br), op("ble", Op::Br), op("blt", Op::Br),
    op("bne.un", Op::Br), op("bge.un", Op::Br), op("bgt.un", Op::Br), op("ble.un", Op::Br), op("blt.un", Op::Br), op("switch", Op::Switch), n("ldind.i1"), n("ldind.u1"),
    n("ldind.i2"), n("ldind.u2"), n("ldind.i4"), n("ldind.u4"), n("ldind.i8"), n("ldind.i"), n("ldind.r4"), n("ldind.r8"),
    n("ldind.ref"), n("stind.ref"), n("stind.i1"), n("stind.i2"), n("stind.i4"), n("stind.i8"), n("stind.r4"), n("stind.r8"),
    n("add"), n("sub"), n("mul"), n("div"), n("div.un"), n("rem"), n("rem.un"), n("and"),
    n("or"), n("xor"), n("shl"), n("shr"), n("shr.un"), n("neg"), n("not"), n("conv.i1"),
    n("conv.i2"), n("conv.i4"), n("conv.i8"), n("conv.r4"), n("conv.r8"), n("conv.u4"), n("conv.u8"), op("callvirt", Op::Tok),
    op("cpobj", Op::Tok), op("ldobj", Op::Tok), op("ldstr", Op::Str), op("newobj", Op::Tok), op("castclass", Op::Tok), op("isinst", Op::Tok), n("conv.r.un"), None,
    None, op("unbox", Op::Tok), n("throw"), op("ldfld", Op::Tok), op("ldflda", Op::Tok), op("stfld", Op::Tok), op("ldsfld", Op::Tok), op("ldsflda", Op::Tok),
    op("stsfld", Op::Tok), op("stobj", Op::Tok), n("conv.ovf.i1.un"), n("conv.ovf.i2.un"), n("conv.ovf.i4.un"), n("conv.ovf.i8.un"), n("conv.ovf.u1.un"), n("conv.ovf.u2.un"),
    n("conv.ovf.u4.un"), n("conv.ovf.u8.un"), n("conv.ovf.i.un"), n("conv.ovf.u.un"), op("box", Op::Tok), op("newarr", Op::Tok), n("ldlen"), op("ldelema", Op::Tok),
    n("ldelem.i1"), n("ldelem.u1"), n("ldelem.i2"), n("ldelem.u2"), n("ldelem.i4"), n("ldelem.u4"), n("ldelem.i8"), n("ldelem.i"),
    n("ldelem.r4"), n("ldelem.r8"), n("ldelem.ref"), n("stelem.i"), n("stelem.i1"), n("stelem.i2"), n("stelem.i4"), n("stelem.i8"),
    n("stelem.r4"), n("stelem.r8"), n("stelem.ref"), op("ldelem", Op::Tok), op("stelem", Op::Tok), op("unbox.any", Op::Tok), None, None,
    None, None, None, None, None, None, None, None,
    None, None, None, n("conv.ovf.i1"), n("conv.ovf.u1"), n("conv.ovf.i2"), n("conv.ovf.u2"), n("conv.ovf.i4"),
    n("conv.ovf.u4"), n("conv.ovf.i8"), n("conv.ovf.u8"), None, None, None, None, None,
    None, None, op("refanyval", Op::Tok), n("ckfinite"), None, None, op("mkrefany", Op::Tok), None,
    None, None, None, None, None, None, None, None,
    op("ldtoken", Op::Tok), n("conv.u2"), n("conv.u1"), n("conv.i"), n("conv.ovf.i"), n("conv.ovf.u"), n("add.ovf"), n("add.ovf.un"),
    n("mul.ovf"), n("mul.ovf.un"), n("sub.ovf"), n("sub.ovf.un"), n("endfinally"), op("leave", Op::Br), op("leave.s", Op::BrS), n("stind.i"),
    n("conv.u"),
];

/// Opcodes with the 0xFE prefix.
#[rustfmt::skip]
const OPS2: [OpInfo; 0x1F] = [
    n("arglist"), n("ceq"), n("cgt"), n("cgt.un"), n("clt"), n("clt.un"), op("ldftn", Op::Tok), op("ldvirtftn", Op::Tok),
    None, op("ldarg", Op::U2), op("ldarga", Op::U2), op("starg", Op::U2), op("ldloc", Op::U2), op("ldloca", Op::U2), op("stloc", Op::U2), n("localloc"),
    None, n("endfilter"), op("unaligned.", Op::U1), n("volatile."), n("tail."), op("initobj", Op::Tok), op("constrained.", Op::Tok), n("cpblk"),
    n("initblk"), op("no.", Op::U1), n("rethrow"), None, op("sizeof", Op::Tok), n("refanytype"), n("readonly."),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// A table stream with only TypeSpec rows, followed by the blob heap.
    fn type_specs(blobs: &[&[u8]]) -> (Vec<u8>, Vec<Stream>) {
        let mut d = vec![0u8; 24];
        d[8..16].copy_from_slice(&(1u64 << 0x1B).to_le_bytes());
        d.extend_from_slice(&(blobs.len() as u32).to_le_bytes());
        let mut heap = vec![0u8];
        for b in blobs {
            d.extend_from_slice(&(heap.len() as u16).to_le_bytes());
            heap.push(b.len() as u8);
            heap.extend_from_slice(b);
        }
        let tables = d.len();
        d.extend_from_slice(&heap);
        let streams = vec![("#~".to_string(), 0, tables), ("#Blob".to_string(), tables, heap.len())];
        (d, streams)
    }

    fn resolved(data: &[u8], streams: &[Stream]) -> Vec<String> {
        let mut out = String::new();
        for n in nodes(data, streams) {
            crate::analysis::dump(&n, 0, &mut out);
        }
        out.lines().filter(|l| l.contains("Signature=")).map(|l| l[l.find("Signature=").unwrap()..].trim_end().to_string()).collect()
    }

    #[test]
    fn a_cut_il_listing_says_so() {
        let (mut d, streams) = type_specs(&[]);
        let body = d.len();
        // Fat header (12 bytes), then nops.
        let il = |d: &mut Vec<u8>, size: u32| {
            d.truncate(body);
            d.extend_from_slice(&[0x03, 0x30, 8, 0]);
            d.extend_from_slice(&size.to_le_bytes());
            d.extend_from_slice(&[0; 4]);
            d.resize(body + 12 + size as usize, 0);
        };
        il(&mut d, 100_007);
        let text = Md::parse(&d, &streams).unwrap().il(body, "m");
        assert!(text.ends_with("IL_1869F: nop\n// listing stopped after 100000 instructions; 7 bytes of code not shown\n"), "{}", &text[text.len() - 120..]);
        il(&mut d, 100_000);
        let text = Md::parse(&d, &streams).unwrap().il(body, "m");
        assert!(text.ends_with("IL_1869F: nop\n"), "a listing that fits has no such line");
    }

    #[test]
    fn an_il_listing_of_long_operands_is_bounded() {
        // A generic instance with 60 arguments: about 400 bytes of text for
        // every `call` of 5 bytes that names it.
        let mut spec = vec![0x15, 0x12, 0x05, 60];
        spec.extend_from_slice(&[0x08; 60]);
        let (mut d, streams) = type_specs(&[&spec]);
        let body = d.len();
        let size = 5 * 90_000u32;
        d.extend_from_slice(&[0x03, 0x30, 8, 0]);
        d.extend_from_slice(&size.to_le_bytes());
        d.extend_from_slice(&[0; 4]);
        d.extend([0x28, 1, 0, 0, 0x1B].repeat(90_000));
        let text = Md::parse(&d, &streams).unwrap().il(body, "m");
        assert!(text.contains("IL_0005: call TypeRef[1]<int32, int32, "), "{}", &text[..200]);
        assert!((MAX_IL_TEXT..MAX_IL_TEXT + 4096).contains(&text.len()), "{} bytes of listing", text.len());
        let last = text.lines().last().unwrap();
        assert!(last.starts_with("// listing stopped after ") && last.ends_with(" bytes of code not shown") && !last.contains(" 90000 "), "{last}");
    }

    #[test]
    fn type_spec_rows_decode_as_types() {
        // ECMA-335 II.23.2.14: no calling convention byte in front.
        let (d, streams) = type_specs(&[&[0x15, 0x12, 0x05, 0x01, 0x08], &[0x12, 0x05], &[0x1D, 0x0E]]);
        let md = Md::parse(&d, &streams).unwrap();
        assert_eq!(md.type_spec_text(&[0x15, 0x12, 0x05, 0x01, 0x08]), "TypeRef[1]<int32>");
        assert_eq!(resolved(&d, &streams), ["Signature=TypeRef[1]<int32>", "Signature=TypeRef[1]", "Signature=string[]"]);
        assert_eq!(md.token_text(0x1B00_0001), "TypeRef[1]<int32>");
    }

    #[test]
    fn self_referencing_type_spec_is_bounded() {
        // A function pointer with 24 parameters that each name TypeSpec row 1
        // again: 24^16 nodes without a budget.
        let mut blob = vec![0x1B, 0x00, 24, 0x01];
        blob.extend_from_slice(&[0x12, 0x06].repeat(24));
        let (d, streams) = type_specs(&[&blob]);
        let rows = resolved(&d, &streams);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].contains("TypeSpec[1]") && rows[0].len() < 2 * MAX_SIG_TEXT, "{}", rows[0]);
        // Without a cycle the budget ends it.
        let mut chain: Vec<Vec<u8>> = Vec::new();
        // Rows 1..=8, each naming the next one 60 times; the last names nothing.
        for i in 0..8u8 {
            let mut x = vec![0x1B, 0x00, 60, 0x01];
            x.extend_from_slice(&[0x12, if i == 7 { 0x05 } else { ((i + 2) << 2) | 2 }].repeat(60));
            chain.push(x);
        }
        let refs: Vec<&[u8]> = chain.iter().map(|v| v.as_slice()).collect();
        let (d, streams) = type_specs(&refs);
        let md = Md::parse(&d, &streams).unwrap();
        let text = md.token_text(0x1B00_0001);
        assert_eq!(text, "?", "60^7 nodes must not be decoded");
        assert!(md.token_text(0x1B00_0008).len() <= MAX_SIG_TEXT + 3);
    }

    /// One TypeDef whose name and namespace are 600 bytes each, and `rows`
    /// TypeSpec rows that all share one blob.
    fn long_named(rows: usize, blob: &[u8]) -> (Vec<u8>, Vec<Stream>) {
        let mut d = vec![0u8; 24];
        d[8..16].copy_from_slice(&((1u64 << 2) | (1u64 << 0x1B)).to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&(rows as u32).to_le_bytes());
        // TypeDef: Flags, Name, Namespace, Extends, FieldList, MethodList.
        d.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        d.extend_from_slice(&[1, 0].repeat(rows));
        let tables = d.len();
        d.push(0);
        d.extend_from_slice(&[b'A'; 600]);
        d.push(0);
        let heap = d.len();
        d.push(0);
        d.extend_from_slice(&[0x80 | (blob.len() >> 8) as u8, blob.len() as u8]);
        d.extend_from_slice(blob);
        let streams = vec![("#~".to_string(), 0, tables), ("#Strings".to_string(), tables, heap - tables), ("#Blob".to_string(), heap, d.len() - heap)];
        (d, streams)
    }

    #[test]
    fn long_names_do_not_multiply_the_work() {
        // A function pointer with three function pointer parameters that each
        // take 255 times the long named type: 780 KB of text per row if the
        // text were built before it is cut.
        let mut blob = vec![0x1B, 0x00, 0x03, 0x01];
        for _ in 0..3 {
            blob.extend_from_slice(&[0x1B, 0x00, 0x80, 0xFF, 0x01]);
            blob.extend_from_slice(&[0x12, 0x04].repeat(255));
        }
        let (d, streams) = long_named(2000, &blob);
        let md = Md::parse(&d, &streams).unwrap();
        assert_eq!(md.type_name(2, 1, 0).len(), 1025, "heap strings are read up to 512 bytes");
        let node = md.table_node(0x1B);
        // The second name no longer fits, and that ends the row.
        let used = WORK_BUDGET - md.work.get();
        assert!(used <= 2000 * 8, "{used} type nodes decoded for 2000 rows");
        let mut out = String::new();
        crate::analysis::dump(&node, 0, &mut out);
        assert!(out.len() < 2000 * 200, "{} bytes of text for 2000 rows", out.len());
        assert_eq!(md.token_text(0x1B00_0001), "?");
    }

    /// One TypeDef with a 600 byte name and namespace, one MethodDef and one
    /// MemberRef of that method with the same name, and `rows` CustomAttribute
    /// rows that all name the method as parent and the MemberRef as type.
    fn long_named_attributes(rows: usize) -> (Vec<u8>, Vec<Stream>) {
        let mut d = vec![0u8; 24];
        d[8..16].copy_from_slice(&((1u64 << 2) | (1 << 6) | (1 << 0x0A) | (1 << 0x0C)).to_le_bytes());
        for n in [1, 1, 1, rows as u32] {
            d.extend_from_slice(&n.to_le_bytes());
        }
        d.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0]); // TypeDef
        d.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0]); // MethodDef
        d.extend_from_slice(&[(1 << 3) | 3, 0, 1, 0, 0, 0]); // MemberRef: Class = MethodDef[1]
        // CustomAttribute: Parent = MethodDef[1], Type = MemberRef[1].
        d.extend_from_slice(&[1 << 5, 0, (1 << 3) | 3, 0, 0, 0].repeat(rows));
        let tables = d.len();
        d.push(0);
        d.extend_from_slice(&[b'A'; 600]);
        d.push(0);
        let streams = vec![("#~".to_string(), 0, tables), ("#Strings".to_string(), tables, d.len() - tables)];
        (d, streams)
    }

    #[test]
    fn names_reached_through_an_index_are_clipped_and_budgeted() {
        let (d, streams) = long_named_attributes(20_000);
        let md = Md::parse(&d, &streams).unwrap();
        assert_eq!(md.method_name(1).len(), 1025 + 2 + 512);
        assert_eq!(md.member_ref_name(1).len(), 1025 + 2 + 512 + 2 + 512);
        // 3.6 KB per row of 6 bytes if the names were joined as they are.
        let mut out = String::new();
        for n in md.nodes() {
            crate::analysis::dump(&n, 0, &mut out);
        }
        assert!(out.contains("[CustomAttribute (20000)]"), "the budget is not reached");
        assert!(out.len() < 20_000 * 700, "{} bytes of text for 20,000 rows", out.len());
        let methods = md.methods();
        assert_eq!(methods[0].name.len(), MAX_NAME + 3);

        // All tables of a file share one budget; past it the rows show row numbers.
        let md = Md::parse(&d, &streams).unwrap();
        md.resolved.set(10_000);
        let node = md.table_node(0x0C);
        assert_eq!(node.title, "CustomAttribute (20000, names resolved for the first 19)");
        let crate::model::View::Grid(g) = &node.view else { panic!("a table is a grid") };
        let text = |row: usize| g.rows[row].last().unwrap().text.as_str();
        assert!(text(18).starts_with("Parent=AAAA") && text(18).len() == 2 * (MAX_NAME + 3) + 14, "{}", text(18));
        assert_eq!(text(19), "Parent=MethodDef[1], Type=MemberRef[1]");
        assert_eq!(text(19_999), "Parent=MethodDef[1], Type=MemberRef[1]");
        assert_eq!(md.table_node(0x0A).title, "MemberRef (1, names resolved for the first 0)");
        let methods = md.methods();
        assert_eq!((methods[0].name.as_str(), methods[0].signature.as_str()), ("MethodDef[1]", ""));
    }

    #[test]
    fn one_table_has_a_total_work_budget() {
        // 255 cheap nodes per row: each row is fine alone, 100,000 are not.
        let mut blob = vec![0x1B, 0x00, 0x80, 0xFE, 0x01];
        blob.extend_from_slice(&[0x08].repeat(254));
        let rows = WORK_BUDGET / 256 + 100;
        let (d, streams) = long_named(rows, &blob);
        let md = Md::parse(&d, &streams).unwrap();
        let node = md.table_node(0x1B);
        assert_eq!(md.work.get(), 0, "the budget is used up before the last row");
        let crate::model::View::Grid(g) = &node.view else { panic!("a table is a grid") };
        let texts: Vec<&str> = g.rows.iter().filter_map(|r| r.last()).map(|c| c.text.as_str()).collect();
        assert_eq!(texts.len(), rows);
        assert!(texts[0].starts_with("Signature=method void *(int32, int32"), "{}", texts[0]);
        assert_eq!(texts[rows - 1], "Signature=?");
        // The next batch starts with a full budget again.
        assert_eq!(md.methods().len(), 0);
        assert_eq!(md.work.get(), WORK_BUDGET);
    }
}
