//! Mach-O dynamic linking data and language metadata: the exports trie, the
//! classic bind and rebase opcode streams, chained fixups, Objective-C
//! classes and methods, and Swift type descriptors.
//!
//! Everything here is little endian, as on every platform that uses these
//! structures. Offsets are absolute file offsets unless stated otherwise.

use crate::model::*;

const LE: Endian = Endian::Little;
const MAX_ROWS: usize = 100_000;
/// Memory the grids of one file may take, shared by all its architecture
/// slices. The row caps alone do not bound it: a few bytes of opcodes repeat
/// a row 100,000 times, every row carries a symbol name of up to 4 KB, and a
/// fat file can name the same slice 30 times.
pub const GRID_BUDGET: usize = 256 << 20;
/// Grid memory per byte of input, with a floor of `MIN_GRID_BUDGET`: a file of
/// a few KB must not reach `GRID_BUDGET` (a 3.8 KB file whose bind opcodes
/// repeated one 4 KB symbol took 519 MB). Real files stay far below it.
pub const GRID_BUDGET_PER_BYTE: usize = 64;
pub const MIN_GRID_BUDGET: usize = 16 << 20;
/// Chained fixup links followed per file. Segments, pages and the slices of
/// a fat file may all describe the same bytes.
pub const MAX_LINKS: usize = 4_000_000;
/// Segments kept per slice for address lookups, which scan them. dyld allows
/// 255; the load commands could name 4096.
pub const MAX_SEGS: usize = 256;

/// What one file may still spend, shared by all its architecture slices.
pub struct Budget {
    /// What is left of `GRID_BUDGET`.
    pub grid: std::cell::Cell<usize>,
    /// What is left of `MAX_LINKS`.
    pub links: std::cell::Cell<usize>,
}

impl Budget {
    pub fn new() -> Budget {
        Budget { grid: std::cell::Cell::new(GRID_BUDGET), links: std::cell::Cell::new(MAX_LINKS) }
    }

    /// The budget for a file of `len` bytes.
    pub fn for_file(len: usize) -> Budget {
        let b = Budget::new();
        b.grid.set(grid_budget(len));
        b
    }
}

/// Grid memory a file of `len` bytes may use.
pub fn grid_budget(len: usize) -> usize {
    len.saturating_mul(GRID_BUDGET_PER_BYTE).clamp(MIN_GRID_BUDGET, GRID_BUDGET)
}

impl Default for Budget {
    fn default() -> Budget {
        Budget::new()
    }
}

pub struct Seg {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    /// Relative to the start of the architecture slice.
    pub fileoff: u64,
    pub filesize: u64,
}

pub struct Sect {
    pub name: String,
    pub seg: String,
    pub addr: u64,
    pub size: u64,
    /// Relative to the start of the architecture slice.
    pub offset: usize,
}

/// What the load commands say about one architecture slice.
pub struct Ctx<'a> {
    pub data: &'a [u8],
    pub base: usize,
    pub is64: bool,
    /// At most `MAX_SEGS`, in load command order.
    pub segs: Vec<Seg>,
    /// Load address of the image: where `__TEXT` is mapped. Resolved once;
    /// it is needed for every chained fixup link.
    pub image_base: u64,
    pub sects: Vec<Sect>,
    pub dylibs: Vec<String>,
    /// LC_DYLD_INFO: rebase, bind, weak bind, lazy bind, export (offset, size) pairs, slice relative.
    pub dyld_info: Option<[(usize, usize); 5]>,
    /// LC_DYLD_EXPORTS_TRIE and LC_DYLD_CHAINED_FIXUPS data, slice relative.
    pub exports_trie: Option<(usize, usize)>,
    pub chained: Option<(usize, usize)>,
    pub budget: &'a Budget,
}

/// Bounds checked reader over one blob.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn byte(&mut self) -> Option<u8> {
        let v = *self.b.get(self.p)?;
        self.p += 1;
        Some(v)
    }

    fn uleb(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    fn sleb(&mut self) -> Option<i64> {
        let mut v = 0i64;
        let mut shift = 0;
        loop {
            let b = self.byte()?;
            v |= ((b & 0x7f) as i64) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1i64 << shift;
                }
                return Some(v);
            }
            if shift >= 64 {
                return None;
            }
        }
    }

    fn cstr(&mut self) -> Option<String> {
        let rest = self.b.get(self.p..)?;
        let n = rest.iter().take(4096).position(|c| *c == 0)?;
        self.p += n + 1;
        Some(printable(&rest[..n]))
    }
}

impl<'a> Ctx<'a> {
    fn rd(&self) -> Rd<'a> {
        Rd::new(self.data, LE)
    }

    fn blob(&self, r: (usize, usize)) -> &'a [u8] {
        let start = self.base.saturating_add(r.0);
        self.data.get(start..start.saturating_add(r.1).min(self.data.len())).unwrap_or(&[])
    }

    fn vm_to_off(&self, vm: u64) -> Option<usize> {
        let s = self.segs.iter().find(|s| vm >= s.vmaddr && vm - s.vmaddr < s.filesize)?;
        self.base.checked_add(clamp_off(s.fileoff.saturating_add(vm - s.vmaddr)))
    }

    fn sect(&self, name: &str) -> Option<&Sect> {
        self.sects.iter().find(|s| s.name == name && s.offset != 0)
    }

    fn lib(&self, ordinal: i64) -> String {
        match ordinal {
            0 => "(this image)".into(),
            -1 => "(main executable)".into(),
            -2 => "(flat lookup)".into(),
            -3 => "(weak lookup)".into(),
            n if n > 0 => self.dylibs.get(n as usize - 1).cloned().unwrap_or_else(|| format!("library {n}")),
            n => format!("ordinal {n}"),
        }
    }

    fn seg_addr(&self, seg: usize, off: u64) -> (String, u64) {
        match self.segs.get(seg) {
            Some(s) => (s.name.clone(), s.vmaddr.wrapping_add(off)),
            None => (format!("segment {seg}"), off),
        }
    }

    /// Add a row and charge its cells and text to the budget. Returns false,
    /// without adding it, once the budget is used up.
    fn push(&self, g: &mut Grid, row: Vec<Cell>, span: Option<(usize, usize)>) -> bool {
        let left = self.budget.grid.get();
        if left == 0 {
            return false;
        }
        let cost: usize = row.iter().map(|c| c.text.len() + std::mem::size_of::<Cell>()).sum();
        self.budget.grid.set(left.saturating_sub(cost));
        g.push(row, span);
        true
    }

    /// Rows a grid can still take.
    fn room(&self, g: &Grid) -> usize {
        if self.budget.grid.get() == 0 { 0 } else { MAX_ROWS.saturating_sub(g.rows.len()) }
    }

    /// Row count for a title; says so when the budget cut the grid short.
    fn count(&self, n: usize) -> String {
        if self.budget.grid.get() == 0 { format!("first {n} shown") } else { n.to_string() }
    }

    fn cstr_at(&self, vm: u64) -> Option<String> {
        Some(self.rd().cstr(self.vm_to_off(vm)?, 512))
    }
}

/// All nodes this module can produce for a slice.
pub fn nodes(ctx: &Ctx) -> Vec<Node> {
    let mut out = Vec::new();
    let trie = ctx.exports_trie.or(ctx.dyld_info.map(|d| d[4])).filter(|r| r.1 != 0);
    if let Some(r) = trie {
        out.push(exports(ctx, r));
    }
    if let Some(d) = ctx.dyld_info {
        for (r, title, lazy) in [(d[1], "Binds", false), (d[2], "Weak Binds", false), (d[3], "Lazy Binds", true)] {
            if r.1 != 0 {
                out.push(binds(ctx, r, title, lazy));
            }
        }
        if d[0].1 != 0 {
            out.push(rebases(ctx, d[0]));
        }
    }
    let format = ctx.chained.filter(|r| r.1 != 0).and_then(|r| {
        let (node, format) = chained_fixups(ctx, r);
        out.push(node);
        format
    });
    if ctx.is64 {
        if let Some(n) = objc(ctx, format) {
            out.push(n);
        }
        if let Some(n) = swift(ctx, format) {
            out.push(n);
        }
    }
    out
}

// --- exports trie -------------------------------------------------------------

fn exports(ctx: &Ctx, r: (usize, usize)) -> Node {
    let blob = ctx.blob(r);
    let mut g = Grid::new(&["Symbol", "Address", "Flags", "Kind"]);
    // Depth first walk with an explicit stack; every node offset is visited once.
    // The stack holds, per open node, where its next child record is, how many
    // are left and how long the prefix was, so the prefix exists only once.
    let mut prefix = String::new();
    let mut stack: Vec<(usize, u8, usize)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut next = Some(0usize);
    // A well formed trie reads every byte once; nodes that overlap cannot buy more than this.
    let mut work = blob.len().saturating_mul(8).saturating_add(4096);
    loop {
        if let Some(off) = next.take() {
            if ctx.room(&g) == 0 || seen.len() > 1_000_000 {
                break;
            }
            if seen.insert(off) {
                let mut c = Cur { b: blob, p: off };
                let Some(terminal) = c.uleb() else { continue };
                let children_at = c.p.saturating_add(terminal as usize);
                if terminal != 0
                    && let Some(flags) = c.uleb()
                {
                    let (address, kind) = if flags & 0x8 != 0 {
                        let ordinal = c.uleb().unwrap_or(0);
                        let name = c.cstr().unwrap_or_default();
                        (
                            String::new(),
                            format!("re-export from {}{}", ctx.lib(ordinal as i64), if name.is_empty() { String::new() } else { format!(" as {name}") }),
                        )
                    } else {
                        let addr = c.uleb().unwrap_or(0);
                        let kind = match flags & 3 {
                            1 => "thread local",
                            2 => "absolute",
                            _ if flags & 0x10 != 0 => "stub and resolver",
                            _ => "regular",
                        };
                        (
                            format!("{:X}", if flags & 3 == 2 { addr } else { ctx.image_base.wrapping_add(addr) }),
                            format!("{kind}{}", if flags & 0x4 != 0 { ", weak" } else { "" }),
                        )
                    };
                    ctx.push(
                        &mut g,
                        vec![Cell::text(prefix.clone()), Cell::text(address), Cell::text(format!("{flags:X}")), Cell::text(kind)],
                        Some((ctx.base + r.0 + off, 1)),
                    );
                }
                let mut c = Cur { b: blob, p: children_at };
                if let Some(count) = c.byte() {
                    stack.push((c.p, count, prefix.len()));
                }
            }
        }
        let Some(top) = stack.last_mut() else { break };
        prefix.truncate(top.2);
        if top.1 == 0 {
            stack.pop();
            continue;
        }
        top.1 -= 1;
        let mut c = Cur { b: blob, p: top.0 };
        let (Some(label), Some(child)) = (c.cstr(), c.uleb()) else {
            stack.pop();
            continue;
        };
        let Some(left) = work.checked_sub(c.p - top.0) else { break };
        work = left;
        top.0 = c.p;
        if prefix.len() + label.len() <= 4096 {
            prefix.push_str(&label);
            next = Some(child as usize);
        }
    }
    g.rows.sort_by(|a, b| a[0].text.cmp(&b[0].text));
    Node::grid(format!("Exports Trie ({})", ctx.count(g.rows.len())), g).with_span(ctx.base + r.0, r.1)
}

// --- classic bind and rebase opcodes -------------------------------------------

fn bind_type(t: u8) -> &'static str {
    match t {
        1 => "pointer",
        2 => "text absolute32",
        3 => "text pcrel32",
        _ => "?",
    }
}

fn binds(ctx: &Ctx, r: (usize, usize), title: &str, lazy: bool) -> Node {
    let mut c = Cur { b: ctx.blob(r), p: 0 };
    let ps = if ctx.is64 { 8u64 } else { 4 };
    let mut g = Grid::new(&["Segment", "Address", "Type", "Library", "Symbol", "Addend"]);
    let (mut seg, mut off, mut ty, mut lib, mut sym, mut addend) = (0usize, 0u64, 1u8, 0i64, String::new(), 0i64);
    let emit = |g: &mut Grid, seg: usize, off: u64, ty: u8, lib: i64, sym: &str, addend: i64| {
        if ctx.room(g) > 0 {
            let (name, addr) = ctx.seg_addr(seg, off);
            ctx.push(
                g,
                vec![
                    Cell::text(name),
                    Cell::text(format!("{addr:X}")),
                    Cell::text(bind_type(ty)),
                    Cell::text(ctx.lib(lib)),
                    Cell::text(sym),
                    Cell::text(if addend == 0 { String::new() } else { addend.to_string() }),
                ],
                ctx.vm_to_off(addr).map(|o| (o, ps as usize)),
            );
        }
    };
    let mut steps = 0;
    while let Some(op) = c.byte() {
        steps += 1;
        if steps > 4_000_000 {
            break;
        }
        let imm = (op & 0x0f) as u64;
        let ok = match op & 0xf0 {
            // In the lazy stream DONE only ends one entry.
            0x00 if lazy => Some(()),
            0x00 => break,
            0x10 => {
                lib = imm as i64;
                Some(())
            }
            0x20 => c.uleb().map(|v| lib = v as i64),
            0x30 => {
                lib = if imm == 0 { 0 } else { (imm as i8 | -16i8) as i64 };
                Some(())
            }
            0x40 => c.cstr().map(|s| sym = s),
            0x50 => {
                ty = imm as u8;
                Some(())
            }
            0x60 => c.sleb().map(|v| addend = v),
            0x70 => c.uleb().map(|v| {
                seg = imm as usize;
                off = v;
            }),
            0x80 => c.uleb().map(|v| off = off.wrapping_add(v)),
            0x90 => {
                emit(&mut g, seg, off, ty, lib, &sym, addend);
                off = off.wrapping_add(ps);
                Some(())
            }
            0xA0 => c.uleb().map(|v| {
                emit(&mut g, seg, off, ty, lib, &sym, addend);
                off = off.wrapping_add(ps).wrapping_add(v);
            }),
            0xB0 => {
                emit(&mut g, seg, off, ty, lib, &sym, addend);
                off = off.wrapping_add(ps).wrapping_add(imm * ps);
                Some(())
            }
            0xC0 => c.uleb().zip(c.uleb()).map(|(count, skip)| {
                // Rows past the cap are not shown, so the rest of the run only moves the address.
                let shown = count.min(ctx.room(&g) as u64);
                for _ in 0..shown {
                    emit(&mut g, seg, off, ty, lib, &sym, addend);
                    off = off.wrapping_add(ps).wrapping_add(skip);
                }
                off = off.wrapping_add((count - shown).wrapping_mul(ps.wrapping_add(skip)));
            }),
            // Threaded binds (arm64e) carry their own table; not decoded here.
            _ => None,
        };
        if ok.is_none() {
            break;
        }
    }
    Node::grid(format!("{title} ({})", ctx.count(g.rows.len())), g).with_span(ctx.base + r.0, r.1)
}

fn rebases(ctx: &Ctx, r: (usize, usize)) -> Node {
    let mut c = Cur { b: ctx.blob(r), p: 0 };
    let ps = if ctx.is64 { 8u64 } else { 4 };
    let mut g = Grid::new(&["Segment", "Address", "Type"]);
    let (mut seg, mut off, mut ty) = (0usize, 0u64, 1u8);
    let mut total = 0u64;
    let emit = |g: &mut Grid, seg: usize, off: u64, ty: u8| {
        let (name, addr) = ctx.seg_addr(seg, off);
        ctx.push(g, vec![Cell::text(name), Cell::text(format!("{addr:X}")), Cell::text(bind_type(ty))], ctx.vm_to_off(addr).map(|o| (o, ps as usize)));
    };
    let mut steps = 0u64;
    while let Some(op) = c.byte() {
        let imm = (op & 0x0f) as u64;
        steps += 1;
        if steps > 4_000_000 {
            break;
        }
        // Runs are only looped over while rows are shown; past the cap the
        // rest is counted and the address moved arithmetically, so a stream
        // of huge repeat counts costs one step per opcode.
        let mut run = |g: &mut Grid, count: u64, skip: u64, off: &mut u64| {
            let shown = count.min(ctx.room(g) as u64);
            for _ in 0..shown {
                emit(g, seg, *off, ty);
                *off = off.wrapping_add(ps).wrapping_add(skip);
            }
            total = total.saturating_add(count);
            *off = off.wrapping_add((count - shown).wrapping_mul(ps.wrapping_add(skip)));
        };
        let ok = match op & 0xf0 {
            0x00 => break,
            0x10 => {
                ty = imm as u8;
                Some(())
            }
            0x20 => c.uleb().map(|v| {
                seg = imm as usize;
                off = v;
            }),
            0x30 => c.uleb().map(|v| off = off.wrapping_add(v)),
            0x40 => {
                off = off.wrapping_add(imm * ps);
                Some(())
            }
            0x50 => {
                run(&mut g, imm, 0, &mut off);
                Some(())
            }
            0x60 => c.uleb().map(|n| run(&mut g, n, 0, &mut off)),
            0x70 => c.uleb().map(|v| run(&mut g, 1, v, &mut off)),
            0x80 => c.uleb().zip(c.uleb()).map(|(n, skip)| run(&mut g, n, skip, &mut off)),
            _ => None,
        };
        if ok.is_none() {
            break;
        }
    }
    let shown = g.rows.len();
    let title = if total > shown as u64 { format!("Rebases ({total}, first {shown} shown)") } else { format!("Rebases ({shown})") };
    Node::grid(title, g).with_span(ctx.base + r.0, r.1)
}

// --- chained fixups -------------------------------------------------------------

const PTR_FORMATS: Names = &[
    (1, "ARM64E"),
    (2, "PTR_64"),
    (3, "PTR_32"),
    (4, "PTR_32_CACHE"),
    (5, "PTR_32_FIRMWARE"),
    (6, "PTR_64_OFFSET"),
    (7, "ARM64E_KERNEL"),
    (8, "PTR_64_KERNEL_CACHE"),
    (9, "ARM64E_USERLAND"),
    (10, "ARM64E_FIRMWARE"),
    (11, "X86_64_KERNEL_CACHE"),
    (12, "ARM64E_USERLAND24"),
];

enum Fixup {
    /// Target virtual address.
    Rebase(u64, bool),
    /// Import ordinal and addend.
    Bind(u32, i64, bool),
}

/// Decode one 64 bit chained pointer. Returns the fixup and the distance to the next one.
fn decode_chained(raw: u64, format: u16, image_base: u64) -> Option<(Fixup, u64)> {
    match format {
        2 | 6 => {
            let next = (raw >> 51 & 0xfff) * 4;
            Some(if raw >> 63 != 0 {
                (Fixup::Bind((raw & 0xff_ffff) as u32, (raw >> 24 & 0xff) as i64, false), next)
            } else {
                let target = raw & 0xf_ffff_ffff;
                let high8 = (raw >> 36 & 0xff) << 56;
                (Fixup::Rebase(if format == 6 { image_base.wrapping_add(target) } else { target } | high8, false), next)
            })
        }
        1 | 9 | 12 => {
            let next = (raw >> 51 & 0x7ff) * 8;
            let auth = raw >> 63 != 0;
            Some(if raw >> 62 & 1 != 0 {
                let ordinal = if format == 12 { raw & 0xff_ffff } else { raw & 0xffff } as u32;
                let addend = if auth { 0 } else { ((raw >> 32 & 0x7_ffff) as i64) << 45 >> 45 };
                (Fixup::Bind(ordinal, addend, auth), next)
            } else if auth {
                (Fixup::Rebase(image_base.wrapping_add(raw & 0xffff_ffff), true), next)
            } else {
                let target = raw & 0x7ff_ffff_ffff;
                let high8 = (raw >> 43 & 0xff) << 56;
                (Fixup::Rebase(if format == 1 { target } else { image_base.wrapping_add(target) } | high8, false), next)
            })
        }
        _ => None,
    }
}

/// Target address of a pointer stored in the file, undoing chained fixup encoding.
fn pointer(ctx: &Ctx, off: usize, format: Option<u16>) -> Option<u64> {
    let rd = ctx.rd();
    if !rd.has(off, 8) {
        return None;
    }
    let raw = rd.u64(off);
    match format {
        None => Some(raw),
        Some(f) => match decode_chained(raw, f, ctx.image_base)? {
            (Fixup::Rebase(t, _), _) => Some(t & 0x00ff_ffff_ffff_ffff),
            (Fixup::Bind(..), _) => None,
        },
    }
}

fn chained_fixups(ctx: &Ctx, r: (usize, usize)) -> (Node, Option<u16>) {
    let rd = ctx.rd();
    let start = ctx.base + r.0;
    let end = start.saturating_add(r.1).min(ctx.data.len());
    let mut f = Fields::new(ctx.data, LE);
    f.seq(
        start,
        &[
            ("fixups_version", 4, Kind::Dec),
            ("starts_offset", 4, Kind::Hex),
            ("imports_offset", 4, Kind::Hex),
            ("symbols_offset", 4, Kind::Hex),
            ("imports_count", 4, Kind::Dec),
            ("imports_format", 4, Kind::Dec),
            ("symbols_format", 4, Kind::Dec),
        ],
    );
    let starts = start + rd.u32(start + 4) as usize;
    let imports_off = start + rd.u32(start + 8) as usize;
    let symbols = start + rd.u32(start + 12) as usize;
    let count = (rd.u32(start + 16) as usize).min(MAX_ROWS);
    let import_format = rd.u32(start + 20);

    // Imports.
    let mut imports: Vec<String> = Vec::new();
    let mut ig = Grid::new(&["#", "Library", "Symbol", "Weak", "Addend"]);
    let entry = match import_format {
        1 => 4,
        2 => 8,
        3 => 16,
        _ => 0,
    };
    for i in 0..if entry == 0 { 0 } else { count } {
        let o = imports_off + i * entry;
        if o + entry > end {
            break;
        }
        let (lib, weak, name_off, addend) = if import_format == 3 {
            let v = rd.u64(o);
            ((v & 0xffff) as u16 as i16 as i64, v >> 16 & 1 != 0, (v >> 32) as usize, rd.u64(o + 8) as i64)
        } else {
            let v = rd.u32(o);
            ((v & 0xff) as u8 as i8 as i64, v >> 8 & 1 != 0, (v >> 9) as usize, if import_format == 2 { rd.u32(o + 4) as i32 as i64 } else { 0 })
        };
        let name = if symbols + name_off < end { rd.cstr(symbols + name_off, (end - symbols - name_off).min(1024)) } else { String::new() };
        ctx.push(
            &mut ig,
            vec![
                Cell::text(i.to_string()),
                Cell::text(ctx.lib(lib)),
                Cell::text(name.clone()),
                Cell::text(if weak { "weak" } else { "" }),
                Cell::text(if addend == 0 { String::new() } else { addend.to_string() }),
            ],
            Some((o, entry)),
        );
        imports.push(name);
    }

    // Chains, segment by segment and page by page.
    let mut fg = Grid::new(&["Segment", "Address", "Kind", "Target"]);
    let mut total = 0usize;
    let mut capped = false;
    let mut format_seen = None;
    let seg_count = (rd.u32(starts) as usize).min(256);
    'segs: for seg in 0..seg_count {
        let info = rd.u32(starts + 4 + seg * 4) as usize;
        if info == 0 || starts + info + 22 > end {
            continue;
        }
        let s = starts + info;
        let page_size = rd.u16(s + 4) as u64;
        let format = rd.u16(s + 6);
        let seg_off = rd.u64(s + 8);
        let pages = (rd.u16(s + 20) as usize).min(65535);
        format_seen.get_or_insert(format);
        // segment_offset is a memory offset from the image base, not a file
        // offset: the two differ after a segment with zero fill. The segment
        // is resolved once here, so a link does not scan the segments.
        let seg_vm = ctx.image_base.wrapping_add(seg_off);
        let mapped = |x: &&Seg| seg_vm >= x.vmaddr && seg_vm - x.vmaddr < x.filesize;
        let Some(home) = ctx.segs.iter().find(|x| x.vmaddr == seg_vm && mapped(x)).or_else(|| ctx.segs.iter().find(mapped)) else { continue };
        let into = seg_vm - home.vmaddr;
        for page in 0..pages {
            if s + 22 + page * 2 + 2 > end {
                break;
            }
            let first = rd.u16(s + 22 + page * 2);
            if first == 0xffff {
                continue;
            }
            // Offset of the link from the address the entry names.
            let mut rel = (page as u64 * page_size).saturating_add(first as u64);
            // A chain cannot have more links than a page has 4 byte slots.
            for _ in 0..page_size.max(4) / 4 + 1 {
                let delta = into.saturating_add(rel);
                if delta >= home.filesize {
                    break;
                }
                let off = ctx.base.saturating_add(clamp_off(home.fileoff.saturating_add(delta)));
                if !rd.has(off, 8) {
                    break;
                }
                let Some((fixup, next)) = decode_chained(rd.u64(off), format, ctx.image_base) else { break };
                // Segments and pages may all describe the same bytes, so the links are capped in total.
                let left = ctx.budget.links.get();
                if left == 0 {
                    capped = true;
                    break 'segs;
                }
                ctx.budget.links.set(left - 1);
                total += 1;
                if ctx.room(&fg) > 0 {
                    let (kind, target) = match fixup {
                        Fixup::Rebase(t, auth) => (if auth { "rebase (authenticated)" } else { "rebase" }, format!("{:X}", t & 0x00ff_ffff_ffff_ffff)),
                        Fixup::Bind(ordinal, addend, auth) => (
                            if auth { "bind (authenticated)" } else { "bind" },
                            format!(
                                "{}{}",
                                imports.get(ordinal as usize).cloned().unwrap_or_else(|| format!("import {ordinal}")),
                                if addend == 0 { String::new() } else { format!(" + {addend}") }
                            ),
                        ),
                    };
                    ctx.push(
                        &mut fg,
                        vec![Cell::text(home.name.clone()), Cell::text(format!("{:X}", seg_vm.wrapping_add(rel))), Cell::text(kind), Cell::text(target)],
                        Some((off, 8)),
                    );
                }
                if next == 0 {
                    break;
                }
                rel = rel.saturating_add(next);
            }
        }
    }
    if let Some(fmt) = format_seen {
        let name = lookup(PTR_FORMATS, fmt as u64).unwrap_or("unknown");
        f.note(format!("pointer format {fmt} ({name}){}", if decode_chained(0, fmt, 0).is_none() { ", chains not decoded" } else { "" }));
    }
    let shown = fg.rows.len();
    let fixups_title = if capped {
        format!("Fixups (more than {total}, first {shown} shown)")
    } else if total > shown {
        format!("Fixups ({total}, first {shown} shown)")
    } else {
        format!("Fixups ({shown})")
    };
    let node = Node::grid("Chained Fixups", f.finish())
        .with_span(start, r.1)
        .with_children(vec![Node::grid(format!("Imports ({})", ctx.count(ig.rows.len())), ig), Node::grid(fixups_title, fg)]);
    (node, format_seen.filter(|f| decode_chained(0, *f, 0).is_some()))
}

// --- Objective-C ------------------------------------------------------------------

fn objc(ctx: &Ctx, format: Option<u16>) -> Option<Node> {
    let rd = ctx.rd();
    let list = ctx.sect("__objc_classlist")?;
    let mut g = Grid::new(&["Class", "Method", "Types", "Implementation"]);
    let ptr = |off: usize| pointer(ctx, off, format);
    let methods = |g: &mut Grid, class: &str, list_vm: u64, prefix: &str| -> Option<()> {
        let m = ctx.vm_to_off(list_vm)?;
        let flags = rd.u32(m);
        let count = (rd.u32(m + 4) as usize).min(10_000);
        let relative = flags & 0x8000_0000 != 0;
        let entsize = (flags & 0xfffc) as usize;
        if entsize != if relative { 12 } else { 24 } {
            return None;
        }
        for i in 0..count {
            if ctx.room(g) == 0 {
                break;
            }
            let e = m + 8 + i * entsize;
            if !rd.has(e, entsize) {
                break;
            }
            let (name, types, imp) = if relative {
                // Offsets are relative to the field itself, in virtual address space.
                let vm = list_vm.wrapping_add(8 + (i * entsize) as u64);
                let rel = |k: u64| vm.wrapping_add(k).wrapping_add(rd.u32(e + k as usize) as i32 as i64 as u64);
                // The name is a selector reference unless the list says selectors are direct.
                let name = if flags & 0x4000_0000 != 0 { ctx.cstr_at(rel(0)) } else { ctx.vm_to_off(rel(0)).and_then(ptr).and_then(|p| ctx.cstr_at(p)) };
                (name, ctx.cstr_at(rel(4)), if rd.u32(e + 8) == 0 { 0 } else { rel(8) })
            } else {
                (ptr(e).and_then(|p| ctx.cstr_at(p)), ptr(e + 8).and_then(|p| ctx.cstr_at(p)), ptr(e + 16).unwrap_or(0))
            };
            ctx.push(
                g,
                vec![
                    Cell::text(class),
                    Cell::text(format!("{prefix}{}", name.unwrap_or_default())),
                    Cell::text(types.unwrap_or_default()),
                    Cell::text(if imp == 0 { String::new() } else { format!("{imp:X}") }),
                ],
                Some((e, entsize)),
            );
        }
        Some(())
    };
    let mut classes = 0;
    for i in 0..(clamp_off(list.size) / 8).min(20_000) {
        if ctx.budget.grid.get() == 0 {
            break;
        }
        let Some(class_vm) = ptr(ctx.base + list.offset + i * 8) else { continue };
        let Some(c) = ctx.vm_to_off(class_vm) else { continue };
        // class_t: isa, superclass, cache, vtable, data (low bits are flags).
        let ro_of = |class_off: usize| ptr(class_off + 32).and_then(|d| ctx.vm_to_off(d & !7));
        let Some(ro) = ro_of(c) else { continue };
        // class_ro_t: flags, instanceStart, instanceSize, reserved, ivarLayout, name, baseMethods.
        let name = ptr(ro + 24).and_then(|p| ctx.cstr_at(p)).unwrap_or_default();
        classes += 1;
        let before = g.rows.len();
        if let Some(m) = ptr(ro + 32).filter(|m| *m != 0) {
            methods(&mut g, &name, m, "-");
        }
        // Class methods live on the metaclass, reached through isa.
        if let Some(meta_ro) = ptr(c).and_then(|m| ctx.vm_to_off(m)).and_then(ro_of)
            && let Some(m) = ptr(meta_ro + 32).filter(|m| *m != 0)
        {
            methods(&mut g, &name, m, "+");
        }
        if g.rows.len() == before && ctx.room(&g) > 0 {
            ctx.push(&mut g, vec![Cell::text(name), Cell::text("(no methods)"), Cell::text(""), Cell::text("")], Some((c, 40)));
        }
    }
    (classes > 0).then(|| Node::grid(format!("Objective-C Classes ({})", ctx.count(classes)), g).with_span(ctx.base + list.offset, clamp_off(list.size)))
}

// --- Swift --------------------------------------------------------------------------

fn swift(ctx: &Ctx, format: Option<u16>) -> Option<Node> {
    let rd = ctx.rd();
    let sect = ctx.sect("__swift5_types")?;
    let mut g = Grid::new(&["Kind", "Name", "Parent", "Descriptor"]);
    // Relative pointers are 32 bit offsets from the field's own address.
    let rel = |field_vm: u64| -> Option<(u64, u32)> {
        let off = ctx.vm_to_off(field_vm)?;
        rd.has(off, 4).then(|| (field_vm.wrapping_add(rd.u32(off) as i32 as i64 as u64), rd.u32(off)))
    };
    // "Indirectable" pointers set the low bit when they go through a pointer slot.
    let indirectable = |field_vm: u64| -> Option<u64> {
        let (target, raw) = rel(field_vm)?;
        if raw == 0 {
            None
        } else if raw & 1 != 0 {
            pointer(ctx, ctx.vm_to_off(target & !1)?, format)
        } else {
            Some(target)
        }
    };
    let kind_name = |flags: u32| match flags & 0x1f {
        0 => "module",
        1 => "extension",
        2 => "anonymous",
        3 => "protocol",
        4 => "opaque type",
        16 => "class",
        17 => "struct",
        18 => "enum",
        _ => "other",
    };
    let name_of = |desc: u64| -> String { rel(desc.wrapping_add(8)).filter(|r| r.1 != 0).and_then(|r| ctx.cstr_at(r.0)).unwrap_or_default() };
    for i in 0..(clamp_off(sect.size) / 4).min(MAX_ROWS) {
        let field = sect.addr.wrapping_add((i * 4) as u64);
        let Some((target, raw)) = rel(field) else { continue };
        let desc = match raw & 3 {
            0 => target,
            1 => match ctx.vm_to_off(target & !3).and_then(|o| pointer(ctx, o, format)) {
                Some(d) => d,
                None => continue,
            },
            _ => continue,
        };
        let Some(off) = ctx.vm_to_off(desc) else { continue };
        let flags = rd.u32(off);
        // Walk the parents up to the module to give the type its full context.
        let mut parents = Vec::new();
        let mut cur = desc;
        for _ in 0..8 {
            let Some(p) = indirectable(cur.wrapping_add(4)) else { break };
            let Some(po) = ctx.vm_to_off(p) else { break };
            let kind = rd.u32(po) & 0x1f;
            if matches!(kind, 0 | 16 | 17 | 18) {
                parents.push(name_of(p));
            }
            if kind == 0 {
                break;
            }
            cur = p;
        }
        parents.reverse();
        let row = vec![Cell::text(kind_name(flags)), Cell::text(name_of(desc)), Cell::text(parents.join(".")), Cell::text(format!("{desc:X}"))];
        if !ctx.push(&mut g, row, Some((off, 16))) {
            break;
        }
    }
    (!g.rows.is_empty()).then(|| Node::grid(format!("Swift Types ({})", ctx.count(g.rows.len())), g).with_span(ctx.base + sect.offset, clamp_off(sect.size)))
}
