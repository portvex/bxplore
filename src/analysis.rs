//! Format detection plus format independent analysis: hashes, strings,
//! disassembly and a plain text dump of the node tree.

use crate::model::*;
use crate::{elf, macho, pe};

pub fn parse(data: &[u8]) -> Parsed {
    let mut parsed = pe::parse(data).map(|(p, _)| p).or_else(|| elf::parse(data)).or_else(|| macho::parse(data)).unwrap_or_else(|| Parsed {
        format: Format::Unknown,
        description: "Unknown format (raw data)".into(),
        root: Node::tool("File", Tool::FileInfo, kv_grid(vec![("File Type".into(), "Unknown format, shown as raw data".into())])),
        maps: vec![],
        image_base: 0,
        entry: None,
        arch: Arch::Other,
        symbols: Vec::new(),
        functions: Vec::new(),
    });
    parsed.symbols.retain(|s| !s.1.is_empty());
    parsed.symbols.sort();
    parsed.symbols.dedup_by_key(|s| s.0);
    parsed.functions.retain(|f| f.0 < f.1);
    parsed.functions.sort();
    parsed.functions.dedup_by_key(|f| f.0);
    let tools = &mut parsed.root.children;
    match parsed.format {
        Format::MachO => tools.push(Node::tool("Load Command Editor", Tool::MachoEdit, Grid::default())),
        Format::Elf => {
            tools.push(Node::tool("Dynamic Editor", Tool::ElfDynamic, Grid::default()));
            tools.push(Node::tool("Section Editor", Tool::ElfSections, Grid::default()));
        }
        _ => {}
    }
    if parsed.format != Format::Unknown {
        tools.push(Node::tool("Address Converter", Tool::AddressConverter, Grid::default()));
        tools.push(Node::tool("Disassembler", Tool::Disassembler, Grid::default()));
    }
    tools.push(Node::tool("Strings", Tool::Strings, Grid::default()));
    tools.push(Node::tool("Hex Editor", Tool::HexEditor, Grid::default()));
    tools.push(Node::tool("Bookmarks", Tool::Bookmarks, Grid::default()));
    tools.push(Node::tool("Compare", Tool::Compare, Grid::default()));
    tools.push(Node::tool("Search", Tool::Search, Grid::default()));
    unique_titles(&mut parsed.root);
    parsed
}

/// The GUI addresses nodes by their title path, so siblings need distinct titles.
fn unique_titles(node: &mut Node) {
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for c in &mut node.children {
        let n = seen.entry(c.title.clone()).or_insert(0);
        *n += 1;
        if *n > 1 {
            c.title = format!("{} #{}", c.title, n);
        }
        unique_titles(c);
    }
}

pub fn hashes(data: &[u8]) -> [String; 3] {
    use md5::Md5;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};
    [hex_bytes(&Md5::digest(data)).to_lowercase(), hex_bytes(&Sha1::digest(data)).to_lowercase(), hex_bytes(&Sha256::digest(data)).to_lowercase()]
}

pub struct StrHit {
    pub offset: usize,
    pub wide: bool,
    pub text: String,
}

const MAX_STRINGS: usize = 500_000;
const MAX_STRING_LEN: usize = 512;

fn is_text(c: u8) -> bool {
    (0x20..0x7f).contains(&c) || c == b'\t'
}

pub fn strings(data: &[u8], min_len: usize) -> Vec<StrHit> {
    let min_len = min_len.max(2);
    let mut out = Vec::new();
    // ASCII
    let mut start = 0;
    for i in 0..=data.len() {
        if i < data.len() && is_text(data[i]) {
            continue;
        }
        if i - start >= min_len && out.len() < MAX_STRINGS {
            let end = i.min(start + MAX_STRING_LEN);
            out.push(StrHit { offset: start, wide: false, text: String::from_utf8_lossy(&data[start..end]).into_owned() });
        }
        start = i + 1;
    }
    // UTF-16LE
    let mut i = 0;
    while i + 1 < data.len() && out.len() < MAX_STRINGS {
        if is_text(data[i]) && data[i + 1] == 0 {
            let s = i;
            let mut text = String::new();
            while i + 1 < data.len() && is_text(data[i]) && data[i + 1] == 0 {
                if text.len() < MAX_STRING_LEN {
                    text.push(data[i] as char);
                }
                i += 2;
            }
            if (i - s) / 2 >= min_len {
                out.push(StrHit { offset: s, wide: true, text });
            }
        } else {
            i += 1;
        }
    }
    out.sort_by_key(|h| h.offset);
    out
}

pub struct Insn {
    pub addr: u64,
    pub len: usize,
    pub bytes: String,
    pub text: String,
    /// Address a direct branch or call goes to, when it lies inside the file.
    pub target: Option<u64>,
    /// Symbol name or string the operands refer to.
    pub comment: String,
}

fn is_branch(mnemonic: &str) -> bool {
    let m = mnemonic.trim();
    const NOT_BRANCH: [&str; 12] = ["bic", "bfi", "bfc", "brk", "bsf", "bsr", "bts", "btr", "btc", "bt", "bnd", "bswap"];
    m == "call"
        || m == "loop"
        || m.starts_with('j')
        || m.starts_with("b.")
        || matches!(m, "b" | "bl" | "blx" | "cbz" | "cbnz" | "tbz" | "tbnz")
        || (m.len() == 3 && m.starts_with('b') && !NOT_BRANCH.contains(&m))
}

/// All `0x...` numbers in an operand string.
fn hex_numbers(ops: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let mut rest = ops;
    while let Some(i) = rest.find("0x") {
        let digits: String = rest[i + 2..].chars().take_while(char::is_ascii_hexdigit).take(16).collect();
        if let Ok(v) = u64::from_str_radix(&digits, 16) {
            out.push(v);
        }
        rest = &rest[i + 2..];
    }
    out
}

fn string_at(data: &[u8], parsed: &Parsed, va: u64) -> Option<String> {
    let (off, _) = parsed.va_to_offset(va)?;
    let b = data.get(usize::try_from(off).ok()?..)?;
    let n = b.iter().take(64).position(|c| !is_text(*c)).unwrap_or(b.len().min(64));
    (n >= 4 && (n == 64 || b.get(n) == Some(&0))).then(|| format!("\"{}\"", String::from_utf8_lossy(&b[..n])))
}

/// Fill in branch targets and comments from the file's symbols and strings.
pub fn annotate(insns: &mut [Insn], parsed: &Parsed, data: &[u8]) {
    for insn in insns {
        let split = insn.text.find(' ').unwrap_or(insn.text.len());
        let (mnemonic, ops) = (insn.text[..split].to_string(), insn.text[split..].to_string());
        let numbers = hex_numbers(&ops);
        let mut refs: Vec<u64> = Vec::new();
        // x86-64 addresses data relative to the next instruction.
        if let Some(r) = ops.find("[rip ") {
            let rest = &ops[r + 5..];
            if let Some(disp) = hex_numbers(rest).first().copied() {
                let next = insn.addr.wrapping_add(insn.len as u64);
                refs.push(if rest.starts_with('-') { next.wrapping_sub(disp) } else { next.wrapping_add(disp) });
            }
        } else {
            refs.extend(numbers.iter().copied().filter(|v| *v >= 0x1000));
        }
        if is_branch(&mnemonic)
            && !ops.contains('[')
            && let Some(t) = numbers.last().copied()
            && parsed.va_to_offset(t).is_some()
        {
            insn.target = Some(t);
        }
        for r in refs {
            if let Some(name) = parsed.symbol_at(r) {
                insn.comment = name.to_string();
                break;
            }
            if insn.target.is_none()
                && let Some(s) = string_at(data, parsed, r)
            {
                insn.comment = s;
                break;
            }
        }
    }
}

pub fn disasm(code: &[u8], arch: Arch, addr: u64, count: usize) -> Result<Vec<Insn>, String> {
    use capstone::prelude::*;
    let cs = match arch {
        Arch::X86 => Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).syntax(arch::x86::ArchSyntax::Intel).build(),
        Arch::X64 => Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).syntax(arch::x86::ArchSyntax::Intel).build(),
        Arch::Arm => Capstone::new().arm().mode(arch::arm::ArchMode::Arm).build(),
        Arch::Arm64 => Capstone::new().arm64().mode(arch::arm64::ArchMode::Arm).build(),
        Arch::Other => return Err("disassembly is not supported for this CPU architecture".into()),
    }
    .map_err(|e| e.to_string())?;
    let insns = cs.disasm_count(code, addr, count).map_err(|e| e.to_string())?;
    Ok(insns
        .iter()
        .map(|i| Insn {
            addr: i.address(),
            len: i.bytes().len(),
            bytes: hex_bytes(i.bytes()),
            text: format!("{:8} {}", i.mnemonic().unwrap_or(""), i.op_str().unwrap_or("")),
            target: None,
            comment: String::new(),
        })
        .collect())
}

/// Plain text rendering of the whole tree, used by `--dump`.
pub fn dump(node: &Node, depth: usize, out: &mut String) {
    let pad = "  ".repeat(depth);
    out.push_str(&format!("{pad}[{}]\n", node.title));
    match &node.view {
        View::Text(t) => {
            for line in t.lines() {
                out.push_str(&format!("{pad}  {line}\n"));
            }
        }
        View::Grid(g) | View::Tool(_, g) => {
            if !g.rows.is_empty() {
                let mut widths: Vec<usize> = g.columns.iter().map(|c| c.len()).collect();
                for row in g.rows.iter().take(2000) {
                    for (i, c) in row.iter().enumerate() {
                        if i < widths.len() {
                            widths[i] = widths[i].max(c.text.chars().count().min(60));
                        }
                    }
                }
                let line = |cells: Vec<&str>| {
                    let parts: Vec<String> = cells.iter().enumerate().map(|(i, c)| format!("{:w$}", c, w = widths.get(i).copied().unwrap_or(0))).collect();
                    format!("{pad}  {}\n", parts.join("  ").trim_end())
                };
                out.push_str(&line(g.columns.to_vec()));
                for row in g.rows.iter().take(2000) {
                    out.push_str(&line(row.iter().map(|c| c.text.as_str()).collect()));
                }
                if g.rows.len() > 2000 {
                    out.push_str(&format!("{pad}  ... {} more rows\n", g.rows.len() - 2000));
                }
            }
        }
    }
    for c in &node.children {
        dump(c, depth + 1, out);
    }
}
