//! Queries over the parsed structure tree: text search, locating the
//! structure that covers a file offset, and a structural diff of two files.

use crate::model::{Grid, Node, Parsed, View};

pub struct Hit {
    pub path: Vec<String>,
    pub row: Option<usize>,
    /// Column name, or "title" / "text".
    pub place: String,
    pub text: String,
}

fn grid_of(node: &Node) -> Option<&Grid> {
    match &node.view {
        View::Grid(g) | View::Tool(_, g) => Some(g),
        View::Text(_) => None,
    }
}

/// Case insensitive substring search in titles, table cells and text views.
pub fn search(root: &Node, needle: &str, limit: usize) -> Vec<Hit> {
    fn walk(node: &Node, needle: &str, path: &mut Vec<String>, out: &mut Vec<Hit>, limit: usize) {
        path.push(node.title.clone());
        if out.len() < limit && node.title.to_lowercase().contains(needle) {
            out.push(Hit { path: path.clone(), row: None, place: "title".into(), text: node.title.clone() });
        }
        match &node.view {
            View::Text(t) => {
                for line in t.lines().filter(|l| l.to_lowercase().contains(needle)) {
                    if out.len() >= limit {
                        break;
                    }
                    out.push(Hit { path: path.clone(), row: None, place: "text".into(), text: line.trim().to_string() });
                }
            }
            View::Grid(g) | View::Tool(_, g) => {
                'rows: for (ri, row) in g.rows.iter().enumerate() {
                    for (ci, c) in row.iter().enumerate() {
                        if out.len() >= limit {
                            break 'rows;
                        }
                        if c.text.to_lowercase().contains(needle) {
                            let label = row.first().map(|f| f.text.as_str()).filter(|_| ci != 0).unwrap_or("");
                            let text = if label.is_empty() { c.text.clone() } else { format!("{label}: {}", c.text) };
                            out.push(Hit { path: path.clone(), row: Some(ri), place: g.columns.get(ci).copied().unwrap_or("").to_string(), text });
                            // One hit per row is enough to find it.
                            continue 'rows;
                        }
                    }
                }
            }
        }
        for c in &node.children {
            if out.len() >= limit {
                break;
            }
            walk(c, needle, path, out, limit);
        }
        path.pop();
    }
    let needle = needle.trim().to_lowercase();
    let mut out = Vec::new();
    if !needle.is_empty() {
        walk(root, &needle, &mut Vec::new(), &mut out, limit);
    }
    out
}

/// The deepest structure whose file range contains `off`, and the row in it.
pub fn node_at(root: &Node, off: usize) -> Option<(Vec<String>, Option<usize>)> {
    fn covers(span: Option<(usize, usize)>, off: usize) -> bool {
        span.is_some_and(|(o, l)| off >= o && off - o < l)
    }
    fn row_at(node: &Node, off: usize) -> Option<usize> {
        let g = grid_of(node)?;
        // Prefer the exact field, then the row's span.
        g.rows
            .iter()
            .position(|r| r.iter().any(|c| c.field.is_some_and(|f| off >= f.offset && off - f.offset < f.size)))
            .or_else(|| g.spans.iter().position(|s| covers(*s, off)))
    }
    fn walk(node: &Node, off: usize, path: &mut Vec<String>, best: &mut Option<(Vec<String>, Option<usize>, usize)>) {
        path.push(node.title.clone());
        let row = row_at(node, off);
        if covers(node.span, off) || row.is_some() {
            // Smaller spans are more specific; a row match beats a bare span.
            let size = node.span.map_or(usize::MAX / 2, |s| s.1) / if row.is_some() { 2 } else { 1 };
            if best.as_ref().is_none_or(|b| size <= b.2) {
                *best = Some((path.clone(), row, size));
            }
        }
        for c in &node.children {
            walk(c, off, path, best);
        }
        path.pop();
    }
    let mut best = None;
    walk(root, off, &mut Vec::new(), &mut best);
    best.map(|b| (b.0, b.1))
}

#[derive(Clone, Debug, PartialEq)]
pub struct Diff {
    pub path: Vec<String>,
    /// Row in the left file's table, when the difference is inside a table.
    pub row: Option<usize>,
    pub what: String,
    pub left: String,
    pub right: String,
}

pub struct Comparison {
    pub diffs: Vec<Diff>,
    pub truncated: bool,
    pub summary: Vec<(String, String)>,
}

const MAX_DIFFS: usize = 5000;

/// Titles carry counts ("Imports (12)"); ignore them when pairing nodes.
fn key(title: &str) -> &str {
    match title.rfind(" (") {
        Some(i) if title.ends_with(')') && title[i + 2..title.len() - 1].chars().all(|c| c.is_ascii_digit() || c == ' ' || c.is_ascii_alphabetic()) => {
            &title[..i]
        }
        _ => title,
    }
}

fn row_key(g: &Grid, r: usize) -> String {
    // Offsets shift between builds, so prefer a name-like column as identity.
    let cols = &g.columns;
    let pick = cols.iter().position(|c| matches!(*c, "Name" | "Member" | "Module Name" | "Symbol" | "Section" | "Library" | "Tag Name" | "Token")).unwrap_or(0);
    g.rows[r].get(pick).map(|c| c.text.clone()).unwrap_or_default()
}

fn diff_grids(a: &Grid, b: &Grid, path: &[String], out: &mut Vec<Diff>) {
    if a.columns != b.columns {
        out.push(Diff { path: path.to_vec(), row: None, what: "columns".into(), left: a.columns.join(", "), right: b.columns.join(", ") });
        return;
    }
    let cells = |g: &Grid, r: usize| g.rows[r].iter().map(|c| c.text.as_str()).collect::<Vec<_>>().join("  ");
    let cmp_rows = |ra: usize, rb: usize, out: &mut Vec<Diff>| {
        for (ci, (x, y)) in a.rows[ra].iter().zip(&b.rows[rb]).enumerate() {
            if x.text != y.text && out.len() < MAX_DIFFS {
                let label = if ci == 0 { String::new() } else { format!("{} / ", a.rows[ra][0].text) };
                out.push(Diff {
                    path: path.to_vec(),
                    row: Some(ra),
                    what: format!("{label}{}", a.columns.get(ci).copied().unwrap_or("")),
                    left: x.text.clone(),
                    right: y.text.clone(),
                });
            }
        }
    };
    if a.rows.len() == b.rows.len() {
        for r in 0..a.rows.len() {
            cmp_rows(r, r, out);
        }
        return;
    }
    // Different row counts: pair rows by identity, report the rest as added or removed.
    let mut right: std::collections::HashMap<String, Vec<usize>> = std::collections::HashMap::new();
    for r in (0..b.rows.len()).rev() {
        right.entry(row_key(b, r)).or_default().push(r);
    }
    for r in 0..a.rows.len() {
        match right.get_mut(&row_key(a, r)).and_then(Vec::pop) {
            Some(rb) => cmp_rows(r, rb, out),
            None if out.len() < MAX_DIFFS => {
                out.push(Diff { path: path.to_vec(), row: Some(r), what: "row only in left".into(), left: cells(a, r), right: String::new() })
            }
            None => {}
        }
    }
    let mut extra: Vec<usize> = right.into_values().flatten().collect();
    extra.sort();
    for rb in extra {
        if out.len() < MAX_DIFFS {
            out.push(Diff { path: path.to_vec(), row: None, what: "row only in right".into(), left: String::new(), right: cells(b, rb) });
        }
    }
}

fn diff_nodes(a: &Node, b: &Node, path: &mut Vec<String>, out: &mut Vec<Diff>) {
    path.push(a.title.clone());
    match (&a.view, &b.view) {
        (View::Text(x), View::Text(y)) => {
            if x != y {
                let first = x.lines().zip(y.lines()).find(|(l, r)| l != r);
                let (l, r) = first
                    .map(|(l, r)| (l.trim().to_string(), r.trim().to_string()))
                    .unwrap_or_else(|| (format!("{} lines", x.lines().count()), format!("{} lines", y.lines().count())));
                out.push(Diff { path: path.clone(), row: None, what: "text".into(), left: l, right: r });
            }
        }
        _ => {
            if let (Some(x), Some(y)) = (grid_of(a), grid_of(b)) {
                diff_grids(x, y, path, out);
            }
        }
    }
    let mut used = vec![false; b.children.len()];
    for ca in &a.children {
        let found = b.children.iter().enumerate().position(|(i, cb)| !used[i] && key(&cb.title) == key(&ca.title));
        match found {
            Some(i) => {
                used[i] = true;
                if out.len() < MAX_DIFFS {
                    diff_nodes(ca, &b.children[i], path, out);
                }
            }
            None if out.len() < MAX_DIFFS => {
                let mut p = path.clone();
                p.push(ca.title.clone());
                out.push(Diff { path: p, row: None, what: "structure only in left".into(), left: ca.title.clone(), right: String::new() });
            }
            None => {}
        }
    }
    for (i, cb) in b.children.iter().enumerate() {
        if !used[i] && out.len() < MAX_DIFFS {
            out.push(Diff { path: path.clone(), row: None, what: "structure only in right".into(), left: String::new(), right: cb.title.clone() });
        }
    }
    path.pop();
}

/// Structure level diff of two parsed files plus a byte level summary.
pub fn compare(a: &Parsed, da: &[u8], b: &Parsed, db: &[u8]) -> Comparison {
    let mut diffs = Vec::new();
    diff_nodes(&a.root, &b.root, &mut Vec::new(), &mut diffs);
    let common = da.len().min(db.len());
    let mut differing = 0usize;
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < common {
        if da[i] != db[i] {
            let start = i;
            while i < common && da[i] != db[i] {
                i += 1;
            }
            differing += i - start;
            if ranges.len() < 8 {
                ranges.push((start, i - start));
            }
        } else {
            i += 1;
        }
    }
    let mut summary = vec![
        ("Left".to_string(), format!("{} ({} bytes)", a.description, da.len())),
        ("Right".into(), format!("{} ({} bytes)", b.description, db.len())),
        (
            "Bytes".into(),
            if da == db {
                "identical".into()
            } else {
                format!("{differing} differing byte(s) in the common {common} bytes, size difference {}", db.len() as i64 - da.len() as i64)
            },
        ),
    ];
    if !ranges.is_empty() {
        summary.push(("First differing ranges".into(), ranges.iter().map(|(o, l)| format!("{o:X}+{l:X}")).collect::<Vec<_>>().join(", ")));
    }
    summary.push(("Structures".into(), if diffs.is_empty() { "no differences".into() } else { format!("{} difference(s)", diffs.len()) }));
    Comparison { truncated: diffs.len() >= MAX_DIFFS, diffs, summary }
}

// --- patches: the edits made to a file, as something that can be reapplied ------

/// Runs of differing bytes in the part both buffers have: (offset, length).
pub fn diff_runs(a: &[u8], b: &[u8]) -> Vec<(usize, usize)> {
    let common = a.len().min(b.len());
    let mut runs = Vec::new();
    let mut i = 0;
    while i < common {
        if a[i] != b[i] {
            let start = i;
            while i < common && a[i] != b[i] {
                i += 1;
            }
            runs.push((start, i - start));
        } else {
            i += 1;
        }
    }
    runs
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    crate::model::hex_bytes(&Sha256::digest(data)).to_lowercase()
}

/// A file name that is safe on one `#` comment line. The name comes from the
/// opened file and is untrusted: line breaks would end the comment, and in
/// the Python script what follows a line break is code.
fn comment_name(name: &str) -> String {
    name.chars().take(200).map(|c| if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') { '?' } else { c }).collect()
}

/// Human readable list of the changes: `OFFSET: old bytes -> new bytes`.
pub fn patch_text(name: &str, original: &[u8], patched: &[u8]) -> String {
    let hex = crate::model::hex_bytes;
    let name = comment_name(name);
    let mut out = format!(
        "# bxplore patch for {name}\n# original: {} bytes, sha256 {}\n# patched:  {} bytes, sha256 {}\n",
        original.len(),
        sha256_hex(original),
        patched.len(),
        sha256_hex(patched)
    );
    for (off, len) in diff_runs(original, patched) {
        // Long runs are split so every line stays readable.
        for chunk in (0..len).step_by(16) {
            let (o, n) = (off + chunk, 16.min(len - chunk));
            out.push_str(&format!("{o:08X}: {} -> {}\n", hex(&original[o..o + n]), hex(&patched[o..o + n])));
        }
    }
    match patched.len().cmp(&original.len()) {
        std::cmp::Ordering::Greater => {
            out.push_str(&format!("# {} bytes appended at {:08X}:\n", patched.len() - original.len(), original.len()));
            for (i, chunk) in patched[original.len()..].chunks(32).enumerate() {
                out.push_str(&format!("{:08X}: + {}\n", original.len() + i * 32, hex(chunk)));
            }
        }
        std::cmp::Ordering::Less => out.push_str(&format!("# truncated to {:08X} ({} bytes removed)\n", patched.len(), original.len() - patched.len())),
        std::cmp::Ordering::Equal => {}
    }
    out
}

/// A standalone Python 3 script that turns the original file into the patched one.
pub fn patch_python(name: &str, original: &[u8], patched: &[u8]) -> String {
    let hex = |b: &[u8]| crate::model::hex_bytes(b).to_lowercase();
    let mut out = String::from("#!/usr/bin/env python3\n");
    // The name only ever appears in a comment, never inside a string or the docstring.
    out.push_str(&format!("# Patch for {}\n", comment_name(name)));
    out.push_str("\"\"\"Patch written by bxplore.\n\nUsage: python3 this_script.py <original file> <output file>\n\"\"\"\n");
    out.push_str("import hashlib\nimport sys\n\n");
    out.push_str(&format!("ORIGINAL_SHA256 = \"{}\"\nPATCHED_SHA256 = \"{}\"\nPATCHED_SIZE = {}\n", sha256_hex(original), sha256_hex(patched), patched.len()));
    out.push_str("# (offset, new bytes as hex)\nCHANGES = [\n");
    for (off, len) in diff_runs(original, patched) {
        for chunk in (0..len).step_by(64) {
            let (o, n) = (off + chunk, 64.min(len - chunk));
            out.push_str(&format!("    (0x{o:X}, \"{}\"),\n", hex(&patched[o..o + n])));
        }
    }
    if patched.len() > original.len() {
        for (i, chunk) in patched[original.len()..].chunks(64).enumerate() {
            out.push_str(&format!("    (0x{:X}, \"{}\"),\n", original.len() + i * 64, hex(chunk)));
        }
    }
    out.push_str("]\n\n");
    out.push_str(
        "def main():\n    if len(sys.argv) != 3:\n        sys.exit(__doc__)\n    data = bytearray(open(sys.argv[1], \"rb\").read())\n    if hashlib.sha256(data).hexdigest() != ORIGINAL_SHA256:\n        sys.exit(\"the input is not the file this patch was made for\")\n    if len(data) < PATCHED_SIZE:\n        data.extend(bytes(PATCHED_SIZE - len(data)))\n    del data[PATCHED_SIZE:]\n    for offset, new in CHANGES:\n        new = bytes.fromhex(new)\n        data[offset:offset + len(new)] = new\n    if hashlib.sha256(data).hexdigest() != PATCHED_SHA256:\n        sys.exit(\"internal error: the result does not match the expected hash\")\n    open(sys.argv[2], \"wb\").write(data)\n    print(\"wrote\", sys.argv[2])\n\n\nif __name__ == \"__main__\":\n    main()\n",
    );
    out
}
