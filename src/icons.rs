//! Icon glyphs of the bundled Phosphor icon font (assets/Phosphor.ttf, MIT
//! license, see assets/Phosphor-LICENSE-MIT.txt). The codes are private use
//! code points that only that font draws.

pub const FOLDER: &str = "\u{E24A}";
pub const FOLDER_OPEN: &str = "\u{E256}";
pub const FOLDER_SIMPLE: &str = "\u{E25A}";
pub const FILE: &str = "\u{E230}";
pub const FILE_TEXT: &str = "\u{E23A}";
pub const FILE_CODE: &str = "\u{E914}";
pub const TABLE: &str = "\u{E476}";
pub const FLOPPY_DISK: &str = "\u{E248}";
pub const ARROW_COUNTER_CLOCKWISE: &str = "\u{E038}";
pub const ARROW_LEFT: &str = "\u{E058}";
pub const ARROW_RIGHT: &str = "\u{E06C}";
pub const BINARY: &str = "\u{EE60}";
pub const MAGNIFYING_GLASS: &str = "\u{E30C}";
pub const X: &str = "\u{E4F6}";
pub const CPU: &str = "\u{E610}";
pub const QUOTES: &str = "\u{E660}";
pub const ARROWS_LEFT_RIGHT: &str = "\u{E0A0}";
pub const GIT_DIFF: &str = "\u{E27C}";
pub const WRENCH: &str = "\u{E5D4}";
pub const PENCIL_SIMPLE: &str = "\u{E3B4}";
pub const STACK: &str = "\u{E466}";
pub const IMAGES: &str = "\u{E836}";
pub const HAMMER: &str = "\u{E80E}";
pub const CODE: &str = "\u{E1BC}";
pub const ARROW_SQUARE_IN: &str = "\u{E5DC}";
pub const ARROW_SQUARE_OUT: &str = "\u{E5DE}";
pub const CERTIFICATE: &str = "\u{E766}";
pub const SEAL_CHECK: &str = "\u{E606}";
pub const ARROWS_CLOCKWISE: &str = "\u{E094}";
pub const BUG: &str = "\u{E5F4}";
pub const WARNING: &str = "\u{E4E0}";
pub const SLIDERS: &str = "\u{E432}";
pub const CODE_BLOCK: &str = "\u{EAFE}";
pub const TAG: &str = "\u{E478}";
pub const SQUARES_FOUR: &str = "\u{E464}";
pub const ROWS: &str = "\u{E5A2}";
pub const BOOKS: &str = "\u{E758}";
pub const PLUS_SQUARE: &str = "\u{ED4A}";
pub const FINGERPRINT: &str = "\u{E23E}";
pub const NOTE: &str = "\u{E348}";
pub const LIST_BULLETS: &str = "\u{E2F2}";
pub const HASH: &str = "\u{E2A2}";
pub const TREE_STRUCTURE: &str = "\u{E67C}";
pub const BOOKMARK_SIMPLE: &str = "\u{E0EA}";
pub const GEAR: &str = "\u{E270}";
pub const LINK: &str = "\u{E2E2}";
pub const TERMINAL_WINDOW: &str = "\u{EAE8}";
pub const SHIELD_CHECK: &str = "\u{E40C}";
pub const PUZZLE_PIECE: &str = "\u{E596}";
pub const HARD_DRIVES: &str = "\u{E2A0}";
pub const IDENTIFICATION_CARD: &str = "\u{E2C8}";
pub const FUNCTION: &str = "\u{EBE4}";
pub const EXPORT: &str = "\u{EAF0}";
pub const LIGHTNING: &str = "\u{E2DE}";
pub const KEY: &str = "\u{E2D6}";
pub const PACKAGE: &str = "\u{E390}";
pub const BOOKMARKS: &str = "\u{E0EC}";
pub const FILE_ARROW_UP: &str = "\u{E61E}";
pub const CLOCK: &str = "\u{E19A}";

use crate::model::{Node, Tool, View};

/// What a tree icon stands for; the theme gives each kind its colour.
#[derive(Clone, Copy, PartialEq)]
pub enum Tint {
    Folder,
    Structure,
    Tool,
    Editor,
    Security,
    Code,
}

/// Icon for a node of the structure tree, chosen from its tool or title.
pub fn for_node(node: &Node, depth: usize, open: bool) -> (&'static str, Tint) {
    if let View::Tool(tool, _) = &node.view {
        match tool {
            Tool::FileInfo if depth == 0 => return (FILE_CODE, Tint::Structure),
            Tool::HexEditor => return (BINARY, Tint::Tool),
            Tool::AddressConverter => return (ARROWS_LEFT_RIGHT, Tint::Tool),
            Tool::Disassembler => return (CPU, Tint::Code),
            Tool::Strings => return (QUOTES, Tint::Tool),
            Tool::Compare => return (GIT_DIFF, Tint::Tool),
            Tool::Search => return (MAGNIFYING_GLASS, Tint::Tool),
            Tool::Bookmarks => return (BOOKMARKS, Tint::Tool),
            Tool::PeSections => return (ROWS, Tint::Structure),
            Tool::PeResources => return (IMAGES, Tint::Structure),
            Tool::PeRebuilder => return (HAMMER, Tint::Editor),
            Tool::DotnetIl => return (CODE, Tint::Code),
            Tool::PeImportAdder | Tool::PeExports | Tool::PeRelocs | Tool::MachoEdit | Tool::ElfDynamic | Tool::ElfSections => return (WRENCH, Tint::Editor),
            Tool::FileInfo => {}
        }
    }
    let t = node.title.to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| t.contains(w));
    let pick = if has(&["signature", "security", "certificate", "authenticode"]) {
        (CERTIFICATE, Tint::Security)
    } else if has(&["import", "libraries", "needed", "bind"]) {
        (ARROW_SQUARE_IN, Tint::Structure)
    } else if has(&["export"]) {
        (ARROW_SQUARE_OUT, Tint::Structure)
    } else if has(&["resource"]) {
        (IMAGES, Tint::Structure)
    } else if has(&["reloc", "fixup", "rebase"]) {
        (ARROWS_CLOCKWISE, Tint::Structure)
    } else if has(&["debug", "pdb"]) {
        (BUG, Tint::Structure)
    } else if has(&["exception", "unwind"]) {
        // Unwind tables are ordinary structures; the warning glyph is for actual problems.
        (TABLE, Tint::Structure)
    } else if has(&["tls", "thread"]) {
        (STACK, Tint::Structure)
    } else if has(&["load config", "dynamic section", "version"]) {
        (SLIDERS, Tint::Structure)
    } else if has(&[".net", "metadata", "method", "typedef", "objective-c", "swift", "class"]) {
        (CODE_BLOCK, Tint::Code)
    } else if has(&["symbol", "hash"]) {
        (TAG, Tint::Structure)
    } else if has(&["section", "segment"]) {
        (ROWS, Tint::Structure)
    } else if has(&["program header", "load command", "architecture"]) {
        (LIST_BULLETS, Tint::Structure)
    } else if has(&["string"]) {
        (QUOTES, Tint::Structure)
    } else if has(&["rich"]) {
        (FINGERPRINT, Tint::Structure)
    } else if has(&["overlay"]) {
        (PACKAGE, Tint::Structure)
    } else if has(&["note", "guid"]) {
        (NOTE, Tint::Structure)
    } else if has(&["header"]) {
        (FILE_TEXT, Tint::Structure)
    } else if !node.children.is_empty() {
        (if open { FOLDER_OPEN } else { FOLDER }, Tint::Folder)
    } else {
        (TABLE, Tint::Structure)
    };
    // A group that only holds other structures reads best as a folder.
    if !node.children.is_empty() && matches!(node.view, View::Text(_)) && pick.1 == Tint::Structure {
        return (if open { FOLDER_OPEN } else { FOLDER }, Tint::Folder);
    }
    pick
}
