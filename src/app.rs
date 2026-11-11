//! Application shell: document handling, menu, structure tree and the
//! generic editable grid every structure is shown in.

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use eframe::egui;
use egui::{Align, Key, KeyboardShortcut, Layout, Modifiers, RichText, Sense, TextStyle, Ui};
use egui_extras::{Column, TableBuilder};

use crate::analysis;
use crate::hexview::HexState;
use crate::icons;
use crate::model::*;
use crate::pe::Pe;
use crate::query;
use crate::store::{self, Bookmark, Settings, ThemeChoice};
use crate::theme;
use crate::tools::ToolState;

static NEXT_REV: AtomicU64 = AtomicU64::new(1);
const MAX_SNAPSHOTS: usize = 8;
const MAX_UNDO: usize = 2000;

enum Undo {
    Patch { off: usize, old: Vec<u8> },
    Snapshot(Vec<u8>),
}

pub struct Doc {
    pub path: PathBuf,
    pub data: Vec<u8>,
    pub parsed: Parsed,
    pub pe: Option<Pe>,
    pub dirty: bool,
    /// Changes on every modification; caches are keyed by it.
    pub rev: u64,
    undo: Vec<Undo>,
    backed_up: bool,
    /// The bytes as they were when the file was opened, for patch export.
    pub original: Rc<Vec<u8>>,
    pub bookmarks: Vec<Bookmark>,
}

impl Doc {
    fn new(path: PathBuf, data: Vec<u8>) -> Doc {
        let parsed = analysis::parse(&data);
        let pe = Pe::parse(&data);
        let original = Rc::new(data.clone());
        Doc {
            path,
            data,
            parsed,
            pe,
            dirty: false,
            rev: NEXT_REV.fetch_add(1, Ordering::Relaxed),
            undo: Vec::new(),
            backed_up: false,
            original,
            bookmarks: Vec::new(),
        }
    }

    fn touch(&mut self) {
        self.rev = NEXT_REV.fetch_add(1, Ordering::Relaxed);
        self.dirty = true;
        self.parsed = analysis::parse(&self.data);
        self.pe = Pe::parse(&self.data);
    }

    fn push_undo(&mut self, u: Undo) {
        self.undo.push(u);
        let snapshots = self.undo.iter().filter(|u| matches!(u, Undo::Snapshot(_))).count();
        if snapshots > MAX_SNAPSHOTS || self.undo.len() > MAX_UNDO {
            // Everything older than a dropped entry can no longer be undone.
            let cut = if snapshots > MAX_SNAPSHOTS {
                self.undo.iter().position(|u| matches!(u, Undo::Snapshot(_))).map_or(0, |p| p + 1)
            } else {
                self.undo.len() - MAX_UNDO
            };
            self.undo.drain(..cut);
        }
    }

    pub fn name(&self) -> String {
        self.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    }
}

pub type Op = Box<dyn FnOnce(&mut Vec<u8>) -> Result<String, String>>;

pub enum Action {
    Write {
        off: usize,
        bytes: Vec<u8>,
    },
    Op(Op),
    Select(Vec<String>),
    Open(PathBuf),
    OpenDialog,
    Save,
    SaveAs,
    Close,
    Undo,
    /// Select a structure and optionally a row in it.
    Goto {
        path: Vec<String>,
        row: Option<usize>,
    },
    /// Select the structure that covers a file offset.
    GotoOffset(usize),
    HexGoto(usize),
    Disasm(u64),
    Back,
    Forward,
    SwitchTab(usize),
    CloseTab(usize),
    /// Bookmark a file range.
    Bookmark {
        off: usize,
        len: usize,
    },
    /// Change the note of a bookmark, or delete it with None.
    BookmarkSet {
        index: usize,
        note: Option<String>,
    },
    /// Put back a bookmark that was deleted, with its note.
    BookmarkRestore(Bookmark),
    /// Write the changes since the file was opened as a text list or as a Python script.
    ExportPatch {
        python: bool,
    },
    /// Compare the active file with the one in another tab.
    CompareWithTab(usize),
}

/// What a dragged tab carries, so a view can accept it as a drop.
pub struct TabDrag(pub usize);

/// View state of a file that is open but not the active tab.
struct Tab {
    doc: Doc,
    sel: Vec<String>,
    row: Option<usize>,
    hex: HexState,
    tools: ToolState,
    history: Vec<Location>,
    hist_pos: usize,
}

type Location = (Vec<String>, Option<usize>);

const MAX_RECENT: usize = 12;
const MAX_HISTORY: usize = 200;

/// Where the recent files list is kept. `BXPLORE_CONFIG_DIR` overrides the
/// per-user default.
fn config_file() -> Option<PathBuf> {
    let var = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    let dir = match var("BXPLORE_CONFIG_DIR") {
        Some(d) => d,
        None if cfg!(windows) => var("APPDATA")?.join("bxplore"),
        None if cfg!(target_os = "macos") => var("HOME")?.join("Library/Application Support/bxplore"),
        None => var("XDG_CONFIG_HOME").or_else(|| var("HOME").map(|h| h.join(".config")))?.join("bxplore"),
    };
    Some(dir.join("recent.txt"))
}

fn load_recent(file: Option<&PathBuf>) -> Vec<PathBuf> {
    let Some(text) = file.and_then(|f| std::fs::read_to_string(f).ok()) else { return Vec::new() };
    text.lines().filter(|l| !l.trim().is_empty()).take(MAX_RECENT).map(PathBuf::from).collect()
}

struct CellEdit {
    row: usize,
    col: usize,
    text: String,
    focused: bool,
}

pub struct App {
    pub doc: Option<Doc>,
    pub actions: Vec<Action>,
    sel: Vec<String>,
    pub row: Option<usize>,
    edit: Option<CellEdit>,
    filter: String,
    filter_cache: Option<(String, u64, Rc<Vec<usize>>)>,
    pub status: String,
    pub status_err: bool,
    pub hex: HexState,
    pub tools: ToolState,
    /// Row the table should scroll to on the next frame.
    scroll_to_row: Option<usize>,
    confirm_close: bool,
    allow_close: bool,
    title: String,
    #[cfg(feature = "selftest")]
    frames: u32,
    #[cfg(feature = "selftest")]
    pending_row: Option<usize>,
    /// One slot per open file. The active file lives in `doc` and the view
    /// fields above, so its slot is None.
    tabs: Vec<Option<Tab>>,
    active: usize,
    close_tab_confirm: Option<usize>,
    recent: Vec<PathBuf>,
    /// Where the recent list is stored; None keeps it in memory only.
    recent_file: Option<PathBuf>,
    pub settings: Settings,
    show_prefs: bool,
    /// Outcome of the last "add to the file manager menu" or "remove" in Preferences.
    menu_note: Option<Result<String, String>>,
    /// Settings changed and still have to be applied to the egui context.
    apply_settings: bool,
    history: Vec<Location>,
    hist_pos: usize,
    search_box: String,
    focus_search: bool,
}

fn find<'a>(root: &'a Node, path: &[String]) -> &'a Node {
    let mut n = root;
    for t in path.iter().skip(1) {
        match n.children.iter().find(|c| &c.title == t) {
            Some(c) => n = c,
            None => break,
        }
    }
    n
}

/// Context menu entries that treat a hex value as an RVA, VA or file offset.
fn follow_menu(ui: &mut Ui, doc: &Doc, text: &str, nav: &mut Vec<Action>) {
    let t = text.trim();
    if !(2..=16).contains(&t.len()) || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return;
    }
    let Ok(v) = u64::from_str_radix(t, 16) else { return };
    let p = &doc.parsed;
    let mut targets: Vec<(&str, u64, usize, bool)> = Vec::new();
    if v != 0 && p.format == Format::Pe {
        let va = p.image_base.wrapping_add(v);
        if let Some((off, m)) = p.va_to_offset(va) {
            targets.push(("RVA", va, off as usize, m.exec));
        }
    }
    if v != 0
        && let Some((off, m)) = p.va_to_offset(v)
    {
        targets.push(("VA", v, off as usize, m.exec));
    }
    if v != 0 && (v as usize) < doc.data.len() && usize::try_from(v).is_ok() {
        targets.push(("file offset", 0, v as usize, false));
    }
    if targets.is_empty() {
        return;
    }
    ui.separator();
    for (kind, va, off, exec) in targets {
        if ui.button(format!("Follow as {kind}: structure at {off:X}")).clicked() {
            nav.push(Action::GotoOffset(off));
            ui.close();
        }
        if ui.button(format!("Follow as {kind}: hex view at {off:X}")).clicked() {
            nav.push(Action::HexGoto(off));
            ui.close();
        }
        if exec && ui.button(format!("Follow as {kind}: disassemble {va:X}")).clicked() {
            nav.push(Action::Disasm(va));
            ui.close();
        }
    }
}

fn tree_label(ui: &mut Ui, selected: bool, title: &str, parent: bool, icon: (&str, icons::Tint)) -> egui::Response {
    ui.spacing_mut().item_spacing.x = 5.0;
    ui.label(RichText::new(icon.0).size(15.0).color(theme::tint(ui, icon.1)));
    let mut text = RichText::new(title);
    if selected {
        text = text.color(ui.visuals().strong_text_color());
    } else if parent {
        text = text.color(ui.visuals().text_color());
    }
    ui.add(egui::Button::selectable(selected, text))
}

pub fn char_width(ui: &Ui) -> f32 {
    let font = TextStyle::Monospace.resolve(ui.style());
    ui.painter().layout_no_wrap("0".to_string(), font, egui::Color32::WHITE).size().x
}

impl App {
    pub fn new(initial: Vec<PathBuf>) -> App {
        App::with_recent_file(initial, config_file())
    }

    pub fn with_recent_file(initial: Vec<PathBuf>, recent_file: Option<PathBuf>) -> App {
        let mut app = App {
            doc: None,
            actions: Vec::new(),
            sel: vec!["File".into()],
            row: None,
            edit: None,
            filter: String::new(),
            filter_cache: None,
            status: "Open a file with File > Open, or drop one onto the window.".into(),
            status_err: false,
            hex: HexState::default(),
            tools: ToolState::default(),
            scroll_to_row: None,
            confirm_close: false,
            allow_close: false,
            title: String::new(),
            #[cfg(feature = "selftest")]
            frames: 0,
            #[cfg(feature = "selftest")]
            pending_row: None,
            tabs: Vec::new(),
            active: 0,
            close_tab_confirm: None,
            recent: load_recent(recent_file.as_ref()),
            settings: recent_file.as_ref().and_then(|f| f.parent()).map(Settings::load).unwrap_or_default(),
            show_prefs: false,
            menu_note: None,
            apply_settings: true,
            recent_file,
            history: Vec::new(),
            hist_pos: 0,
            search_box: String::new(),
            focus_search: false,
        };
        app.hex.show = app.settings.hex_panel;
        for p in initial {
            app.open(p);
        }
        // With several files, start on the first one.
        app.switch_tab(0);
        app
    }

    pub fn ok(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_err = false;
    }

    pub fn err(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_err = true;
    }

    fn open(&mut self, path: PathBuf) {
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        if let Some(i) = (0..self.tabs.len()).find(|i| self.tab_doc(*i).is_some_and(|d| d.path == path)) {
            self.switch_tab(i);
            return;
        }
        match std::fs::read(&path) {
            Ok(data) => {
                let mut doc = Doc::new(path.clone(), data);
                if let Some(dir) = self.config_dir() {
                    doc.bookmarks = store::load_bookmarks(&dir, &path);
                }
                self.ok(format!("Opened {}: {}", doc.name(), doc.parsed.description));
                self.stash_active();
                self.tabs.push(None);
                self.active = self.tabs.len() - 1;
                self.doc = Some(doc);
                self.sel = vec!["File".into()];
                self.reset_view();
                self.history = vec![(self.sel.clone(), None)];
                self.hist_pos = 0;
                self.remember(path);
            }
            Err(e) => self.err(format!("Cannot open {}: {e}", path.display())),
        }
    }

    fn config_dir(&self) -> Option<PathBuf> {
        self.recent_file.as_ref().and_then(|f| f.parent()).map(PathBuf::from)
    }

    fn store_bookmarks(&mut self) {
        if let (Some(dir), Some(d)) = (self.config_dir(), &self.doc)
            && let Err(e) = store::save_bookmarks(&dir, &d.path, &d.bookmarks)
        {
            self.err(format!("Cannot store the bookmarks: {e}"));
        }
    }

    /// The format is chosen by the menu entry, not by the name typed in the
    /// dialog: a dialog's file type list does not reliably change the extension.
    fn export_patch(&mut self, python: bool) {
        let Some(d) = &self.doc else { return };
        if *d.original == d.data {
            self.ok("The file has not been changed since it was opened; there is nothing to export");
            return;
        }
        let dlg = rfd::FileDialog::new();
        let dlg = if python {
            dlg.set_title("Export patch as Python script").set_file_name(format!("{}_patch.py", d.name())).add_filter("Python script", &["py"])
        } else {
            dlg.set_title("Export patch as text").set_file_name(format!("{}.patch.txt", d.name())).add_filter("Text patch", &["txt", "patch"])
        };
        let Some(path) = dlg.save_file() else { return };
        let text = if python { query::patch_python(&d.name(), &d.original, &d.data) } else { query::patch_text(&d.name(), &d.original, &d.data) };
        match std::fs::write(&path, text) {
            Ok(()) => self.ok(format!("{} written to {}", if python { "Python patch script" } else { "Text patch" }, path.display())),
            Err(e) => self.err(format!("Cannot write {}: {e}", path.display())),
        }
    }

    fn remember(&mut self, path: PathBuf) {
        self.recent.retain(|p| *p != path);
        self.recent.insert(0, path);
        self.recent.truncate(self.settings.recent_max.min(MAX_RECENT * 4));
        if let Some(f) = &self.recent_file {
            let text: String = self.recent.iter().map(|p| format!("{}\n", p.display())).collect();
            // The list is a convenience; failing to store it is not worth a message.
            let _ = f.parent().map(std::fs::create_dir_all);
            let _ = std::fs::write(f, text);
        }
    }

    // --- tabs -------------------------------------------------------------

    fn tab_doc(&self, i: usize) -> Option<&Doc> {
        match self.tabs.get(i)? {
            Some(t) => Some(&t.doc),
            None => self.doc.as_ref(),
        }
    }

    /// Move the active file and its view state into its tab slot.
    fn stash_active(&mut self) {
        let Some(doc) = self.doc.take() else { return };
        let show = self.hex.show;
        let tab = Tab {
            doc,
            sel: std::mem::take(&mut self.sel),
            row: self.row.take(),
            hex: std::mem::take(&mut self.hex),
            tools: std::mem::take(&mut self.tools),
            history: std::mem::take(&mut self.history),
            hist_pos: self.hist_pos,
        };
        self.hex.show = show;
        self.tabs[self.active] = Some(tab);
        self.edit = None;
        self.filter.clear();
        self.filter_cache = None;
    }

    fn activate(&mut self, i: usize) {
        let Some(t) = self.tabs.get_mut(i).and_then(Option::take) else { return };
        let show = self.hex.show;
        self.doc = Some(t.doc);
        self.sel = t.sel;
        self.row = t.row;
        self.hex = t.hex;
        self.hex.show = show;
        self.tools = t.tools;
        self.history = t.history;
        self.hist_pos = t.hist_pos;
        self.active = i;
    }

    /// The tab after or before the active one, wrapping around.
    fn neighbour_tab(&self, forward: bool) -> usize {
        let n = self.tabs.len().max(1);
        (self.active + if forward { 1 } else { n - 1 }) % n
    }

    fn switch_tab(&mut self, i: usize) {
        if i != self.active && i < self.tabs.len() {
            self.stash_active();
            self.activate(i);
        }
    }

    fn close_tab(&mut self, i: usize) {
        if i >= self.tabs.len() {
            return;
        }
        if i == self.active {
            self.doc = None;
            self.tabs.remove(i);
            self.sel = vec!["File".into()];
            self.reset_view();
            self.tools = ToolState::default();
            self.history.clear();
            self.hist_pos = 0;
            self.active = 0;
            if !self.tabs.is_empty() {
                self.activate(i.min(self.tabs.len() - 1));
            }
        } else {
            self.tabs.remove(i);
            if i < self.active {
                self.active -= 1;
            }
        }
        self.ok("File closed");
    }

    fn any_dirty(&self) -> bool {
        (0..self.tabs.len()).any(|i| self.tab_doc(i).is_some_and(|d| d.dirty))
    }

    // --- navigation -------------------------------------------------------

    /// Show a location without touching the history.
    fn show_location(&mut self, path: Vec<String>, row: Option<usize>) {
        let Some(d) = &self.doc else { return };
        let node = find(&d.parsed.root, &path);
        let grid = match &node.view {
            View::Grid(g) | View::Tool(_, g) => Some(g),
            View::Text(_) => None,
        };
        let row = row.filter(|r| grid.is_some_and(|g| *r < g.rows.len()));
        let span = row
            .and_then(|r| grid.and_then(|g| g.spans.get(r).copied().flatten().or_else(|| g.rows[r].iter().find_map(|c| c.field).map(|f| (f.offset, f.size)))))
            .or(node.span);
        if path != self.sel {
            self.sel = path;
            self.reset_view();
        }
        self.row = row;
        self.scroll_to_row = row;
        if let Some((off, len)) = span {
            self.hex.show_range(off, len);
        }
    }

    /// Go to a location and record it, so Back returns to where we were.
    fn goto(&mut self, path: Vec<String>, row: Option<usize>) {
        if path == self.sel && row == self.row {
            return;
        }
        if let Some(cur) = self.history.get_mut(self.hist_pos) {
            cur.1 = self.row;
        }
        self.history.truncate(self.hist_pos + 1);
        self.history.push((path.clone(), row));
        if self.history.len() > MAX_HISTORY {
            self.history.remove(0);
        }
        self.hist_pos = self.history.len() - 1;
        self.show_location(path, row);
    }

    fn step_history(&mut self, forward: bool) {
        let target = if forward { self.hist_pos + 1 } else { self.hist_pos.wrapping_sub(1) };
        let Some((path, row)) = self.history.get(target).cloned() else { return };
        if let Some(cur) = self.history.get_mut(self.hist_pos) {
            cur.1 = self.row;
        }
        self.hist_pos = target;
        self.show_location(path, row);
    }

    fn reset_view(&mut self) {
        self.row = None;
        self.edit = None;
        self.filter.clear();
        self.filter_cache = None;
    }

    fn save(&mut self, target: Option<PathBuf>) {
        let Some(doc) = &mut self.doc else { return };
        let path = target.clone().unwrap_or_else(|| doc.path.clone());
        let mut note = String::new();
        if target.is_none() && !doc.backed_up && self.settings.backup_on_save {
            let mut bak = path.clone().into_os_string();
            bak.push(".bak");
            let bak = PathBuf::from(bak);
            if !bak.exists() && std::fs::copy(&path, &bak).is_ok() {
                note = format!(" (original kept as {})", bak.file_name().unwrap_or_default().to_string_lossy());
            }
            doc.backed_up = true;
        }
        match std::fs::write(&path, &doc.data) {
            Ok(()) => {
                // The same form of the path that opening the file gives: bookmarks are stored under it.
                let path = std::fs::canonicalize(&path).unwrap_or(path);
                let moved = path != doc.path;
                doc.dirty = false;
                doc.path = path.clone();
                self.ok(format!("Saved {}{note}", path.display()));
                if moved {
                    // Save As: the bookmarks follow the file. The original keeps its own list.
                    self.store_bookmarks();
                }
            }
            Err(e) => self.err(format!("Cannot save {}: {e}", path.display())),
        }
    }

    fn apply(&mut self, action: Action) {
        match action {
            Action::Write { off, bytes } => {
                let Some(d) = &mut self.doc else { return };
                let Some(range) = off.checked_add(bytes.len()).filter(|e| *e <= d.data.len()).map(|e| off..e) else {
                    self.err("The write is outside the file");
                    return;
                };
                if d.data[range.clone()] != bytes[..] {
                    let old = d.data[range.clone()].to_vec();
                    d.push_undo(Undo::Patch { off, old });
                    d.data[range].copy_from_slice(&bytes);
                    d.touch();
                    self.ok(format!("Wrote {} byte(s) at offset {off:08X}", bytes.len()));
                }
            }
            Action::Op(f) => {
                let Some(d) = &mut self.doc else { return };
                let snapshot = d.data.clone();
                match f(&mut d.data) {
                    Ok(msg) => {
                        if d.data != snapshot {
                            d.push_undo(Undo::Snapshot(snapshot));
                            d.touch();
                        }
                        self.row = None;
                        self.edit = None;
                        self.ok(msg);
                    }
                    Err(e) => {
                        d.data = snapshot;
                        self.err(format!("Operation failed, nothing was changed: {e}"));
                    }
                }
            }
            Action::Select(path) => self.goto(path, None),
            Action::Goto { path, row } => self.goto(path, row),
            Action::GotoOffset(off) => {
                let found = self.doc.as_ref().and_then(|d| query::node_at(&d.parsed.root, off));
                match found {
                    Some((path, row)) => {
                        self.goto(path, row);
                        self.hex.show_range(off, 1);
                    }
                    None => {
                        self.hex.show_range(off, 1);
                        self.ok(format!("No structure covers offset {off:08X}; it is shown in the hex view"));
                    }
                }
            }
            Action::HexGoto(off) => {
                self.hex.show = true;
                self.hex.show_range(off, 1);
            }
            Action::Disasm(va) => {
                self.tools.disasm_at(va);
                self.goto(vec!["File".into(), "Disassembler".into()], None);
            }
            Action::Bookmark { off, len } => {
                let Some(d) = &mut self.doc else { return };
                // A range taken from header fields ends where the file does.
                let len = len.min(d.data.len().saturating_sub(off)).max(1);
                if d.bookmarks.iter().any(|b| b.off == off && b.len == len) {
                    self.ok(format!("Offset {off:08X} is already bookmarked"));
                    return;
                }
                // The note starts as the name of the structure at that place.
                let note = query::node_at(&d.parsed.root, off).map(|(path, _)| path.last().cloned().unwrap_or_default()).unwrap_or_default();
                d.bookmarks.push(Bookmark { off, len, note });
                d.bookmarks.sort_by_key(|b| b.off);
                self.store_bookmarks();
                self.ok(format!("Bookmarked offset {off:08X}; see Bookmarks in the tree"));
            }
            Action::BookmarkSet { index, note } => {
                let Some(d) = &mut self.doc else { return };
                if index < d.bookmarks.len() {
                    let deleted = match note {
                        Some(n) => {
                            d.bookmarks[index].note = n;
                            None
                        }
                        None => Some(d.bookmarks.remove(index).off),
                    };
                    if let Some(off) = deleted {
                        self.ok(format!("Bookmark at {off:08X} deleted"));
                    }
                    self.store_bookmarks();
                }
            }
            Action::BookmarkRestore(b) => {
                let Some(d) = &mut self.doc else { return };
                if !d.bookmarks.iter().any(|o| o.off == b.off && o.len == b.len) {
                    let off = b.off;
                    d.bookmarks.push(b);
                    d.bookmarks.sort_by_key(|b| b.off);
                    self.ok(format!("Bookmark at {off:08X} restored"));
                    self.store_bookmarks();
                }
            }
            Action::ExportPatch { python } => self.export_patch(python),
            Action::CompareWithTab(i) => {
                let other = self.tab_doc(i).filter(|_| i != self.active).map(|d| (d.path.clone(), Rc::new(d.data.clone())));
                if let Some((path, data)) = other {
                    self.tools.x.set_compare_data(path, data);
                    self.goto(vec!["File".into(), "Compare".into()], None);
                }
            }
            Action::Back => self.step_history(false),
            Action::Forward => self.step_history(true),
            Action::SwitchTab(i) => self.switch_tab(i),
            Action::CloseTab(i) => {
                if self.tab_doc(i).is_some_and(|d| d.dirty) {
                    self.close_tab_confirm = Some(i);
                } else {
                    self.close_tab(i);
                }
            }
            Action::Open(p) => self.open(p),
            Action::OpenDialog => {
                if let Some(p) = rfd::FileDialog::new().set_title("Open file").pick_file() {
                    self.open(p);
                }
            }
            Action::Save => self.save(None),
            Action::SaveAs => {
                if let Some(d) = &self.doc {
                    let dlg = rfd::FileDialog::new().set_title("Save as").set_file_name(d.name());
                    if let Some(p) = dlg.save_file() {
                        self.save(Some(p));
                    }
                }
            }
            Action::Close => self.apply(Action::CloseTab(self.active)),
            Action::Undo => {
                let Some(d) = &mut self.doc else { return };
                match d.undo.pop() {
                    Some(Undo::Patch { off, old }) => {
                        d.data[off..off + old.len()].copy_from_slice(&old);
                        d.touch();
                        self.hex.show_range(off, old.len());
                        self.ok(format!("Undid change at offset {off:08X}"));
                    }
                    Some(Undo::Snapshot(s)) => {
                        d.data = s;
                        d.touch();
                        self.row = None;
                        self.ok("Undid structural change");
                    }
                    None => self.ok("Nothing to undo"),
                }
            }
        }
    }

    // -----------------------------------------------------------------------

    fn menu(&mut self, ui: &mut Ui) {
        let has_doc = self.doc.is_some();
        let cmd = |k| KeyboardShortcut::new(Modifiers::COMMAND, k);
        let (open, save, undo) = (cmd(Key::O), cmd(Key::S), cmd(Key::Z));
        let (back, forward, close, search) = (cmd(Key::OpenBracket), cmd(Key::CloseBracket), cmd(Key::W), cmd(Key::F));
        let next_tab = KeyboardShortcut::new(Modifiers::CTRL, Key::Tab);
        let prev_tab = KeyboardShortcut::new(Modifiers::CTRL | Modifiers::SHIFT, Key::Tab);
        let many = self.tabs.len() > 1;
        // Undo belongs to the focused text box while one is being edited.
        let typing = ui.ctx().text_edit_focused();
        ui.input_mut(|i| {
            // The shortcut with Shift first: the plain one matches it as well.
            if many && i.consume_shortcut(&prev_tab) {
                self.actions.push(Action::SwitchTab(self.neighbour_tab(false)));
            }
            if many && i.consume_shortcut(&next_tab) {
                self.actions.push(Action::SwitchTab(self.neighbour_tab(true)));
            }
            if i.consume_shortcut(&open) {
                self.actions.push(Action::OpenDialog);
            }
            if has_doc && i.consume_shortcut(&save) {
                self.actions.push(Action::Save);
            }
            if has_doc && !typing && i.consume_shortcut(&undo) {
                self.actions.push(Action::Undo);
            }
            if has_doc && i.consume_shortcut(&back) {
                self.actions.push(Action::Back);
            }
            if has_doc && i.consume_shortcut(&forward) {
                self.actions.push(Action::Forward);
            }
            if has_doc && i.consume_shortcut(&close) {
                self.actions.push(Action::Close);
            }
            if has_doc && i.consume_shortcut(&search) {
                self.focus_search = true;
            }
        });
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.add(egui::Button::new("Open...").shortcut_text(ui.ctx().format_shortcut(&open))).clicked() {
                    self.actions.push(Action::OpenDialog);
                }
                if ui.add_enabled(has_doc, egui::Button::new("Save").shortcut_text(ui.ctx().format_shortcut(&save))).clicked() {
                    self.actions.push(Action::Save);
                }
                if ui.add_enabled(has_doc, egui::Button::new("Save As...")).clicked() {
                    self.actions.push(Action::SaveAs);
                }
                // Cheap to know every frame; a change that was undone by hand is reported after the click.
                let changed = self.doc.as_ref().is_some_and(|d| d.dirty || !d.undo.is_empty());
                for (python, label, hint) in [
                    (false, "Export Patch as Text...", "The changes since the file was opened, as a readable list of offsets and bytes"),
                    (true, "Export Patch as Python Script...", "The changes since the file was opened, as a script that applies them to the original file"),
                ] {
                    if ui
                        .add_enabled(changed, egui::Button::new(label))
                        .on_hover_text(hint)
                        .on_disabled_hover_text("No changes since the file was opened")
                        .clicked()
                    {
                        self.actions.push(Action::ExportPatch { python });
                    }
                }
                ui.menu_button("Open Recent", |ui| {
                    let shown = self.recent.len().min(self.settings.recent_max);
                    if shown == 0 {
                        ui.weak("No recent files");
                    }
                    for p in &self.recent[..shown] {
                        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                        if ui.button(name).on_hover_text(p.display().to_string()).clicked() {
                            self.actions.push(Action::Open(p.clone()));
                            ui.close();
                        }
                    }
                });
                ui.separator();
                if ui.add_enabled(has_doc, egui::Button::new("Close").shortcut_text(ui.ctx().format_shortcut(&close))).clicked() {
                    self.actions.push(Action::Close);
                }
            });
            ui.menu_button("Edit", |ui| {
                let can = self.doc.as_ref().is_some_and(|d| !d.undo.is_empty());
                if ui.add_enabled(can, egui::Button::new("Undo").shortcut_text(ui.ctx().format_shortcut(&undo))).clicked() {
                    self.actions.push(Action::Undo);
                }
                ui.separator();
                if ui.button("Preferences...").clicked() {
                    self.show_prefs = true;
                }
            });
            ui.menu_button("Go", |ui| {
                if ui.add_enabled(self.hist_pos > 0, egui::Button::new("Back").shortcut_text(ui.ctx().format_shortcut(&back))).clicked() {
                    self.actions.push(Action::Back);
                }
                if ui
                    .add_enabled(self.hist_pos + 1 < self.history.len(), egui::Button::new("Forward").shortcut_text(ui.ctx().format_shortcut(&forward)))
                    .clicked()
                {
                    self.actions.push(Action::Forward);
                }
                ui.separator();
                if ui.add_enabled(many, egui::Button::new("Next File").shortcut_text(ui.ctx().format_shortcut(&next_tab))).clicked() {
                    self.actions.push(Action::SwitchTab(self.neighbour_tab(true)));
                }
                if ui.add_enabled(many, egui::Button::new("Previous File").shortcut_text(ui.ctx().format_shortcut(&prev_tab))).clicked() {
                    self.actions.push(Action::SwitchTab(self.neighbour_tab(false)));
                }
                ui.separator();
                if ui.add_enabled(has_doc, egui::Button::new("Search structures").shortcut_text(ui.ctx().format_shortcut(&search))).clicked() {
                    self.focus_search = true;
                }
            });
            ui.menu_button("View", |ui| {
                ui.checkbox(&mut self.hex.show, "Hex panel");
                ui.separator();
                ui.label("Theme and other options are in Edit > Preferences.");
            });
        });
    }

    fn tree_ui(&mut self, ui: &mut Ui, node: &Node, path: &mut Vec<String>, depth: usize) {
        path.push(node.title.clone());
        let selected = *path == self.sel;
        if node.children.is_empty() {
            ui.horizontal(|ui| {
                ui.add_space(18.0);
                if tree_label(ui, selected, &node.title, false, icons::for_node(node, depth, false)).clicked() {
                    self.actions.push(Action::Select(path.clone()));
                }
            });
        } else {
            let id = ui.make_persistent_id(("tree", path.join("\u{1}")));
            let state = egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, depth < 1);
            let open = state.is_open();
            state
                .show_header(ui, |ui| {
                    if tree_label(ui, selected, &node.title, true, icons::for_node(node, depth, open)).clicked() {
                        self.actions.push(Action::Select(path.clone()));
                    }
                })
                .body(|ui| {
                    for c in &node.children {
                        self.tree_ui(ui, c, path, depth + 1);
                    }
                });
        }
        path.pop();
    }

    pub fn select_row(&mut self, g: &Grid, ri: usize) {
        self.row = Some(ri);
        let span = g.spans.get(ri).copied().flatten().or_else(|| g.rows[ri].iter().find_map(|c| c.field).map(|f| (f.offset, f.size)));
        if let Some((off, len)) = span {
            self.hex.show_range(off, len);
        }
    }

    fn flags_ui(&mut self, ui: &mut Ui, doc: &Doc, f: FieldRef) {
        let value = f.value(&doc.data);
        let mut new = value;
        match f.kind {
            Kind::Flags(names) => {
                ui.horizontal_wrapped(|ui| {
                    for (bit, name) in names {
                        let mut on = value & bit == *bit;
                        if ui.checkbox(&mut on, *name).on_hover_text(format!("0x{bit:X}")).changed() {
                            new = if on { value | bit } else { value & !bit };
                        }
                    }
                });
            }
            Kind::Enum(names) => {
                ui.horizontal(|ui| {
                    ui.label("Value:");
                    let current = lookup(names, value).map(str::to_string).unwrap_or_else(|| format!("0x{value:X}"));
                    egui::ComboBox::from_id_salt("enum_value").selected_text(current).width(280.0).show_ui(ui, |ui| {
                        for (v, name) in names {
                            if ui.selectable_label(*v == value, format!("{name} (0x{v:X})")).clicked() {
                                new = *v;
                            }
                        }
                    });
                });
            }
            _ => {}
        }
        if new != value {
            self.actions.push(Action::Write { off: f.offset, bytes: uint_bytes(new, f.size, f.endian) });
        }
    }

    /// Generic table with in place editing of cells that map to file bytes.
    pub fn grid_ui(&mut self, ui: &mut Ui, doc: &Doc, g: &Grid) {
        if g.rows.is_empty() {
            if !g.columns.is_empty() {
                ui.weak("No entries.");
            }
            return;
        }
        if g.rows.len() > 12 {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.filter).desired_width(260.0).hint_text("Filter rows (any column)"));
                if !self.filter.is_empty() && ui.button("Clear").clicked() {
                    self.filter.clear();
                }
                ui.weak(format!("{} rows", g.rows.len()));
            });
            ui.add_space(4.0);
        }
        let order: Option<Rc<Vec<usize>>> = if self.filter.is_empty() {
            None
        } else {
            let fresh = matches!(&self.filter_cache, Some((f, rev, _)) if *f == self.filter && *rev == doc.rev);
            if !fresh {
                let needle = self.filter.to_lowercase();
                let hits: Vec<usize> = (0..g.rows.len()).filter(|i| g.rows[*i].iter().any(|c| c.text.to_lowercase().contains(&needle))).collect();
                self.filter_cache = Some((self.filter.clone(), doc.rev, Rc::new(hits)));
            }
            self.filter_cache.as_ref().map(|c| c.2.clone())
        };

        // Details editor for flag and enumeration fields of the selected row.
        let detail =
            self.row.and_then(|r| g.rows.get(r)).and_then(|row| row.iter().filter_map(|c| c.field).find(|f| matches!(f.kind, Kind::Flags(_) | Kind::Enum(_))));
        if let Some(f) = detail {
            egui::Panel::bottom("field_details").resizable(false).show(ui, |ui| {
                ui.add_space(8.0);
                theme::caption(ui, if matches!(f.kind, Kind::Flags(_)) { "Flags" } else { "Value" });
                ui.add_space(2.0);
                self.flags_ui(ui, doc, f);
                ui.add_space(6.0);
            });
        }

        let n = order.as_ref().map_or(g.rows.len(), |o| o.len());
        let cw = char_width(ui);
        let row_at = |i: usize| order.as_ref().map_or(i, |o| o[i]);
        let mut widths: Vec<usize> = g.columns.iter().map(|c| c.len() + 1).collect();
        for i in 0..n.min(300) {
            for (ci, c) in g.rows[row_at(i)].iter().enumerate() {
                if let Some(w) = widths.get_mut(ci) {
                    *w = (*w).max(c.text.chars().count().min(70));
                }
            }
        }
        let row_h = ui.text_style_height(&TextStyle::Monospace) + 9.0;
        let strong = ui.visuals().strong_text_color();
        let weak = ui.visuals().weak_text_color();
        let mut select = None;
        let mut start_edit = None;
        let mut commit: Option<(FieldRef, String)> = None;
        let mut cancel = false;
        let mut nav: Vec<Action> = Vec::new();

        egui::ScrollArea::horizontal().auto_shrink([false, false]).show(ui, |ui| {
            let mut tb = TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .sense(Sense::click())
                .cell_layout(Layout::left_to_right(Align::Center))
                .auto_shrink([false, false])
                .min_scrolled_height(0.0);
            if let Some(r) = self.scroll_to_row.take() {
                // With a filter the table shows a subset, so find the row's position in it.
                let pos = order.as_ref().map_or(Some(r), |o| o.iter().position(|x| *x == r));
                if let Some(pos) = pos {
                    tb = tb.scroll_to_row(pos, Some(Align::Center));
                }
            }
            for (i, w) in widths.iter().enumerate() {
                let px = *w as f32 * cw + 14.0;
                tb = tb.column(if i + 1 == widths.len() { Column::remainder().at_least(px).clip(true) } else { Column::initial(px).at_least(24.0).clip(true) });
            }
            tb.header(row_h + 2.0, |mut h| {
                for c in &g.columns {
                    h.col(|ui| {
                        theme::caption(ui, c);
                    });
                }
            })
            .body(|body| {
                body.rows(row_h, n, |mut row| {
                    let ri = row_at(row.index());
                    row.set_selected(self.row == Some(ri));
                    let mut clicked = false;
                    for (ci, c) in g.rows[ri].iter().enumerate() {
                        let editing = matches!(&self.edit, Some(e) if e.row == ri && e.col == ci);
                        let (_, resp) = row.col(|ui| {
                            if editing {
                                let Some(e) = self.edit.as_mut() else { return };
                                let r = ui.add(egui::TextEdit::singleline(&mut e.text).font(TextStyle::Monospace).desired_width(f32::INFINITY));
                                if !e.focused {
                                    r.request_focus();
                                    e.focused = true;
                                } else if r.lost_focus() {
                                    if ui.input(|i| i.key_pressed(Key::Enter))
                                        && let Some(f) = c.field
                                    {
                                        commit = Some((f, e.text.clone()));
                                    }
                                    cancel = true;
                                }
                            } else {
                                let mut text = RichText::new(&c.text).monospace();
                                if c.field.is_some() {
                                    text = text.color(strong);
                                } else if ci > 0 {
                                    text = text.color(weak);
                                }
                                ui.add(egui::Label::new(text).selectable(false).truncate());
                            }
                        });
                        if c.field.is_some() && resp.double_clicked() {
                            start_edit = Some((ri, ci, c.text.clone()));
                        }
                        clicked |= resp.clicked();
                        resp.context_menu(|ui| {
                            if ui.button("Copy value").clicked() {
                                ui.ctx().copy_text(c.text.clone());
                                ui.close();
                            }
                            let span = g.spans.get(ri).copied().flatten().or_else(|| g.rows[ri].iter().find_map(|c| c.field).map(|f| (f.offset, f.size)));
                            if let Some((off, len)) = span
                                && ui.button("Bookmark this row").clicked()
                            {
                                nav.push(Action::Bookmark { off, len });
                                ui.close();
                            }
                            if ui.button("Copy row").clicked() {
                                ui.ctx().copy_text(g.rows[ri].iter().map(|c| c.text.as_str()).collect::<Vec<_>>().join("\t"));
                                ui.close();
                            }
                            if c.field.is_some() && ui.button("Edit value").clicked() {
                                start_edit = Some((ri, ci, c.text.clone()));
                                ui.close();
                            }
                            follow_menu(ui, doc, &c.text, &mut nav);
                        });
                    }
                    if clicked || row.response().clicked() {
                        select = Some(ri);
                    }
                });
            });
        });

        self.actions.append(&mut nav);
        if let Some(ri) = select {
            self.select_row(g, ri);
        }
        if let Some((f, text)) = commit {
            match f.parse(&text) {
                Ok(bytes) => self.actions.push(Action::Write { off: f.offset, bytes }),
                Err(e) => self.err(format!("Invalid value: {e}")),
            }
        }
        if cancel {
            self.edit = None;
        }
        if let Some((row, col, text)) = start_edit {
            self.edit = Some(CellEdit { row, col, text, focused: false });
            self.select_row(g, row);
        }
    }

    fn node_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        let node = find(&doc.parsed.root, &self.sel);
        ui.horizontal(|ui| {
            ui.label(RichText::new(&node.title).heading().strong());
            if self.sel.len() > 2 {
                ui.weak(self.sel[1..self.sel.len() - 1].join("  /  "));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if let Some((off, len)) = node.span {
                    ui.weak(RichText::new(format!("offset {off:08X}   size {len:X}")).monospace());
                }
            });
        });
        ui.add_space(6.0);
        match &node.view {
            View::Text(t) => {
                egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                    ui.add(egui::Label::new(RichText::new(t).monospace()).selectable(true).extend());
                });
            }
            View::Grid(g) => self.grid_ui(ui, doc, g),
            View::Tool(tool, g) => self.tool_ui(ui, doc, *tool, g),
        }
    }

    /// Push the settings into egui: theme and interface scale.
    fn apply_settings_now(&mut self, ctx: &egui::Context) {
        if !std::mem::take(&mut self.apply_settings) {
            return;
        }
        // A theme forced for a development screenshot wins over the stored one.
        if std::env::var_os("BXPLORE_THEME").is_none() {
            ctx.set_theme(match self.settings.theme {
                ThemeChoice::System => egui::ThemePreference::System,
                ThemeChoice::Dark => egui::ThemePreference::Dark,
                ThemeChoice::Light => egui::ThemePreference::Light,
            });
        }
        ctx.set_zoom_factor(self.settings.zoom);
    }

    fn prefs_ui(&mut self, ctx: &egui::Context) {
        if !self.show_prefs {
            return;
        }
        let before = self.settings.clone();
        let mut open = true;
        let mut menu_result = None;
        egui::Window::new("Preferences").open(&mut open).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
            let s = &mut self.settings;
            egui::Grid::new("prefs").num_columns(2).spacing([18.0, 10.0]).show(ui, |ui| {
                ui.label("Theme");
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut s.theme, ThemeChoice::System, "System");
                    ui.selectable_value(&mut s.theme, ThemeChoice::Dark, "Dark");
                    ui.selectable_value(&mut s.theme, ThemeChoice::Light, "Light");
                });
                ui.end_row();
                ui.label("Interface size");
                ui.horizontal(|ui| {
                    for (z, label) in [(0.85, "Small"), (1.0, "Normal"), (1.15, "Large"), (1.3, "Larger")] {
                        ui.selectable_value(&mut s.zoom, z, label);
                    }
                });
                ui.end_row();
                ui.label("Hex panel");
                ui.checkbox(&mut s.hex_panel, "Show under the structure views when a file is opened");
                ui.end_row();
                ui.label("Saving");
                ui.checkbox(&mut s.backup_on_save, "Keep the original as <name>.bak on the first save");
                ui.end_row();
                ui.label("Recent files");
                ui.add(egui::DragValue::new(&mut s.recent_max).range(0..=50).suffix(" files"))
                    .on_hover_text("How many files Open Recent lists; 0 keeps none. Entries beyond a lower number are forgotten when the next file is opened.");
                ui.end_row();
                ui.label("Strings");
                ui.add(egui::DragValue::new(&mut s.strings_min).range(2..=64).prefix("minimum length "));
                ui.end_row();
            });
            if let Some(target) = crate::shellmenu::target() {
                ui.add_space(10.0);
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("File manager");
                    if ui
                        .button(format!("Add \"{}\"", crate::shellmenu::LABEL))
                        .on_hover_text(format!("Adds this copy of the program to {target}, for your user account only."))
                        .clicked()
                    {
                        menu_result = Some(crate::shellmenu::install());
                    }
                    if ui.button("Remove").on_hover_text(format!("Takes the entry out of {target} again.")).clicked() {
                        menu_result = Some(crate::shellmenu::remove());
                    }
                });
                // A failure in the colour the status bar uses for one, and in words.
                match &self.menu_note {
                    Some(Ok(note)) => {
                        ui.label(note);
                    }
                    Some(Err(e)) => {
                        ui.colored_label(ui.visuals().error_fg_color, format!("Not done: {e}"));
                    }
                    None => {}
                }
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("Restore defaults").clicked() {
                    *s = Settings::default();
                }
                ui.weak(match &self.recent_file {
                    Some(f) => format!("Stored in {}", f.parent().map(|d| d.display().to_string()).unwrap_or_default()),
                    None => "Not stored: no configuration directory".to_string(),
                });
            });
        });
        self.show_prefs = open;
        // The outcome stays in the window, where the button is, and in the status bar.
        if let Some(result) = menu_result {
            match &result {
                Ok(msg) => self.ok(msg.clone()),
                Err(e) => self.err(format!("Cannot change the file manager menu: {e}")),
            }
            self.menu_note = Some(result);
        }
        if self.settings != before {
            self.apply_settings = true;
            self.hex.show = if self.settings.hex_panel != before.hex_panel { self.settings.hex_panel } else { self.hex.show };
            // The recent list is not cut here: a drag passes through values the
            // user never chose. The menus show the first `recent_max` entries
            // and `remember` drops the rest when the next file is opened.
            if let Some(dir) = self.config_dir()
                && let Err(e) = self.settings.save(&dir)
            {
                self.err(format!("Cannot store the settings: {e}"));
            }
        }
    }

    fn confirm_close_ui(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        if let Some(i) = self.close_tab_confirm {
            let name = self.tab_doc(i).map(|d| d.name()).unwrap_or_default();
            egui::Window::new("Close file").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(&ctx, |ui| {
                ui.label(format!("{name} has unsaved changes. Close it anyway?"));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Discard changes and close").clicked() {
                        self.close_tab(i);
                        self.close_tab_confirm = None;
                    }
                    if ui.button("Cancel").clicked() {
                        self.close_tab_confirm = None;
                    }
                });
            });
        }
        let dirty = self.any_dirty();
        let unsaved = (0..self.tabs.len()).filter(|i| self.tab_doc(*i).is_some_and(|d| d.dirty)).count();
        if ctx.input(|i| i.viewport().close_requested()) && dirty && !self.allow_close {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.confirm_close = true;
        }
        if self.confirm_close {
            egui::Window::new("Unsaved changes").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(&ctx, |ui| {
                ui.label(if unsaved > 1 {
                    format!("{unsaved} files have unsaved changes. Quit anyway?")
                } else {
                    "The file has unsaved changes. Quit anyway?".to_string()
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if unsaved == 1 && self.doc.as_ref().is_some_and(|d| d.dirty) && ui.button("Save and quit").clicked() {
                        self.save(None);
                        if !self.status_err {
                            self.allow_close = true;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        self.confirm_close = false;
                    }
                    if ui.button("Discard changes and quit").clicked() {
                        self.allow_close = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if ui.button("Cancel").clicked() {
                        self.confirm_close = false;
                    }
                });
            });
        }
    }
}

#[cfg(feature = "selftest")]
impl App {
    /// Development aid: with BXPLORE_SCREENSHOT=<png> set, select the node named
    /// by BXPLORE_SELECT (titles joined with '/'), save a screenshot and exit.
    fn self_test(&mut self, ctx: &egui::Context) {
        let Ok(target) = std::env::var("BXPLORE_SCREENSHOT") else { return };
        self.frames += 1;
        if self.frames == 2 {
            if let Ok(sel) = std::env::var("BXPLORE_SELECT") {
                let mut path = vec!["File".to_string()];
                path.extend(sel.split('/').filter(|s| !s.is_empty()).map(str::to_string));
                self.actions.push(Action::Select(path));
            }
            if let Ok(res) = std::env::var("BXPLORE_RES") {
                self.tools.select_resource(res.split(',').filter_map(|v| v.parse().ok()).collect());
            }
            if let Ok(q) = std::env::var("BXPLORE_SEARCH") {
                self.tools.set_search(&q);
            }
            if let Ok(p) = std::env::var("BXPLORE_COMPARE") {
                let _ = self.tools.x.set_compare(PathBuf::from(p));
            }
            if let Ok(a) = std::env::var("BXPLORE_DISASM")
                && let Ok(va) = u64::from_str_radix(&a, 16)
            {
                self.tools.disasm_at(va);
            }
            if let Ok(row) = std::env::var("BXPLORE_ROW") {
                self.pending_row = row.parse().ok();
            }
        }
        if self.frames == 4
            && let (Some(r), Some(d)) = (self.pending_row.take(), self.doc.as_ref())
            && let Some(g) = match &find(&d.parsed.root, &self.sel).view {
                View::Grid(g) | View::Tool(_, g) => Some(g),
                View::Text(_) => None,
            }
            && r < g.rows.len()
        {
            let g = g.clone();
            self.select_row(&g, r);
        }
        if self.frames == 12 {
            ctx.request_screenshot(move |img| {
                let [w, h] = img.size;
                let raw: Vec<u8> = img.pixels.iter().flat_map(|p| p.to_array()).collect();
                let _ = image::save_buffer(&target, &raw, w as u32, h as u32, image::ColorType::Rgba8);
                std::process::exit(0);
            });
        }
        if self.frames > 600 {
            std::process::exit(3);
        }
        ctx.request_repaint();
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        for f in ctx.input(|i| i.raw.dropped_files.clone()) {
            let p = f.path().to_path_buf();
            if !p.as_os_str().is_empty() {
                self.actions.push(Action::Open(p));
            }
        }

        let line = egui::Stroke::new(1.0, theme::border(ui));
        egui::Panel::top("menu").frame(theme::bar(ui, egui::Margin::symmetric(8, 3))).show_separator_line(false).show(ui, |ui| self.menu(ui));

        // The document is taken out while rendering so views can borrow it
        // immutably and still update UI state; edits are queued as actions.
        let doc = self.doc.take();

        if self.tabs.len() > 1 {
            let names: Vec<(String, bool)> = (0..self.tabs.len())
                .map(|i| match &self.tabs[i] {
                    Some(t) => (t.doc.name(), t.doc.dirty),
                    None => doc.as_ref().map(|d| (d.name(), d.dirty)).unwrap_or_default(),
                })
                .collect();
            egui::Panel::top("tabs").frame(theme::bar(ui, egui::Margin::symmetric(8, 4))).show_separator_line(false).show(ui, |ui| {
                egui::ScrollArea::horizontal().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 2.0;
                        for (i, (name, dirty)) in names.iter().enumerate() {
                            let label = format!("{}  {name}{}", icons::FILE_CODE, if *dirty { " *" } else { "" });
                            // A tab can be dropped on the Compare view. The button is the drag
                            // source itself: wrapped in `dnd_drag_source` it never sees a click.
                            let tab = ui.add(egui::Button::selectable(i == self.active, label).sense(egui::Sense::click_and_drag()));
                            tab.dnd_set_drag_payload(TabDrag(i));
                            if tab.dragged() {
                                ui.ctx().set_cursor_icon(egui::CursorIcon::Grabbing);
                            }
                            if tab.clicked() {
                                self.actions.push(Action::SwitchTab(i));
                            }
                            tab.context_menu(|ui| {
                                if i != self.active && ui.button("Compare with the active file").clicked() {
                                    self.actions.push(Action::CompareWithTab(i));
                                    ui.close();
                                }
                                if ui.button("Close").clicked() {
                                    self.actions.push(Action::CloseTab(i));
                                    ui.close();
                                }
                            });
                            if ui.add(egui::Button::new(RichText::new(icons::X).size(11.0)).frame(false)).on_hover_text("Close this file").clicked() {
                                self.actions.push(Action::CloseTab(i));
                            }
                            ui.add_space(8.0);
                        }
                    });
                });
            });
        }

        if let Some(d) = &doc {
            egui::Panel::top("toolbar").frame(theme::bar(ui, egui::Margin::symmetric(10, 6)).stroke(line)).show_separator_line(false).show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.button(theme::icon_text(icons::FOLDER_OPEN, "Open")).on_hover_text("Open another file").clicked() {
                        self.actions.push(Action::OpenDialog);
                    }
                    if ui
                        .add_enabled(d.dirty, egui::Button::new(theme::icon_text(icons::FLOPPY_DISK, "Save")))
                        .on_hover_text("Write the changes to disk")
                        .clicked()
                    {
                        self.actions.push(Action::Save);
                    }
                    if ui.add_enabled(!d.undo.is_empty(), egui::Button::new(theme::icon_text(icons::ARROW_COUNTER_CLOCKWISE, "Undo"))).clicked() {
                        self.actions.push(Action::Undo);
                    }
                    ui.separator();
                    if ui
                        .add_enabled(self.hist_pos > 0, egui::Button::new(theme::icon_text(icons::ARROW_LEFT, "Back")))
                        .on_hover_text("Previous location")
                        .clicked()
                    {
                        self.actions.push(Action::Back);
                    }
                    if ui
                        .add_enabled(self.hist_pos + 1 < self.history.len(), egui::Button::new(theme::icon_text(icons::ARROW_RIGHT, "Forward")))
                        .on_hover_text("Next location")
                        .clicked()
                    {
                        self.actions.push(Action::Forward);
                    }
                    ui.separator();
                    ui.toggle_value(&mut self.hex.show, theme::icon_text(icons::BINARY, "Hex panel"));
                    ui.separator();
                    ui.label(RichText::new(icons::MAGNIFYING_GLASS).color(ui.visuals().weak_text_color()));
                    let r = ui.add(egui::TextEdit::singleline(&mut self.search_box).desired_width(190.0).hint_text("Search all structures"));
                    if std::mem::take(&mut self.focus_search) {
                        r.request_focus();
                    }
                    if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) && !self.search_box.trim().is_empty() {
                        self.tools.set_search(self.search_box.trim());
                        self.actions.push(Action::Goto { path: vec!["File".into(), "Search".into()], row: None });
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.weak(size_text(d.data.len() as u64));
                        theme::chip(ui, &d.parsed.description, theme::accent(ui));
                        if d.dirty {
                            theme::chip(ui, "Modified", theme::warn(ui));
                        }
                        ui.add(egui::Label::new(RichText::new(d.name()).strong()).truncate());
                    });
                });
            });
        }

        egui::Panel::bottom("status").frame(theme::bar(ui, egui::Margin::symmetric(12, 4)).stroke(line)).show_separator_line(false).show(ui, |ui| {
            ui.horizontal(|ui| {
                let color = if self.status_err { ui.visuals().error_fg_color } else { ui.visuals().weak_text_color() };
                ui.add(egui::Label::new(RichText::new(&self.status).small().color(color)).truncate());
            });
        });

        match &doc {
            None => {
                egui::CentralPanel::default().frame(theme::content(ui)).show(ui, |ui| {
                    let hovering = ui.ctx().input(|i| !i.raw.hovered_files.is_empty());
                    ui.vertical_centered(|ui| {
                        ui.add_space((ui.available_height() * 0.5 - 130.0).max(0.0));
                        let mut card = theme::card(ui);
                        if hovering {
                            card = card.stroke(egui::Stroke::new(2.0, theme::accent(ui)));
                        }
                        card.show(ui, |ui| {
                            ui.set_width(380.0);
                            ui.vertical_centered(|ui| {
                                ui.label(RichText::new(icons::FILE_CODE).size(44.0).color(theme::accent(ui)));
                                ui.add_space(4.0);
                                ui.label(RichText::new("bxplore").size(26.0).strong());
                                ui.add_space(2.0);
                                ui.weak("Binary eXplorer: inspect and edit executable files");
                                ui.add_space(10.0);
                                ui.horizontal(|ui| {
                                    ui.add_space((ui.available_width() - 150.0).max(0.0) / 2.0);
                                    for f in ["PE", "ELF", "Mach-O"] {
                                        theme::chip(ui, f, theme::accent(ui));
                                    }
                                });
                                ui.add_space(18.0);
                                if theme::primary_button(ui, &format!("  {}  Open a file...  ", icons::FOLDER_OPEN)).clicked() {
                                    self.actions.push(Action::OpenDialog);
                                }
                                ui.add_space(8.0);
                                ui.weak(if hovering { "Release to open" } else { "or drop a file anywhere in this window" });
                            });
                        });
                        if !self.recent.is_empty() && self.settings.recent_max > 0 {
                            ui.add_space(22.0);
                            theme::caption(ui, "Recent files");
                            ui.add_space(4.0);
                            for p in self.recent.iter().take(self.settings.recent_max.min(8)) {
                                let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                                if ui
                                    .add(egui::Button::new(theme::icon_text(icons::CLOCK, &name)).frame(false))
                                    .on_hover_text(p.display().to_string())
                                    .clicked()
                                {
                                    self.actions.push(Action::Open(p.clone()));
                                }
                            }
                        }
                    });
                });
            }
            Some(d) => {
                egui::Panel::left("tree").resizable(true).default_size(270.0).frame(theme::bar(ui, egui::Margin::symmetric(8, 8))).show(ui, |ui| {
                    theme::caption(ui, "Structure");
                    ui.add_space(2.0);
                    egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.visuals_mut().widgets.inactive.weak_bg_fill = egui::Color32::TRANSPARENT;
                        ui.visuals_mut().widgets.inactive.bg_fill = egui::Color32::TRANSPARENT;
                        let mut path = Vec::new();
                        self.tree_ui(ui, &d.parsed.root, &mut path, 0);
                    });
                });
                let is_hex_node = matches!(find(&d.parsed.root, &self.sel).view, View::Tool(Tool::HexEditor, _));
                if self.hex.show && !is_hex_node {
                    egui::Panel::bottom("hex_panel")
                        .resizable(true)
                        .default_size(230.0)
                        .frame(theme::bar(ui, egui::Margin::symmetric(12, 8)))
                        .show(ui, |ui| self.hex_ui(ui, d));
                }
                egui::CentralPanel::default().frame(theme::content(ui)).show(ui, |ui| self.node_ui(ui, d));
            }
        }
        self.doc = doc;

        self.confirm_close_ui(ui);
        self.prefs_ui(&ctx);
        self.apply_settings_now(&ctx);

        for a in std::mem::take(&mut self.actions) {
            self.apply(a);
        }

        #[cfg(feature = "selftest")]
        self.self_test(&ctx);

        let title = match &self.doc {
            Some(d) => format!("{}{} - bxplore", d.name(), if d.dirty { " *" } else { "" }),
            None => "bxplore".to_string(),
        };
        if title != self.title {
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(title.clone()));
            self.title = title;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/parse_any").join(name)
    }
    use std::path::Path;

    fn app(files: &[&str]) -> App {
        let mut a = App::with_recent_file(files.iter().map(|f| seed(f)).collect(), None);
        for act in std::mem::take(&mut a.actions) {
            a.apply(act);
        }
        a
    }

    fn path(parts: &[&str]) -> Vec<String> {
        std::iter::once("File").chain(parts.iter().copied()).map(String::from).collect()
    }

    #[test]
    fn tabs_keep_their_own_state() {
        let mut a = app(&["tiny.exe", "tiny.elf", "tiny.macho"]);
        assert_eq!(a.tabs.len(), 3);
        assert_eq!(a.active, 0);
        assert_eq!(a.doc.as_ref().unwrap().name(), "tiny.exe");
        a.apply(Action::Goto { path: path(&["Section Headers"]), row: Some(0) });
        a.apply(Action::Write { off: 0x200, bytes: vec![0x90] });
        assert!(a.doc.as_ref().unwrap().dirty);

        a.apply(Action::SwitchTab(1));
        assert_eq!(a.doc.as_ref().unwrap().name(), "tiny.elf");
        assert_eq!(a.sel, path(&[]), "a tab starts at its own location");
        assert!(!a.doc.as_ref().unwrap().dirty);
        assert!(a.any_dirty(), "the other tab still has unsaved changes");

        // Ctrl+Tab and Ctrl+Shift+Tab walk the tabs and wrap around.
        assert_eq!((a.neighbour_tab(true), a.neighbour_tab(false)), (2, 0));
        a.apply(Action::SwitchTab(2));
        assert_eq!((a.neighbour_tab(true), a.neighbour_tab(false)), (0, 1));

        a.apply(Action::SwitchTab(0));
        assert_eq!(a.sel, path(&["Section Headers"]));
        assert_eq!(a.row, Some(0));
        assert_eq!(a.doc.as_ref().unwrap().data[0x200], 0x90);

        // Closing a dirty tab asks first; a clean one closes right away.
        a.apply(Action::CloseTab(0));
        assert_eq!((a.tabs.len(), a.close_tab_confirm), (3, Some(0)));
        a.close_tab_confirm = None;
        a.apply(Action::CloseTab(2));
        assert_eq!(a.tabs.len(), 2);
        assert_eq!(a.doc.as_ref().unwrap().name(), "tiny.exe");
        a.close_tab(0);
        assert_eq!(a.doc.as_ref().unwrap().name(), "tiny.elf");
        a.close_tab(0);
        assert!(a.doc.is_none() && a.tabs.is_empty());

        // Opening a file that is already open switches to it.
        let mut a = app(&["tiny.exe", "tiny.elf"]);
        a.apply(Action::Open(seed("tiny.elf")));
        assert_eq!((a.tabs.len(), a.active), (2, 1));
    }

    #[test]
    fn history_goes_back_and_forward() {
        let mut a = app(&["tiny.exe"]);
        a.apply(Action::Select(path(&["Dos Header"])));
        a.row = Some(3);
        a.apply(Action::Select(path(&["Section Headers"])));
        a.apply(Action::Goto { path: path(&["Nt Headers", "File Header"]), row: Some(1) });
        assert_eq!(a.history.len(), 4);

        a.apply(Action::Back);
        assert_eq!(a.sel, path(&["Section Headers"]));
        a.apply(Action::Back);
        assert_eq!((a.sel.clone(), a.row), (path(&["Dos Header"]), Some(3)), "the row is remembered");
        a.apply(Action::Forward);
        a.apply(Action::Forward);
        assert_eq!((a.sel.clone(), a.row), (path(&["Nt Headers", "File Header"]), Some(1)));
        a.apply(Action::Forward);
        assert_eq!(a.hist_pos, 3, "forward stops at the newest entry");

        // Navigating after going back drops the forward entries.
        a.apply(Action::Back);
        a.apply(Action::Select(path(&["Dos Header"])));
        assert_eq!(a.history.len(), 4);
        assert_eq!(a.hist_pos, 3);
    }

    #[test]
    fn goto_offset_finds_the_covering_field() {
        let mut a = app(&["tiny.exe"]);
        // 0x86 is NumberOfSections in the file header of the synthetic PE.
        a.apply(Action::GotoOffset(0x86));
        assert_eq!(a.sel, path(&["Nt Headers", "File Header"]));
        assert_eq!(a.row, Some(1));
        // 0x178 + 12 is the VirtualAddress of the only section.
        a.apply(Action::GotoOffset(0x178 + 12));
        assert_eq!(a.sel, path(&["Section Headers"]));
        a.apply(Action::Back);
        assert_eq!(a.sel, path(&["Nt Headers", "File Header"]));
    }

    #[test]
    fn bookmarks_are_kept_per_file_and_survive_reopening() {
        let dir = std::env::temp_dir().join(format!("bxplore-bm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let recent = dir.join("recent.txt");
        let mut a = App::with_recent_file(vec![seed("tiny.exe"), seed("tiny.elf")], Some(recent.clone()));
        a.apply(Action::Bookmark { off: 0x86, len: 2 });
        a.apply(Action::Bookmark { off: 0x3c, len: 4 });
        a.apply(Action::Bookmark { off: 0x86, len: 2 });
        let d = a.doc.as_ref().unwrap();
        assert_eq!(d.bookmarks.iter().map(|b| b.off).collect::<Vec<_>>(), [0x3c, 0x86], "sorted by offset, no duplicates");
        assert_eq!(d.bookmarks[1].note, "File Header", "the note starts as the structure's name");
        a.apply(Action::BookmarkSet { index: 1, note: Some("section count".into()) });
        a.apply(Action::BookmarkSet { index: 0, note: None });
        assert_eq!(a.status, "Bookmark at 0000003C deleted");
        a.apply(Action::BookmarkRestore(Bookmark { off: 0x3c, len: 4, note: "e_lfanew".into() }));
        assert_eq!(a.doc.as_ref().unwrap().bookmarks[0].note, "e_lfanew", "a deleted bookmark comes back with its note");
        a.apply(Action::BookmarkSet { index: 0, note: None });
        a.apply(Action::SwitchTab(1));
        assert!(a.doc.as_ref().unwrap().bookmarks.is_empty(), "the other file has its own list");

        let mut b = App::with_recent_file(vec![seed("tiny.exe")], Some(recent.clone()));
        let list = &b.doc.as_ref().unwrap().bookmarks;
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].off, list[0].note.as_str()), (0x86, "section count"));

        // Save As: the copy has the bookmarks when it is opened later, and so has the original.
        let copy = dir.join("copy.exe");
        b.save(Some(copy.clone()));
        assert!(!b.status_err, "{}", b.status);
        for file in [copy, seed("tiny.exe")] {
            let c = App::with_recent_file(vec![file], Some(recent.clone()));
            let list = &c.doc.as_ref().unwrap().bookmarks;
            assert_eq!(list.iter().map(|b| (b.off, b.note.as_str())).collect::<Vec<_>>(), [(0x86, "section count")]);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_are_loaded_and_drive_behaviour() {
        let dir = std::env::temp_dir().join(format!("bxplore-set-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Settings { hex_panel: false, recent_max: 1, backup_on_save: false, ..Settings::default() }.save(&dir).unwrap();
        let mut a = App::with_recent_file(vec![seed("tiny.exe"), seed("tiny.elf")], Some(dir.join("recent.txt")));
        assert!(!a.hex.show, "the hex panel follows the setting");
        assert_eq!(a.recent.len(), 1, "the recent list is capped by the setting");
        // Saving to a new place with backups off leaves no .bak behind.
        let copy = dir.join("copy.exe");
        std::fs::copy(seed("tiny.exe"), &copy).unwrap();
        a.apply(Action::Open(copy.clone()));
        a.apply(Action::Write { off: 0x200, bytes: vec![0x90] });
        a.apply(Action::Save);
        assert!(!dir.join("copy.exe.bak").exists());
        assert_eq!(std::fs::read(&copy).unwrap()[0x200], 0x90);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tab_can_be_compared_with_the_active_file() {
        let mut a = app(&["tiny.exe", "tiny.elf"]);
        a.apply(Action::CompareWithTab(1));
        assert_eq!(a.sel, path(&["Compare"]), "the compare view opens");
        a.apply(Action::CompareWithTab(0));
        assert_eq!(a.history.len(), 2, "comparing a file with itself does nothing");
    }

    #[test]
    fn recent_files_are_stored_and_deduplicated() {
        let file = std::env::temp_dir().join(format!("bxplore-recent-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let mut a = App::with_recent_file(vec![seed("tiny.exe"), seed("tiny.elf")], Some(file.clone()));
        a.apply(Action::Open(seed("tiny.exe")));
        let names = |a: &App| a.recent.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect::<Vec<_>>();
        assert_eq!(names(&a), ["tiny.elf", "tiny.exe"], "switching to an open file does not reorder the list");
        let b = App::with_recent_file(Vec::new(), Some(file.clone()));
        assert_eq!(names(&b), names(&a), "the list survives a restart");
        let _ = std::fs::remove_file(&file);
    }
}
