//! More tool views: structure search, file comparison, and the editors for
//! PE imports and exports, Mach-O load commands and the ELF dynamic section.

use std::path::PathBuf;
use std::rc::Rc;

use eframe::egui;
use egui::{Align, Layout, RichText, Sense, TextStyle, Ui};
use egui_extras::{Column, TableBuilder};

use crate::app::{Action, App, Doc};
use crate::model::clamp_off;
use crate::pe::edit::{self, ExportFn, ExportTable};
use crate::query::{self, Comparison, Hit};
use crate::{analysis, elf_edit, macho_edit, theme};

#[derive(Default)]
pub struct State {
    search: Search,
    cmp: Option<Cmp>,
    macho: MachoUi,
    elf: ElfUi,
    exp: Option<ExpUi>,
    imp: ImpUi,
    /// IL text of the selected method, keyed by file revision and row.
    il: Option<((u64, Option<usize>), String)>,
    bm: BookmarkUi,
    rel: RelocUi,
    sec: ElfSecUi,
}

#[derive(Default)]
struct BookmarkUi {
    /// Offset and length of the selected bookmark. The list is sorted by
    /// offset, so a position in it stops meaning the same bookmark as soon
    /// as one is added or deleted.
    sel: Option<(usize, usize)>,
    /// The note being edited; it belongs to the bookmark `sel` names.
    note: String,
    /// Structure path of every bookmark, for one revision of the file and one
    /// list of (offset, length) pairs: finding a path walks the whole tree.
    paths: Option<BookmarkPaths>,
    /// The bookmark deleted last and the file it belonged to. Bookmarks are
    /// not on the undo stack, so this is the way back from a misclick.
    deleted: Option<(PathBuf, crate::store::Bookmark)>,
}

type BookmarkPaths = (u64, Vec<(usize, usize)>, Rc<Vec<String>>);

impl BookmarkUi {
    /// Where the selected bookmark is in the list now; the selection is dropped when it is gone.
    fn index(&mut self, list: &[crate::store::Bookmark]) -> Option<usize> {
        let i = self.sel.and_then(|key| list.iter().position(|b| (b.off, b.len) == key));
        if i.is_none() {
            self.sel = None;
        }
        i
    }
}

#[derive(Default)]
struct RelocUi {
    rva: String,
    ty: usize,
    callback: String,
    tls_sel: Option<usize>,
    cache: Option<(u64, Rc<Vec<(u32, u8)>>)>,
    /// TLS callbacks by file revision; `None` inside when there is no TLS directory.
    tls: Option<(u64, Option<Rc<Vec<u64>>>)>,
}

#[derive(Default)]
struct ElfSecUi {
    name: String,
    file: Option<PathBuf>,
    sel: Option<usize>,
    /// The section list by file revision, so it is not rebuilt every frame.
    cache: Option<(u64, Rc<Result<Vec<elf_edit::SectionInfo>, String>>)>,
}

#[derive(Default)]
struct Search {
    query: String,
    ran: Option<(u64, String)>,
    hits: Rc<Vec<Hit>>,
    sel: Option<usize>,
}

struct Cmp {
    path: PathBuf,
    data: Rc<Vec<u8>>,
    rev: u64,
    result: Rc<Comparison>,
    sel: Option<usize>,
}

#[derive(Default)]
struct MachoUi {
    kind: usize,
    path: String,
    sel: Option<(u32, String)>,
}

#[derive(Default)]
struct ElfUi {
    text: String,
    sel: Option<usize>,
}

struct ExpRow {
    rva: String,
    names: String,
    forwarder: String,
}

struct ExpUi {
    rev: u64,
    dll: String,
    base: String,
    table: ExportTable,
    rows: Vec<ExpRow>,
    sel: Option<usize>,
    dirty: bool,
}

#[derive(Default)]
struct ImpUi {
    sel: Option<(usize, Option<usize>)>,
    name: String,
    cache: Option<(u64, Rc<Vec<(String, Vec<String>)>>)>,
    /// Number of delay-loaded modules, by file revision.
    delay: Option<(u64, usize)>,
}

impl State {
    pub fn set_search(&mut self, q: &str) {
        self.search.query = q.to_string();
    }

    /// Compare against bytes already in memory (another open tab).
    pub fn set_compare_data(&mut self, path: PathBuf, data: Rc<Vec<u8>>) {
        self.cmp = Some(Cmp { path, data, rev: 0, result: Rc::new(Comparison { diffs: Vec::new(), truncated: false, summary: Vec::new() }), sel: None });
    }

    /// Load the file to compare against. Returns an error text when it cannot be read.
    pub fn set_compare(&mut self, path: PathBuf) -> Result<(), String> {
        let data = std::fs::read(&path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        self.cmp = Some(Cmp {
            path,
            data: Rc::new(data),
            rev: 0,
            result: Rc::new(Comparison { diffs: Vec::new(), truncated: false, summary: Vec::new() }),
            sel: None,
        });
        Ok(())
    }
}

const SEARCH_LIMIT: usize = 5000;

/// A read-only table with click selection. Returns the clicked row.
fn list_table(
    ui: &mut Ui,
    id: &str,
    cols: &[(&str, f32)],
    n: usize,
    selected: Option<usize>,
    max_height: Option<f32>,
    cell: impl Fn(usize, usize) -> String,
) -> Option<usize> {
    let row_h = ui.text_style_height(&TextStyle::Monospace) + 9.0;
    let mut clicked = None;
    ui.push_id(id, |ui| {
        let mut tb = TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .min_scrolled_height(0.0);
        tb = match max_height {
            Some(h) => tb.auto_shrink([false, true]).max_scroll_height(h),
            None => tb.auto_shrink([false, false]),
        };
        for (i, (_, w)) in cols.iter().enumerate() {
            tb = tb.column(if i + 1 == cols.len() { Column::remainder().at_least(*w).clip(true) } else { Column::initial(*w).at_least(24.0).clip(true) });
        }
        tb.header(row_h + 2.0, |mut h| {
            for (name, _) in cols {
                h.col(|ui| theme::caption(ui, name));
            }
        })
        .body(|body| {
            body.rows(row_h, n, |mut row| {
                let i = row.index();
                row.set_selected(selected == Some(i));
                let mut hit = false;
                for c in 0..cols.len() {
                    let (_, resp) = row.col(|ui| {
                        ui.add(egui::Label::new(RichText::new(cell(i, c)).monospace()).selectable(false).truncate());
                    });
                    hit |= resp.clicked();
                }
                if hit || row.response().clicked() {
                    clicked = Some(i);
                }
            });
        });
    });
    clicked
}

fn path_text(path: &[String]) -> String {
    if path.len() <= 1 { "File".into() } else { path[1..].join(" / ") }
}

impl App {
    pub fn search_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        let s = &mut self.tools.x.search;
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut s.query).desired_width(320.0).hint_text("Text to find in any structure"));
            ui.weak(match s.hits.len() {
                0 if s.query.trim().is_empty() => "Searches titles, table cells and text views of every structure.".to_string(),
                0 => "No matches".to_string(),
                SEARCH_LIMIT => format!("first {SEARCH_LIMIT} matches"),
                n => format!("{n} match(es)"),
            });
        });
        let key = (doc.rev, s.query.trim().to_string());
        if s.ran.as_ref() != Some(&key) {
            s.hits = Rc::new(query::search(&doc.parsed.root, &key.1, SEARCH_LIMIT));
            s.ran = Some(key);
            s.sel = None;
        }
        ui.add_space(4.0);
        let hits = s.hits.clone();
        let sel = s.sel;
        let clicked = list_table(ui, "search", &[("Structure", 320.0), ("Where", 130.0), ("Match", 300.0)], hits.len(), sel, None, |i, c| match c {
            0 => path_text(&hits[i].path),
            1 => hits[i].place.clone(),
            _ => hits[i].text.clone(),
        });
        if let Some(i) = clicked {
            self.tools.x.search.sel = Some(i);
            self.actions.push(Action::Goto { path: hits[i].path.clone(), row: hits[i].row });
        }
    }

    pub fn compare_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        ui.horizontal(|ui| {
            if ui.button("Choose file to compare...").clicked()
                && let Some(p) = rfd::FileDialog::new().set_title("Compare with").pick_file()
                && let Err(e) = self.tools.x.set_compare(p)
            {
                self.err(e);
            }
            match &self.tools.x.cmp {
                Some(c) => ui.label(format!("This file (left) against {} (right)", c.path.display())),
                None => ui.weak("Compares every structure of this file with another file, for example before and after an edit."),
            };
        });
        // Another open file can be dropped here, or picked from its tab's context menu.
        let frame = egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(10, 6))
            .corner_radius(egui::CornerRadius::same(6))
            .stroke(egui::Stroke::new(1.0, theme::border(ui)));
        let (_, dropped) = ui.dnd_drop_zone::<crate::app::TabDrag, _>(frame, |ui| {
            ui.weak("Drop a tab here to compare with that open file (or right click the tab).");
        });
        if let Some(tab) = dropped {
            self.actions.push(Action::CompareWithTab(tab.0));
        }
        let Some(c) = &mut self.tools.x.cmp else { return };
        if c.rev != doc.rev {
            let other = analysis::parse(&c.data);
            c.result = Rc::new(query::compare(&doc.parsed, &doc.data, &other, &c.data));
            c.rev = doc.rev;
            c.sel = None;
        }
        let result = c.result.clone();
        let sel = c.sel;
        ui.add_space(6.0);
        egui::Grid::new("cmp_summary").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
            for (k, v) in &result.summary {
                ui.weak(k);
                ui.label(v);
                ui.end_row();
            }
        });
        if result.truncated {
            ui.colored_label(theme::warn(ui), "The list is cut off at 5000 differences.");
        }
        ui.add_space(6.0);
        let d = &result.diffs;
        let clicked = list_table(
            ui,
            "cmp",
            &[("Structure", 260.0), ("Item", 220.0), ("This file", 200.0), ("Other file", 200.0)],
            d.len(),
            sel,
            None,
            |i, col| match col {
                0 => path_text(&d[i].path),
                1 => d[i].what.clone(),
                2 => d[i].left.clone(),
                _ => d[i].right.clone(),
            },
        );
        if let Some(i) = clicked {
            if let Some(c) = &mut self.tools.x.cmp {
                c.sel = Some(i);
            }
            self.actions.push(Action::Goto { path: d[i].path.clone(), row: d[i].row });
        }
    }

    // --- Mach-O -------------------------------------------------------------

    pub fn macho_edit_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        const KINDS: [(u32, &str); 4] = [
            (macho_edit::LC_LOAD_DYLIB, "Library (LC_LOAD_DYLIB)"),
            (macho_edit::LC_LOAD_WEAK_DYLIB, "Weak library (LC_LOAD_WEAK_DYLIB)"),
            (macho_edit::LC_REEXPORT_DYLIB, "Re-exported library (LC_REEXPORT_DYLIB)"),
            (macho_edit::LC_RPATH, "Run path (LC_RPATH)"),
        ];
        let slices = macho_edit::slices(&doc.data);
        let Some(first) = slices.first() else {
            ui.weak("The load commands of this file cannot be edited.");
            return;
        };
        ui.label("Add, change or remove the load commands that name libraries and run paths. New commands use the padding after the load commands, so nothing else in the file moves.");
        let free = slices.iter().map(|s| s.free_space()).min().unwrap_or(0);
        ui.weak(format!(
            "{} architecture(s), edited together. Free header space: {free} bytes{}.",
            slices.len(),
            if free < 64 { " (little room; a file linked with -headerpad has more)" } else { "" }
        ));
        ui.colored_label(theme::warn(ui), "Any change invalidates the code signature. Re-sign afterwards: codesign -f -s - <file>");
        ui.add_space(6.0);

        let cmds: Vec<(u32, String)> = first.cmds.iter().filter_map(|c| first.path(&doc.data, c).map(|p| (c.cmd, p))).collect();
        let name = |cmd: u32| match cmd {
            macho_edit::LC_LOAD_DYLIB => "LC_LOAD_DYLIB",
            macho_edit::LC_ID_DYLIB => "LC_ID_DYLIB",
            macho_edit::LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB",
            macho_edit::LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB",
            macho_edit::LC_LAZY_LOAD_DYLIB => "LC_LAZY_LOAD_DYLIB",
            macho_edit::LC_RPATH => "LC_RPATH",
            _ => "?",
        };
        let t = &mut self.tools.x.macho;
        let sel = t.sel.as_ref().and_then(|s| cmds.iter().position(|c| c == s));
        let h = (ui.available_height() - 130.0).max(120.0);
        if let Some(i) = list_table(ui, "macho_cmds", &[("Command", 200.0), ("Path", 300.0)], cmds.len(), sel, Some(h), |i, c| {
            if c == 0 { name(cmds[i].0).to_string() } else { cmds[i].1.clone() }
        }) {
            t.sel = Some(cmds[i].clone());
            t.path = cmds[i].1.clone();
        }
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("macho_kind").selected_text(KINDS[t.kind.min(3)].1).width(270.0).show_ui(ui, |ui| {
                for (i, (_, label)) in KINDS.iter().enumerate() {
                    ui.selectable_value(&mut t.kind, i, *label);
                }
            });
            ui.add(egui::TextEdit::singleline(&mut t.path).desired_width(360.0).hint_text("@rpath/libexample.dylib or /usr/lib/libz.1.dylib"));
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let path = t.path.trim().to_string();
            if ui.add_enabled(!path.is_empty(), egui::Button::new("Add")).clicked() {
                let cmd = KINDS[t.kind.min(3)].0;
                self.actions.push(Action::Op(Box::new(move |d| macho_edit::add_path_command(d, cmd, &path))));
            }
            let path = t.path.trim().to_string();
            if let Some((cmd, old)) = t.sel.clone().filter(|_| sel.is_some()) {
                if ui.add_enabled(!path.is_empty() && path != old, egui::Button::new("Change selected")).clicked() {
                    let (o, n) = (old.clone(), path.clone());
                    t.sel = Some((cmd, path));
                    self.actions.push(Action::Op(Box::new(move |d| macho_edit::change_path(d, cmd, &o, &n))));
                }
                if ui.add_enabled(cmd != macho_edit::LC_ID_DYLIB, egui::Button::new("Remove selected")).clicked() {
                    self.actions.push(Action::Op(Box::new(move |d| macho_edit::remove_path_command(d, cmd, &old))));
                }
            }
            ui.separator();
            if ui.add_enabled(first.cmds.iter().any(|c| c.cmd == macho_edit::LC_CODE_SIGNATURE), egui::Button::new("Remove code signature")).clicked() {
                self.actions.push(Action::Op(Box::new(macho_edit::remove_signature)));
            }
        });
    }

    // --- ELF ----------------------------------------------------------------

    pub fn elf_dynamic_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        let info = match elf_edit::info(&doc.data) {
            Ok(i) => i,
            Err(e) => {
                ui.weak(format!("The dynamic section cannot be edited: {e}."));
                return;
            }
        };
        ui.label(
            "Edit the needed libraries, SONAME, RPATH and RUNPATH. Changes are made in place when the strings fit and the dynamic table has a spare slot.",
        );
        ui.weak(format!(
            "Spare slots in the dynamic table: {}. {}",
            info.spare_slots,
            if info.can_grow {
                "When more room is needed, the tables are copied to the end of the file and the PT_NOTE program header is turned into a PT_LOAD that maps them."
            } else {
                "This file has no PT_NOTE program header, so edits that need more room will be refused."
            }
        ));
        ui.add_space(6.0);
        let rows: Vec<(usize, &elf_edit::DynEntry)> = info
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e.tag, elf_edit::DT_NEEDED | elf_edit::DT_SONAME | elf_edit::DT_RPATH | elf_edit::DT_RUNPATH))
            .collect();
        let t = &mut self.tools.x.elf;
        let sel_row = t.sel.and_then(|s| rows.iter().position(|r| r.0 == s));
        let h = (ui.available_height() - 110.0).max(120.0);
        let text = |e: &elf_edit::DynEntry| e.text.clone().unwrap_or_else(|| format!("<string at {:X} is outside the table>", e.value));
        if let Some(i) = list_table(ui, "elf_dyn", &[("Entry", 120.0), ("Value", 300.0)], rows.len(), sel_row, Some(h), |i, c| {
            if c == 0 { elf_edit::tag_name(rows[i].1.tag).to_string() } else { text(rows[i].1) }
        }) {
            t.sel = Some(rows[i].0);
            t.text = text(rows[i].1);
        }
        ui.add_space(8.0);
        ui.add(egui::TextEdit::singleline(&mut t.text).desired_width(520.0).hint_text("libexample.so.1, or a path list such as $ORIGIN/../lib:/opt/lib"));
        ui.add_space(4.0);
        let value = t.text.trim().to_string();
        let selected = sel_row.map(|r| (rows[r].0, rows[r].1.tag, text(rows[r].1)));
        ui.horizontal(|ui| {
            let ok = !value.is_empty();
            if ui.add_enabled(ok, egui::Button::new("Add needed library")).clicked() {
                let v = value.clone();
                self.actions.push(Action::Op(Box::new(move |d| elf_edit::add_needed(d, &v))));
            }
            if let Some((_, elf_edit::DT_NEEDED, old)) = &selected
                && ui.add_enabled(ok && *old != value, egui::Button::new("Rename selected library")).clicked()
            {
                let (o, v) = (old.clone(), value.clone());
                self.actions.push(Action::Op(Box::new(move |d| elf_edit::rename_needed(d, &o, &v))));
            }
            for (tag, label) in [(elf_edit::DT_SONAME, "Set SONAME"), (elf_edit::DT_RUNPATH, "Set RUNPATH"), (elf_edit::DT_RPATH, "Set RPATH")] {
                if ui.add_enabled(ok, egui::Button::new(label)).clicked() {
                    let v = value.clone();
                    self.actions.push(Action::Op(Box::new(move |d| elf_edit::set_string(d, tag, &v))));
                }
            }
            if let Some((index, _, _)) = selected
                && ui.button("Remove selected").clicked()
            {
                self.tools.x.elf.sel = None;
                self.actions.push(Action::Op(Box::new(move |d| elf_edit::remove_entry(d, index))));
            }
        });
    }

    // --- PE imports ---------------------------------------------------------

    /// Existing imports: rename, remove a module, unbind.
    pub fn import_edit_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        let Some(pe) = &doc.pe else { return };
        let t = &mut self.tools.x.imp;
        if t.cache.as_ref().is_none_or(|c| c.0 != doc.rev) {
            let list = pe
                .imports(&doc.data)
                .into_iter()
                .map(|m| (m.name, m.funcs.into_iter().map(|f| f.name.unwrap_or_else(|| format!("#{}", f.ordinal.unwrap_or(0)))).collect()))
                .collect();
            t.cache = Some((doc.rev, Rc::new(list)));
            t.sel = None;
        }
        let Some(mods) = t.cache.as_ref().map(|c| c.1.clone()) else { return };
        theme::caption(ui, "Existing imports");
        // Flatten to one row per module and function.
        let flat: Vec<(usize, Option<usize>)> =
            mods.iter().enumerate().flat_map(|(mi, m)| std::iter::once((mi, None)).chain((0..m.1.len()).map(move |fi| (mi, Some(fi))))).collect();
        let sel = t.sel.and_then(|s| flat.iter().position(|f| *f == s));
        let h = 190.0;
        let clicked = list_table(ui, "imp_existing", &[("Module", 220.0), ("Function", 300.0)], flat.len(), sel, Some(h), |i, c| match (flat[i], c) {
            ((mi, None), 0) => mods[mi].0.clone(),
            ((mi, None), _) => format!("({} functions)", mods[mi].1.len()),
            ((_, Some(_)), 0) => String::new(),
            ((mi, Some(fi)), _) => mods[mi].1[fi].clone(),
        });
        if let Some(i) = clicked {
            t.sel = Some(flat[i]);
            t.name = match flat[i] {
                (mi, None) => mods[mi].0.clone(),
                (mi, Some(fi)) => mods[mi].1[fi].clone(),
            };
        }
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut t.name).desired_width(300.0).hint_text("new name for the selected row"));
            let name = t.name.trim().to_string();
            match t.sel {
                Some((mi, func)) => {
                    let by_ordinal = func.is_some_and(|fi| mods[mi].1[fi].starts_with('#'));
                    if ui
                        .add_enabled(!name.is_empty() && !by_ordinal, egui::Button::new(if func.is_some() { "Rename function" } else { "Rename module" }))
                        .clicked()
                    {
                        self.actions.push(Action::Op(Box::new(move |d| edit::rename_import(d, mi, func, &name))));
                    }
                    if ui.button("Remove module").on_hover_text("Removes the whole module of the selected row from the import directory").clicked() {
                        self.actions.push(Action::Op(Box::new(move |d| edit::remove_import_module(d, mi))));
                    }
                }
                None => {
                    ui.weak("Select a module or function to rename or remove it.");
                }
            }
            ui.separator();
            if ui.button("Unbind imports").on_hover_text("Clears binding timestamps, restores the IAT and drops the bound import directory").clicked() {
                self.actions.push(Action::Op(Box::new(edit::unbind_imports)));
            }
            if t.delay.is_none_or(|d| d.0 != doc.rev) {
                t.delay = Some((doc.rev, edit::delay_imports(&doc.data, pe).len()));
            }
            let delay = t.delay.map_or(0, |d| d.1);
            if ui
                .add_enabled(delay > 0, egui::Button::new(format!("Convert delay imports ({delay})")))
                .on_hover_text("Turns delay-loaded modules into ordinary imports that the loader resolves at start-up")
                .clicked()
            {
                self.actions.push(Action::Op(Box::new(edit::convert_delay_imports)));
            }
        });
        ui.weak("A longer name is stored in a new section. Removing a module leaves its IAT slots unresolved.");
    }

    // --- .NET IL -------------------------------------------------------------

    /// Method list on top, IL of the selected method below.
    pub fn il_ui(&mut self, ui: &mut Ui, doc: &Doc, g: &crate::model::Grid) {
        let key = (doc.rev, self.row);
        if self.tools.x.il.as_ref().is_none_or(|c| c.0 != key) {
            let text = match (self.row, &doc.pe) {
                (Some(r), Some(pe)) => crate::pe::method_il(&doc.data, pe, r + 1).unwrap_or_else(|| "The method body could not be read.".into()),
                _ => "Select a method to see its IL.".to_string(),
            };
            self.tools.x.il = Some((key, text));
        }
        // Borrowed: the listing can be megabytes, and this runs every frame.
        let text = self.tools.x.il.as_ref().map_or("", |c| c.1.as_str());
        egui::Panel::bottom("il_text").resizable(true).default_size((ui.available_height() * 0.5).max(120.0)).show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                theme::caption(ui, "IL");
                if ui.small_button("Copy").clicked() {
                    ui.ctx().copy_text(text.to_string());
                }
            });
            egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                ui.add(egui::Label::new(RichText::new(text).monospace()).selectable(true).extend());
            });
        });
        self.grid_ui(ui, doc, g);
    }

    // --- PE exports ---------------------------------------------------------

    pub fn exports_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        let Some(pe) = &doc.pe else { return };
        if self.tools.x.exp.as_ref().is_none_or(|e| e.rev != doc.rev) {
            let table = edit::parse_exports(&doc.data, pe).unwrap_or_else(|| ExportTable { dll_name: doc.name(), base: 1, ..Default::default() });
            let rows = table
                .funcs
                .iter()
                .map(|f| ExpRow { rva: format!("{:08X}", f.rva), names: f.names.join(", "), forwarder: f.forwarder.clone().unwrap_or_default() })
                .collect();
            self.tools.x.exp = Some(ExpUi { rev: doc.rev, dll: table.dll_name.clone(), base: table.base.to_string(), table, rows, sel: None, dirty: false });
        }
        let Some(e) = &mut self.tools.x.exp else { return };
        ui.label("Edit the export table. Writing it builds a fresh export directory in a new section, with the names sorted as the loader requires.");
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("DLL name:");
            e.dirty |= ui.add(egui::TextEdit::singleline(&mut e.dll).desired_width(200.0)).changed();
            ui.label("Ordinal base:");
            e.dirty |= ui.add(egui::TextEdit::singleline(&mut e.base).desired_width(60.0)).changed();
            ui.weak(format!("{} function(s)", e.rows.len()));
        });
        ui.add_space(4.0);
        let base: u32 = e.base.trim().parse().unwrap_or(1);
        let row_h = ui.spacing().interact_size.y + 4.0;
        let h = (ui.available_height() - 80.0).max(120.0);
        ui.horizontal(|ui| {
            for (t, w) in [("Ordinal", 70.0), ("Function RVA", 118.0), ("Names (comma separated)", 338.0), ("Forwarder (DLL.Function)", 228.0)] {
                ui.allocate_ui_with_layout(egui::vec2(w, 16.0), Layout::left_to_right(Align::Center), |ui| {
                    ui.set_min_width(w);
                    theme::caption(ui, t);
                });
            }
        });
        let mut dirty = false;
        let mut pick = None;
        let sel = e.sel;
        egui::ScrollArea::vertical().max_height(h).auto_shrink([false, true]).show_rows(ui, row_h, e.rows.len(), |ui, range| {
            for i in range {
                let r = &mut e.rows[i];
                ui.horizontal(|ui| {
                    if ui
                        .add_sized(
                            [70.0, row_h - 4.0],
                            egui::Button::selectable(sel == Some(i), RichText::new(format!("{}", base as u64 + i as u64)).monospace()),
                        )
                        .clicked()
                    {
                        pick = Some(i);
                    }
                    dirty |= ui.add(egui::TextEdit::singleline(&mut r.rva).font(TextStyle::Monospace).desired_width(110.0)).changed();
                    dirty |= ui.add(egui::TextEdit::singleline(&mut r.names).font(TextStyle::Monospace).desired_width(330.0)).changed();
                    dirty |= ui.add(egui::TextEdit::singleline(&mut r.forwarder).font(TextStyle::Monospace).desired_width(220.0)).changed();
                });
            }
        });
        e.dirty |= dirty;
        if pick.is_some() {
            e.sel = pick;
        }
        ui.add_space(6.0);
        let mut revert = false;
        ui.horizontal(|ui| {
            if ui.button("Add export").clicked() {
                e.rows.push(ExpRow { rva: "00000000".into(), names: String::new(), forwarder: String::new() });
                e.sel = Some(e.rows.len() - 1);
                e.dirty = true;
            }
            if let Some(i) = e.sel.filter(|i| *i < e.rows.len())
                && ui.button("Delete selected").on_hover_text("Later exports move up by one ordinal").clicked()
            {
                e.rows.remove(i);
                e.sel = None;
                e.dirty = true;
            }
            ui.separator();
            if ui.add_enabled(e.dirty, egui::Button::new("Write export directory")).clicked() {
                let mut table = ExportTable { dll_name: e.dll.trim().to_string(), base, funcs: Vec::new(), ..e.table.clone() };
                let mut problem = None;
                for (i, r) in e.rows.iter().enumerate() {
                    let forwarder = Some(r.forwarder.trim().to_string()).filter(|f| !f.is_empty());
                    let rva = match u32::from_str_radix(r.rva.trim(), 16) {
                        Ok(v) => v,
                        Err(_) if forwarder.is_some() => 0,
                        Err(_) => {
                            problem = Some(format!("Ordinal {}: the RVA is not a hex number", base as u64 + i as u64));
                            break;
                        }
                    };
                    let names = r.names.split(',').map(|n| n.trim().to_string()).filter(|n| !n.is_empty()).collect();
                    table.funcs.push(ExportFn { rva, forwarder, names });
                }
                match problem {
                    Some(p) => {
                        self.status = p;
                        self.status_err = true;
                    }
                    None => self.actions.push(Action::Op(Box::new(move |d| edit::write_exports(d, &table)))),
                }
            }
            revert = e.dirty && ui.button("Revert").clicked();
        });
        if revert {
            self.tools.x.exp = None;
        }
    }
}

impl App {
    // --- bookmarks --------------------------------------------------------------

    pub fn bookmarks_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        ui.label("Places in this file you marked, with your notes. They are remembered per file.");
        ui.weak("Add one with \"Bookmark this row\" in a table's context menu, or with Bookmark in the hex panel.");
        ui.add_space(6.0);
        let list = &doc.bookmarks;
        let t = &mut self.tools.x.bm;
        let sel = t.index(list);
        if !t.paths.as_ref().is_some_and(|(rev, key, _)| *rev == doc.rev && key.iter().copied().eq(list.iter().map(|b| (b.off, b.len)))) {
            let paths = list.iter().map(|b| query::node_at(&doc.parsed.root, b.off).map(|(p, _)| path_text(&p)).unwrap_or_default()).collect();
            t.paths = Some((doc.rev, list.iter().map(|b| (b.off, b.len)).collect(), Rc::new(paths)));
        }
        let Some(paths) = t.paths.as_ref().map(|p| p.2.clone()) else { return };
        let h = (ui.available_height() - 90.0).max(120.0);
        let clicked = list_table(
            ui,
            "bookmarks",
            &[("Offset", 100.0), ("Length", 70.0), ("Structure", 260.0), ("Note", 300.0)],
            list.len(),
            sel,
            Some(h),
            |i, c| match c {
                0 => format!("{:08X}", list[i].off),
                1 => format!("{:X}", list[i].len),
                2 => paths[i].clone(),
                _ => list[i].note.lines().next().unwrap_or("").to_string(),
            },
        );
        if let Some(i) = clicked {
            t.sel = Some((list[i].off, list[i].len));
            t.note = list[i].note.clone();
            self.hex.show_range(list[i].off, list[i].len);
        }
        ui.add_space(8.0);
        if let Some((_, b)) = t.deleted.as_ref().filter(|(path, _)| *path == doc.path) {
            let restore = ui.horizontal(|ui| {
                ui.weak(format!("Bookmark at {:08X} deleted.", b.off));
                ui.button("Restore deleted bookmark").clicked()
            });
            if restore.inner
                && let Some((_, b)) = t.deleted.take()
            {
                t.sel = Some((b.off, b.len));
                t.note = b.note.clone();
                self.actions.push(Action::BookmarkRestore(b));
            }
            ui.add_space(4.0);
        }
        let Some(i) = clicked.or(sel) else {
            if list.is_empty() {
                ui.weak("No bookmarks yet.");
            }
            return;
        };
        let (off, len) = (list[i].off, list[i].len);
        ui.horizontal(|ui| {
            ui.label("Note:");
            let r = ui.add(egui::TextEdit::singleline(&mut self.tools.x.bm.note).desired_width(420.0));
            if r.changed() {
                self.actions.push(Action::BookmarkSet { index: i, note: Some(self.tools.x.bm.note.clone()) });
            }
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button("Go to structure").clicked() {
                self.actions.push(Action::GotoOffset(off));
            }
            if ui.button("Show in hex").clicked() {
                self.hex.show = true;
                self.hex.show_range(off, len);
            }
            ui.separator();
            if ui.button("Delete").clicked() {
                self.tools.x.bm.sel = None;
                self.tools.x.bm.deleted = Some((doc.path.clone(), list[i].clone()));
                self.actions.push(Action::BookmarkSet { index: i, note: None });
            }
        });
    }

    // --- PE relocations and TLS callbacks ------------------------------------------

    pub fn relocs_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        const TYPES: [(u8, &str); 4] = [(10, "DIR64 (64 bit address)"), (3, "HIGHLOW (32 bit address)"), (1, "HIGH"), (2, "LOW")];
        let Some(pe) = &doc.pe else { return };
        let t = &mut self.tools.x.rel;
        if t.cache.as_ref().is_none_or(|c| c.0 != doc.rev) {
            t.cache = Some((doc.rev, Rc::new(edit::parse_relocs(&doc.data, pe))));
            t.tls_sel = None;
            if t.ty == 0 && !pe.is64 {
                t.ty = 1;
            }
        }
        let relocs = t.cache.as_ref().map(|c| c.1.clone()).unwrap_or_default();
        theme::caption(ui, "Base relocations");
        ui.label(format!(
            "{} relocation(s). The table itself is under Relocation Directory. A smaller table is rewritten in place; a larger one moves to a new section.",
            relocs.len()
        ));
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("RVA:");
            ui.add(egui::TextEdit::singleline(&mut t.rva).font(TextStyle::Monospace).desired_width(110.0).hint_text("hex"));
            egui::ComboBox::from_id_salt("reloc_type").selected_text(TYPES[t.ty.min(3)].1).width(220.0).show_ui(ui, |ui| {
                for (i, (_, label)) in TYPES.iter().enumerate() {
                    ui.selectable_value(&mut t.ty, i, *label);
                }
            });
            let rva = crate::model::parse_number(&t.rva, 16).ok().and_then(|v| u32::try_from(v).ok());
            let exists = rva.is_some_and(|r| relocs.iter().any(|x| x.0 == r));
            if ui.add_enabled(rva.is_some() && !exists, egui::Button::new("Add")).clicked()
                && let Some(r) = rva
            {
                let ty = TYPES[t.ty.min(3)].0;
                self.actions.push(Action::Op(Box::new(move |d| edit::add_reloc(d, r, ty))));
            }
            if ui.add_enabled(exists, egui::Button::new("Remove")).clicked()
                && let Some(r) = rva
            {
                self.actions.push(Action::Op(Box::new(move |d| edit::remove_reloc(d, r))));
            }
            if rva.is_some() {
                ui.weak(if exists { "this RVA has a relocation" } else { "this RVA has no relocation" });
            } else if !t.rva.trim().is_empty() {
                ui.weak("not a 32 bit hex number");
            }
        });
        ui.add_space(10.0);
        ui.separator();
        theme::caption(ui, "TLS callbacks");
        if t.tls.as_ref().is_none_or(|c| c.0 != doc.rev) {
            // A directory without a callback array is an empty list that can still get a callback.
            let list = edit::tls_directory(&doc.data, pe).map(|_| Rc::new(edit::tls_callbacks(&doc.data, pe).map(|c| c.1).unwrap_or_default()));
            t.tls = Some((doc.rev, list));
        }
        let Some(callbacks) = t.tls.as_ref().and_then(|c| c.1.clone()) else {
            ui.weak("This file has no TLS directory, so callbacks cannot be attached.");
            return;
        };
        ui.label("Functions the loader calls before the entry point and on thread start and exit. Adding one moves the callback array to a new section and relocates it.");
        ui.add_space(4.0);
        let t = &mut self.tools.x.rel;
        let sel = t.tls_sel;
        let name = |va: u64| doc.parsed.symbol_at(va).map(str::to_string).unwrap_or_default();
        if let Some(i) =
            list_table(ui, "tls_callbacks", &[("#", 40.0), ("Address (VA)", 170.0), ("Symbol", 200.0)], callbacks.len(), sel, Some(160.0), |i, c| match c {
                0 => i.to_string(),
                1 => format!("{:X}", callbacks[i]),
                _ => name(callbacks[i]),
            })
        {
            t.tls_sel = Some(i);
        }
        if callbacks.is_empty() {
            ui.weak("No callbacks registered.");
        }
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("Address (VA):");
            ui.add(egui::TextEdit::singleline(&mut t.callback).font(TextStyle::Monospace).desired_width(170.0).hint_text("hex"));
            let va = crate::model::parse_number(&t.callback, 16).ok();
            if ui.add_enabled(va.is_some(), egui::Button::new("Add callback")).clicked()
                && let Some(v) = va
            {
                self.actions.push(Action::Op(Box::new(move |d| edit::add_tls_callback(d, v))));
            }
            if let Some(i) = t.tls_sel.filter(|i| *i < callbacks.len())
                && ui.button("Remove selected").clicked()
            {
                self.actions.push(Action::Op(Box::new(move |d| edit::remove_tls_callback(d, i))));
            }
            if let Some(i) = t.tls_sel.filter(|i| *i < callbacks.len())
                && ui.button("Disassemble").clicked()
            {
                self.actions.push(Action::Disasm(callbacks[i]));
            }
            if va.is_none() && !t.callback.trim().is_empty() {
                ui.weak("not a hex number");
            }
        });
    }

    // --- ELF sections ------------------------------------------------------------------

    pub fn elf_sections_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        let t = &mut self.tools.x.sec;
        if t.cache.as_ref().is_none_or(|c| c.0 != doc.rev) {
            t.cache = Some((doc.rev, Rc::new(elf_edit::sections(&doc.data))));
        }
        let Some(cached) = t.cache.as_ref().map(|c| c.1.clone()) else { return };
        let list = match &*cached {
            Ok(l) => l,
            Err(e) => {
                ui.weak(format!("The sections cannot be edited: {e}."));
                return;
            }
        };
        ui.label("Add a data section from a file, or remove a section that is not loaded at run time (debug information, comments, notes added earlier).");
        ui.weak("Added sections are appended to the file and are not mapped into memory. Loaded sections are protected from removal.");
        ui.add_space(6.0);
        let t = &mut self.tools.x.sec;
        if t.sel.is_some_and(|i| i >= list.len()) {
            t.sel = None;
        }
        let h = (ui.available_height() - 100.0).max(120.0);
        if let Some(i) = list_table(
            ui,
            "elf_sections",
            &[("#", 40.0), ("Name", 200.0), ("Offset", 100.0), ("Size", 100.0), ("Loaded", 80.0)],
            list.len(),
            t.sel,
            Some(h),
            |i, c| match c {
                0 => i.to_string(),
                1 => list[i].name.clone(),
                2 => format!("{:08X}", list[i].offset),
                3 => format!("{:X}", list[i].size),
                _ => if list[i].loaded { "yes" } else { "no" }.to_string(),
            },
        ) {
            t.sel = Some(i);
            self.hex.show_range(clamp_off(list[i].offset), clamp_off(list[i].size));
        }
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("New section:");
            ui.add(egui::TextEdit::singleline(&mut t.name).desired_width(140.0).hint_text(".name"));
            if ui
                .button(match &t.file {
                    Some(p) => p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                    None => "Choose content file...".to_string(),
                })
                .clicked()
            {
                t.file = rfd::FileDialog::new().set_title("Section content").pick_file().or(t.file.take());
            }
            let name = t.name.trim().to_string();
            if ui.add_enabled(!name.is_empty() && t.file.is_some(), egui::Button::new("Add section")).clicked()
                && let Some(path) = t.file.clone()
            {
                self.actions.push(Action::Op(Box::new(move |d| {
                    let content = std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                    elf_edit::add_section(d, &name, &content)
                })));
            }
        });
        ui.add_space(4.0);
        let sel = t.sel.filter(|i| *i > 0);
        ui.horizontal(|ui| {
            let removable = sel.is_some_and(|i| !list[i].loaded);
            if ui.add_enabled(removable, egui::Button::new("Remove selected")).clicked()
                && let Some(i) = sel
            {
                self.tools.x.sec.sel = None;
                self.actions.push(Action::Op(Box::new(move |d| elf_edit::remove_section(d, i))));
            }
            if ui.add_enabled(sel.is_some_and(|i| list[i].ty != 8), egui::Button::new("Dump selected...")).clicked()
                && let Some(i) = sel
            {
                let (o, n) = (clamp_off(list[i].offset), clamp_off(list[i].size));
                match doc.data.get(o..o.saturating_add(n)) {
                    Some(bytes) => {
                        if let Some(p) =
                            rfd::FileDialog::new().set_title("Dump section").set_file_name(format!("{}.bin", list[i].name.trim_start_matches('.'))).save_file()
                        {
                            match std::fs::write(&p, bytes) {
                                Ok(()) => self.ok(format!("Section written to {}", p.display())),
                                Err(e) => self.err(format!("Cannot write {}: {e}", p.display())),
                            }
                        }
                    }
                    None => self.err("The section data is outside the file"),
                }
            }
            if sel.is_some() && !removable {
                ui.weak("This section is loaded at run time and cannot be removed.");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Bookmark;

    #[test]
    fn the_bookmark_selection_follows_the_bookmark() {
        let mark = |off: usize| Bookmark { off, len: 4, note: format!("note {off:X}") };
        let mut list = vec![mark(0x86)];
        let mut ui = BookmarkUi { sel: Some((0x86, 4)), note: list[0].note.clone(), ..Default::default() };
        assert_eq!(ui.index(&list), Some(0));
        // A bookmark added in front moves the selected one down the sorted list.
        list.insert(0, mark(0x3c));
        let i = ui.index(&list).unwrap();
        assert_eq!((i, list[i].note.as_str()), (1, ui.note.as_str()), "the note field and the row are the same bookmark");
        // Deleting another one moves it back; deleting it clears the selection.
        list.remove(0);
        assert_eq!(ui.index(&list), Some(0));
        list.clear();
        assert_eq!(ui.index(&list), None);
        assert_eq!(ui.sel, None);
    }
}
