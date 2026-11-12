//! Interactive tool views: file info, address converter, disassembler,
//! strings, and the PE editors (sections, imports, rebuilder, resources).

use std::path::PathBuf;
use std::rc::Rc;

use eframe::egui;
use egui::{Align, Key, Layout, RichText, Sense, TextStyle, Ui};
use egui_extras::{Column, TableBuilder};

use crate::analysis::{self, Insn, StrHit};
use crate::app::{Action, App, Doc, char_width};
use crate::model::*;
use crate::pe::edit::{self, NewImport};
use crate::pe::resources::{self, ResDir, ResId, ResNode, Src};
use crate::theme;

const AUTO_HASH_LIMIT: usize = 64 << 20;

#[derive(Default)]
pub struct ToolState {
    hashes: Option<(u64, Vec<(String, String)>)>,
    conv: [String; 3],
    conv_info: String,
    conv_off: Option<usize>,
    dis: Dis,
    strs: Strs,
    sec: Option<SecDlg>,
    imp: Imp,
    rebuild: Rebuild,
    res: Res,
    pub x: crate::tools2::State,
}

#[derive(Default)]
struct Dis {
    addr: String,
    lines: Vec<Insn>,
    offs: Vec<usize>,
    /// What is drawn: instructions interleaved with symbol labels.
    rows: Vec<DisRow>,
    err: String,
    rev: u64,
    sel: Option<usize>,
    /// Addresses to return to after following a branch.
    back: Vec<u64>,
    funcs: Option<(u64, Rc<Vec<(u64, String)>>)>,
    func_filter: String,
}

enum DisRow {
    Label(String),
    Insn(usize),
}

#[derive(Default)]
struct Strs {
    min: usize,
    hits: Rc<Vec<StrHit>>,
    key: (u64, usize),
    filter: String,
    order: Option<(String, Rc<Vec<usize>>)>,
    sel: Option<usize>,
}

struct SecDlg {
    name: String,
    size: String,
    file: Option<PathBuf>,
    code: bool,
    idata: bool,
    r: bool,
    w: bool,
    x: bool,
}

#[derive(Default)]
struct Imp {
    dll: String,
    func: String,
    list: Vec<(String, Vec<NewImport>)>,
}

struct Rebuild {
    image: bool,
    headers: bool,
    checksum: bool,
    overlay: bool,
    sig: bool,
}

impl Default for Rebuild {
    fn default() -> Self {
        Rebuild { image: true, headers: false, checksum: true, overlay: false, sig: false }
    }
}

enum Preview {
    Text(String),
    /// The texture, and the image's own width and height before any scaling.
    Image(egui::TextureHandle, (u32, u32)),
}

#[derive(Default)]
struct Res {
    tree: Option<(u64, Rc<ResDir>)>,
    sel: Vec<usize>,
    preview: Option<(u64, Vec<usize>, Preview)>,
    add: Option<AddRes>,
}

struct AddRes {
    ty: String,
    name: String,
    lang: String,
    file: Option<PathBuf>,
}

impl ToolState {
    pub fn select_resource(&mut self, path: Vec<usize>) {
        self.res.sel = path;
    }

    /// Point the disassembler at an address; it runs when next shown.
    pub fn disasm_at(&mut self, va: u64) {
        if let Ok(old) = parse_number(&self.dis.addr, 16)
            && old != va
            && !self.dis.lines.is_empty()
        {
            self.dis.back.push(old);
        }
        self.dis.addr = format!("{va:X}");
        self.dis.rev = 0;
    }

    pub fn set_search(&mut self, q: &str) {
        self.x.set_search(q);
    }
}

fn hexdump(bytes: &[u8], limit: usize) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes[..bytes.len().min(limit)].chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02X}")).collect();
        out.push_str(&format!("{:08X}  {:<47}  {}\n", i * 16, hex.join(" "), printable(chunk)));
    }
    if bytes.len() > limit {
        out.push_str(&format!("... {} more bytes (use the hex panel to see everything)\n", bytes.len() - limit));
    }
    out
}

fn pick(title: &str) -> Option<PathBuf> {
    rfd::FileDialog::new().set_title(title).pick_file()
}

impl App {
    pub fn tool_ui(&mut self, ui: &mut Ui, doc: &Doc, tool: Tool, g: &Grid) {
        match tool {
            Tool::FileInfo => self.file_info_ui(ui, doc, g),
            Tool::HexEditor => self.hex_ui(ui, doc),
            Tool::AddressConverter => self.conv_ui(ui, doc),
            Tool::Disassembler => self.disasm_ui(ui, doc),
            Tool::Strings => self.strings_ui(ui, doc),
            Tool::PeSections => self.sections_ui(ui, doc, g),
            Tool::PeImportAdder => {
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    self.import_edit_ui(ui, doc);
                    ui.add_space(6.0);
                    ui.separator();
                    theme::caption(ui, "Add imports");
                    self.import_adder_ui(ui, doc)
                });
            }
            Tool::PeExports => self.exports_ui(ui, doc),
            Tool::DotnetIl => self.il_ui(ui, doc, g),
            Tool::MachoEdit => self.macho_edit_ui(ui, doc),
            Tool::ElfDynamic => self.elf_dynamic_ui(ui, doc),
            Tool::Compare => self.compare_ui(ui, doc),
            Tool::Search => self.search_ui(ui, doc),
            Tool::Bookmarks => self.bookmarks_ui(ui, doc),
            Tool::PeRelocs => self.relocs_ui(ui, doc),
            Tool::ElfSections => self.elf_sections_ui(ui, doc),
            Tool::PeRebuilder => self.rebuilder_ui(ui, doc),
            Tool::PeResources => self.resources_ui(ui, doc),
        }
    }

    fn file_info_ui(&mut self, ui: &mut Ui, doc: &Doc, g: &Grid) {
        let mut pairs = vec![("File".to_string(), doc.path.display().to_string()), ("Size".into(), size_text(doc.data.len() as u64))];
        pairs.extend(g.rows.iter().map(|r| (r[0].text.clone(), r[1].text.clone())));
        let cached = matches!(&self.tools.hashes, Some((rev, _)) if *rev == doc.rev);
        let mut compute = !cached && doc.data.len() <= AUTO_HASH_LIMIT;
        if !cached && !compute {
            compute = ui.button("Compute hashes and entropy (large file)").clicked();
        }
        if compute {
            let [md5, sha1, sha256] = analysis::hashes(&doc.data);
            self.tools.hashes = Some((
                doc.rev,
                vec![
                    ("MD5".into(), md5),
                    ("SHA-1".into(), sha1),
                    ("SHA-256".into(), sha256),
                    ("Entropy".into(), format!("{:.3} bits per byte", entropy(&doc.data))),
                ],
            ));
        }
        if let Some((rev, h)) = &self.tools.hashes
            && *rev == doc.rev
        {
            pairs.extend(h.iter().cloned());
        }
        self.grid_ui(ui, doc, &kv_grid(pairs));
    }

    fn conv_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        let p = &doc.parsed;
        let labels = ["Virtual Address (VA)", "Relative Virtual Address (RVA)", "File Offset"];
        let mut changed = None;
        egui::Grid::new("addr_conv").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            for (i, label) in labels.iter().enumerate() {
                ui.label(*label);
                let edit = egui::TextEdit::singleline(&mut self.tools.conv[i]).font(TextStyle::Monospace).desired_width(220.0).hint_text("hex");
                if ui.add(edit).changed() {
                    changed = Some(i);
                }
                ui.end_row();
            }
        });
        if let Some(i) = changed {
            let t = &mut self.tools;
            t.conv_off = None;
            match parse_number(&t.conv[i], 16) {
                Ok(v) => {
                    let (va, off, map) = match i {
                        0 | 1 => {
                            let va = if i == 0 { v } else { p.image_base.wrapping_add(v) };
                            let hit = p.va_to_offset(va);
                            (Some(va), hit.map(|h| h.0), hit.map(|h| h.1.name.clone()))
                        }
                        _ => {
                            let hit = p.offset_to_va(v);
                            (hit.map(|h| h.0), ((v as usize) < doc.data.len()).then_some(v), hit.map(|h| h.1.name.clone()))
                        }
                    };
                    let texts = [va.map(|a| format!("{a:X}")), va.map(|a| format!("{:X}", a.wrapping_sub(p.image_base))), off.map(|o| format!("{o:X}"))];
                    for (k, text) in texts.into_iter().enumerate() {
                        if k != i {
                            t.conv[k] = text.unwrap_or_default();
                        }
                    }
                    t.conv_off = off.map(|o| o as usize);
                    t.conv_info = match (map, off) {
                        (Some(m), Some(_)) => format!("Located in: {m}"),
                        (_, None) if i != 2 => "This address has no bytes in the file (not mapped, or uninitialized data)".into(),
                        _ => "This offset is not mapped into memory (headers, overlay or padding)".into(),
                    };
                }
                Err(e) => t.conv_info = e,
            }
        }
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.add_enabled(self.tools.conv_off.is_some(), egui::Button::new("Show in hex editor")).clicked()
                && let Some(o) = self.tools.conv_off
            {
                self.hex.cursor = Some(o);
                self.hex.show_range(o, 1);
            }
            ui.label(&self.tools.conv_info);
        });
        ui.separator();
        ui.label(format!("Image base: {:X}. Mapped regions:", p.image_base));
        let mut g = Grid::new(&["Name", "Virtual Address", "Virtual Size", "File Offset", "File Size", "Executable"]);
        for m in &p.maps {
            g.push(
                vec![
                    Cell::text(m.name.clone()),
                    Cell::text(format!("{:X}", m.vaddr)),
                    Cell::text(format!("{:X}", m.vsize)),
                    Cell::text(format!("{:X}", m.offset)),
                    Cell::text(format!("{:X}", m.fsize)),
                    Cell::text(if m.exec { "yes" } else { "" }),
                ],
                Some((m.offset as usize, m.fsize as usize)),
            );
        }
        self.grid_ui(ui, doc, &g);
    }

    fn run_disasm(&mut self, doc: &Doc, append: bool) {
        let d = &mut self.tools.dis;
        d.rev = doc.rev;
        d.err.clear();
        let start = if append {
            d.lines.last().map(|l| l.addr + l.len as u64)
        } else {
            d.lines.clear();
            d.offs.clear();
            d.rows.clear();
            d.sel = None;
            parse_number(&d.addr, 16).ok()
        };
        let Some(va) = start else {
            d.err = "Enter a virtual address in hex".into();
            return;
        };
        let Some((off, map)) = doc.parsed.va_to_offset(va) else {
            d.err = format!("Address {va:X} is not backed by file data");
            return;
        };
        let end = ((map.offset + map.fsize) as usize).min(doc.data.len()).min(off as usize + 0x10000);
        match analysis::disasm(&doc.data[off as usize..end], doc.parsed.arch, va, 2000) {
            Ok(mut insns) => {
                if insns.is_empty() {
                    d.err = format!("No valid instruction at {va:X}");
                }
                analysis::annotate(&mut insns, &doc.parsed, &doc.data);
                for i in insns {
                    // A label line in front of every named address and function start.
                    if let Some(name) = doc.parsed.symbol_at(i.addr) {
                        d.rows.push(DisRow::Label(format!("{name}:")));
                    } else if doc.parsed.function_of(i.addr).is_some_and(|f| f.0 == i.addr) {
                        d.rows.push(DisRow::Label(format!("sub_{:X}:", i.addr)));
                    }
                    d.rows.push(DisRow::Insn(d.lines.len()));
                    d.offs.push((off + (i.addr - va)) as usize);
                    d.lines.push(i);
                }
            }
            Err(e) => d.err = e,
        }
    }

    fn disasm_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        let p = &doc.parsed;
        let default_addr = p.entry.or_else(|| p.maps.iter().find(|m| m.exec).map(|m| m.vaddr));
        if self.tools.dis.addr.is_empty()
            && let Some(a) = default_addr
        {
            self.tools.dis.addr = format!("{a:X}");
        }
        let mut run = self.tools.dis.rev != doc.rev;
        let mut more = false;
        let mut jump: Option<u64> = None;
        ui.horizontal(|ui| {
            ui.label("Address (VA):");
            let r = ui.add(egui::TextEdit::singleline(&mut self.tools.dis.addr).font(TextStyle::Monospace).desired_width(160.0));
            run |= r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
            run |= ui.button("Disassemble").clicked();
            if let Some(e) = p.entry
                && ui.button("Entry point").clicked()
            {
                self.tools.dis.addr = format!("{e:X}");
                run = true;
            }
            egui::ComboBox::from_id_salt("dis_regions").selected_text("Code sections").show_ui(ui, |ui| {
                for m in p.maps.iter().filter(|m| m.exec) {
                    if ui.selectable_label(false, format!("{}  {:X}", m.name, m.vaddr)).clicked() {
                        self.tools.dis.addr = format!("{:X}", m.vaddr);
                        run = true;
                    }
                }
            });
            // Named addresses in code, plus unnamed functions the format records.
            if self.tools.dis.funcs.as_ref().is_none_or(|f| f.0 != doc.rev) {
                let in_code = |va: u64| p.maps.iter().any(|m| m.exec && va >= m.vaddr && va - m.vaddr < m.vsize.max(m.fsize));
                let mut list: Vec<(u64, String)> = p.symbols.iter().filter(|s| in_code(s.0)).cloned().collect();
                list.extend(p.functions.iter().filter(|f| p.symbol_at(f.0).is_none()).map(|f| (f.0, format!("sub_{:X}", f.0))));
                list.sort();
                self.tools.dis.funcs = Some((doc.rev, Rc::new(list)));
            }
            let funcs = self.tools.dis.funcs.as_ref().map(|f| f.1.clone()).unwrap_or_default();
            ui.menu_button(format!("Functions ({})", funcs.len()), |ui| {
                ui.set_min_width(360.0);
                ui.add(egui::TextEdit::singleline(&mut self.tools.dis.func_filter).desired_width(f32::INFINITY).hint_text("Filter by name or address"));
                let needle = self.tools.dis.func_filter.to_lowercase();
                let shown: Vec<&(u64, String)> = funcs
                    .iter()
                    .filter(|f| needle.is_empty() || f.1.to_lowercase().contains(&needle) || format!("{:x}", f.0).contains(&needle))
                    .take(2000)
                    .collect();
                let h = ui.spacing().interact_size.y;
                egui::ScrollArea::vertical().max_height(360.0).show_rows(ui, h, shown.len(), |ui, range| {
                    for f in &shown[range] {
                        if ui.selectable_label(false, RichText::new(format!("{:X}  {}", f.0, f.1)).monospace()).clicked() {
                            jump = Some(f.0);
                            ui.close();
                        }
                    }
                });
            });
            if ui
                .add_enabled(!self.tools.dis.back.is_empty(), egui::Button::new("Return"))
                .on_hover_text("Back to where the last followed branch came from")
                .clicked()
                && let Some(a) = self.tools.dis.back.pop()
            {
                self.tools.dis.addr = format!("{a:X}");
                run = true;
            }
            more = ui.add_enabled(!self.tools.dis.lines.is_empty(), egui::Button::new("Continue")).clicked();
            ui.weak(format!("{:?}, {} instructions", p.arch, self.tools.dis.lines.len()));
        });
        if run {
            self.run_disasm(doc, false);
        } else if more {
            self.run_disasm(doc, true);
        }
        if !self.tools.dis.err.is_empty() {
            ui.colored_label(ui.visuals().error_fg_color, &self.tools.dis.err);
        }
        ui.separator();
        let row_h = ui.spacing().interact_size.y;
        let width = if p.maps.iter().any(|m| m.vaddr > u32::MAX as u64) { 16 } else { 8 };
        let mut pick = None;
        let mut follow = None;
        let label_color = theme::accent(ui);
        let comment_color = ui.visuals().weak_text_color();
        ui.weak("Double-click a call or jump to follow it; Return goes back.");
        egui::ScrollArea::both().auto_shrink([false, false]).show_rows(ui, row_h, self.tools.dis.rows.len(), |ui, range| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
            for r in range {
                let i = match &self.tools.dis.rows[r] {
                    DisRow::Label(name) => {
                        ui.label(RichText::new(name).monospace().strong().color(label_color));
                        continue;
                    }
                    DisRow::Insn(i) => *i,
                };
                let l = &self.tools.dis.lines[i];
                ui.horizontal(|ui| {
                    let text = format!("{:0width$X}  {:<24} {}", l.addr, l.bytes, l.text);
                    let resp = ui.selectable_label(self.tools.dis.sel == Some(i), RichText::new(text).monospace());
                    if resp.clicked() {
                        pick = Some(i);
                    }
                    if resp.double_clicked() {
                        follow = l.target;
                    }
                    if let Some(t) = l.target
                        && l.comment.is_empty()
                    {
                        ui.label(RichText::new(format!("; -> {t:X}")).monospace().color(comment_color));
                    } else if !l.comment.is_empty() {
                        ui.label(RichText::new(format!("; {}", l.comment)).monospace().color(comment_color));
                    }
                });
            }
        });
        if let Some(i) = pick {
            self.tools.dis.sel = Some(i);
            self.hex.show_range(self.tools.dis.offs[i], self.tools.dis.lines[i].len);
        }
        if let Some(t) = follow.or(jump) {
            self.tools.disasm_at(t);
        }
    }

    fn strings_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        let s = &mut self.tools.strs;
        if s.min == 0 {
            s.min = self.settings.strings_min;
        }
        ui.horizontal(|ui| {
            ui.label("Minimum length:");
            ui.add(egui::DragValue::new(&mut s.min).range(2..=64));
            ui.separator();
            ui.label("Filter:");
            ui.add(egui::TextEdit::singleline(&mut s.filter).desired_width(240.0));
        });
        if s.key != (doc.rev, s.min) {
            s.hits = Rc::new(analysis::strings(&doc.data, s.min));
            s.key = (doc.rev, s.min);
            s.order = None;
            s.sel = None;
        }
        let hits = s.hits.clone();
        let order: Option<Rc<Vec<usize>>> = if s.filter.is_empty() {
            None
        } else {
            if !matches!(&s.order, Some((f, _)) if *f == s.filter) {
                let needle = s.filter.to_lowercase();
                let v: Vec<usize> = (0..hits.len()).filter(|i| hits[*i].text.to_lowercase().contains(&needle)).collect();
                s.order = Some((s.filter.clone(), Rc::new(v)));
            }
            s.order.as_ref().map(|o| o.1.clone())
        };
        let n = order.as_ref().map_or(hits.len(), |o| o.len());
        ui.weak(format!("{n} of {} strings (ASCII and UTF-16LE)", hits.len()));
        let cw = char_width(ui);
        let row_h = ui.text_style_height(&TextStyle::Monospace) + 4.0;
        let mut pick = None;
        let sel = s.sel;
        TableBuilder::new(ui)
            .striped(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .auto_shrink([false, false])
            .column(Column::initial(cw * 10.0))
            .column(Column::initial(cw * 8.0))
            .column(Column::remainder().clip(true))
            .header(row_h + 2.0, |mut h| {
                for c in ["Offset", "Type", "String"] {
                    h.col(|ui| {
                        ui.strong(c);
                    });
                }
            })
            .body(|body| {
                body.rows(row_h, n, |mut row| {
                    let i = order.as_ref().map_or(row.index(), |o| o[row.index()]);
                    let hit = &hits[i];
                    row.set_selected(sel == Some(i));
                    let mut cell = |text: &str| {
                        let (_, r) = row.col(|ui| {
                            ui.add(egui::Label::new(RichText::new(text).monospace()).selectable(false).truncate());
                        });
                        r.context_menu(|ui| {
                            if ui.button("Copy string").clicked() {
                                ui.ctx().copy_text(hit.text.clone());
                                ui.close();
                            }
                        });
                        r.clicked()
                    };
                    let a = cell(&format!("{:08X}", hit.offset));
                    let b = cell(if hit.wide { "UTF-16" } else { "ASCII" });
                    let c = cell(&hit.text);
                    if a || b || c || row.response().clicked() {
                        pick = Some(i);
                    }
                });
            });
        if let Some(i) = pick {
            self.tools.strs.sel = Some(i);
            let h = &hits[i];
            self.hex.show_range(h.offset, h.text.len() * if h.wide { 2 } else { 1 });
        }
    }

    // -----------------------------------------------------------------------
    // PE editors

    fn sections_ui(&mut self, ui: &mut Ui, doc: &Doc, g: &Grid) {
        let selected = self.row.filter(|r| *r < g.rows.len());
        ui.horizontal(|ui| {
            let new_dlg = |file| SecDlg { name: ".new".into(), size: "1000".into(), file, code: false, idata: true, r: true, w: false, x: false };
            if ui.button("Add Section (Empty Space)...").clicked() {
                self.tools.sec = Some(new_dlg(None));
            }
            if ui.button("Add Section (File Data)...").clicked()
                && let Some(p) = pick("Choose the file to place in the new section")
            {
                self.tools.sec = Some(new_dlg(Some(p)));
            }
            if ui.add_enabled(selected.is_some(), egui::Button::new("Delete Section")).clicked()
                && let Some(i) = selected
            {
                self.actions.push(Action::Op(Box::new(move |d| edit::delete_section(d, i))));
            }
            if ui.add_enabled(selected.is_some(), egui::Button::new("Dump Section...")).clicked()
                && let (Some(i), Some(pe)) = (selected, &doc.pe)
            {
                let s = &pe.sections[i];
                let bytes = Rd::new(&doc.data, Endian::Little).bytes(s.roff as usize, s.rsize as usize);
                let name = format!("{}_{}.bin", doc.name(), s.name.trim_start_matches('.'));
                if let Some(p) = rfd::FileDialog::new().set_title("Dump section").set_file_name(name).save_file() {
                    match std::fs::write(&p, bytes) {
                        Ok(()) => self.ok(format!("Section {} dumped to {} ({} bytes)", s.name, p.display(), bytes.len())),
                        Err(e) => self.err(format!("Cannot write {}: {e}", p.display())),
                    }
                }
            }
        });
        ui.weak("Double-click a value to edit it. Select a row to edit its characteristics below.");
        ui.separator();

        let mut close = false;
        if let Some(dlg) = &mut self.tools.sec {
            let mut open = true;
            let mut apply = false;
            egui::Window::new("Add Section").open(&mut open).collapsible(false).resizable(false).show(ui.ctx(), |ui| {
                egui::Grid::new("add_section").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                    ui.label("Name (max 8 chars)");
                    ui.add(egui::TextEdit::singleline(&mut dlg.name).char_limit(8).desired_width(120.0));
                    ui.end_row();
                    match &dlg.file {
                        Some(p) => {
                            ui.label("Data from file");
                            ui.label(p.display().to_string());
                        }
                        None => {
                            ui.label("Size in bytes (hex)");
                            ui.add(egui::TextEdit::singleline(&mut dlg.size).desired_width(120.0));
                        }
                    }
                    ui.end_row();
                });
                ui.horizontal_wrapped(|ui| {
                    ui.checkbox(&mut dlg.code, "Code");
                    ui.checkbox(&mut dlg.idata, "Initialized data");
                    ui.checkbox(&mut dlg.r, "Readable");
                    ui.checkbox(&mut dlg.w, "Writable");
                    ui.checkbox(&mut dlg.x, "Executable");
                });
                ui.add_space(6.0);
                apply = ui.button("Add section").clicked();
            });
            if apply {
                let mut chars = 0u32;
                for (on, bit) in [(dlg.code, 0x20u32), (dlg.idata, 0x40), (dlg.x, 0x2000_0000), (dlg.r, 0x4000_0000), (dlg.w, 0x8000_0000)] {
                    if on {
                        chars |= bit;
                    }
                }
                let content = match &dlg.file {
                    Some(p) => std::fs::read(p).map_err(|e| format!("Cannot read {}: {e}", p.display())),
                    None => parse_number(&dlg.size, 16)
                        .and_then(|n| if n == 0 || n > 0x4000_0000 { Err("size must be between 1 and 40000000".into()) } else { Ok(vec![0u8; n as usize]) }),
                };
                match content {
                    Ok(content) => {
                        let name = dlg.name.clone();
                        self.actions.push(Action::Op(Box::new(move |d| {
                            let va = edit::add_section(d, &name, &content, content.len() as u32, chars)?;
                            Ok(format!("Section {name} added at RVA {va:08X} ({} bytes)", content.len()))
                        })));
                        close = true;
                    }
                    Err(e) => {
                        self.status = e;
                        self.status_err = true;
                    }
                }
            }
            close |= !open;
        }
        if close {
            self.tools.sec = None;
        }
        self.grid_ui(ui, doc, g);
    }

    fn import_adder_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        let t = &mut self.tools.imp;
        ui.label("Add imports to the file. The import directory is rebuilt in a new section; existing imports keep their thunks, so code that uses them is not affected.");
        ui.add_space(6.0);
        let mut add = false;
        ui.horizontal(|ui| {
            ui.label("Module:");
            ui.add(egui::TextEdit::singleline(&mut t.dll).desired_width(180.0).hint_text("example.dll"));
            ui.label("Function:");
            let r = ui.add(egui::TextEdit::singleline(&mut t.func).desired_width(220.0).hint_text("name, or #ordinal"));
            add = ui.button("Add to list").clicked() || (r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)));
        });
        if add {
            let dll = t.dll.trim().to_string();
            let func = t.func.trim().to_string();
            let item = match func.strip_prefix('#') {
                Some(o) => o.trim().parse::<u16>().map(NewImport::Ordinal).map_err(|_| "ordinal must be a number from 0 to 65535".to_string()),
                None if func.is_empty() => Err("enter a function name or #ordinal".into()),
                None => Ok(NewImport::Name(func)),
            };
            match item {
                Ok(_) if dll.is_empty() => {
                    self.status = "Enter a module name".into();
                    self.status_err = true;
                }
                Ok(item) => {
                    match t.list.iter_mut().find(|(d, _)| d.eq_ignore_ascii_case(&dll)) {
                        Some((_, funcs)) => {
                            if !funcs.contains(&item) {
                                funcs.push(item);
                            }
                        }
                        None => t.list.push((dll, vec![item])),
                    }
                    t.func.clear();
                }
                Err(e) => {
                    self.status = e;
                    self.status_err = true;
                }
            }
        }
        ui.separator();
        let t = &mut self.tools.imp;
        if t.list.is_empty() {
            ui.weak("No pending imports.");
        }
        let mut remove = None;
        egui::ScrollArea::vertical().id_salt("pending_imports").max_height(160.0).show(ui, |ui| {
            for (mi, (dll, funcs)) in t.list.iter().enumerate() {
                ui.strong(dll);
                for (fi, f) in funcs.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.add_space(18.0);
                        if ui.small_button("Remove").clicked() {
                            remove = Some((mi, fi));
                        }
                        ui.monospace(match f {
                            NewImport::Name(n) => n.clone(),
                            NewImport::Ordinal(o) => format!("Ordinal {o}"),
                        });
                    });
                }
            }
        });
        if let Some((mi, fi)) = remove {
            t.list[mi].1.remove(fi);
            if t.list[mi].1.is_empty() {
                t.list.remove(mi);
            }
        }
        ui.separator();
        ui.horizontal(|ui| {
            if ui.add_enabled(!t.list.is_empty() && doc.pe.is_some(), egui::Button::new("Rebuild Import Table")).clicked() {
                let list = std::mem::take(&mut t.list);
                self.actions.push(Action::Op(Box::new(move |d| edit::add_imports(d, &list))));
            }
            if ui.add_enabled(!t.list.is_empty(), egui::Button::new("Clear list")).clicked() {
                t.list.clear();
            }
        });
    }

    fn rebuilder_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        let r = &mut self.tools.rebuild;
        ui.label("Fix up header values after editing, or strip data appended to the image.");
        ui.add_space(6.0);
        ui.checkbox(&mut r.image, "Update SizeOfImage from the section table");
        ui.checkbox(&mut r.headers, "Update SizeOfHeaders");
        ui.checkbox(&mut r.overlay, "Remove overlay (data after the last section, including any signature)");
        ui.checkbox(&mut r.sig, "Remove Authenticode signature");
        ui.checkbox(&mut r.checksum, "Recompute PE header CheckSum");
        ui.add_space(8.0);
        if ui.add_enabled(doc.pe.is_some(), egui::Button::new("Rebuild")).clicked() {
            let (image, headers, overlay, sig, checksum) = (r.image, r.headers, r.overlay, r.sig, r.checksum);
            self.actions.push(Action::Op(Box::new(move |d| {
                let mut log = Vec::new();
                if sig {
                    log.push(edit::remove_signature(d)?);
                }
                if overlay {
                    log.push(edit::remove_overlay(d)?);
                }
                if image {
                    log.push(edit::fix_size_of_image(d)?);
                }
                if headers {
                    log.push(edit::fix_size_of_headers(d)?);
                }
                if checksum {
                    log.push(edit::fix_checksum(d)?);
                }
                Ok(if log.is_empty() { "Nothing selected".into() } else { log.join("; ") })
            })));
        }
    }

    fn build_preview(ctx: &egui::Context, data: &[u8], root: &ResDir, path: &[usize]) -> Preview {
        let Some(leaf) = resources::leaf(root, path) else {
            return Preview::Text(String::new());
        };
        let bytes = leaf.bytes(data);
        let ty = path.first().and_then(|i| root.entries.get(*i)).map(|e| e.id.clone());
        let name_id = match (path.first().and_then(|i| root.entries.get(*i)).map(|e| &e.node), path.get(1)) {
            (Some(ResNode::Dir(d)), Some(i)) => d.entries.get(*i).map(|e| e.id.clone()),
            _ => None,
        };
        let image = |bytes: &[u8], icon: bool| {
            resources::decode_image(bytes, icon, ctx.input(|i| i.max_texture_side)).map(|(w, h, rgba, original)| {
                let img = egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba);
                Preview::Image(ctx.load_texture("resource_preview", img, egui::TextureOptions::NEAREST), original)
            })
        };
        let fallback = || {
            let sample = &bytes[..bytes.len().min(512)];
            let texty = !sample.is_empty() && sample.iter().filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace()).count() * 100 >= sample.len() * 95;
            if texty { Preview::Text(String::from_utf8_lossy(&bytes[..bytes.len().min(1 << 20)]).into_owned()) } else { Preview::Text(hexdump(bytes, 8192)) }
        };
        match ty {
            Some(ResId::Id(3)) => image(bytes, true).unwrap_or_else(fallback),
            Some(ResId::Id(1)) => image(bytes.get(4..).unwrap_or(&[]), true).unwrap_or_else(fallback),
            Some(ResId::Id(2)) => image(bytes, false).unwrap_or_else(fallback),
            Some(ResId::Id(16)) => Preview::Text(resources::version_info(bytes)),
            Some(ResId::Id(6)) => Preview::Text(resources::string_table(
                bytes,
                match name_id {
                    Some(ResId::Id(v)) => v,
                    _ => 1,
                },
            )),
            Some(ResId::Id(12 | 14)) => Preview::Text(resources::group_icon(bytes)),
            Some(ResId::Id(23 | 24)) => Preview::Text(String::from_utf8_lossy(bytes).into_owned()),
            _ if bytes.starts_with(b"\x89PNG") => image(bytes, false).unwrap_or_else(fallback),
            _ => fallback(),
        }
    }

    fn resources_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        let Some(pe) = &doc.pe else { return };
        if !matches!(&self.tools.res.tree, Some((rev, _)) if *rev == doc.rev) {
            let tree = resources::parse(&doc.data, pe).unwrap_or_default();
            self.tools.res.tree = Some((doc.rev, Rc::new(tree)));
            self.tools.res.preview = None;
        }
        let Some(root) = self.tools.res.tree.as_ref().map(|t| t.1.clone()) else { return };
        let sel = self.tools.res.sel.clone();
        let leaf = resources::leaf(&root, &sel);

        ui.horizontal(|ui| {
            if ui.button("Add Resource...").clicked() {
                self.tools.res.add = Some(AddRes { ty: "10".into(), name: "1".into(), lang: "1033".into(), file: None });
            }
            if ui.add_enabled(leaf.is_some(), egui::Button::new("Replace...")).clicked()
                && let Some(p) = pick("Choose the replacement data")
            {
                match std::fs::read(&p) {
                    Ok(bytes) => {
                        let mut tree = (*root).clone();
                        if let Some(l) = resources::leaf_mut(&mut tree, &sel) {
                            l.src = Src::Mem(bytes);
                        }
                        self.actions.push(Action::Op(Box::new(move |d| resources::apply(d, &tree))));
                    }
                    Err(e) => self.err(format!("Cannot read {}: {e}", p.display())),
                }
            }
            if ui.add_enabled(leaf.is_some(), egui::Button::new("Save Resource As...")).clicked()
                && let Some(l) = leaf
                && let Some(p) = rfd::FileDialog::new().set_title("Save resource").set_file_name("resource.bin").save_file()
            {
                match std::fs::write(&p, l.bytes(&doc.data)) {
                    Ok(()) => self.ok(format!("Resource saved to {}", p.display())),
                    Err(e) => self.err(format!("Cannot write {}: {e}", p.display())),
                }
            }
            if ui.add_enabled(leaf.is_some(), egui::Button::new("Delete")).clicked() {
                let mut tree = (*root).clone();
                if resources::remove(&mut tree, &sel) {
                    self.tools.res.sel.clear();
                    self.actions.push(Action::Op(Box::new(move |d| resources::apply(d, &tree))));
                }
            }
        });
        ui.separator();

        // Add dialog
        let mut close = false;
        if let Some(dlg) = &mut self.tools.res.add {
            let mut open = true;
            let mut apply = false;
            egui::Window::new("Add Resource").open(&mut open).collapsible(false).resizable(false).show(ui.ctx(), |ui| {
                egui::Grid::new("add_resource").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                    ui.label("Type (number or name)");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut dlg.ty).desired_width(120.0));
                        egui::ComboBox::from_id_salt("res_type_pick").selected_text("Standard types").show_ui(ui, |ui| {
                            for (id, name) in crate::pe::consts::RES_TYPES {
                                if ui.selectable_label(false, format!("{name} ({id})")).clicked() {
                                    dlg.ty = id.to_string();
                                }
                            }
                        });
                    });
                    ui.end_row();
                    ui.label("Name (number or name)");
                    ui.add(egui::TextEdit::singleline(&mut dlg.name).desired_width(120.0));
                    ui.end_row();
                    ui.label("Language id");
                    ui.add(egui::TextEdit::singleline(&mut dlg.lang).desired_width(120.0));
                    ui.end_row();
                    ui.label("Data file");
                    ui.horizontal(|ui| {
                        if ui.button("Choose...").clicked()
                            && let Some(p) = pick("Choose the resource data")
                        {
                            dlg.file = Some(p);
                        }
                        ui.label(dlg.file.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "none".into()));
                    });
                    ui.end_row();
                });
                ui.add_space(6.0);
                apply = ui.add_enabled(dlg.file.is_some(), egui::Button::new("Add resource")).clicked();
            });
            if apply {
                let lang = dlg.lang.trim().parse::<u32>().ok().filter(|v| *v <= 0xFFFF);
                let bytes = dlg.file.as_ref().map(std::fs::read);
                match (lang, bytes) {
                    (Some(lang), Some(Ok(bytes))) if !dlg.ty.trim().is_empty() && !dlg.name.trim().is_empty() => {
                        let mut tree = (*root).clone();
                        resources::insert(&mut tree, &ResId::parse(&dlg.ty), &ResId::parse(&dlg.name), &ResId::Id(lang), bytes);
                        self.actions.push(Action::Op(Box::new(move |d| resources::apply(d, &tree))));
                        close = true;
                    }
                    (None, _) => {
                        self.status = "Language id must be a number from 0 to 65535".into();
                        self.status_err = true;
                    }
                    (_, Some(Err(e))) => {
                        self.status = format!("Cannot read the data file: {e}");
                        self.status_err = true;
                    }
                    _ => {
                        self.status = "Type and name are required".into();
                        self.status_err = true;
                    }
                }
            }
            close |= !open;
        }
        if close {
            self.tools.res.add = None;
        }

        // Resource tree
        let mut pick_path: Option<Vec<usize>> = None;
        egui::Panel::left("res_tree").resizable(true).default_size(260.0).show(ui, |ui| {
            egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                if root.entries.is_empty() {
                    ui.weak("This file has no resources.");
                }
                for (ti, t) in root.entries.iter().enumerate() {
                    match &t.node {
                        ResNode::Data(_) => {
                            if ui.selectable_label(sel == [ti], t.id.type_label()).clicked() {
                                pick_path = Some(vec![ti]);
                            }
                        }
                        ResNode::Dir(names) => {
                            egui::CollapsingHeader::new(format!("{} [{}]", t.id.type_label(), names.entries.len())).id_salt(("res_type", ti)).show(ui, |ui| {
                                for (ni, n) in names.entries.iter().enumerate() {
                                    match &n.node {
                                        ResNode::Data(_) => {
                                            if ui.selectable_label(sel == [ti, ni], n.id.label()).clicked() {
                                                pick_path = Some(vec![ti, ni]);
                                            }
                                        }
                                        ResNode::Dir(langs) => {
                                            for (li, l) in langs.entries.iter().enumerate() {
                                                let label = format!("{}  (lang {})", n.id.label(), l.id.label());
                                                if ui.selectable_label(sel == [ti, ni, li], label).clicked() {
                                                    pick_path = Some(vec![ti, ni, li]);
                                                }
                                            }
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            });
        });
        if let Some(p) = pick_path {
            if let Some(ResData { src: Src::File { off, size }, .. }) = resources::leaf(&root, &p).cloned() {
                self.hex.show_range(off, size);
            }
            self.tools.res.sel = p;
        }

        // Preview
        egui::CentralPanel::default().show(ui, |ui| {
            let Some(l) = leaf else {
                ui.weak("Select a resource to preview it.");
                return;
            };
            let place = match &l.src {
                Src::File { off, .. } => format!("RVA {:08X}, file offset {off:08X}", l.rva),
                Src::Mem(_) => "pending".into(),
            };
            ui.monospace(format!("{} bytes, {place}, code page {}", l.len(), l.codepage));
            ui.separator();
            if !matches!(&self.tools.res.preview, Some((rev, p, _)) if *rev == doc.rev && *p == sel) {
                let pv = Self::build_preview(ui.ctx(), &doc.data, &root, &sel);
                self.tools.res.preview = Some((doc.rev, sel.clone(), pv));
            }
            egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| match self.tools.res.preview.as_ref().map(|p| &p.2) {
                Some(Preview::Text(t)) => {
                    ui.add(egui::Label::new(RichText::new(t).monospace()).selectable(true).extend());
                }
                Some(Preview::Image(tex, (w, h))) => {
                    let size = tex.size_vec2();
                    let scale = (192.0 / size.x.max(size.y)).clamp(1.0, 4.0).floor();
                    if [*w as usize, *h as usize] == tex.size() {
                        ui.label(format!("{w} x {h} pixels (shown at {scale}x)"));
                    } else {
                        ui.label(format!("{w} x {h} pixels (scaled down to {} x {} to fit)", size.x, size.y));
                    }
                    ui.add(egui::Image::from_texture(egui::load::SizedTexture::new(tex.id(), size * scale)));
                }
                None => {}
            });
        });
    }
}

use crate::pe::resources::ResData;
