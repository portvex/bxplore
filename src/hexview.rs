//! Hex editor: virtualized view of the whole file with in place editing,
//! go to offset and search.

use eframe::egui;
use egui::{Align2, Key, Rect, Sense, TextStyle, Ui, pos2, vec2};

use crate::app::{Action, App, Doc, char_width};
use crate::model::{parse_hex_bytes, parse_number};

pub struct HexState {
    pub cursor: Option<usize>,
    /// The next typed digit replaces the low nibble.
    low: bool,
    /// Keyboard input goes to the hex view.
    active: bool,
    pub highlight: Option<(usize, usize)>,
    jump: Option<usize>,
    goto: String,
    find: String,
    find_text: bool,
    pub show: bool,
    visible: (usize, usize),
}

impl Default for HexState {
    fn default() -> Self {
        HexState {
            cursor: None,
            low: false,
            active: false,
            highlight: None,
            jump: None,
            goto: String::new(),
            find: String::new(),
            find_text: false,
            show: true,
            visible: (0, 0),
        }
    }
}

impl HexState {
    /// Highlight a file range and scroll it into view.
    pub fn show_range(&mut self, off: usize, len: usize) {
        // Callers pass offsets and sizes read from the file; `off + len` must not overflow.
        self.highlight = Some((off, len.min(usize::MAX - off).max(1)));
        self.jump = Some(off);
    }
}

impl App {
    pub fn hex_ui(&mut self, ui: &mut Ui, doc: &Doc) {
        let data = &doc.data;
        // A range set from header fields can reach past the end of the file.
        if let Some((o, l)) = &mut self.hex.highlight {
            *l = (*l).min(data.len().saturating_sub(*o)).max(1);
        }
        let area = ui.max_rect();
        let enter = ui.input(|i| i.key_pressed(Key::Enter));

        ui.horizontal(|ui| {
            ui.label("Go to offset:");
            let r = ui.add(egui::TextEdit::singleline(&mut self.hex.goto).desired_width(90.0).font(TextStyle::Monospace).hint_text("hex"));
            if r.lost_focus() && enter {
                match parse_number(&self.hex.goto, 16) {
                    Ok(v) if (v as usize) < data.len() => {
                        self.hex.cursor = Some(v as usize);
                        self.hex.low = false;
                        self.hex.active = true;
                        self.hex.show_range(v as usize, 1);
                    }
                    Ok(_) => self.err("Offset is beyond the end of the file"),
                    Err(e) => self.err(e),
                }
            }
            ui.separator();
            ui.label("Find:");
            let r = ui.add(egui::TextEdit::singleline(&mut self.hex.find).desired_width(170.0).font(TextStyle::Monospace));
            ui.selectable_value(&mut self.hex.find_text, false, "Hex");
            ui.selectable_value(&mut self.hex.find_text, true, "Text");
            if ui.button("Next").clicked() || (r.lost_focus() && enter) {
                let needle = if self.hex.find_text { Ok(self.hex.find.as_bytes().to_vec()) } else { parse_hex_bytes(&self.hex.find) };
                match needle {
                    Ok(n) if !n.is_empty() => {
                        let from = self.hex.cursor.map_or(0, |c| c + 1).min(data.len());
                        let hit = find(&data[from..], &n).map(|p| p + from).or_else(|| find(&data[..from], &n));
                        match hit {
                            Some(p) => {
                                self.hex.cursor = Some(p);
                                self.hex.low = false;
                                self.hex.show_range(p, n.len());
                                self.ok(format!("Found at offset {p:08X}"));
                            }
                            None => self.err("Pattern not found"),
                        }
                    }
                    Ok(_) => {}
                    Err(e) => self.err(e),
                }
            }
            ui.separator();
            if let Some(c) = self.hex.cursor {
                if ui.button("Structure").on_hover_text("Go to the structure that covers the cursor").clicked() {
                    self.actions.push(crate::app::Action::GotoOffset(c));
                }
                if ui.button("Bookmark").on_hover_text("Bookmark the highlighted range, or the byte under the cursor").clicked() {
                    let (off, len) = self.hex.highlight.filter(|(o, l)| c >= *o && c < o.saturating_add(*l)).unwrap_or((c, 1));
                    self.actions.push(crate::app::Action::Bookmark { off, len });
                }
                let mut text = format!("Offset {c:08X}");
                if let Some((va, m)) = doc.parsed.offset_to_va(c as u64) {
                    text.push_str(&format!("  VA {va:X}  [{}]", m.name));
                }
                ui.monospace(text);
            } else {
                ui.weak("Click a byte and type hex digits to edit");
            }
        });
        ui.separator();

        let font = TextStyle::Monospace.resolve(ui.style());
        let cw = char_width(ui);
        let row_h = ui.text_style_height(&TextStyle::Monospace) + 2.0;
        let step = row_h + ui.spacing().item_spacing.y;
        let total_rows = data.len().div_ceil(16).max(1);
        let mut scroll = egui::ScrollArea::vertical().id_salt("hex_scroll").auto_shrink([false, false]);
        if let Some(j) = self.hex.jump.take() {
            let row = j / 16;
            let (first, last) = self.hex.visible;
            if row < first || row + 2 > last {
                scroll = scroll.vertical_scroll_offset(row.saturating_sub(2) as f32 * step);
            }
        }

        let visuals = ui.visuals().clone();
        let weak = visuals.weak_text_color();
        let hl = visuals.selection.bg_fill.gamma_multiply(0.45);
        let cursor_fill = visuals.selection.bg_fill;
        let (hl_start, hl_end) = self.hex.highlight.map_or((0, 0), |(o, l)| (o, o.saturating_add(l)));
        let cursor = self.hex.cursor;
        let low = self.hex.low;
        let mut clicked: Option<usize> = None;
        let mut visible = self.hex.visible;

        scroll.show_rows(ui, row_h, total_rows, |ui, range| {
            visible = (range.start, range.end);
            let width = (cw * 80.0).max(ui.available_width());
            for r in range {
                let (rect, resp) = ui.allocate_exact_size(vec2(width, row_h), Sense::click());
                let p = ui.painter();
                let base = r * 16;
                let hex_x = |i: usize| rect.left() + cw * (10.0 + i as f32 * 3.0 + if i >= 8 { 1.0 } else { 0.0 });
                let asc_x = |i: usize| rect.left() + cw * (62.0 + i as f32);
                p.text(rect.left_top(), Align2::LEFT_TOP, format!("{base:08X}"), font.clone(), weak);
                for i in 0..16 {
                    let off = base + i;
                    let Some(b) = data.get(off).copied() else { break };
                    let (hx, ax) = (hex_x(i), asc_x(i));
                    if off >= hl_start && off < hl_end {
                        p.rect_filled(Rect::from_min_size(pos2(hx - cw * 0.5, rect.top()), vec2(cw * 3.0, row_h)), 0.0, hl);
                        p.rect_filled(Rect::from_min_size(pos2(ax, rect.top()), vec2(cw, row_h)), 0.0, hl);
                    }
                    if cursor == Some(off) {
                        let nib = if low { cw } else { 0.0 };
                        p.rect_filled(Rect::from_min_size(pos2(hx + nib, rect.top()), vec2(cw, row_h)), 2.0, cursor_fill);
                        p.rect_filled(Rect::from_min_size(pos2(ax, rect.top()), vec2(cw, row_h)), 2.0, cursor_fill);
                    }
                    let color = crate::theme::byte_color(ui, b);
                    p.text(pos2(hx, rect.top() + 1.0), Align2::LEFT_TOP, format!("{b:02X}"), font.clone(), color);
                    let ch = if (0x20..0x7f).contains(&b) { b as char } else { '.' };
                    p.text(pos2(ax, rect.top() + 1.0), Align2::LEFT_TOP, ch, font.clone(), color);
                }
                if resp.clicked()
                    && let Some(pos) = resp.interact_pointer_pos()
                {
                    let rel = (pos.x - rect.left()) / cw;
                    let idx = if rel >= 62.0 {
                        Some((rel - 62.0) as usize)
                    } else if rel >= 9.5 {
                        let mut c = rel - 9.5;
                        if c > 24.5 {
                            c -= 1.0;
                        }
                        Some((c / 3.0) as usize)
                    } else {
                        None
                    };
                    if let Some(i) = idx.filter(|i| *i < 16 && base + i < data.len()) {
                        clicked = Some(base + i);
                    }
                }
            }
        });
        self.hex.visible = visible;

        if let Some(off) = clicked {
            self.hex.cursor = Some(off);
            self.hex.low = false;
            self.hex.active = true;
        } else if ui.input(|i| i.pointer.any_pressed()) {
            let inside = ui.input(|i| i.pointer.interact_pos()).is_some_and(|p| area.contains(p));
            if !inside {
                self.hex.active = false;
            }
        }

        // Keyboard editing and navigation.
        let Some(mut cur) = self.hex.cursor else { return };
        if !self.hex.active || ui.ctx().text_edit_focused() || data.is_empty() {
            return;
        }
        let events = ui.input(|i| i.events.clone());
        let before = cur;
        let mut current = data[cur.min(data.len() - 1)];
        for e in events {
            match e {
                egui::Event::Text(s) => {
                    for d in s.chars().filter_map(|c| c.to_digit(16)) {
                        let d = d as u8;
                        current = if self.hex.low { (current & 0xF0) | d } else { (d << 4) | (current & 0x0F) };
                        self.actions.push(Action::Write { off: cur, bytes: vec![current] });
                        if self.hex.low && cur + 1 < data.len() {
                            cur += 1;
                            current = data[cur];
                        }
                        self.hex.low = !self.hex.low;
                    }
                }
                egui::Event::Key { key, pressed: true, modifiers, .. } if !modifiers.command => {
                    let page = (visible.1.saturating_sub(visible.0)).max(1) * 16;
                    let target = match key {
                        Key::ArrowLeft => cur.checked_sub(1),
                        Key::ArrowRight => Some(cur + 1),
                        Key::ArrowUp => cur.checked_sub(16),
                        Key::ArrowDown => Some(cur + 16),
                        Key::PageUp => Some(cur.saturating_sub(page)),
                        Key::PageDown => Some(cur + page),
                        Key::Home => Some(cur - cur % 16),
                        Key::End => Some(cur - cur % 16 + 15),
                        _ => None,
                    };
                    if let Some(t) = target {
                        cur = t.min(data.len() - 1);
                        current = data[cur];
                        self.hex.low = false;
                    }
                }
                _ => {}
            }
        }
        if cur != before {
            self.hex.cursor = Some(cur);
            self.hex.jump = Some(cur);
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let last = hay.len() - needle.len();
    let mut i = 0;
    while i <= last {
        {
            let p = hay[i..=last].iter().position(|b| *b == first)?;
            i += p;
            if &hay[i..i + needle.len()] == needle {
                return Some(i);
            }
            i += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_range_takes_any_offset_from_the_file() {
        let mut h = HexState::default();
        // An ELF section header can name the last offset there is.
        h.show_range(usize::MAX, 16);
        assert_eq!(h.highlight, Some((usize::MAX, 1)));
        h.show_range(usize::MAX - 4, 16);
        assert_eq!(h.highlight, Some((usize::MAX - 4, 4)));
        h.show_range(0x10, 0);
        assert_eq!(h.highlight, Some((0x10, 1)), "an empty range still shows where it is");
    }
}
