//! Look and feel: colour palettes for the dark and light themes, spacing,
//! rounded widgets and a few small reusable pieces (chips, cards, headers).

use eframe::egui;
use egui::{Color32, CornerRadius, FontId, Margin, RichText, Stroke, TextStyle, Theme, Ui, Visuals, vec2};

struct Palette {
    bg: Color32,
    panel: Color32,
    raised: Color32,
    hover: Color32,
    border: Color32,
    text: Color32,
    strong: Color32,
    weak: Color32,
    accent: Color32,
    accent_soft: Color32,
    extreme: Color32,
    faint: Color32,
    error: Color32,
    warn: Color32,
}

const fn rgb(v: u32) -> Color32 {
    Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

const DARK: Palette = Palette {
    bg: rgb(0x14161B),
    panel: rgb(0x1A1D24),
    raised: rgb(0x242833),
    hover: rgb(0x2E3442),
    border: rgb(0x2B303B),
    text: rgb(0xC5CAD6),
    strong: rgb(0xF1F3F8),
    weak: rgb(0x7A8194),
    accent: rgb(0x6C8CFF),
    accent_soft: rgb(0x2A3764),
    extreme: rgb(0x0F1115),
    faint: rgb(0x1D2028),
    error: rgb(0xFF6B6B),
    warn: rgb(0xF0B255),
};

const LIGHT: Palette = Palette {
    bg: rgb(0xFFFFFF),
    panel: rgb(0xF5F6F9),
    raised: rgb(0xE9EBF1),
    hover: rgb(0xDDE1EA),
    border: rgb(0xD9DCE5),
    text: rgb(0x3A4050),
    strong: rgb(0x10131A),
    weak: rgb(0x8189A0),
    accent: rgb(0x3B5BDB),
    accent_soft: rgb(0xD6DFFF),
    extreme: rgb(0xFFFFFF),
    faint: rgb(0xF4F5F9),
    error: rgb(0xD0312D),
    warn: rgb(0xB36B00),
};

fn palette(dark: bool) -> &'static Palette {
    if dark { &DARK } else { &LIGHT }
}

fn visuals(dark: bool) -> Visuals {
    let p = palette(dark);
    let mut v = if dark { Visuals::dark() } else { Visuals::light() };
    let radius = CornerRadius::same(6);

    v.panel_fill = p.panel;
    v.window_fill = p.panel;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(10);
    v.menu_corner_radius = CornerRadius::same(8);
    v.extreme_bg_color = p.extreme;
    v.faint_bg_color = p.faint;
    v.code_bg_color = p.raised;
    v.text_edit_bg_color = Some(p.raised);
    v.hyperlink_color = p.accent;
    v.error_fg_color = p.error;
    v.warn_fg_color = p.warn;
    v.weak_text_color = Some(p.weak);
    v.selection.bg_fill = p.accent_soft;
    v.selection.stroke = Stroke::new(1.0, p.accent);
    v.striped = true;
    v.indent_has_left_vline = true;
    v.slider_trailing_fill = true;

    let w = &mut v.widgets;
    w.noninteractive.bg_fill = p.panel;
    w.noninteractive.weak_bg_fill = p.panel;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    w.noninteractive.corner_radius = radius;

    w.inactive.bg_fill = p.raised;
    w.inactive.weak_bg_fill = p.raised;
    w.inactive.bg_stroke = Stroke::NONE;
    w.inactive.fg_stroke = Stroke::new(1.0, p.text);
    w.inactive.corner_radius = radius;

    w.hovered.bg_fill = p.hover;
    w.hovered.weak_bg_fill = p.hover;
    w.hovered.bg_stroke = Stroke::new(1.0, p.accent.gamma_multiply(0.6));
    w.hovered.fg_stroke = Stroke::new(1.0, p.strong);
    w.hovered.corner_radius = radius;
    w.hovered.expansion = 0.0;

    w.active.bg_fill = p.accent_soft;
    w.active.weak_bg_fill = p.accent_soft;
    w.active.bg_stroke = Stroke::new(1.0, p.accent);
    w.active.fg_stroke = Stroke::new(1.0, p.strong);
    w.active.corner_radius = radius;
    w.active.expansion = 0.0;

    w.open.bg_fill = p.hover;
    w.open.weak_bg_fill = p.hover;
    w.open.bg_stroke = Stroke::new(1.0, p.border);
    w.open.fg_stroke = Stroke::new(1.0, p.strong);
    w.open.corner_radius = radius;
    v
}

/// Installs both themes; the user can still switch between them in the View menu.
pub fn install(ctx: &egui::Context) {
    // The icon font is a fallback of both text families, so icons can be
    // mixed into any label.
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert("phosphor".into(), std::sync::Arc::new(egui::FontData::from_static(include_bytes!("../assets/Phosphor.ttf"))));
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        let keys = fonts.families.entry(family).or_default();
        keys.insert(keys.len().min(1), "phosphor".into());
    }
    ctx.set_fonts(fonts);
    for (theme, dark) in [(Theme::Dark, true), (Theme::Light, false)] {
        ctx.style_mut_of(theme, |s| {
            s.visuals = visuals(dark);
            s.spacing.item_spacing = vec2(8.0, 5.0);
            s.spacing.button_padding = vec2(10.0, 4.0);
            s.spacing.menu_margin = Margin::same(6);
            s.spacing.window_margin = Margin::same(12);
            s.spacing.indent = 16.0;
            s.spacing.interact_size.y = 24.0;
            s.spacing.scroll.bar_width = 8.0;
            s.spacing.scroll.floating = true;
            s.text_styles.insert(TextStyle::Body, FontId::proportional(13.5));
            s.text_styles.insert(TextStyle::Button, FontId::proportional(13.5));
            s.text_styles.insert(TextStyle::Monospace, FontId::monospace(12.5));
            s.text_styles.insert(TextStyle::Heading, FontId::proportional(20.0));
            s.text_styles.insert(TextStyle::Small, FontId::proportional(11.0));
        });
    }
}

fn pal(ui: &Ui) -> &'static Palette {
    palette(ui.visuals().dark_mode)
}

/// Colour of a tree icon by what it stands for.
pub fn tint(ui: &Ui, t: crate::icons::Tint) -> Color32 {
    use crate::icons::Tint;
    let dark = ui.visuals().dark_mode;
    let pick = |d: u32, l: u32| if dark { rgb(d) } else { rgb(l) };
    match t {
        Tint::Folder => pick(0xE5B45A, 0xC98A12),
        Tint::Structure => pick(0x7FA2FF, 0x3B5BDB),
        Tint::Tool => pick(0x5CC8B8, 0x0E8F7E),
        Tint::Editor => pick(0xF08A5D, 0xC2410C),
        // Not green: the icon is chosen from the title and would look like a
        // passed verification next to a signature that failed.
        Tint::Security => pick(0x7FA2FF, 0x3B5BDB),
        Tint::Code => pick(0xC792EA, 0x7C3AED),
    }
}

/// Button label with an icon in front of the text.
pub fn icon_text(icon: &str, text: &str) -> String {
    format!("{icon}  {text}")
}

pub fn accent(ui: &Ui) -> Color32 {
    pal(ui).accent
}

/// Background of the main content area, slightly different from the side panels.
pub fn content_bg(ui: &Ui) -> Color32 {
    pal(ui).bg
}

pub fn border(ui: &Ui) -> Color32 {
    pal(ui).border
}

/// Frame for a side or tool bar panel.
pub fn bar(ui: &Ui, margin: Margin) -> egui::Frame {
    egui::Frame::new().fill(pal(ui).panel).inner_margin(margin)
}

/// Frame for the main content area.
pub fn content(ui: &Ui) -> egui::Frame {
    egui::Frame::new().fill(content_bg(ui)).inner_margin(Margin::symmetric(14, 10))
}

/// A raised rounded box used on the welcome screen and in summaries.
pub fn card(ui: &Ui) -> egui::Frame {
    let p = pal(ui);
    egui::Frame::new().fill(p.panel).stroke(Stroke::new(1.0, p.border)).corner_radius(CornerRadius::same(12)).inner_margin(Margin::same(24))
}

/// Small rounded label, used for the file format and state badges.
pub fn chip(ui: &mut Ui, text: &str, color: Color32) {
    egui::Frame::new().fill(color.gamma_multiply(0.18)).corner_radius(CornerRadius::same(9)).inner_margin(Margin::symmetric(8, 1)).show(ui, |ui| {
        ui.label(RichText::new(text).small().strong().color(color));
    });
}

/// Small upper case caption above a group of controls.
pub fn caption(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text.to_uppercase()).small().strong().color(pal(ui).weak));
}

pub fn warn(ui: &Ui) -> Color32 {
    pal(ui).warn
}

/// Colour of a byte in the hex view, by class: zero, printable text, 0xFF, other.
pub fn byte_color(ui: &Ui, b: u8) -> Color32 {
    let p = pal(ui);
    match b {
        0 => p.weak.gamma_multiply(0.6),
        0x20..=0x7e => p.accent.lerp_to_gamma(p.strong, 0.25),
        0xff => p.warn,
        _ => p.text,
    }
}

/// Button filled with the accent colour, for the primary action of a view.
pub fn primary_button(ui: &mut Ui, text: &str) -> egui::Response {
    let p = pal(ui);
    let fg = if ui.visuals().dark_mode { p.extreme } else { Color32::WHITE };
    ui.add(egui::Button::new(RichText::new(text).strong().color(fg)).fill(p.accent).min_size(vec2(0.0, 30.0)))
}
