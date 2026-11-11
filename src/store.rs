//! Things the application remembers between runs, kept as small text files
//! in its configuration directory: settings and per-file bookmarks.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ThemeChoice {
    System,
    Dark,
    Light,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Settings {
    pub theme: ThemeChoice,
    /// Scale of the whole interface, 1.0 is the default size.
    pub zoom: f32,
    /// Show the hex panel under the structure views.
    pub hex_panel: bool,
    /// Keep the original as `<name>.bak` on the first save.
    pub backup_on_save: bool,
    pub recent_max: usize,
    /// Default minimum length in the strings view.
    pub strings_min: usize,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { theme: ThemeChoice::System, zoom: 1.0, hex_panel: true, backup_on_save: true, recent_max: 12, strings_min: 5 }
    }
}

impl Settings {
    /// Unknown keys and bad values are ignored, so an old or hand-edited file still loads.
    pub fn parse(text: &str) -> Settings {
        let mut s = Settings::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else { continue };
            let value = value.trim();
            let flag = || matches!(value, "true" | "1" | "yes");
            match key.trim() {
                "theme" => {
                    s.theme = match value {
                        "dark" => ThemeChoice::Dark,
                        "light" => ThemeChoice::Light,
                        _ => ThemeChoice::System,
                    }
                }
                "zoom" => s.zoom = value.parse::<f32>().ok().filter(|z| z.is_finite()).unwrap_or(1.0).clamp(0.7, 2.0),
                "hex_panel" => s.hex_panel = flag(),
                "backup_on_save" => s.backup_on_save = flag(),
                "recent_max" => s.recent_max = value.parse::<usize>().unwrap_or(12).clamp(0, 50),
                "strings_min" => s.strings_min = value.parse::<usize>().unwrap_or(5).clamp(2, 64),
                _ => {}
            }
        }
        s
    }

    pub fn to_text(&self) -> String {
        let theme = match self.theme {
            ThemeChoice::System => "system",
            ThemeChoice::Dark => "dark",
            ThemeChoice::Light => "light",
        };
        format!(
            "theme={theme}\nzoom={}\nhex_panel={}\nbackup_on_save={}\nrecent_max={}\nstrings_min={}\n",
            self.zoom, self.hex_panel, self.backup_on_save, self.recent_max, self.strings_min
        )
    }

    pub fn load(dir: &Path) -> Settings {
        std::fs::read_to_string(dir.join("settings.txt")).map(|t| Settings::parse(&t)).unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("settings.txt"), self.to_text())
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Bookmark {
    pub off: usize,
    pub len: usize,
    pub note: String,
}

/// Bookmarks are stored per file path, under a name derived from the path.
fn bookmark_file(dir: &Path, file: &Path) -> PathBuf {
    let digest = Sha256::digest(file.to_string_lossy().as_bytes());
    let name: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    dir.join("bookmarks").join(format!("{name}.txt"))
}

/// A note is one field on one line: tabs become spaces, and a line break is
/// written as `\n`, with the backslash itself doubled so that the note reads back as typed.
fn escape_note(note: &str) -> String {
    note.replace('\t', " ").replace('\\', "\\\\").replace('\n', "\\n")
}

fn unescape_note(text: &str) -> String {
    let mut note = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            note.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => note.push('\n'),
            Some('\\') | None => note.push('\\'),
            // Not an escape this code writes: kept as it is.
            Some(other) => {
                note.push('\\');
                note.push(other);
            }
        }
    }
    note
}

pub fn load_bookmarks(dir: &Path, file: &Path) -> Vec<Bookmark> {
    let Ok(text) = std::fs::read_to_string(bookmark_file(dir, file)) else { return Vec::new() };
    text.lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            let off = usize::from_str_radix(parts.next()?, 16).ok()?;
            let len = usize::from_str_radix(parts.next()?, 16).ok()?;
            Some(Bookmark { off, len, note: unescape_note(parts.next().unwrap_or("")) })
        })
        .take(10_000)
        .collect()
}

pub fn save_bookmarks(dir: &Path, file: &Path, list: &[Bookmark]) -> std::io::Result<()> {
    let path = bookmark_file(dir, file);
    if list.is_empty() {
        // No bookmarks, no file.
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text: String = list.iter().map(|b| format!("{:x}\t{:x}\t{}\n", b.off, b.len, escape_note(&b.note))).collect();
    std::fs::write(path, text)
}
