//! bxplore: a cross-platform viewer and editor for PE, ELF and Mach-O files.
//!
//! The parsers and editors are plain library code without any GUI
//! dependency; the desktop application lives behind the `gui` feature.

pub mod analysis;
pub mod elf;
pub mod elf_edit;
pub mod fuzzgen;
pub mod fuzzing;
pub mod macho;
pub mod macho_dyld;
pub mod macho_edit;
pub mod macho_sig;
pub mod model;
pub mod pe;
pub mod query;
pub mod shellmenu;
pub mod store;

#[cfg(feature = "gui")]
pub mod app;
#[cfg(feature = "gui")]
pub mod hexview;
pub mod icons;
#[cfg(feature = "gui")]
pub mod theme;
#[cfg(feature = "gui")]
pub mod tools;
#[cfg(feature = "gui")]
pub mod tools2;
