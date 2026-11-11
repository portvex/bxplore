#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use bxplore::{analysis, app, theme};

fn main() {
    // A file manager hands over any file name, valid Unicode or not.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|a| a == "--dump") {
        let Some(path) = args.get(1) else {
            eprintln!("usage: bxplore --dump <file>");
            std::process::exit(2);
        };
        let path = std::path::Path::new(path);
        match std::fs::read(path) {
            Ok(data) => {
                let parsed = analysis::parse(&data);
                let mut out = format!("{}: {}\n", path.display(), parsed.description);
                analysis::dump(&parsed.root, 0, &mut out);
                print!("{out}");
            }
            Err(e) => {
                eprintln!("{}: {e}", path.display());
                std::process::exit(1);
            }
        }
        return;
    }

    let initial: Vec<std::path::PathBuf> = args.iter().map(std::path::PathBuf::from).collect();
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_inner_size([1280.0, 820.0]).with_min_inner_size([720.0, 480.0]).with_drag_and_drop(true),
        ..Default::default()
    };
    let result = eframe::run_native(
        "bxplore",
        options,
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            match std::env::var("BXPLORE_THEME").as_deref() {
                Ok("dark") => cc.egui_ctx.set_theme(eframe::egui::Theme::Dark),
                Ok("light") => cc.egui_ctx.set_theme(eframe::egui::Theme::Light),
                _ => {}
            }
            Ok(Box::new(app::App::new(initial)))
        }),
    );
    if let Err(e) = result {
        eprintln!("failed to start the user interface: {e}");
        std::process::exit(1);
    }
}
