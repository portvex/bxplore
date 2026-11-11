//! Mach-O load command editing, checked against the system tools: a small C
//! program is compiled, edited, inspected with `otool`, re-signed and run.
//! Skipped where `cc`, `otool` or `codesign` are missing (anything but macOS).

use bxplore::macho_edit::{self, LC_LOAD_DYLIB, LC_RPATH};
use std::path::Path;
use std::process::Command;

fn tool(name: &str) -> bool {
    Command::new("which").arg(name).output().is_ok_and(|o| o.status.success())
}

fn run(cmd: &str, args: &[&str]) -> (bool, String) {
    let o = Command::new(cmd).args(args).output().unwrap();
    (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr))
}

fn build(dir: &Path, extra: &[&str]) -> Option<Vec<u8>> {
    if !cfg!(target_os = "macos") || !["cc", "otool", "codesign"].iter().all(|t| tool(t)) {
        return None;
    }
    let src = dir.join("hello.c");
    std::fs::write(&src, "#include <stdio.h>\nint main(void) { puts(\"hello from bxplore test\"); return 0; }\n").unwrap();
    let exe = dir.join("hello");
    let mut args = vec![src.to_str().unwrap(), "-o", exe.to_str().unwrap()];
    args.extend_from_slice(extra);
    let (ok, out) = run("cc", &args);
    assert!(ok, "cc failed: {out}");
    Some(std::fs::read(exe).unwrap())
}

fn check_runs(path: &Path) {
    // Only reached on macOS (build() returns None elsewhere), but the file must compile everywhere.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let p = path.to_str().unwrap();
    let (ok, out) = run("codesign", &["-f", "-s", "-", p]);
    assert!(ok, "codesign failed: {out}");
    let (ok, out) = run("codesign", &["--verify", "--strict", p]);
    assert!(ok, "codesign --verify failed: {out}");
    let (ok, out) = run(p, &[]);
    assert!(ok && out.contains("hello from bxplore test"), "edited program did not run: {out}");
}

#[test]
fn add_change_remove_commands() {
    let dir = std::env::temp_dir().join(format!("bxplore-macho-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // The linker leaves little header padding by default (32 bytes on arm64, 64 on
    // x86_64); like install_name_tool, the editor needs the room to exist. The path is
    // long enough not to fit on either architecture.
    let Some(tight) = build(&dir, &[]) else { return };
    let long = format!("/usr/lib/{}.dylib", "x".repeat(100));
    let err = macho_edit::add_path_command(&mut tight.clone(), LC_LOAD_DYLIB, &long).unwrap_err();
    assert!(err.contains("not enough header padding"), "{err}");
    let Some(orig) = build(&dir, &["-Wl,-headerpad,0x400"]) else { return };
    let edited = dir.join("hello_edited");
    let p = edited.to_str().unwrap();

    let mut data = orig.clone();
    macho_edit::add_path_command(&mut data, LC_RPATH, "@executable_path/../Frameworks").unwrap();
    macho_edit::add_path_command(&mut data, LC_LOAD_DYLIB, "/usr/lib/libz.1.dylib").unwrap();
    assert_eq!(data.len(), orig.len(), "commands go into header padding; the file must not grow");
    assert!(macho_edit::add_path_command(&mut data, LC_RPATH, "@executable_path/../Frameworks").is_err(), "duplicates are refused");
    std::fs::write(&edited, &data).unwrap();
    let (_, listing) = run("otool", &["-l", p]);
    assert!(listing.contains("@executable_path/../Frameworks"), "otool does not see the rpath:\n{listing}");
    let (_, libs) = run("otool", &["-L", p]);
    assert!(libs.contains("/usr/lib/libz.1.dylib"), "otool does not see the library:\n{libs}");
    check_runs(&edited);

    // Longer and shorter replacement paths, then removal back to the original commands.
    macho_edit::change_path(&mut data, LC_RPATH, "@executable_path/../Frameworks", "@loader_path/a/much/longer/run/path/than/before/Frameworks").unwrap();
    macho_edit::change_path(&mut data, LC_LOAD_DYLIB, "/usr/lib/libz.1.dylib", "/usr/lib/libz.dylib").unwrap();
    std::fs::write(&edited, &data).unwrap();
    let (_, listing) = run("otool", &["-l", p]);
    assert!(listing.contains("@loader_path/a/much/longer/run/path/than/before/Frameworks") && !listing.contains("@executable_path/../Frameworks"));
    let (_, libs) = run("otool", &["-L", p]);
    assert!(libs.contains("/usr/lib/libz.dylib"));
    check_runs(&edited);

    macho_edit::remove_path_command(&mut data, LC_RPATH, "@loader_path/a/much/longer/run/path/than/before/Frameworks").unwrap();
    macho_edit::remove_path_command(&mut data, LC_LOAD_DYLIB, "/usr/lib/libz.dylib").unwrap();
    assert_eq!(data, orig, "removing what was added restores the original bytes");

    let mut data = orig.clone();
    macho_edit::remove_signature(&mut data).unwrap();
    std::fs::write(&edited, &data).unwrap();
    let (_, listing) = run("otool", &["-l", p]);
    assert!(!listing.contains("LC_CODE_SIGNATURE"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn universal_binary_edits_every_slice() {
    let dir = std::env::temp_dir().join(format!("bxplore-macho-fat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let Some(orig) = build(&dir, &["-arch", "arm64", "-arch", "x86_64"]) else { return };
    assert_eq!(macho_edit::slices(&orig).len(), 2);
    let mut data = orig.clone();
    macho_edit::add_path_command(&mut data, LC_RPATH, "/opt/example/lib").unwrap();
    let edited = dir.join("hello_fat_edited");
    std::fs::write(&edited, &data).unwrap();
    let (_, listing) = run("otool", &["-arch", "all", "-l", edited.to_str().unwrap()]);
    assert_eq!(listing.matches("/opt/example/lib").count(), 2, "both architectures get the rpath:\n{listing}");
    check_runs(&edited);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn signature_page_hashes_detect_tampering() {
    let dir = std::env::temp_dir().join(format!("bxplore-macho-sig-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // The linker signs arm64 output on its own but x86_64 output only when asked.
    let Some(orig) = build(&dir, &["-Wl,-adhoc_codesign"]) else { return };
    let mut text = String::new();
    bxplore::analysis::dump(&bxplore::analysis::parse(&orig).root, 0, &mut text);
    assert!(text.contains("Page hashes: OK"), "a freshly linked binary must verify:\n{text}");
    let mut bad = orig.clone();
    let n = bad.len();
    bad[n / 4] ^= 0xff;
    let mut text = String::new();
    bxplore::analysis::dump(&bxplore::analysis::parse(&bad).root, 0, &mut text);
    assert!(text.contains("Page hashes: MISMATCH"), "tampering must be detected");
    let _ = std::fs::remove_dir_all(&dir);
}

// --- dynamic linking data and language metadata --------------------------------

fn dump(data: &[u8]) -> String {
    let mut text = String::new();
    bxplore::analysis::dump(&bxplore::analysis::parse(data).root, 0, &mut text);
    text
}

/// The rows of one node of the dump, without the header line.
fn rows(text: &str, title_start: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim_start();
        if t.starts_with('[') {
            if inside {
                break;
            }
            inside = t.starts_with(title_start);
            continue;
        }
        if inside {
            out.push(t.to_string());
        }
    }
    out.into_iter().skip(1).collect()
}

fn compile(dir: &Path, name: &str, source: &str, cmd: &str, args: &[&str]) -> Option<Vec<u8>> {
    if !cfg!(target_os = "macos") || !tool(cmd) {
        return None;
    }
    let src = dir.join(name);
    std::fs::write(&src, source).unwrap();
    let exe = dir.join(format!("{name}.out"));
    let mut all = vec![src.to_str().unwrap(), "-o", exe.to_str().unwrap()];
    all.extend_from_slice(args);
    let (ok, out) = run(cmd, &all);
    assert!(ok, "{cmd} failed: {out}");
    Some(std::fs::read(exe).unwrap())
}

const OBJC: &str = r#"
#import <Foundation/Foundation.h>
@interface Greeter : NSObject
@property(copy) NSString *name;
- (void)greet:(int)times;
+ (instancetype)greeterNamed:(NSString *)name;
@end
@implementation Greeter
- (void)greet:(int)times { for (int i = 0; i < times; i++) NSLog(@"hello %@", self.name); }
+ (instancetype)greeterNamed:(NSString *)name { Greeter *g = [Greeter new]; g.name = name; return g; }
@end
int exported_helper(int x) { return x + 1; }
int main(void) { @autoreleasepool { [[Greeter greeterNamed:@"bxplore"] greet:1]; } return exported_helper(-1); }
"#;

#[test]
fn objc_classes_exports_and_fixups_match_the_system_tools() {
    let dir = std::env::temp_dir().join(format!("bxplore-macho-objc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Chained fixups (the modern default) and the classic opcode streams, on both architectures.
    for (arch, extra) in [("arm64", &[][..]), ("x86_64", &[][..]), ("arm64", &["-Wl,-no_fixup_chains"][..]), ("x86_64", &["-Wl,-no_fixup_chains"][..])] {
        let mut args = vec!["-arch", arch, "-fobjc-arc", "-framework", "Foundation"];
        args.extend_from_slice(extra);
        let Some(data) = compile(&dir, "o.m", OBJC, "cc", &args) else { return };
        let text = dump(&data);
        let what = format!("{arch} {extra:?}");

        // Objective-C: the class with its instance and class methods and type encodings.
        let methods = rows(&text, "[Objective-C Classes (1)]");
        for want in ["Greeter  -greet:         v20@0:8i16", "Greeter  -name ", "Greeter  -setName:", "Greeter  +greeterNamed:  @24@0:8@16"] {
            assert!(methods.iter().any(|m| m.starts_with(want)), "{what}: missing {want:?} in {methods:#?}");
        }
        // Every implementation address is a function nm knows.
        let exe = dir.join("o.m.out");
        let (_, nm) = run("nm", &["-arch", arch, exe.to_str().unwrap()]);
        for m in &methods {
            let imp = m.split_whitespace().last().unwrap().to_lowercase();
            assert!(nm.lines().any(|l| l.trim_start_matches('0').starts_with(&imp)), "{what}: implementation {imp} of {m:?} is not a symbol");
        }

        // Exports: same names and addresses as `dyld_info -exports`.
        if tool("dyld_info") {
            let (_, info) = run("dyld_info", &["-arch", arch, "-exports", exe.to_str().unwrap()]);
            let ours = rows(&text, "[Exports Trie (");
            let theirs: Vec<(u64, &str)> = info
                .lines()
                .filter_map(|l| {
                    let mut p = l.split_whitespace();
                    let off = u64::from_str_radix(p.next()?.strip_prefix("0x")?, 16).ok()?;
                    Some((off, p.next()?))
                })
                .collect();
            assert!(theirs.len() >= 3, "{what}: could not read dyld_info output:\n{info}");
            assert_eq!(ours.len(), theirs.len(), "{what}: export count\n{info}");
            for (off, name) in theirs {
                let row = ours.iter().find(|r| r.split_whitespace().next() == Some(name)).unwrap_or_else(|| panic!("{what}: export {name} missing"));
                let addr = u64::from_str_radix(row.split_whitespace().nth(1).unwrap(), 16).unwrap();
                assert_eq!(addr, 0x1_0000_0000 + off, "{what}: address of {name}");
            }

            // Imports bound by the fixups: every symbol dyld_info lists is in ours, with its library.
            let (_, fixups) = run("dyld_info", &["-arch", arch, "-fixups", exe.to_str().unwrap()]);
            let binds: Vec<&str> = fixups.lines().filter(|l| l.contains(" bind ")).collect();
            assert!(!binds.is_empty(), "{what}:\n{fixups}");
            let ours = if extra.is_empty() { rows(&text, "[Fixups (") } else { [rows(&text, "[Binds ("), rows(&text, "[Lazy Binds (")].concat() };
            for b in &binds {
                let sym = b.split('/').next_back().unwrap_or("").trim();
                let sym = sym.split_whitespace().next().unwrap_or("");
                let addr = b.split_whitespace().nth(2).unwrap_or("").trim_start_matches("0x").trim_start_matches('0').to_uppercase();
                assert!(ours.iter().any(|r| r.contains(sym) && r.contains(&addr)), "{what}: bind of {sym} at {addr} missing\nours: {ours:#?}");
            }
            assert!(text.contains("NSLog") && text.contains("Foundation"), "{what}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn swift_types_are_listed_with_their_context() {
    let dir = std::env::temp_dir().join(format!("bxplore-macho-swift-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = "struct Point { var x: Int; var y: Int }\nenum Shape { case circle(Double), square(Double) }\nfinal class Canvas { var shapes: [Shape] = []; struct Layer { var z: Int } }\nprint(Point(x: 1, y: 2), Canvas().shapes.count, Canvas.Layer(z: 3))\n";
    let Some(data) = compile(&dir, "sample.swift", source, "swiftc", &["-module-name", "Sample"]) else { return };
    let types = rows(&dump(&data), "[Swift Types (4)]");
    let has = |kind: &str, name: &str, parent: &str| types.iter().any(|t| t.split_whitespace().take(3).collect::<Vec<_>>() == [kind, name, parent]);
    assert!(
        has("struct", "Point", "Sample") && has("enum", "Shape", "Sample") && has("class", "Canvas", "Sample") && has("struct", "Layer", "Sample.Canvas"),
        "{types:#?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
