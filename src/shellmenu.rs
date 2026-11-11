//! "Open with bxplore" in the file manager, for a copy of the program that was
//! not put there by an installer (the portable zip, the standalone
//! executable, an app dragged out of the DMG).
//!
//! - Windows: a context menu entry per executable file type, in the current
//!   user's registry.
//! - macOS: a Finder Quick Action in `~/Library/Services`. A document type in
//!   the app's `Info.plist` would not do: Finder hands the file over in an
//!   event that the GUI toolkit does not deliver, while a Quick Action starts
//!   the program with the file as an argument.
//! - Linux: a desktop entry with the executable MIME types in the user's
//!   applications directory, which puts the program in "Open With".
//!
//! Everything is per user and needs no administrator rights. What is written
//! is computed by pure functions, so it can be tested on any platform.

use std::path::{Path, PathBuf};

/// The text of the menu entry.
pub const LABEL: &str = "Open with bxplore";

/// File types that get the entry on Windows: Windows executables, and the
/// ELF and Mach-O files someone inspecting other platforms' binaries meets.
pub const EXTENSIONS: &[&str] =
    &["exe", "dll", "sys", "ocx", "scr", "cpl", "drv", "efi", "mui", "ax", "tlb", "so", "elf", "o", "ko", "dylib", "bundle", "a", "lib"];

/// MIME types of executable files, for the Linux desktop entry.
pub const MIME_TYPES: &[&str] = &[
    "application/x-executable",
    "application/x-pie-executable",
    "application/x-sharedlib",
    "application/x-object",
    "application/x-archive",
    "application/x-core",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-ms-dos-executable",
    "application/x-mach-binary",
    "application/x-mach-o-executable",
];

const APP_ID: &str = "io.github.bxplore.Bxplore";
const WORKFLOW: &str = "Open with bxplore.workflow";
const ICON: &[u8] = include_bytes!("../packaging/icons/bxplore-256.png");

/// Where the entry goes, in words, or `None` when this copy of the program
/// cannot or need not register itself: inside Flatpak or snap the package
/// already did, and other systems have no such menu.
pub fn target() -> Option<&'static str> {
    if std::env::var_os("FLATPAK_ID").is_some() || std::env::var_os("SNAP").is_some() {
        return None;
    }
    // The Nix package registered itself too, and its store path does not last.
    if cfg!(target_os = "linux") && std::env::current_exe().is_ok_and(|exe| linux_unstable(&exe).is_some()) {
        return None;
    }
    if cfg!(windows) {
        Some("Explorer's right-click menu")
    } else if cfg!(target_os = "macos") {
        Some("Finder's Quick Actions menu")
    } else if cfg!(target_os = "linux") {
        Some("the file manager's Open With list")
    } else {
        None
    }
}

/// Add the entry for the running program.
pub fn install() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find the program's own path: {e}"))?;
    install_for(&exe)
}

/// Remove the entry again.
pub fn remove() -> Result<String, String> {
    platform::remove()
}

fn install_for(exe: &Path) -> Result<String, String> {
    // The path ends up inside a registry value, a shell script or a desktop
    // entry; none of them can hold a line break.
    let text = exe.to_str().ok_or("the program's path is not valid Unicode")?;
    if text.chars().any(|c| c.is_control()) {
        return Err("the program's path contains control characters".into());
    }
    platform::install(exe)
}

/// What Remove reports. `removed`: the entry added from Preferences was
/// there. `remaining`: an entry this program cannot remove is still in the
/// menu, and this is what to do about it.
#[cfg(any(windows, target_os = "macos", target_os = "linux", test))]
fn removal_note(removed: bool, place: &str, remaining: Option<&str>) -> String {
    let own = if removed { format!("\"{LABEL}\" removed from {place}") } else { "No entry added from Preferences was found".to_string() };
    match remaining {
        Some(rest) => format!("{own}. {rest}"),
        None => own,
    }
}

// ---------------------------------------------------------------------------
// Windows

/// One registry value: key (under HKEY_CURRENT_USER), value name (`None` for
/// the default value) and data.
pub type RegValue = (String, Option<&'static str>, String);

/// The registry key that holds the entry for one file type.
pub fn windows_key(ext: &str) -> String {
    format!(r"Software\Classes\SystemFileAssociations\.{ext}\shell\bxplore")
}

/// The registry values that make up the entry, for a program at `exe`.
/// `SystemFileAssociations` applies whatever program the type is opened with.
pub fn windows_values(exe: &str) -> Vec<RegValue> {
    let mut out = Vec::new();
    for ext in EXTENSIONS {
        let key = windows_key(ext);
        out.push((key.clone(), None, LABEL.to_string()));
        out.push((key.clone(), Some("Icon"), format!("\"{exe}\"")));
        out.push((format!(r"{key}\command"), None, format!("\"{exe}\" \"%1\"")));
    }
    out
}

/// Where `reg.exe` is, given the value of `SystemRoot`. Always an absolute
/// path: a bare name would be looked up next to the running program first.
pub fn windows_reg_exe(system_root: Option<std::ffi::OsString>) -> PathBuf {
    let root = system_root.filter(|r| !r.is_empty()).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join("reg.exe")
}

/// A string as it stands between quotes in a `.reg` file.
fn reg_file_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', r"\\").replace('"', "\\\""))
}

const REG_FILE_HEADER: &str = "Windows Registry Editor Version 5.00\r\n";

/// A `.reg` file that adds the entry for a program at `exe`, so that one run
/// of `reg import` writes every value.
pub fn windows_reg_file(exe: &str) -> String {
    let mut out = String::from(REG_FILE_HEADER);
    let mut last = String::new();
    for (key, name, data) in windows_values(exe) {
        if key != last {
            out.push_str(&format!("\r\n[HKEY_CURRENT_USER\\{key}]\r\n"));
            last = key;
        }
        let name = name.map_or_else(|| "@".to_string(), reg_file_quote);
        out.push_str(&format!("{name}={}\r\n", reg_file_quote(&data)));
    }
    out
}

/// A `.reg` file that deletes the entry of every file type; a key that is
/// not there is skipped.
pub fn windows_unreg_file() -> String {
    let mut out = String::from(REG_FILE_HEADER);
    for ext in EXTENSIONS {
        out.push_str(&format!("\r\n[-HKEY_CURRENT_USER\\{}]\r\n", windows_key(ext)));
    }
    out
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    /// `reg.exe` is part of Windows; it keeps this crate free of unsafe code.
    fn reg(args: &[&str]) -> Result<bool, String> {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let program = windows_reg_exe(std::env::var_os("SystemRoot"));
        if !program.is_file() {
            return Err(format!("{} is missing", program.display()));
        }
        let out = Command::new(&program).args(args).creation_flags(CREATE_NO_WINDOW).output().map_err(|e| format!("cannot run {}: {e}", program.display()))?;
        Ok(out.status.success())
    }

    /// Apply the text of a `.reg` file with a single run of `reg import`.
    fn import(text: &str) -> Result<bool, String> {
        let file = std::env::temp_dir().join(format!("bxplore-menu-{}.reg", std::process::id()));
        // UTF-16 with a byte order mark, so any path survives.
        let bytes: Vec<u8> = std::iter::once(0xFEFF).chain(text.encode_utf16()).flat_map(u16::to_le_bytes).collect();
        std::fs::write(&file, bytes).map_err(|e| format!("cannot write {}: {e}", file.display()))?;
        let done = match file.to_str() {
            Some(f) => reg(&["import", f]),
            None => Err("the temporary directory's path is not valid Unicode".into()),
        };
        let _ = std::fs::remove_file(&file);
        done
    }

    pub fn install(exe: &Path) -> Result<String, String> {
        let exe = exe.to_str().ok_or("the program's path is not valid Unicode")?;
        if exe.contains('"') || exe.contains('%') {
            return Err("the program's path contains a quote or percent sign, which a registry command cannot hold".into());
        }
        if !import(&windows_reg_file(exe))? {
            // Leave nothing half written.
            let _ = import(&windows_unreg_file());
            return Err("the registry refused the entry".into());
        }
        Ok(format!("\"{LABEL}\" added to Explorer for {} file types (under \"Show more options\" on Windows 11)", EXTENSIONS.len()))
    }

    pub fn remove() -> Result<String, String> {
        // Add writes every file type at once, so the first one stands for all.
        let shown = format!(r"\{}", windows_key(EXTENSIONS[0]));
        let removed = reg(&["query", &format!("HKCU{shown}")])?;
        if !import(&windows_unreg_file())? {
            return Err("the registry refused to delete the entry".into());
        }
        // The installer writes the same entry for all users; only it can take that out.
        let installer = reg(&["query", &format!("HKLM{shown}")])?.then_some(
            "The entry for all users was added by the installer: uninstall bxplore, or run the installer again without \"Explorer menu\", to remove it",
        );
        Ok(removal_note(removed, "Explorer", installer))
    }
}

// ---------------------------------------------------------------------------
// macOS

/// The application bundle `exe` is the main program of, if it is in one.
pub fn bundle_of(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    (macos.file_name()? == "MacOS" && contents.file_name()? == "Contents" && app.extension()? == "app").then(|| app.to_path_buf())
}

/// Why a Quick Action for a program at `exe` would stop working: a program
/// started from a disk image, or from the temporary copy macOS runs a
/// quarantined app from, has a path that is gone after an eject or a restart.
pub fn macos_unstable(exe: &Path) -> Option<&'static str> {
    let text = exe.to_string_lossy();
    (text.starts_with("/Volumes/") || text.contains("/AppTranslocation/"))
        .then_some("bxplore is running from a disk image or a temporary location; move it to Applications first, then add the entry")
}

/// A string inside single quotes for /bin/sh.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// The shell command of the Quick Action. The selected files arrive as
/// arguments. A program in a bundle is started through `open`, so it comes to
/// the front like any application; `-n` because a running instance would not
/// be handed the arguments.
pub fn macos_command(exe: &Path) -> String {
    match bundle_of(exe) {
        Some(app) => format!("/usr/bin/open -n -a {} --args \"$@\"", sh_quote(&app.to_string_lossy())),
        None => format!("{} \"$@\" >/dev/null 2>&1 &", sh_quote(&exe.to_string_lossy())),
    }
}

/// `Contents/Info.plist` of the Quick Action: a service that takes files.
pub fn macos_info_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en_US</string>
	<key>CFBundleIdentifier</key>
	<string>{APP_ID}.OpenWith</string>
	<key>CFBundleName</key>
	<string>{LABEL}</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
	<key>NSServices</key>
	<array>
		<dict>
			<key>NSMenuItem</key>
			<dict>
				<key>default</key>
				<string>{LABEL}</string>
			</dict>
			<key>NSMessage</key>
			<string>runWorkflowAsService</string>
			<key>NSSendFileTypes</key>
			<array>
				<string>public.data</string>
			</array>
		</dict>
	</array>
</dict>
</plist>
"#
    )
}

/// `Contents/document.wflow`: one "Run Shell Script" action that gets the
/// files as arguments.
pub fn macos_workflow(exe: &Path) -> String {
    let command = xml_escape(&macos_command(exe));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AMApplicationBuild</key>
	<string>523</string>
	<key>AMApplicationVersion</key>
	<string>2.10</string>
	<key>AMDocumentVersion</key>
	<string>2</string>
	<key>actions</key>
	<array>
		<dict>
			<key>action</key>
			<dict>
				<key>AMAccepts</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Optional</key>
					<true/>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.string</string>
					</array>
				</dict>
				<key>AMActionVersion</key>
				<string>2.0.3</string>
				<key>AMApplication</key>
				<array>
					<string>Automator</string>
				</array>
				<key>AMParameterProperties</key>
				<dict>
					<key>COMMAND_STRING</key>
					<dict/>
					<key>CheckedForUserDefaultShell</key>
					<dict/>
					<key>inputMethod</key>
					<dict/>
					<key>shell</key>
					<dict/>
					<key>source</key>
					<dict/>
				</dict>
				<key>AMProvides</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.string</string>
					</array>
				</dict>
				<key>ActionBundlePath</key>
				<string>/System/Library/Automator/Run Shell Script.action</string>
				<key>ActionName</key>
				<string>Run Shell Script</string>
				<key>ActionParameters</key>
				<dict>
					<key>COMMAND_STRING</key>
					<string>{command}</string>
					<key>CheckedForUserDefaultShell</key>
					<true/>
					<key>inputMethod</key>
					<integer>1</integer>
					<key>shell</key>
					<string>/bin/sh</string>
					<key>source</key>
					<string></string>
				</dict>
				<key>BundleIdentifier</key>
				<string>com.apple.RunShellScript</string>
				<key>CFBundleVersion</key>
				<string>2.0.3</string>
				<key>CanShowSelectedItemsWhenRun</key>
				<false/>
				<key>CanShowWhenRun</key>
				<true/>
				<key>Category</key>
				<array>
					<string>AMCategoryUtilities</string>
				</array>
				<key>Class Name</key>
				<string>RunShellScriptAction</string>
				<key>InputUUID</key>
				<string>6F2B7C1E-5D0A-4E0B-9C55-0A6E3B1D2F01</string>
				<key>Keywords</key>
				<array>
					<string>Shell</string>
					<string>Script</string>
					<string>Command</string>
					<string>Run</string>
					<string>Unix</string>
				</array>
				<key>OutputUUID</key>
				<string>6F2B7C1E-5D0A-4E0B-9C55-0A6E3B1D2F02</string>
				<key>UUID</key>
				<string>6F2B7C1E-5D0A-4E0B-9C55-0A6E3B1D2F03</string>
				<key>UnlocalizedApplications</key>
				<array>
					<string>Automator</string>
				</array>
				<key>arguments</key>
				<dict/>
				<key>isViewVisible</key>
				<integer>1</integer>
			</dict>
			<key>isViewVisible</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>connectors</key>
	<dict/>
	<key>workflowMetaData</key>
	<dict>
		<key>applicationBundleIDsByPath</key>
		<dict/>
		<key>applicationPaths</key>
		<array/>
		<key>inputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>outputTypeIdentifier</key>
		<string>com.apple.Automator.nothing</string>
		<key>presentationMode</key>
		<integer>15</integer>
		<key>processesInput</key>
		<false/>
		<key>serviceInputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>serviceOutputTypeIdentifier</key>
		<string>com.apple.Automator.nothing</string>
		<key>serviceProcessesInput</key>
		<false/>
		<key>systemImageName</key>
		<string>NSActionTemplate</string>
		<key>useAutomaticInputType</key>
		<false/>
		<key>workflowTypeIdentifier</key>
		<string>com.apple.Automator.servicesMenu</string>
	</dict>
</dict>
</plist>
"#
    )
}

/// Write the Quick Action for `exe` into `services` (`~/Library/Services`).
pub fn macos_install_in(services: &Path, exe: &Path) -> Result<PathBuf, String> {
    let bundle = services.join(WORKFLOW);
    let contents = bundle.join("Contents");
    std::fs::create_dir_all(&contents).map_err(|e| format!("cannot create {}: {e}", contents.display()))?;
    for (name, text) in [("Info.plist", macos_info_plist()), ("document.wflow", macos_workflow(exe))] {
        let file = contents.join(name);
        std::fs::write(&file, text).map_err(|e| format!("cannot write {}: {e}", file.display()))?;
    }
    Ok(bundle)
}

/// Remove the Quick Action from `services`; false when it was not there.
pub fn macos_remove_in(services: &Path) -> Result<bool, String> {
    let bundle = services.join(WORKFLOW);
    if !bundle.exists() {
        return Ok(false);
    }
    std::fs::remove_dir_all(&bundle).map_err(|e| format!("cannot remove {}: {e}", bundle.display()))?;
    Ok(true)
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    fn services() -> Result<PathBuf, String> {
        let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).ok_or("HOME is not set")?;
        Ok(PathBuf::from(home).join("Library/Services"))
    }

    /// Ask the system to read the services directory again; without it the
    /// entry shows up only after the next login.
    fn refresh() {
        let _ = std::process::Command::new("/System/Library/CoreServices/pbs").arg("-update").output();
    }

    pub fn install(exe: &Path) -> Result<String, String> {
        if let Some(why) = macos_unstable(exe) {
            return Err(why.into());
        }
        macos_install_in(&services()?, exe)?;
        refresh();
        Ok(format!("\"{LABEL}\" added to Finder: right-click a file, then Quick Actions (or Services)"))
    }

    pub fn remove() -> Result<String, String> {
        let removed = macos_remove_in(&services()?)?;
        refresh();
        Ok(removal_note(removed, "Finder", None))
    }
}

// ---------------------------------------------------------------------------
// Linux

/// Why a desktop entry for a program at `exe` would stop working: a path in
/// the Nix store is gone after an upgrade and a garbage collection, and the
/// entry would hide the one the package installed.
pub fn linux_unstable(exe: &Path) -> Option<&'static str> {
    exe.starts_with("/nix/store").then_some("this copy is in the Nix store, and its package already offers bxplore in the Open With list")
}

/// A value for the `Exec` key of a desktop entry: quoted, with the characters
/// that are special inside the quotes escaped, and `%` doubled. The escape
/// rule for string values is applied before the quoting rule, so every
/// backslash is written twice: `\\$` for a dollar sign, four for a backslash.
fn desktop_exec_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' | '`' | '$' => {
                out.push_str(r"\\");
                out.push(c);
            }
            '\\' => out.push_str(r"\\\\"),
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The desktop entry for a program at `exe`.
pub fn linux_desktop_entry(exe: &Path) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName=bxplore\nGenericName=Binary eXplorer\nComment=Viewer and editor for PE, ELF and Mach-O files\nExec={} %F\nIcon={APP_ID}\nTerminal=false\nCategories=Development;Debugger;\nMimeType={};\n",
        desktop_exec_quote(&exe.to_string_lossy()),
        MIME_TYPES.join(";")
    )
}

fn linux_files(data: &Path) -> (PathBuf, PathBuf) {
    (data.join("applications").join(format!("{APP_ID}.desktop")), data.join("icons/hicolor/256x256/apps").join(format!("{APP_ID}.png")))
}

/// Write the desktop entry and the icon under `data` (`~/.local/share`).
pub fn linux_install_in(data: &Path, exe: &Path) -> Result<PathBuf, String> {
    let (entry, icon) = linux_files(data);
    for (file, bytes) in [(&entry, linux_desktop_entry(exe).into_bytes()), (&icon, ICON.to_vec())] {
        let dir = file.parent().unwrap_or(data);
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        std::fs::write(file, bytes).map_err(|e| format!("cannot write {}: {e}", file.display()))?;
    }
    Ok(entry)
}

/// Remove them again; false when the entry was not there.
pub fn linux_remove_in(data: &Path) -> Result<bool, String> {
    let (entry, icon) = linux_files(data);
    if !entry.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&entry).map_err(|e| format!("cannot remove {}: {e}", entry.display()))?;
    let _ = std::fs::remove_file(icon);
    Ok(true)
}

/// The desktop entry a package installed, looked for in the directories of
/// `XDG_DATA_DIRS` (`data_dirs`) other than the user's own (`data`).
pub fn linux_package_entry(data_dirs: Option<&std::ffi::OsStr>, data: &Path) -> Option<PathBuf> {
    let dirs = data_dirs.filter(|d| !d.is_empty()).unwrap_or(std::ffi::OsStr::new("/usr/local/share:/usr/share"));
    std::env::split_paths(dirs).filter(|d| d != data).map(|d| linux_files(&d).0).find(|f| f.is_file())
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    fn data_dir() -> Result<PathBuf, String> {
        if let Some(d) = std::env::var_os("XDG_DATA_HOME").filter(|d| !d.is_empty()) {
            return Ok(PathBuf::from(d));
        }
        let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).ok_or("HOME is not set")?;
        Ok(PathBuf::from(home).join(".local/share"))
    }

    /// File managers read a cache of the MIME types; it is rebuilt when the
    /// tool is installed, and picked up at the next login otherwise.
    fn refresh(data: &Path) {
        let _ = std::process::Command::new("update-desktop-database").arg(data.join("applications")).output();
    }

    pub fn install(exe: &Path) -> Result<String, String> {
        if let Some(why) = linux_unstable(exe) {
            return Err(why.into());
        }
        let data = data_dir()?;
        let entry = linux_install_in(&data, exe)?;
        refresh(&data);
        Ok(format!("bxplore added to the file manager's Open With list for executable files ({})", entry.display()))
    }

    pub fn remove() -> Result<String, String> {
        let data = data_dir()?;
        let removed = linux_remove_in(&data)?;
        refresh(&data);
        let package = linux_package_entry(std::env::var_os("XDG_DATA_DIRS").as_deref(), &data)
            .map(|f| format!("bxplore is still offered through the installed package ({})", f.display()));
        Ok(removal_note(removed, "the file manager's Open With list", package.as_deref()))
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;

    pub fn install(_exe: &Path) -> Result<String, String> {
        Err("not supported on this system".into())
    }

    pub fn remove() -> Result<String, String> {
        Err("not supported on this system".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_values_cover_every_type_with_a_quoted_command() {
        let values = windows_values(r"C:\Program Files\bxplore\bxplore.exe");
        assert_eq!(values.len(), EXTENSIONS.len() * 3);
        let command = values.iter().find(|v| v.0 == r"Software\Classes\SystemFileAssociations\.dll\shell\bxplore\command").unwrap();
        assert_eq!(command.1, None);
        assert_eq!(command.2, r#""C:\Program Files\bxplore\bxplore.exe" "%1""#);
        let label = values.iter().find(|v| v.0 == windows_key("exe") && v.1.is_none()).unwrap();
        assert_eq!(label.2, LABEL);
        assert!(values.iter().any(|v| v.0 == windows_key("so") && v.1 == Some("Icon")));
    }

    #[test]
    fn a_program_in_a_bundle_is_opened_as_an_application() {
        let exe = Path::new("/Applications/It's bxplore.app/Contents/MacOS/bxplore");
        assert_eq!(bundle_of(exe).unwrap(), Path::new("/Applications/It's bxplore.app"));
        assert_eq!(macos_command(exe), r#"/usr/bin/open -n -a '/Applications/It'\''s bxplore.app' --args "$@""#);
        let bare = Path::new("/usr/local/bin/bxplore");
        assert!(bundle_of(bare).is_none());
        assert_eq!(macos_command(bare), r#"'/usr/local/bin/bxplore' "$@" >/dev/null 2>&1 &"#);
    }

    #[test]
    fn the_workflow_holds_the_command_as_xml_text() {
        let text = macos_workflow(Path::new("/opt/a&b/bxplore"));
        assert!(text.contains("<string>'/opt/a&amp;b/bxplore' \"$@\" &gt;/dev/null 2&gt;&amp;1 &amp;</string>"), "{text}");
        assert!(macos_info_plist().contains(&format!("<string>{LABEL}</string>")));
    }

    #[test]
    fn quick_action_and_desktop_entry_are_written_and_removed() {
        let dir = std::env::temp_dir().join(format!("bxplore-shellmenu-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let exe = Path::new("/opt/my tools/bxplore");

        let bundle = macos_install_in(&dir.join("Services"), exe).unwrap();
        assert!(bundle.join("Contents/Info.plist").is_file());
        assert!(bundle.join("Contents/document.wflow").is_file());
        assert!(macos_remove_in(&dir.join("Services")).unwrap());
        assert!(!macos_remove_in(&dir.join("Services")).unwrap());

        let entry = linux_install_in(&dir.join("share"), exe).unwrap();
        let text = std::fs::read_to_string(&entry).unwrap();
        assert!(text.contains("Exec=\"/opt/my tools/bxplore\" %F\n"), "{text}");
        assert!(text.contains("MimeType=application/x-executable;"));
        assert!(text.ends_with(";\n"));
        assert!(dir.join("share/icons/hicolor/256x256/apps/io.github.bxplore.Bxplore.png").is_file());
        assert!(linux_remove_in(&dir.join("share")).unwrap());
        assert!(!linux_remove_in(&dir.join("share")).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn special_characters_in_the_path_are_escaped_in_the_desktop_entry() {
        let text = linux_desktop_entry(Path::new("/opt/100%/a\"b$c/bxplore"));
        assert!(text.contains(r#"Exec="/opt/100%%/a\\"b\\$c/bxplore" %F"#), "{text}");
        let text = linux_desktop_entry(Path::new(r"/opt/a\b`c/bxplore"));
        assert!(text.contains(r#"Exec="/opt/a\\\\b\\`c/bxplore" %F"#), "{text}");
    }

    #[test]
    fn reg_exe_is_always_an_absolute_path() {
        assert_eq!(windows_reg_exe(Some(r"D:\WinNT".into())), Path::new(r"D:\WinNT").join("System32").join("reg.exe"));
        for missing in [None, Some(std::ffi::OsString::new())] {
            assert_eq!(windows_reg_exe(missing), Path::new(r"C:\Windows").join("System32").join("reg.exe"));
        }
    }

    #[test]
    fn the_reg_files_add_and_delete_every_type() {
        let add = windows_reg_file(r"C:\My Tools\bxplore.exe");
        assert!(add.starts_with("Windows Registry Editor Version 5.00\r\n\r\n["), "{add}");
        assert!(
            add.contains(concat!(
                r"[HKEY_CURRENT_USER\Software\Classes\SystemFileAssociations\.exe\shell\bxplore]",
                "\r\n",
                r#"@="Open with bxplore""#,
                "\r\n",
                r#""Icon"="\"C:\\My Tools\\bxplore.exe\"""#,
                "\r\n\r\n",
                r"[HKEY_CURRENT_USER\Software\Classes\SystemFileAssociations\.exe\shell\bxplore\command]",
                "\r\n",
                r#"@="\"C:\\My Tools\\bxplore.exe\" \"%1\"""#,
                "\r\n"
            )),
            "{add}"
        );
        assert_eq!(add.matches("\r\n[HKEY_CURRENT_USER").count(), EXTENSIONS.len() * 2);
        let delete = windows_unreg_file();
        assert_eq!(delete.matches("\r\n[-HKEY_CURRENT_USER\\Software\\Classes\\SystemFileAssociations\\.").count(), EXTENSIONS.len());
        assert!(delete.contains(r"[-HKEY_CURRENT_USER\Software\Classes\SystemFileAssociations\.lib\shell\bxplore]"));
    }

    #[test]
    fn a_path_that_does_not_last_is_refused() {
        assert!(macos_unstable(Path::new("/Volumes/bxplore/bxplore.app/Contents/MacOS/bxplore")).is_some());
        assert!(macos_unstable(Path::new("/private/var/folders/ab/T/AppTranslocation/1F2E/d/bxplore.app/Contents/MacOS/bxplore")).is_some());
        assert!(macos_unstable(Path::new("/Applications/bxplore.app/Contents/MacOS/bxplore")).is_none());
        assert!(macos_unstable(Path::new("/Users/me/Volumes/bxplore")).is_none());
        assert!(linux_unstable(Path::new("/nix/store/abc-bxplore-0.1.0/bin/bxplore")).is_some());
        assert!(linux_unstable(Path::new("/home/me/nix/store/bxplore")).is_none());
        assert!(linux_unstable(Path::new("/usr/bin/bxplore")).is_none());
    }

    #[test]
    fn remove_says_what_is_still_in_the_menu() {
        assert_eq!(removal_note(true, "Finder", None), "\"Open with bxplore\" removed from Finder");
        assert_eq!(removal_note(false, "Finder", None), "No entry added from Preferences was found");
        assert_eq!(
            removal_note(false, "Explorer", Some("The installer's entry stays")),
            "No entry added from Preferences was found. The installer's entry stays"
        );

        let dir = std::env::temp_dir().join(format!("bxplore-shellmenu-package-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (user, system) = (dir.join("user"), dir.join("system"));
        let entry = linux_install_in(&system, Path::new("/usr/bin/bxplore")).unwrap();
        linux_install_in(&user, Path::new("/opt/bxplore")).unwrap();
        let dirs = std::env::join_paths([&user, &dir.join("empty"), &system]).unwrap();
        assert_eq!(linux_package_entry(Some(&dirs), &user), Some(entry));
        assert_eq!(linux_package_entry(Some(&dirs), &system), Some(linux_files(&user).0));
        assert_eq!(linux_package_entry(Some(dir.join("empty").as_os_str()), &user), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_with_a_line_break_is_refused() {
        assert!(install_for(Path::new("/opt/a\nb/bxplore")).is_err());
    }
}
