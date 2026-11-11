# Packaging

Scripts that build the release packages into `dist/` (ignored by git).

| Platform | Package | Architectures | Built by |
|---|---|---|---|
| Windows | `bxplore-<v>-windows-<arch>-portable.zip` (just `bxplore.exe`) | x64, arm64 | `packaging/vm.sh windows` |
| Windows | `bxplore-<v>-windows-<arch>-setup.exe` (NSIS installer) | x64, arm64 | `packaging/vm.sh windows` |
| macOS | `bxplore-<v>-macos-universal.dmg` | Intel and Apple Silicon in one app | `packaging/macos/build.sh` |
| Linux | `bxplore-<v>-linux-<arch>` and `.tar.gz` (standalone executable) | x86_64, aarch64 | `packaging/vm.sh linux bin` |
| Linux | `bxplore-<v>-linux-<arch>.flatpak` | x86_64, aarch64 | `packaging/vm.sh linux flatpak` |
| Linux | `bxplore_<v>_<arch>.snap` | amd64, arm64 | `packaging/vm.sh linux snap` |
| Linux | Nix flake (`flake.nix` in the repository root) | x86_64, aarch64 | `nix build` |

The version comes from `Cargo.toml`. The application ID, title and publisher are set in
`packaging/common.sh`; the ID also appears in `linux/bxplore.desktop`, `linux/metainfo.xml` and
`flake.nix`.

## Building

The Linux and Windows packages are built in a Lima VM with Ubuntu 26.04 (`brew install lima`).
The VM sees only this repository (read-only) and `dist/` (writable).

    packaging/vm.sh create     # once: creates the VM and installs the tools (about 15 minutes)
    packaging/vm.sh linux      # executables, Flatpak and snap
    packaging/vm.sh windows    # portable zip and installer
    packaging/macos/build.sh   # on the Mac itself
    packaging/vm.sh test       # tests everything in dist/
    packaging/vm.sh delete     # removes the VM

The Flatpak and the snap wrap the standalone executable, so build `bin` before them.

## Releases

`.github/workflows/release.yml` builds the same packages on GitHub Actions with these scripts
(Nix excepted) and attaches them, with a `SHA256SUMS` file, to a draft release:

    git tag v0.2.0 && git push origin v0.2.0

- The tag must be `v` plus the version in `Cargo.toml`, or the run stops before building.
  A tag with a hyphen (`v0.2.0-rc1`) makes a prerelease.
- The tests run first. The Windows packages are cross-built on Ubuntu as in the VM. The
  Flatpak and snap for each architecture build on a runner of that architecture. The DMG
  builds on macOS.
- The release stays a draft until you publish it from the Releases page. To rebuild a
  draft, open the tag's run in the Actions tab and choose **Re-run all jobs**; this replaces
  the files in the draft. Once the release is published, a re-run fails instead of
  changing its files.
- **Run workflow** in the Actions tab builds the packages as workflow artifacts and never
  touches a release, even when you pick a tag.
- Signing turns on when its repository secrets are set (see the comment at the top of the
  workflow).

## How each package is made

- **Linux executable**: `cargo zigbuild` links against glibc 2.17, so one file runs on
  distributions from CentOS 7 (2014) onwards. It needs glibc: it does not run on musl
  distributions such as Alpine. The GUI needs X11 or Wayland and OpenGL or Vulkan drivers,
  which every desktop installation has.
- **Flatpak**: runtime `org.freedesktop.Platform` 25.08, with access to the host file system
  because the files to inspect can be anywhere.
- **Snap**: base `core24`, strict confinement with the `home` and `removable-media` plugs, so
  it opens files in the home directory and on removable media only.
- **Windows**: cross-compiled with MinGW-w64 (x64) and llvm-mingw (arm64), C runtime linked
  statically, icon and version information embedded. The installer adds a Start menu shortcut,
  an optional desktop shortcut, an "Open with bxplore" Explorer menu entry on executable files and an uninstaller. The
  installer program itself is 32-bit x86, which every 64-bit Windows runs.
- **macOS**: both architectures built with the `standalone` profile and joined with `lipo`,
  minimum macOS 11.
- **Nix**: `nix build`, `nix run` and `nix develop` on Linux. On NixOS the program runs as it
  is. With Nix on another distribution the GUI needs
  [nixGL](https://github.com/nix-community/nixGL) to find the graphics drivers
  (`nixGL bxplore`); the command line (`bxplore --dump`) works without it.

## "Open with bxplore"

| Package | How the file manager entry gets there |
|---|---|
| Windows installer | Optional component (on by default): a right-click entry on executable file types (`.exe`, `.dll`, `.sys`, `.so`, `.dylib` and others), for all users. Removed by the uninstaller. |
| Windows portable zip | Preferences, "Add Open with bxplore": the same entry for the current user, pointing at wherever `bxplore.exe` is. |
| macOS | Preferences adds a Finder Quick Action (`~/Library/Services`). The app declares no document types, because it would not receive a file that Finder opens. |
| Flatpak, snap, Nix | The desktop entry lists the executable MIME types, so file managers offer bxplore under "Open With". |
| Linux standalone executable | Preferences writes the same desktop entry and the icon to `~/.local/share`. |

The file type and MIME type lists are in `src/shellmenu.rs`; the installer script
(`windows/bxplore.nsi`) and `linux/bxplore.desktop` repeat them.

## Signing

Packages are unsigned unless these variables are set:

| Variable | Effect |
|---|---|
| `MACOS_SIGN_IDENTITY` | Developer ID used by `codesign` (default: ad hoc signature) |
| `MACOS_NOTARY_PROFILE` | `notarytool` keychain profile; the DMG is notarized and stapled |
| `WINDOWS_SIGN_PFX`, `WINDOWS_SIGN_PASSWORD` | PKCS#12 certificate for `osslsigncode` (install it in the VM); signs `bxplore.exe` and the installer |
| `WINDOWS_SIGN_TS` | timestamp server for the Windows signature |

Unsigned, Windows shows a SmartScreen prompt and macOS asks for confirmation on first launch
(right click, Open).

## What the tests cover

`packaging/vm.sh test` runs in the arm64 VM; x86_64 Linux code runs through Rosetta.

- Standalone executables: glibc requirement, and a run on CentOS 7, Debian 11, Ubuntu 26.04
  and Fedora containers for both architectures; the arm64 window is opened under Xvfb.
- Flatpak: installed and run for both architectures, command line and window.
- Snap: the arm64 snap is installed and run; the amd64 snap is only inspected.
- Windows: the executables and installers are inspected (architecture, subsystem, resources,
  DLL imports), not run.
- Nix: `nix build`, `nix flake check`, and a run of the result (window through nixGL).

The DMG is checked on the Mac by the build script (`codesign --verify`).

## Icons

`icons/bxplore.svg` is the source. `icons/generate.sh` (run in the VM) writes the PNG sizes and
`bxplore.ico`; the macOS build makes the `.icns` from the PNGs.
