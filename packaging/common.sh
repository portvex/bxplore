# Shared settings for the packaging scripts. Sourced, not run.
# Change the identity here; every package reads it from this file.
APP_NAME="bxplore"
APP_TITLE="bxplore"
APP_ID="io.github.bxplore.Bxplore"
APP_PUBLISHER="bxplore contributors"
APP_SUMMARY="Viewer and editor for PE, ELF and Mach-O files"
APP_LICENSE="MIT"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
# Numeric part only (0.2.0-rc1 -> 0.2.0), for fields that accept nothing else:
# Windows VERSIONINFO, NSIS VIProductVersion, macOS CFBundleVersion.
APP_VERSION_NUM="${APP_VERSION%%-*}"
