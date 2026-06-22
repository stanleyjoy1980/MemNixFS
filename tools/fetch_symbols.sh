#!/usr/bin/env bash
# fetch_symbols.sh — auto-generate a Volatility-compatible ISF for a Linux
# kernel release.
#
# Usage:
#   ./fetch_symbols.sh <release> [output_path]
#
# Examples:
#   ./fetch_symbols.sh 6.14.0-36-generic
#   ./fetch_symbols.sh 6.14.0-36-generic /tmp/my.json.xz
#
# What it does (per distro):
#   ubuntu  →  Enable the ddebs repo, install `linux-image-<release>-dbgsym`,
#             extract vmlinux, run dwarf2json, patch for vol3 compat, xz-compress.
#   debian  →  TODO (placeholder)
#   other   →  Refuses; print a manual recipe.
#
# Outputs the resulting ISF to either the user-given path or, if omitted, to
# the standard cache:
#   $LMPFS_SYMBOL_CACHE/<release>.json.xz                       (if set)
#   $XDG_CACHE_HOME/lmpfs/symbols/<release>.json.xz             (if set)
#   ~/.cache/lmpfs/symbols/<release>.json.xz                    (default)
#
# Designed to be safely re-runnable: if the ISF already exists, skip the rest.
#
# Invoked by the engine via:
#   wsl bash -lc "/mnt/c/.../tools/fetch_symbols.sh '<release>' '<output>'"
# but is also useful standalone.

set -euo pipefail

err() { echo "[fetch_symbols] $*" >&2; }
log() { echo "[fetch_symbols] $*"; }

RELEASE="${1:-}"
OUTPUT="${2:-}"
VMLINUX_PATH="${3:-}"   # OPTIONAL: pre-supplied vmlinux skips distro install
[ -z "$RELEASE" ] && { err "usage: $0 <release> [output_path] [vmlinux_path]"; exit 1; }

# Resolve default output path.
if [ -z "$OUTPUT" ]; then
    if [ -n "${LMPFS_SYMBOL_CACHE:-}" ]; then
        OUTPUT="$LMPFS_SYMBOL_CACHE/$RELEASE.json.xz"
    elif [ -n "${XDG_CACHE_HOME:-}" ]; then
        OUTPUT="$XDG_CACHE_HOME/lmpfs/symbols/$RELEASE.json.xz"
    else
        OUTPUT="${HOME:-/tmp}/.cache/lmpfs/symbols/$RELEASE.json.xz"
    fi
fi
mkdir -p "$(dirname "$OUTPUT")"

if [ -f "$OUTPUT" ]; then
    log "ISF already exists: $OUTPUT  (delete to regenerate)"
    exit 0
fi

# -- Distro detection --------------------------------------------------------
DISTRO=unknown
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO="${ID:-unknown}"
fi
log "Distro: $DISTRO"
log "Target release: $RELEASE"
log "Output ISF: $OUTPUT"

# -- Install dwarf2json if absent --------------------------------------------
DWARF2JSON=""
for c in dwarf2json "$HOME/go/bin/dwarf2json" /usr/local/bin/dwarf2json; do
    if command -v "$c" >/dev/null 2>&1; then DWARF2JSON="$c"; break; fi
    if [ -x "$c" ]; then DWARF2JSON="$c"; break; fi
done
if [ -z "$DWARF2JSON" ]; then
    log "Installing dwarf2json (Go)..."
    if ! command -v go >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update -y
            sudo apt-get install -y golang-go
        else
            err "Need 'go' to build dwarf2json. Install Go, then re-run."
            exit 2
        fi
    fi
    GO111MODULE=on go install github.com/volatilityfoundation/dwarf2json@latest
    DWARF2JSON="$HOME/go/bin/dwarf2json"
fi
log "dwarf2json: $DWARF2JSON"

need_pkg() {
    command -v "$1" >/dev/null 2>&1 || sudo apt-get install -y "$1"
}

VMLINUX=""

# Pre-supplied vmlinux short-circuits the distro-specific install.
if [ -n "$VMLINUX_PATH" ]; then
    [ -f "$VMLINUX_PATH" ] || { err "vmlinux not found at: $VMLINUX_PATH"; exit 6; }
    log "Using user-supplied vmlinux: $VMLINUX_PATH"
    VMLINUX="$VMLINUX_PATH"
    DISTRO="user-supplied"
fi

case "$DISTRO" in
user-supplied)
    : # vmlinux already set; skip distro install
    ;;
ubuntu)
    # Enable ddebs (debug symbol repo) if not already.
    if [ ! -f /etc/apt/sources.list.d/ddebs.sources ] \
       && [ ! -f /etc/apt/sources.list.d/ddebs.list ]; then
        log "Enabling Ubuntu ddebs repo..."
        sudo apt-get update -y
        sudo apt-get install -y ubuntu-dbgsym-keyring
        CODENAME="${VERSION_CODENAME:-noble}"
        sudo tee /etc/apt/sources.list.d/ddebs.sources >/dev/null <<EOF
Types: deb
URIs: http://ddebs.ubuntu.com/
Suites: $CODENAME ${CODENAME}-updates ${CODENAME}-proposed
Components: main universe restricted multiverse
Signed-By: /usr/share/keyrings/ubuntu-dbgsym-keyring.gpg
EOF
        sudo apt-get update -y
    fi
    need_pkg dpkg-dev
    need_pkg xz-utils
    need_pkg python3

    # Download the dbgsym package.
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    pushd "$work" >/dev/null
    PKG="linux-image-unsigned-${RELEASE}-dbgsym"
    if ! apt-get download -y "$PKG" 2>/dev/null; then
        # Some kernels are packaged as linux-image-<release>-dbgsym (no unsigned).
        PKG="linux-image-${RELEASE}-dbgsym"
        apt-get download -y "$PKG"
    fi
    dpkg-deb -x ./"$PKG"_*.ddeb extracted
    VMLINUX="$work/extracted/usr/lib/debug/boot/vmlinux-$RELEASE"
    [ -f "$VMLINUX" ] || { err "vmlinux not found inside $PKG"; exit 3; }
    popd >/dev/null
    ;;
debian)
    CODENAME="${VERSION_CODENAME:-bookworm}"
    # Add debian-debug repo if absent
    if ! grep -rq "debug.mirrors.debian.org" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
        log "Enabling Debian debug-symbol repo..."
        sudo tee /etc/apt/sources.list.d/debian-dbg.list >/dev/null <<EOF
deb http://debug.mirrors.debian.org/debian-debug/ ${CODENAME}-debug main contrib non-free non-free-firmware
EOF
        sudo apt-get update -y || true
    fi
    need_pkg dpkg-dev
    need_pkg xz-utils
    need_pkg python3
    work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
    pushd "$work" >/dev/null
    PKG="linux-image-${RELEASE}-dbg"
    apt-get download -y "$PKG"
    dpkg-deb -x ./"$PKG"_*.deb extracted
    VMLINUX="$work/extracted/usr/lib/debug/boot/vmlinux-${RELEASE}"
    [ -f "$VMLINUX" ] || { err "vmlinux not in $PKG"; exit 3; }
    popd >/dev/null
    ;;
fedora|rhel|rocky|almalinux|centos)
    # dnf debuginfo-install handles repo activation automatically
    if ! command -v dnf >/dev/null 2>&1; then
        err "dnf not found; cannot auto-fetch on this RPM-based system"; exit 4
    fi
    log "Installing kernel-debuginfo for $RELEASE via dnf..."
    sudo dnf debuginfo-install -y "kernel-${RELEASE%.*}" || \
    sudo dnf install -y "kernel-debuginfo-${RELEASE}"
    VMLINUX="/usr/lib/debug/lib/modules/${RELEASE}/vmlinux"
    [ -f "$VMLINUX" ] || VMLINUX="/usr/lib/debug/boot/vmlinux-${RELEASE}"
    [ -f "$VMLINUX" ] || { err "vmlinux not found under /usr/lib/debug"; exit 3; }
    ;;
arch|manjaro|endeavouros)
    if ! command -v pacman >/dev/null 2>&1; then
        err "pacman not found on '$DISTRO'"; exit 4
    fi
    # Arch ships debug symbols via the separate core-debug / extra-debug repos
    if ! grep -q "^\[core-debug\]" /etc/pacman.conf 2>/dev/null; then
        log "Enabling Arch debug repos in /etc/pacman.conf..."
        sudo tee -a /etc/pacman.conf >/dev/null <<'EOF'

[core-debug]
Include = /etc/pacman.d/mirrorlist
[extra-debug]
Include = /etc/pacman.d/mirrorlist
EOF
        sudo pacman -Sy
    fi
    sudo pacman -S --noconfirm linux-debug
    VMLINUX="/usr/lib/debug/usr/lib/modules/${RELEASE}/vmlinux"
    [ -f "$VMLINUX" ] || { err "vmlinux not found at $VMLINUX"; exit 3; }
    ;;
opensuse*)
    sudo zypper install -y "kernel-default-debuginfo=${RELEASE%-*}"
    VMLINUX="/usr/lib/debug/boot/vmlinux-${RELEASE}.debug"
    [ -f "$VMLINUX" ] || { err "vmlinux not found at $VMLINUX"; exit 3; }
    ;;
*)
    err "Distro '$DISTRO' auto-fetch not implemented."
    err "Generic recipe:"
    err "  1. Install the debug symbol package for kernel $RELEASE on a"
    err "     machine running the same distro, OR mount the disk image."
    err "  2. Locate the vmlinux file with full DWARF (e.g."
    err "     /usr/lib/debug/lib/modules/$RELEASE/vmlinux)."
    err "  3. Run: $DWARF2JSON linux --elf <path-to-vmlinux> | xz > '$OUTPUT'"
    exit 5
    ;;
esac

# -- Generate ISF ------------------------------------------------------------
log "Running dwarf2json on $VMLINUX ..."
tmp_json="$(mktemp --suffix=.json)"
"$DWARF2JSON" linux --elf "$VMLINUX" > "$tmp_json"

# -- Patch for vol3 / lmpfs compatibility ------------------------------------
# Some kernels rename module_sect_attrs → module_sect_attr; we add an alias
# so plugins keyed on either name work.
python3 - "$tmp_json" <<'PY'
import json, sys
p = sys.argv[1]
with open(p) as f: d = json.load(f)
ut = d.get('user_types', {})
if 'module_sect_attr' not in ut and 'module_sect_attrs' in ut:
    ut['module_sect_attr'] = ut['module_sect_attrs']
if 'module_sect_attrs' not in ut and 'module_sect_attr' in ut:
    ut['module_sect_attrs'] = ut['module_sect_attr']
with open(p, 'w') as f: json.dump(d, f)
PY

# -- Compress + place ---------------------------------------------------------
case "$OUTPUT" in
*.xz) xz -T0 -z -c "$tmp_json" > "$OUTPUT" ;;
*)    cp "$tmp_json" "$OUTPUT" ;;
esac
rm -f "$tmp_json"

log "OK: ISF written to $OUTPUT"
