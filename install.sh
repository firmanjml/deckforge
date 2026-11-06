#!/bin/sh
# DeckForge installer: downloads the latest release into Decky Loader.
#
#   curl -L https://github.com/firmanjml/deckforge/raw/master/install.sh | sh
#
# Add "-s -- --yes" after "sh" to skip the reinstall question.
#
# All work happens in main, called on the last line, so a download cut off
# partway through runs nothing.
set -eu

PLUGIN_NAME="DeckForge"
REPO="firmanjml/deckforge"
ZIP_URL="${DECKFORGE_ZIP_URL:-https://github.com/$REPO/releases/latest/download/deckforge.zip}"

TEMP_DIR=""
ASSUME_YES=0

cleanup() {
    if [ -n "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}

fail() {
    echo "" >&2
    echo "Error: $1" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || fail "'$1' is required but was not found."
}

check_system() {
    [ "$(uname -s)" = "Linux" ] || fail "This installer is for SteamOS/Linux only."
    [ "$(uname -m)" = "x86_64" ] || fail "DeckForge only has an x86_64 build."
    [ "$(id -u)" -ne 0 ] || fail "Run this as your normal user, not as root. It asks for sudo when needed."
    need_command curl
    need_command unzip
    need_command sudo
    [ -d "$HOME/homebrew/plugins" ] || fail "Decky Loader does not appear to be installed. Install it first: https://decky.xyz"
}

# Reads from the terminal, because under "curl | sh" stdin is this script.
confirm_reinstall() {
    echo ""
    echo "Existing installation found at: $PLUGIN_DIR"
    echo "It will be replaced. Installed trainers are kept."
    if [ "$ASSUME_YES" -eq 1 ]; then
        return 0
    fi
    if ! (: </dev/tty) 2>/dev/null; then
        fail "No terminal to ask for confirmation. Add \"-s -- --yes\" after \"sh\" to reinstall."
    fi
    printf 'Continue? (y/N): ' >/dev/tty
    reply=""
    read -r reply </dev/tty || true
    case "$reply" in
        [Yy]*) return 0 ;;
    esac
    return 1
}

# Download and check the release before touching any existing installation.
download_release() {
    echo ""
    echo "Downloading the latest release..."
    if ! curl -L -f -sS "$ZIP_URL" -o "$TEMP_DIR/deckforge.zip"; then
        fail "Could not download a release. Check your internet connection, and that a release exists: https://github.com/$REPO/releases"
    fi
    echo "Extracting..."
    if ! unzip -q -o "$TEMP_DIR/deckforge.zip" -d "$TEMP_DIR/plugin"; then
        fail "The downloaded release could not be extracted."
    fi
    for file in plugin.json main.py dist/index.js bin/deckforge-engine relay/main.py; do
        [ -f "$TEMP_DIR/plugin/$file" ] || fail "The downloaded release is missing $file."
    done
}

install_files() {
    echo ""
    echo "Installing to $PLUGIN_DIR (requires sudo permission)..."
    sudo rm -rf "$PLUGIN_DIR" || fail "Could not remove the old installation."
    sudo mkdir -p "$PLUGIN_DIR" || fail "Could not create the plugin directory."
    sudo cp -R "$TEMP_DIR/plugin/." "$PLUGIN_DIR/" || fail "Could not copy the plugin files."
    sudo chown -R "$(id -un):$(id -gn)" "$PLUGIN_DIR" || fail "Could not set the plugin file owner."
    chmod -R u+rwX,go+rX "$PLUGIN_DIR"
    chmod 755 "$PLUGIN_DIR/bin/deckforge-engine"
}

restart_decky() {
    echo ""
    echo "Restarting Decky Loader..."
    if sudo systemctl restart plugin_loader; then
        echo "Decky Loader restarted. DeckForge is in the Quick Access menu."
    else
        echo "Could not restart Decky Loader automatically. Reboot, or run:"
        echo "  sudo systemctl restart plugin_loader"
    fi
}

main() {
    for arg in "$@"; do
        case "$arg" in
            --yes | -y) ASSUME_YES=1 ;;
            *) fail "Unknown option: $arg" ;;
        esac
    done

    echo "================================"
    echo "  $PLUGIN_NAME Installer"
    echo "================================"

    check_system
    PLUGIN_DIR="$HOME/homebrew/plugins/$PLUGIN_NAME"

    if [ -d "$PLUGIN_DIR" ] && ! confirm_reinstall; then
        echo "Installation cancelled."
        exit 0
    fi

    trap cleanup EXIT
    TEMP_DIR="$(mktemp -d)"
    download_release
    install_files
    restart_decky

    echo ""
    echo "================================"
    echo "  Installation Complete!"
    echo "================================"
    echo "Plugin installed to: $PLUGIN_DIR"
}

main "$@"
