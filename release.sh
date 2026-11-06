#!/bin/sh
# Builds the Decky plugin and packages it as deckforge.zip, the file install.sh
# downloads. CI runs this for each version tag; run it yourself on Linux to test
# a build. The version must match package.json.
#
#   ./release.sh 0.1.0
set -eu

cd "$(dirname "$0")"

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "Usage: ./release.sh <version>" >&2; exit 1; }

PACKAGE_VERSION="$(node -p "require('./package.json').version")"
if [ "$VERSION" != "$PACKAGE_VERSION" ]; then
    echo "Error: version $VERSION does not match package.json ($PACKAGE_VERSION)." >&2
    exit 1
fi

cargo build --release --manifest-path forge/Cargo.toml
npm ci
npm run build

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir "$STAGE/bin"
cp "${CARGO_TARGET_DIR:-forge/target}/release/deckforge-engine" "$STAGE/bin/deckforge-engine"
chmod 755 "$STAGE/bin/deckforge-engine"
cp -R dist relay main.py plugin.json package.json LICENSE readme.md "$STAGE/"
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} +

# Python's zipfile, so this needs no zip tool beyond what the build already uses.
OUTPUT="$PWD/deckforge.zip"
rm -f "$OUTPUT"
(cd "$STAGE" && python3 -m zipfile -c "$OUTPUT" bin dist relay main.py plugin.json package.json LICENSE readme.md)

echo "Created $OUTPUT for DeckForge v$VERSION"
