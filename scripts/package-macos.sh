#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: bash $0 <release-directory> <output.tar.gz>" >&2
    exit 2
fi
if [[ $(uname -s) != Darwin ]]; then
    echo "PakCipher app bundles must be packaged on macOS." >&2
    exit 2
fi

release_dir=$1
archive=$2
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=$("$release_dir/pakcipher" --version)
version=${version#pakcipher }
staging=$(mktemp -d "${TMPDIR:-/tmp}/pakcipher.XXXXXXXX")
trap 'rm -rf -- "$staging"' EXIT

app="$staging/PakCipher.app"
mkdir -p "$app/Contents/MacOS"
install -m 755 "$release_dir/pakcipher-gui" "$app/Contents/MacOS/pakcipher-gui"
install -m 755 "$release_dir/pakcipher" "$staging/pakcipher"
install -m 644 "$repo_dir/gui/macos/Info.plist" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy \
    -c "Add :CFBundleVersion string $version" \
    -c "Add :CFBundleShortVersionString string $version" \
    "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist"
codesign --force --sign - "$app"
codesign --verify --strict "$app"
tar -czf "$archive" -C "$staging" PakCipher.app pakcipher
