#!/bin/sh
set -eu

# macOS/Xcode-only syntax check for the open Objective-C core. It deliberately
# does not link or inject anything; Linux/Windows CI should run the Go tests in
# open-engine instead.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if SDK=$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null); then
  SDK_NAME=iphoneos
else
  SDK=$(xcrun --sdk macosx --show-sdk-path)
  SDK_NAME=macosx
fi
CLANG=$(xcrun --find clang)

echo "Objective-C syntax SDK: $SDK_NAME ($SDK)"
echo "Objective-C syntax clang: $CLANG"

for source in "$ROOT"/src/idh-core/*.m; do
  "$CLANG" -fobjc-arc -fblocks -fsyntax-only -isysroot "$SDK" \
    -I"$ROOT/src/idh-core" "$source"
done

echo "idh-core Objective-C syntax: OK"
