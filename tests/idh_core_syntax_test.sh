#!/bin/sh
set -eu

# macOS/Xcode-only syntax check for the open Objective-C core. It deliberately
# does not link or inject anything; Linux/Windows CI should run the Go tests in
# open-engine instead.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SDK=$(xcrun --sdk iphoneos --show-sdk-path)

for source in "$ROOT"/src/idh-core/*.m; do
  clang -fobjc-arc -fblocks -fsyntax-only -isysroot "$SDK" \
    -I"$ROOT/src/idh-core" "$source"
done

echo "idh-core Objective-C syntax: OK"
