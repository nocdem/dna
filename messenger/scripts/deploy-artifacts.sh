#!/bin/sh
# Deploy artifacts to artifacts.cpunk.io
set -e

VERSION=$(grep '^version:' dna_messenger_flutter/pubspec.yaml | sed 's/version: //' | cut -d'+' -f1)
BUILD_CODE=$(grep '^version:' dna_messenger_flutter/pubspec.yaml | sed 's/version: //' | cut -d'+' -f2)
echo "Deploying version ${VERSION} (build ${BUILD_CODE})"

mkdir -p /artifacts/dna-messenger/android
mkdir -p /artifacts/dna-messenger/linux
mkdir -p /artifacts/dna-messenger/windows

# Copy artifacts
cp dist/*.AppImage /artifacts/dna-messenger/linux/dna-messenger-${VERSION}-x86_64.AppImage 2>/dev/null || true
cp dist/*.tar.gz /artifacts/dna-messenger/linux/dna-messenger-${VERSION}-linux-x64.tar.gz 2>/dev/null || true
cp dist/*.apk /artifacts/dna-messenger/android/dna-messenger-${VERSION}.apk 2>/dev/null || true
cp dist/dna-messenger-setup-*.exe /artifacts/dna-messenger/windows/dna-messenger-${VERSION}-setup.exe 2>/dev/null || true

# Determine Windows URL
WINURL="null"
if [ -f "/artifacts/dna-messenger/windows/dna-messenger-${VERSION}-setup.exe" ]; then
    WINURL="https://artifacts.cpunk.io/dna-messenger/windows/dna-messenger-${VERSION}-setup.exe"
fi

# Create latest.json
cat > /artifacts/dna-messenger/latest.json << EOF
{
  "version": "${VERSION}",
  "build_code": "${BUILD_CODE}",
  "commit": "${CI_COMMIT_SHORT_SHA}",
  "date": "$(date -Iseconds)",
  "pipeline": "${CI_PIPELINE_ID}",
  "downloads": {
    "android": "https://artifacts.cpunk.io/dna-messenger/android/dna-messenger-${VERSION}.apk",
    "linux_appimage": "https://artifacts.cpunk.io/dna-messenger/linux/dna-messenger-${VERSION}-x86_64.AppImage",
    "linux_tarball": "https://artifacts.cpunk.io/dna-messenger/linux/dna-messenger-${VERSION}-linux-x64.tar.gz",
    "windows": "${WINURL}"
  }
}
EOF

echo "=== latest.json ==="
cat /artifacts/dna-messenger/latest.json

echo "=== Deployed artifacts ==="
ls -la /artifacts/dna-messenger/android/ 2>/dev/null || echo "No Android artifacts"
ls -la /artifacts/dna-messenger/linux/ 2>/dev/null || echo "No Linux artifacts"
ls -la /artifacts/dna-messenger/windows/ 2>/dev/null || echo "No Windows artifacts"
