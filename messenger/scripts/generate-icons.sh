#!/bin/bash
# Generate app icons from logo.svg for all platforms

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOGO="$PROJECT_DIR/logo.svg"
FLUTTER_DIR="$PROJECT_DIR/dna_messenger_flutter"

if [ ! -f "$LOGO" ]; then
    echo "Error: logo.svg not found at $LOGO"
    exit 1
fi

echo "Generating icons from $LOGO..."

# Flutter asset icon (1024x1024)
mkdir -p "$FLUTTER_DIR/assets"
convert -background none "$LOGO" -resize 1024x1024 "$FLUTTER_DIR/assets/icon.png"
echo "  Created assets/icon.png (1024x1024)"

# Android launcher icons
convert -background none "$LOGO" -resize 48x48 "$FLUTTER_DIR/android/app/src/main/res/mipmap-mdpi/ic_launcher.png"
convert -background none "$LOGO" -resize 72x72 "$FLUTTER_DIR/android/app/src/main/res/mipmap-hdpi/ic_launcher.png"
convert -background none "$LOGO" -resize 96x96 "$FLUTTER_DIR/android/app/src/main/res/mipmap-xhdpi/ic_launcher.png"
convert -background none "$LOGO" -resize 144x144 "$FLUTTER_DIR/android/app/src/main/res/mipmap-xxhdpi/ic_launcher.png"
convert -background none "$LOGO" -resize 192x192 "$FLUTTER_DIR/android/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png"
echo "  Created Android launcher icons (mdpi-xxxhdpi)"

# Windows icon
convert -background none "$LOGO" -resize 256x256 "$FLUTTER_DIR/windows/runner/resources/app_icon.ico"
echo "  Created Windows app_icon.ico (256x256)"

# Linux desktop icon (for GNOME/etc)
mkdir -p "$FLUTTER_DIR/linux/icons"
convert -background none "$LOGO" -resize 256x256 "$FLUTTER_DIR/linux/icons/dna-messenger.png"
echo "  Created Linux icon (256x256)"

echo "Done! All icons generated."
