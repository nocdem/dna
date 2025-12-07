#!/bin/bash
# Generate app icons from logo.svg for all platforms
# Requires: inkscape (preferred) or rsvg-convert, and ImageMagick for .ico

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOGO="$PROJECT_DIR/logo.svg"
FLUTTER_DIR="$PROJECT_DIR/dna_messenger_flutter"

if [ ! -f "$LOGO" ]; then
    echo "Error: logo.svg not found at $LOGO"
    exit 1
fi

# Function to convert SVG to PNG using best available tool
svg_to_png() {
    local input="$1"
    local output="$2"
    local size="$3"

    if command -v inkscape &> /dev/null; then
        inkscape "$input" -w "$size" -h "$size" -o "$output" 2>/dev/null
    elif command -v rsvg-convert &> /dev/null; then
        rsvg-convert -w "$size" -h "$size" "$input" -o "$output"
    else
        # Fallback to ImageMagick
        convert -background none -density 300 "$input" -resize "${size}x${size}" "$output"
    fi
}

echo "Generating icons from $LOGO..."

# Flutter asset icon (1024x1024)
mkdir -p "$FLUTTER_DIR/assets"
svg_to_png "$LOGO" "$FLUTTER_DIR/assets/icon.png" 1024
echo "  Created assets/icon.png (1024x1024)"

# Android launcher icons
svg_to_png "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-mdpi/ic_launcher.png" 48
svg_to_png "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-hdpi/ic_launcher.png" 72
svg_to_png "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-xhdpi/ic_launcher.png" 96
svg_to_png "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-xxhdpi/ic_launcher.png" 144
svg_to_png "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png" 192
echo "  Created Android launcher icons (mdpi-xxxhdpi)"

# Windows icon (create PNG first, then convert to ICO)
mkdir -p "$FLUTTER_DIR/linux/icons"
svg_to_png "$LOGO" "$FLUTTER_DIR/linux/icons/dna-messenger.png" 256
convert "$FLUTTER_DIR/linux/icons/dna-messenger.png" "$FLUTTER_DIR/windows/runner/resources/app_icon.ico"
echo "  Created Windows app_icon.ico (256x256)"
echo "  Created Linux icon (256x256)"

echo "Done! All icons generated."
