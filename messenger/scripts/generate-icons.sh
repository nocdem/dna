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

# Function to create adaptive icon foreground (icon centered with padding)
# Adaptive icons use 108dp canvas with 72dp safe zone (66%)
# The icon should be ~66% of the foreground size
create_adaptive_foreground() {
    local input="$1"
    local output="$2"
    local canvas_size="$3"
    local icon_size=$((canvas_size * 66 / 100))
    local padding=$(((canvas_size - icon_size) / 2))

    # Create icon at correct size, then place on transparent canvas
    local temp_icon="/tmp/adaptive_icon_temp.png"
    svg_to_png "$input" "$temp_icon" "$icon_size"

    # Create transparent canvas and composite icon in center
    convert -size "${canvas_size}x${canvas_size}" xc:none \
        "$temp_icon" -gravity center -composite \
        "$output"

    rm -f "$temp_icon"
}

echo "Generating icons from $LOGO..."

# Flutter asset icon (1024x1024)
mkdir -p "$FLUTTER_DIR/assets"
svg_to_png "$LOGO" "$FLUTTER_DIR/assets/icon.png" 1024
echo "  Created assets/icon.png (1024x1024)"

# Android launcher icons (legacy, for older devices)
svg_to_png "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-mdpi/ic_launcher.png" 48
svg_to_png "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-hdpi/ic_launcher.png" 72
svg_to_png "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-xhdpi/ic_launcher.png" 96
svg_to_png "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-xxhdpi/ic_launcher.png" 144
svg_to_png "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png" 192
echo "  Created Android launcher icons (mdpi-xxxhdpi)"

# Android adaptive icon foregrounds (API 26+)
# Foreground sizes: mdpi=108, hdpi=162, xhdpi=216, xxhdpi=324, xxxhdpi=432
create_adaptive_foreground "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-mdpi/ic_launcher_foreground.png" 108
create_adaptive_foreground "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-hdpi/ic_launcher_foreground.png" 162
create_adaptive_foreground "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-xhdpi/ic_launcher_foreground.png" 216
create_adaptive_foreground "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-xxhdpi/ic_launcher_foreground.png" 324
create_adaptive_foreground "$LOGO" "$FLUTTER_DIR/android/app/src/main/res/mipmap-xxxhdpi/ic_launcher_foreground.png" 432
echo "  Created Android adaptive icon foregrounds (mdpi-xxxhdpi)"

# Windows icon (create PNG first, then convert to ICO)
mkdir -p "$FLUTTER_DIR/linux/icons"
svg_to_png "$LOGO" "$FLUTTER_DIR/linux/icons/dna-messenger.png" 256
convert "$FLUTTER_DIR/linux/icons/dna-messenger.png" "$FLUTTER_DIR/windows/runner/resources/app_icon.ico"
echo "  Created Windows app_icon.ico (256x256)"
echo "  Created Linux icon (256x256)"

echo "Done! All icons generated."
