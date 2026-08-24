# DNA Connect — Flutter App

Cross-platform UI for DNA Connect built with Flutter and Dart.

**Current Version:** v1.0.0-rc240+10591 (from `pubspec.yaml`)

## Platforms

| Platform | Status |
|----------|--------|
| Android | RC build target |
| Linux | RC build target |
| Windows | RC build target |
| iOS | Planned |

“Build target” means that platform-specific source is present. It is not a
production-readiness, store-availability or security-certification claim.

## Quick Start

From the repository root, build the C library first:

```bash
# Build C library
cmake -S messenger -B messenger/build -DCMAKE_BUILD_TYPE=Release
cmake --build messenger/build -j"$(nproc)"

# Run Flutter app
cd messenger/dna_messenger_flutter
flutter pub get && flutter run
```

## Build

```bash
flutter build linux      # Linux desktop
flutter build apk        # Android APK
flutter build appbundle  # Android App Bundle (Play Store)
flutter build windows    # Windows desktop (on a Windows Flutter host)
```

## Architecture

The Flutter app connects to the DNA Connect C library via `dart:ffi`:

- **FFI bindings:** `lib/ffi/dna_bindings.dart` — Hand-written C bindings
- **Dart wrapper:** `lib/ffi/dna_engine.dart` — Converts C callbacks to Futures/Streams
- **State management:** Riverpod providers in `lib/providers/`
- **Platform abstraction:** `lib/platform/` — Android vs Desktop handlers
- **Icons:** Font Awesome only (`FaIcon(FontAwesomeIcons.xxx)`)

## Documentation

See [docs/FLUTTER_UI.md](../docs/FLUTTER_UI.md) for comprehensive documentation including:
- Screen architecture and navigation
- FFI bindings to the C library
- State management (Riverpod)
- Platform-specific handling

## License

This Flutter application is [source-available (proprietary)](LICENSE).

The underlying C library and cryptographic libraries are licensed under [Apache 2.0](../LICENSE).
