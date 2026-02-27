// Crypto operations that can run in isolates
// These load the native library independently, avoiding main isolate blocking

import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'package:ffi/ffi.dart';

/// BIP39 constants
const int _bip39Words24 = 24;
const int _bip39MaxMnemonicLength = 512;

/// Load the DNA native library
DynamicLibrary _loadLibrary() {
  if (Platform.isAndroid) {
    return DynamicLibrary.open('libdna_lib.so');
  } else if (Platform.isLinux) {
    // Try common locations
    const paths = [
      'libdna_lib.so',
      './libdna_lib.so',
      '../build/libdna_lib.so',
    ];
    for (final path in paths) {
      try {
        return DynamicLibrary.open(path);
      } catch (_) {
        continue;
      }
    }
    throw Exception('Failed to load libdna_lib.so');
  } else if (Platform.isWindows) {
    return DynamicLibrary.open('dna_lib.dll');
  } else if (Platform.isMacOS || Platform.isIOS) {
    return DynamicLibrary.process();
  }
  throw UnsupportedError('Unsupported platform');
}

/// Generate mnemonic in isolate (non-blocking)
Future<String> generateMnemonicAsync() async {
  return Isolate.run(() {
    final lib = _loadLibrary();
    final generateFn = lib.lookupFunction<
        Int32 Function(Int32, Pointer<Char>, Int32),
        int Function(int, Pointer<Char>, int)>('bip39_generate_mnemonic');

    final mnemonicPtr = calloc<Uint8>(_bip39MaxMnemonicLength);
    try {
      final result = generateFn(_bip39Words24, mnemonicPtr.cast(), _bip39MaxMnemonicLength);
      if (result != 0) {
        throw Exception('Failed to generate mnemonic');
      }
      return mnemonicPtr.cast<Utf8>().toDartString();
    } finally {
      calloc.free(mnemonicPtr);
    }
  });
}

/// Validate mnemonic in isolate (non-blocking)
Future<bool> validateMnemonicAsync(String mnemonic) async {
  return Isolate.run(() {
    final lib = _loadLibrary();
    final validateFn = lib.lookupFunction<
        Bool Function(Pointer<Char>),
        bool Function(Pointer<Char>)>('bip39_validate_mnemonic');

    final mnemonicPtr = mnemonic.toNativeUtf8();
    try {
      return validateFn(mnemonicPtr.cast());
    } finally {
      calloc.free(mnemonicPtr);
    }
  });
}

/// Seeds result from derivation
class DerivedSeeds {
  final List<int> signingSeed;
  final List<int> encryptionSeed;
  final List<int> masterSeed;

  DerivedSeeds({
    required this.signingSeed,
    required this.encryptionSeed,
    required this.masterSeed,
  });
}

/// Derive seeds from mnemonic in isolate (non-blocking)
/// This is the heavy PBKDF2 operation that can take 100-500ms
Future<DerivedSeeds> deriveSeedsWithMasterAsync(String mnemonic, {String passphrase = ''}) async {
  return Isolate.run(() {
    final lib = _loadLibrary();
    final deriveFn = lib.lookupFunction<
        Int32 Function(Pointer<Char>, Pointer<Char>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>),
        int Function(Pointer<Char>, Pointer<Char>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>('qgp_derive_seeds_with_master');

    final mnemonicPtr = mnemonic.toNativeUtf8();
    final passphrasePtr = passphrase.toNativeUtf8();
    final signingSeedPtr = calloc<Uint8>(32);
    final encryptionSeedPtr = calloc<Uint8>(32);
    final masterSeedPtr = calloc<Uint8>(64);

    try {
      final result = deriveFn(
        mnemonicPtr.cast(),
        passphrasePtr.cast(),
        signingSeedPtr,
        encryptionSeedPtr,
        masterSeedPtr,
      );

      if (result != 0) {
        throw Exception('Failed to derive seeds from mnemonic');
      }

      final signingSeed = <int>[];
      final encryptionSeed = <int>[];
      final masterSeed = <int>[];

      for (var i = 0; i < 32; i++) {
        signingSeed.add(signingSeedPtr[i]);
        encryptionSeed.add(encryptionSeedPtr[i]);
      }
      for (var i = 0; i < 64; i++) {
        masterSeed.add(masterSeedPtr[i]);
      }

      return DerivedSeeds(
        signingSeed: signingSeed,
        encryptionSeed: encryptionSeed,
        masterSeed: masterSeed,
      );
    } finally {
      calloc.free(mnemonicPtr);
      calloc.free(passphrasePtr);
      calloc.free(signingSeedPtr);
      calloc.free(encryptionSeedPtr);
      calloc.free(masterSeedPtr);
    }
  });
}
