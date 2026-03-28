// MediaService — upload/download media with encryption via Nodus DHT.
// Uses the C library (libdna) for SHA3-512 hashing and AES-256-GCM encryption.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:image/image.dart' as img;

import '../ffi/dna_engine.dart';
import '../models/media_ref.dart';
import '../utils/logger.dart';

const String _tag = 'MEDIA_SVC';

// AES-256-GCM constants
const int _aesKeyLen = 32; // 256 bits
const int _aesNonceLen = 12;
const int _aesTagLen = 16;

// Thumbnail settings
const int _thumbnailMaxWidth = 200;
const int _thumbnailJpegQuality = 60;

// Image compression settings
const int _maxImageDimension = 2560;
const int _defaultJpegQuality = 85;

/// Service for uploading and downloading encrypted media via Nodus DHT.
class MediaService {
  final DnaEngine _engine;
  final DynamicLibrary _nativeLib;

  // Native function pointers (looked up once, reused)
  late final int Function(Pointer<Uint8>, int, Pointer<Uint8>) _sha3_512;
  late final int Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      Pointer<Size>,
      Pointer<Uint8>,
      Pointer<Uint8>) _aesEncrypt;
  late final int Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Size>) _aesDecrypt;

  MediaService(this._engine) : _nativeLib = _loadNativeLibrary() {
    _sha3_512 = _nativeLib.lookupFunction<
        Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>),
        int Function(Pointer<Uint8>, int, Pointer<Uint8>)>('qgp_sha3_512');

    _aesEncrypt = _nativeLib.lookupFunction<
        Int32 Function(
            Pointer<Uint8>,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Pointer<Size>,
            Pointer<Uint8>,
            Pointer<Uint8>),
        int Function(
            Pointer<Uint8>,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            Pointer<Size>,
            Pointer<Uint8>,
            Pointer<Uint8>)>('qgp_aes256_encrypt');

    _aesDecrypt = _nativeLib.lookupFunction<
        Int32 Function(
            Pointer<Uint8>,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Pointer<Uint8>,
            Pointer<Uint8>,
            Pointer<Size>),
        int Function(
            Pointer<Uint8>,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            Pointer<Uint8>,
            Pointer<Uint8>,
            Pointer<Size>)>('qgp_aes256_decrypt');
  }

  /// Load the native library (same pattern as crypto_isolate.dart)
  static DynamicLibrary _loadNativeLibrary() {
    if (Platform.isAndroid) {
      return DynamicLibrary.open('libdna.so');
    } else if (Platform.isLinux) {
      const paths = ['libdna.so', './libdna.so', '../build/libdna.so'];
      for (final path in paths) {
        try {
          return DynamicLibrary.open(path);
        } catch (_) {
          continue;
        }
      }
      throw Exception('Failed to load libdna.so');
    } else if (Platform.isWindows) {
      return DynamicLibrary.open('dna.dll');
    } else if (Platform.isMacOS || Platform.isIOS) {
      return DynamicLibrary.process();
    }
    throw UnsupportedError('Unsupported platform');
  }

  // ---------------------------------------------------------------------------
  // PUBLIC API
  // ---------------------------------------------------------------------------

  /// Upload an image to Nodus DHT.
  ///
  /// [bytes] raw image bytes (JPEG, PNG, GIF).
  /// [encrypted] true to AES-256-GCM encrypt before upload (default true).
  /// [caption] optional caption text.
  /// [ttl] time-to-live in seconds (default 7 days).
  ///
  /// Returns a [MediaRef] that can be serialized into a message.
  Future<MediaRef> uploadImage(
    Uint8List bytes, {
    bool encrypted = true,
    String? caption,
    int ttl = 604800,
  }) async {
    DnaLogger.log(_tag, 'uploadImage: ${bytes.length} bytes, encrypted=$encrypted');

    // 1. Decode and compress image
    final decoded = img.decodeImage(bytes);
    if (decoded == null) {
      throw MediaServiceException('Failed to decode image');
    }

    final compressed = _compressImage(decoded);
    DnaLogger.log(_tag,
        'Compressed: ${bytes.length} -> ${compressed.length} bytes');

    // 2. Generate thumbnail
    final thumbnailBytes = _generateThumbnail(decoded);

    // 3. Encrypt if requested
    Uint8List uploadData;
    String? aesKeyBase64;
    if (encrypted) {
      final aesKey = _generateRandomBytes(_aesKeyLen);
      uploadData = _aesGcmEncrypt(compressed, aesKey);
      aesKeyBase64 = base64Encode(aesKey);
    } else {
      uploadData = compressed;
    }

    // 4. Compute SHA3-512 of upload data
    final contentHash = _computeSha3_512(uploadData);

    // 5. Upload to Nodus
    final hashHex = await _engine.mediaUpload(
      uploadData,
      contentHash,
      0, // image
      encrypted,
      ttl,
    );
    DnaLogger.log(_tag, 'Uploaded: hash=${hashHex.substring(0, 16)}...');

    // 6. Get dimensions from decoded image (before compression may resize)
    // Use compressed dimensions — _compressImage may have resized
    final compressedDecoded = img.decodeImage(compressed);
    final width = compressedDecoded?.width ?? decoded.width;
    final height = compressedDecoded?.height ?? decoded.height;

    return MediaRef(
      contentHash: hashHex,
      mediaType: 0,
      mimeType: 'image/jpeg',
      size: uploadData.length,
      width: width,
      height: height,
      thumbnail: base64Encode(thumbnailBytes),
      caption: caption,
      encryptionKey: aesKeyBase64,
    );
  }

  /// Download and optionally decrypt media from Nodus DHT.
  ///
  /// [ref] the MediaRef containing content hash and optional encryption key.
  /// Returns the decrypted media bytes.
  Future<Uint8List> download(MediaRef ref) async {
    DnaLogger.log(_tag,
        'download: hash=${ref.contentHash.substring(0, 16)}...');

    final data = await _engine.mediaDownload(ref.contentHash);
    DnaLogger.log(_tag, 'Downloaded ${data.length} bytes');

    if (ref.isEncrypted && ref.encryptionKey != null) {
      final aesKey = base64Decode(ref.encryptionKey!);
      final decrypted = _aesGcmDecrypt(data, aesKey);
      DnaLogger.log(_tag, 'Decrypted: ${data.length} -> ${decrypted.length} bytes');
      return decrypted;
    }
    return data;
  }

  /// Check if media exists (complete) on Nodus DHT.
  Future<bool> exists(String contentHashHex) async {
    return _engine.mediaExists(contentHashHex);
  }

  // ---------------------------------------------------------------------------
  // IMAGE COMPRESSION
  // ---------------------------------------------------------------------------

  /// Compress image to JPEG, resizing if needed.
  /// Follows same logic as ImageAttachmentService but without the 2MB limit
  /// (chunked storage removes that constraint).
  Uint8List _compressImage(img.Image decoded) {
    int width = decoded.width;
    int height = decoded.height;

    // Resize if larger than max dimension
    if (width > _maxImageDimension || height > _maxImageDimension) {
      final scale =
          _maxImageDimension / (width > height ? width : height);
      width = (width * scale).toInt();
      height = (height * scale).toInt();
    }

    img.Image resized = decoded;
    if (width < decoded.width || height < decoded.height) {
      resized = img.copyResize(decoded, width: width, height: height);
    }

    return Uint8List.fromList(
        img.encodeJpg(resized, quality: _defaultJpegQuality));
  }

  /// Generate a small thumbnail (~10-20KB mini JPEG).
  Uint8List _generateThumbnail(img.Image decoded) {
    int thumbWidth = _thumbnailMaxWidth;
    int thumbHeight =
        (decoded.height * _thumbnailMaxWidth / decoded.width).toInt();

    // If image is portrait, constrain height instead
    if (decoded.height > decoded.width) {
      thumbHeight = _thumbnailMaxWidth;
      thumbWidth =
          (decoded.width * _thumbnailMaxWidth / decoded.height).toInt();
    }

    final resized =
        img.copyResize(decoded, width: thumbWidth, height: thumbHeight);
    return Uint8List.fromList(
        img.encodeJpg(resized, quality: _thumbnailJpegQuality));
  }

  // ---------------------------------------------------------------------------
  // CRYPTO — via C library FFI
  // ---------------------------------------------------------------------------

  /// Compute SHA3-512 hash, returns 64 bytes.
  Uint8List _computeSha3_512(Uint8List data) {
    final dataPtr = calloc<Uint8>(data.length);
    final hashPtr = calloc<Uint8>(64);
    try {
      for (var i = 0; i < data.length; i++) {
        dataPtr[i] = data[i];
      }

      final result = _sha3_512(dataPtr, data.length, hashPtr);
      if (result != 0) {
        throw MediaServiceException('SHA3-512 computation failed');
      }

      final hash = Uint8List(64);
      for (var i = 0; i < 64; i++) {
        hash[i] = hashPtr[i];
      }
      return hash;
    } finally {
      calloc.free(dataPtr);
      calloc.free(hashPtr);
    }
  }

  /// AES-256-GCM encrypt. Returns [nonce(12) || ciphertext || tag(16)].
  Uint8List _aesGcmEncrypt(Uint8List plaintext, Uint8List key) {
    if (key.length != _aesKeyLen) {
      throw ArgumentError('AES key must be $_aesKeyLen bytes');
    }

    final keyPtr = calloc<Uint8>(_aesKeyLen);
    final plaintextPtr = calloc<Uint8>(plaintext.length);
    final ciphertextPtr = calloc<Uint8>(plaintext.length);
    final ciphertextLenPtr = calloc<Size>(1);
    final noncePtr = calloc<Uint8>(_aesNonceLen);
    final tagPtr = calloc<Uint8>(_aesTagLen);

    try {
      for (var i = 0; i < _aesKeyLen; i++) {
        keyPtr[i] = key[i];
      }
      for (var i = 0; i < plaintext.length; i++) {
        plaintextPtr[i] = plaintext[i];
      }

      final result = _aesEncrypt(
        keyPtr,
        plaintextPtr,
        plaintext.length,
        nullptr, // no AAD
        0,
        ciphertextPtr,
        ciphertextLenPtr,
        noncePtr,
        tagPtr,
      );

      if (result != 0) {
        throw MediaServiceException('AES-256-GCM encryption failed');
      }

      final ctLen = ciphertextLenPtr.value;

      // Pack as [nonce(12) || ciphertext || tag(16)]
      final output = Uint8List(_aesNonceLen + ctLen + _aesTagLen);
      for (var i = 0; i < _aesNonceLen; i++) {
        output[i] = noncePtr[i];
      }
      for (var i = 0; i < ctLen; i++) {
        output[_aesNonceLen + i] = ciphertextPtr[i];
      }
      for (var i = 0; i < _aesTagLen; i++) {
        output[_aesNonceLen + ctLen + i] = tagPtr[i];
      }
      return output;
    } finally {
      calloc.free(keyPtr);
      calloc.free(plaintextPtr);
      calloc.free(ciphertextPtr);
      calloc.free(ciphertextLenPtr);
      calloc.free(noncePtr);
      calloc.free(tagPtr);
    }
  }

  /// AES-256-GCM decrypt. Expects [nonce(12) || ciphertext || tag(16)].
  Uint8List _aesGcmDecrypt(Uint8List packed, Uint8List key) {
    if (key.length != _aesKeyLen) {
      throw ArgumentError('AES key must be $_aesKeyLen bytes');
    }
    if (packed.length < _aesNonceLen + _aesTagLen) {
      throw MediaServiceException(
          'Encrypted data too short (${packed.length} bytes)');
    }

    final ctLen = packed.length - _aesNonceLen - _aesTagLen;

    final keyPtr = calloc<Uint8>(_aesKeyLen);
    final ciphertextPtr = calloc<Uint8>(ctLen);
    final noncePtr = calloc<Uint8>(_aesNonceLen);
    final tagPtr = calloc<Uint8>(_aesTagLen);
    final plaintextPtr = calloc<Uint8>(ctLen);
    final plaintextLenPtr = calloc<Size>(1);

    try {
      for (var i = 0; i < _aesKeyLen; i++) {
        keyPtr[i] = key[i];
      }
      // Unpack nonce
      for (var i = 0; i < _aesNonceLen; i++) {
        noncePtr[i] = packed[i];
      }
      // Unpack ciphertext
      for (var i = 0; i < ctLen; i++) {
        ciphertextPtr[i] = packed[_aesNonceLen + i];
      }
      // Unpack tag
      for (var i = 0; i < _aesTagLen; i++) {
        tagPtr[i] = packed[_aesNonceLen + ctLen + i];
      }

      final result = _aesDecrypt(
        keyPtr,
        ciphertextPtr,
        ctLen,
        nullptr, // no AAD
        0,
        noncePtr,
        tagPtr,
        plaintextPtr,
        plaintextLenPtr,
      );

      if (result != 0) {
        throw MediaServiceException(
            'AES-256-GCM decryption failed (authentication error)');
      }

      final ptLen = plaintextLenPtr.value;
      final output = Uint8List(ptLen);
      for (var i = 0; i < ptLen; i++) {
        output[i] = plaintextPtr[i];
      }
      return output;
    } finally {
      calloc.free(keyPtr);
      calloc.free(ciphertextPtr);
      calloc.free(noncePtr);
      calloc.free(tagPtr);
      calloc.free(plaintextPtr);
      calloc.free(plaintextLenPtr);
    }
  }

  /// Generate cryptographically secure random bytes.
  Uint8List _generateRandomBytes(int length) {
    final rng = Random.secure();
    return Uint8List.fromList(
        List<int>.generate(length, (_) => rng.nextInt(256)));
  }
}

/// Exception thrown by MediaService operations.
class MediaServiceException implements Exception {
  final String message;
  MediaServiceException(this.message);

  @override
  String toString() => 'MediaServiceException: $message';
}
