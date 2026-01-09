// Image Cache Service - Local caching for received image attachments
import 'dart:io';
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';

/// Service for caching received images locally
class ImageCacheService {
  static ImageCacheService? _instance;
  late Directory _cacheDir;
  bool _initialized = false;

  ImageCacheService._();

  /// Get the singleton instance
  static Future<ImageCacheService> getInstance() async {
    if (_instance == null) {
      _instance = ImageCacheService._();
      await _instance!._init();
    }
    return _instance!;
  }

  Future<void> _init() async {
    if (_initialized) return;

    final appDir = await getApplicationSupportDirectory();
    _cacheDir = Directory('${appDir.path}/image_cache');
    if (!await _cacheDir.exists()) {
      await _cacheDir.create(recursive: true);
    }
    _initialized = true;
  }

  /// Get cached image by message ID
  /// Returns null if not cached
  Future<Uint8List?> getCached(int messageId) async {
    await _ensureInitialized();
    final file = File('${_cacheDir.path}/$messageId.jpg');
    if (await file.exists()) {
      return file.readAsBytes();
    }
    return null;
  }

  /// Cache image for a message ID
  Future<void> cache(int messageId, Uint8List bytes) async {
    await _ensureInitialized();
    final file = File('${_cacheDir.path}/$messageId.jpg');
    await file.writeAsBytes(bytes);
  }

  /// Check if image is cached
  Future<bool> isCached(int messageId) async {
    await _ensureInitialized();
    final file = File('${_cacheDir.path}/$messageId.jpg');
    return file.exists();
  }

  /// Remove cached image for a message
  Future<void> remove(int messageId) async {
    await _ensureInitialized();
    final file = File('${_cacheDir.path}/$messageId.jpg');
    if (await file.exists()) {
      await file.delete();
    }
  }

  /// Clear all cached images
  Future<void> clearAll() async {
    await _ensureInitialized();
    if (await _cacheDir.exists()) {
      await _cacheDir.delete(recursive: true);
      await _cacheDir.create();
    }
  }

  /// Get total cache size in bytes
  Future<int> getCacheSize() async {
    await _ensureInitialized();
    int totalSize = 0;
    if (await _cacheDir.exists()) {
      await for (final entity in _cacheDir.list()) {
        if (entity is File) {
          totalSize += await entity.length();
        }
      }
    }
    return totalSize;
  }

  /// Get human-readable cache size
  Future<String> getCacheSizeString() async {
    final bytes = await getCacheSize();
    if (bytes < 1024) {
      return '$bytes B';
    } else if (bytes < 1024 * 1024) {
      return '${(bytes / 1024).toStringAsFixed(1)} KB';
    } else {
      return '${(bytes / 1024 / 1024).toStringAsFixed(1)} MB';
    }
  }

  Future<void> _ensureInitialized() async {
    if (!_initialized) {
      await _init();
    }
  }
}
