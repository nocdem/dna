// Media Cache Service - Persistent disk cache for all media types (image, video, audio).
// Keyed by content hash (SHA3-512 hex) for content-addressable deduplication.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';

import '../ffi/dna_engine.dart';
import '../models/media_ref.dart';
import '../utils/logger.dart';
import 'media_service.dart';

const String _tag = 'MEDIA_CACHE';

/// Persistent disk cache for downloaded/uploaded media.
/// Keyed by contentHash (SHA3-512 hex string).
class MediaCacheService {
  static MediaCacheService? _instance;
  late Directory _cacheDir;
  bool _initialized = false;

  // Background download queue
  final List<_PrefetchRequest> _prefetchQueue = [];
  bool _prefetchRunning = false;

  MediaCacheService._();

  /// Get the singleton instance
  static Future<MediaCacheService> getInstance() async {
    if (_instance == null) {
      _instance = MediaCacheService._();
      await _instance!._init();
    }
    return _instance!;
  }

  /// Synchronous access (only after getInstance() has been called once)
  static MediaCacheService? get instance => _instance;

  Future<void> _init() async {
    if (_initialized) return;

    final appDir = await getApplicationSupportDirectory();
    _cacheDir = Directory('${appDir.path}/media_cache');
    if (!await _cacheDir.exists()) {
      await _cacheDir.create(recursive: true);
    }
    _initialized = true;
    log(_tag, 'Initialized: ${_cacheDir.path}');
  }

  /// Get file extension from mime type
  String _extForMime(String mimeType) {
    if (mimeType.contains('jpeg') || mimeType.contains('jpg')) return '.jpg';
    if (mimeType.contains('png')) return '.png';
    if (mimeType.contains('gif')) return '.gif';
    if (mimeType.contains('webp')) return '.webp';
    if (mimeType.contains('mp4')) return '.mp4';
    if (mimeType.contains('webm')) return '.webm';
    if (mimeType.contains('ogg')) return '.ogg';
    if (mimeType.contains('wav')) return '.wav';
    if (mimeType.contains('mp3')) return '.mp3';
    if (mimeType.contains('aac') || mimeType.contains('m4a')) return '.m4a';
    return '.bin';
  }

  /// Build cache file path for a content hash + mime type
  File _cacheFile(String contentHash, String mimeType) {
    final ext = _extForMime(mimeType);
    return File('${_cacheDir.path}/$contentHash$ext');
  }

  /// Get cached media by content hash.
  /// Returns null if not cached.
  Future<Uint8List?> get(String contentHash, String mimeType) async {
    await _ensureInitialized();
    final file = _cacheFile(contentHash, mimeType);
    if (await file.exists()) {
      return file.readAsBytes();
    }
    return null;
  }

  /// Cache media bytes for a content hash.
  Future<void> put(String contentHash, String mimeType, Uint8List bytes) async {
    await _ensureInitialized();
    final file = _cacheFile(contentHash, mimeType);
    await file.writeAsBytes(bytes);
  }

  /// Check if media is cached.
  Future<bool> isCached(String contentHash, String mimeType) async {
    await _ensureInitialized();
    final file = _cacheFile(contentHash, mimeType);
    return file.exists();
  }

  /// Get the cache file path (for audio/video players that need a File).
  /// Returns null if not cached.
  Future<File?> getCacheFile(String contentHash, String mimeType) async {
    await _ensureInitialized();
    final file = _cacheFile(contentHash, mimeType);
    if (await file.exists()) {
      return file;
    }
    return null;
  }

  /// Remove cached media for a content hash.
  Future<void> remove(String contentHash, String mimeType) async {
    await _ensureInitialized();
    final file = _cacheFile(contentHash, mimeType);
    if (await file.exists()) {
      await file.delete();
    }
  }

  /// Clear all cached media.
  Future<void> clearAll() async {
    await _ensureInitialized();
    if (await _cacheDir.exists()) {
      await _cacheDir.delete(recursive: true);
      await _cacheDir.create();
    }
    log(_tag, 'Cache cleared');
  }

  /// Get total cache size in bytes.
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

  /// Get human-readable cache size.
  Future<String> getCacheSizeString() async {
    final bytes = await getCacheSize();
    if (bytes < 1024) {
      return '$bytes B';
    } else if (bytes < 1024 * 1024) {
      return '${(bytes / 1024).toStringAsFixed(1)} KB';
    } else if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    } else {
      return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
    }
  }

  // ---------------------------------------------------------------------------
  // Background prefetch (lazy download)
  // ---------------------------------------------------------------------------

  /// Queue a media_ref for background download.
  /// Skips if already cached. Downloads sequentially (max 1 concurrent).
  void prefetch(MediaRef ref, DnaEngine engine) {
    // Skip if already queued
    for (final req in _prefetchQueue) {
      if (req.ref.contentHash == ref.contentHash) return;
    }
    _prefetchQueue.add(_PrefetchRequest(ref: ref, engine: engine));
    log(_tag, 'Queued prefetch: ${ref.contentHash.substring(0, 16)}... (queue=${_prefetchQueue.length})');
    _processPrefetchQueue();
  }

  void _processPrefetchQueue() {
    if (_prefetchRunning || _prefetchQueue.isEmpty) return;
    _prefetchRunning = true;
    _runNextPrefetch();
  }

  Future<void> _runNextPrefetch() async {
    while (_prefetchQueue.isNotEmpty) {
      final req = _prefetchQueue.removeAt(0);
      final ref = req.ref;

      try {
        // Already cached?
        if (await isCached(ref.contentHash, ref.mimeType)) {
          log(_tag, 'Prefetch skip (cached): ${ref.contentHash.substring(0, 16)}...');
          continue;
        }

        log(_tag, 'Prefetch downloading: ${ref.contentHash.substring(0, 16)}...');
        final mediaService = MediaService(req.engine);
        final bytes = await mediaService.download(ref);
        await put(ref.contentHash, ref.mimeType, bytes);
        log(_tag, 'Prefetch done: ${ref.contentHash.substring(0, 16)}... (${bytes.length} bytes)');
      } catch (e) {
        logError(_tag, 'Prefetch failed: ${ref.contentHash.substring(0, 16)}... $e');
        // Don't retry — user can tap to download manually
      }
    }

    _prefetchRunning = false;
  }

  Future<void> _ensureInitialized() async {
    if (!_initialized) {
      await _init();
    }
  }
}

/// Internal request for background prefetch queue.
class _PrefetchRequest {
  final MediaRef ref;
  final DnaEngine engine;
  const _PrefetchRequest({required this.ref, required this.engine});
}
