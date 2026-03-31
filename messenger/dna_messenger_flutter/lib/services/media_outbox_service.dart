// MediaOutboxService — Resume/retry failed media uploads from SQLite outbox.
// Reads pending_uploads table, re-uploads encrypted bytes from disk,
// and sends the media_ref message on success.

import 'dart:io';
import 'dart:typed_data';

import '../ffi/dna_engine.dart';
import '../models/media_ref.dart';
import '../utils/logger.dart';
import 'cache_database.dart';
import 'media_service.dart';

const String _tag = 'MEDIA_OUTBOX';
const int _maxRetries = 5;

class MediaOutboxService {
  static MediaOutboxService? _instance;
  static MediaOutboxService get instance {
    _instance ??= MediaOutboxService._();
    return _instance!;
  }

  MediaOutboxService._();

  bool _processing = false;

  /// Process all pending/failed uploads. Safe to call multiple times —
  /// returns immediately if already processing.
  Future<void> processPendingUploads(DnaEngine engine) async {
    if (_processing) {
      log(_tag, 'Already processing, skipping');
      return;
    }
    _processing = true;

    try {
      final db = CacheDatabase.instance;

      // Reset any 'uploading' entries to 'failed' (app crashed mid-upload)
      await _resetStaleUploading(db);

      final pending = await db.getPendingUploads();

      if (pending.isEmpty) {
        log(_tag, 'No pending uploads');
        return;
      }
      log(_tag, 'Processing ${pending.length} pending uploads');

      for (final upload in pending) {
        final hashShort = upload.contentHash.substring(0, 16);

        if (upload.retryCount >= _maxRetries) {
          log(_tag, 'SKIP $hashShort (max retries ${upload.retryCount}/$_maxRetries)');
          continue;
        }

        log(_tag, 'Processing $hashShort: status=${upload.status}, '
            'chunks=${upload.chunksSent}/${upload.chunkCount}, '
            'retries=${upload.retryCount}, size=${upload.totalSize}');

        await _processUpload(engine, upload);
      }
    } catch (e) {
      logError(_tag, 'processPendingUploads error: $e');
    } finally {
      _processing = false;
    }
  }

  /// Reset 'uploading' entries to 'failed' — these were interrupted by app crash.
  Future<void> _resetStaleUploading(CacheDatabase db) async {
    final dbObj = await db.database;
    final count = await dbObj.rawUpdate(
      "UPDATE pending_uploads SET status = 'failed' WHERE status = 'uploading'",
    );
    if (count > 0) {
      log(_tag, 'Reset $count stale uploading entries to failed');
    }
  }

  Future<void> _processUpload(DnaEngine engine, PendingUpload upload) async {
    final db = CacheDatabase.instance;
    final hashShort = upload.contentHash.substring(0, 16);

    // Check if encrypted file still exists on disk
    final encFile = File(upload.encryptedFilePath);
    if (!await encFile.exists()) {
      log(_tag, '$hashShort: encrypted file missing at ${upload.encryptedFilePath}, removing');
      await db.deletePendingUpload(upload.contentHash);
      return;
    }

    // Check if already complete on server (dedup)
    try {
      final exists = await engine.mediaExists(upload.contentHash);
      if (exists) {
        log(_tag, '$hashShort: already on server, sending message only');
        _sendMediaMessage(engine, upload);
        await db.updateUploadStatus(upload.contentHash, 'complete');
        return;
      }
    } catch (e) {
      log(_tag, '$hashShort: mediaExists check failed: $e (continuing with upload)');
    }

    // Resume upload from chunks_sent
    await db.updateUploadStatus(upload.contentHash, 'uploading');
    log(_tag, '$hashShort: starting upload from chunk ${upload.chunksSent}');

    try {
      final encBytes = await encFile.readAsBytes();
      final hashBytes = _hexToBytes(upload.contentHash);

      // Track chunk progress in DB
      int lastChunk = upload.chunksSent;
      final sub = engine.events
          .where((e) => e is MediaUploadProgressEvent)
          .cast<MediaUploadProgressEvent>()
          .listen((e) {
        if (e.totalBytes > 0) {
          final currentChunk = (e.bytesSent / mediaChunkSize).floor();
          if (currentChunk > lastChunk) {
            lastChunk = currentChunk;
            db.updateChunksSent(upload.contentHash, currentChunk);
          }
          MediaUploadTracker.instance.update(
              upload.contentHash, e.bytesSent, e.totalBytes);
        }
      });

      try {
        await engine.mediaUpload(
          encBytes,
          hashBytes,
          upload.mediaType,
          upload.encryptionKey != null,
          604800,
          startChunk: upload.chunksSent,
        );

        log(_tag, '$hashShort: upload complete, sending message');
        _sendMediaMessage(engine, upload);
        await db.updateUploadStatus(upload.contentHash, 'complete');
        MediaUploadTracker.instance.clear();
      } catch (e) {
        logError(_tag, '$hashShort: upload failed at chunk ~$lastChunk: $e');
        await db.updateUploadStatus(upload.contentHash, 'failed', e.toString());
        await db.incrementRetryCount(upload.contentHash);
        MediaUploadTracker.instance.clear();
      } finally {
        await sub.cancel();
      }
    } catch (e) {
      logError(_tag, '$hashShort: failed to read encrypted file: $e');
      await db.updateUploadStatus(upload.contentHash, 'failed', e.toString());
      await db.incrementRetryCount(upload.contentHash);
    }
  }

  /// Send the media_ref message via the engine message queue.
  void _sendMediaMessage(DnaEngine engine, PendingUpload upload) {
    final ref = MediaRef(
      contentHash: upload.contentHash,
      mediaType: upload.mediaType,
      mimeType: upload.mimeType,
      size: upload.totalSize,
      width: upload.width,
      height: upload.height,
      duration: upload.duration,
      thumbnail: upload.thumbnail ?? '',
      caption: upload.caption,
      encryptionKey: upload.encryptionKey,
    );
    final result = engine.queueMessage(upload.recipientFp, ref.toMessageJson());
    if (result >= 0) {
      log(_tag, 'Queued media message to ${upload.recipientFp.substring(0, 16)}...');
    } else {
      logError(_tag, 'Failed to queue media message: result=$result');
    }
  }

  /// Convert hex string to bytes.
  static Uint8List _hexToBytes(String hex) {
    final bytes = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return bytes;
  }
}
