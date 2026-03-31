// MediaOutboxService — Resume/retry failed media uploads from SQLite outbox.
// Reads pending_uploads table, re-uploads encrypted bytes from disk,
// and sends the media_ref message on success.

import 'dart:io';
import 'dart:typed_data';

import '../ffi/dna_engine.dart';
import '../models/media_ref.dart';
import '../utils/logger.dart';
import 'cache_database.dart';

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
    if (_processing) return;
    _processing = true;

    try {
      final db = CacheDatabase.instance;
      final pending = await db.getPendingUploads();

      if (pending.isEmpty) return;
      log(_tag, 'Processing ${pending.length} pending uploads');

      for (final upload in pending) {
        if (upload.retryCount >= _maxRetries) {
          log(_tag, 'Skipping ${upload.contentHash.substring(0, 16)}... (max retries)');
          continue;
        }

        await _processUpload(engine, upload);
      }
    } catch (e) {
      logError(_tag, 'processPendingUploads error: $e');
    } finally {
      _processing = false;
    }
  }

  Future<void> _processUpload(DnaEngine engine, PendingUpload upload) async {
    final db = CacheDatabase.instance;
    final hashShort = upload.contentHash.substring(0, 16);

    // Check if encrypted file still exists on disk
    final encFile = File(upload.encryptedFilePath);
    if (!await encFile.exists()) {
      log(_tag, 'Encrypted file missing for $hashShort, removing from outbox');
      await db.deletePendingUpload(upload.contentHash);
      return;
    }

    // Check if already complete on server (dedup)
    try {
      final exists = await engine.mediaExists(upload.contentHash);
      if (exists) {
        log(_tag, '$hashShort already on server, sending message');
        _sendMediaMessage(engine, upload);
        await db.updateUploadStatus(upload.contentHash, 'complete');
        return;
      }
    } catch (e) {
      log(_tag, 'mediaExists check failed for $hashShort: $e');
      // Continue to upload attempt anyway
    }

    // Resume upload from chunks_sent
    await db.updateUploadStatus(upload.contentHash, 'uploading');
    try {
      final encBytes = await encFile.readAsBytes();
      final hashBytes = _hexToBytes(upload.contentHash);

      log(_tag, 'Resuming $hashShort from chunk ${upload.chunksSent}/${upload.chunkCount}');

      await engine.mediaUpload(
        encBytes,
        hashBytes,
        upload.mediaType,
        upload.encryptionKey != null, // encrypted
        604800, // 7 day TTL
        startChunk: upload.chunksSent,
      );

      // Success — send the message and mark complete
      log(_tag, 'Upload complete: $hashShort');
      _sendMediaMessage(engine, upload);
      await db.updateUploadStatus(upload.contentHash, 'complete');
    } catch (e) {
      logError(_tag, 'Upload failed for $hashShort: $e');
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
