// Image Attachment Service - Image picking, compression, and base64 encoding for chat
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:image_picker/image_picker.dart';
import 'package:image/image.dart' as img;

/// Result of image processing - ready for JSON embedding
class ImageAttachment {
  final String base64Data;
  final String mimeType;
  final int width;
  final int height;
  final int originalSize;
  final int compressedSize;

  ImageAttachment({
    required this.base64Data,
    required this.mimeType,
    required this.width,
    required this.height,
    required this.originalSize,
    required this.compressedSize,
  });

  /// Convert to JSON map for message embedding
  Map<String, dynamic> toJson({String? caption}) => {
        'type': 'image_attachment',
        'mimeType': mimeType,
        'width': width,
        'height': height,
        'data': base64Data,
        if (caption != null && caption.isNotEmpty) 'caption': caption,
      };

  /// Encode as JSON string ready for queueMessage()
  String toMessageJson({String? caption}) => jsonEncode(toJson(caption: caption));
}

/// Exception thrown when image processing fails
class ImageAttachmentException implements Exception {
  final String message;
  ImageAttachmentException(this.message);

  @override
  String toString() => message;
}

/// Service for picking and processing images for chat attachments
class ImageAttachmentService {
  // Max raw file size (user requirement)
  static const int maxFileSizeBytes = 2 * 1024 * 1024; // 2MB

  // Target compressed size for DHT transport
  // DHT values can be up to ~64KB, but encrypted messages have overhead
  // Target 500KB compressed which becomes ~667KB base64
  static const int maxCompressedSizeBytes = 500 * 1024; // 500KB

  // Max dimensions for resize (preserving aspect ratio)
  static const int maxDimension = 1920;

  final ImagePicker _picker = ImagePicker();

  /// Pick an image from gallery or camera
  /// Returns null if user cancelled
  Future<Uint8List?> pickImage(ImageSource source) async {
    try {
      final XFile? image = await _picker.pickImage(
        source: source,
        preferredCameraDevice: CameraDevice.rear,
      );

      if (image == null) return null;
      return File(image.path).readAsBytes();
    } catch (e) {
      throw ImageAttachmentException('Failed to pick image: $e');
    }
  }

  /// Process raw image bytes: validate, compress, and encode to base64
  /// Throws ImageAttachmentException on failure
  Future<ImageAttachment> processImage(Uint8List bytes) async {
    // Validate file size
    if (bytes.length > maxFileSizeBytes) {
      throw ImageAttachmentException(
          'Image exceeds 2MB limit (${(bytes.length / 1024 / 1024).toStringAsFixed(1)}MB)');
    }

    // Detect format
    final mimeType = _detectMimeType(bytes);
    if (mimeType == null) {
      throw ImageAttachmentException(
          'Unsupported format (use JPEG, PNG, or GIF)');
    }

    // Decode image
    final img.Image? decoded = img.decodeImage(bytes);
    if (decoded == null) {
      throw ImageAttachmentException('Failed to decode image');
    }

    // Progressive compression to fit under limit
    Uint8List compressed;
    int quality = 85;
    int width = decoded.width;
    int height = decoded.height;

    // Initial resize if image is very large
    if (width > maxDimension || height > maxDimension) {
      final scale = maxDimension / (width > height ? width : height);
      width = (width * scale).toInt();
      height = (height * scale).toInt();
    }

    int attempts = 0;
    const maxAttempts = 10;

    do {
      attempts++;

      // Resize if needed
      img.Image resized = decoded;
      if (width < decoded.width || height < decoded.height) {
        resized = img.copyResize(decoded, width: width, height: height);
      }

      // Encode as JPEG (best compression for photos)
      compressed = Uint8List.fromList(img.encodeJpg(resized, quality: quality));

      // Check if under limit
      if (compressed.length <= maxCompressedSizeBytes) {
        break;
      }

      // Reduce quality first, then dimensions
      if (quality > 30) {
        quality -= 10;
      } else if (width > 640) {
        // Scale down by 25%
        width = (width * 0.75).toInt();
        height = (height * 0.75).toInt();
        quality = 80; // Reset quality for smaller image
      } else {
        throw ImageAttachmentException(
            'Image cannot be compressed under 500KB limit');
      }
    } while (attempts < maxAttempts);

    if (compressed.length > maxCompressedSizeBytes) {
      throw ImageAttachmentException(
          'Image cannot be compressed under 500KB limit');
    }

    return ImageAttachment(
      base64Data: base64Encode(compressed),
      mimeType: 'image/jpeg', // Always JPEG after compression
      width: width,
      height: height,
      originalSize: bytes.length,
      compressedSize: compressed.length,
    );
  }

  /// Detect MIME type from magic bytes
  String? _detectMimeType(Uint8List bytes) {
    if (bytes.length < 4) return null;

    // JPEG: FF D8 FF
    if (bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF) {
      return 'image/jpeg';
    }
    // PNG: 89 50 4E 47
    if (bytes[0] == 0x89 &&
        bytes[1] == 0x50 &&
        bytes[2] == 0x4E &&
        bytes[3] == 0x47) {
      return 'image/png';
    }
    // GIF: 47 49 46 38
    if (bytes[0] == 0x47 &&
        bytes[1] == 0x49 &&
        bytes[2] == 0x46 &&
        bytes[3] == 0x38) {
      return 'image/gif';
    }
    return null;
  }
}
