// Avatar Crop Screen - Telegram-style circular crop with pan/zoom
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:crop_your_image/crop_your_image.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

/// Screen for cropping avatar images with circular mask
/// Returns cropped Uint8List on success, null on cancel
class AvatarCropScreen extends StatefulWidget {
  final Uint8List imageBytes;

  const AvatarCropScreen({
    super.key,
    required this.imageBytes,
  });

  @override
  State<AvatarCropScreen> createState() => _AvatarCropScreenState();
}

class _AvatarCropScreenState extends State<AvatarCropScreen> {
  final _cropController = CropController();
  bool _isCropping = false;

  void _onCrop() {
    if (_isCropping) return;
    setState(() => _isCropping = true);
    _cropController.crop();
  }

  void _onCropped(Uint8List croppedData) {
    Navigator.of(context).pop(croppedData);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black,
        foregroundColor: Colors.white,
        title: const Text('Crop Avatar'),
        leading: IconButton(
          icon: const FaIcon(FontAwesomeIcons.xmark),
          onPressed: () => Navigator.of(context).pop(null),
        ),
        actions: [
          if (_isCropping)
            const Padding(
              padding: EdgeInsets.all(16),
              child: SizedBox(
                width: 24,
                height: 24,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  color: Colors.white,
                ),
              ),
            )
          else
            IconButton(
              icon: const FaIcon(FontAwesomeIcons.check),
              onPressed: _onCrop,
            ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: Crop(
              controller: _cropController,
              image: widget.imageBytes,
              onCropped: _onCropped,
              // Circular crop for avatars
              withCircleUi: true,
              // Square aspect ratio (will be circular mask)
              aspectRatio: 1,
              // Initial crop area size (fraction of image)
              initialSize: 0.8,
              // Base color for area outside crop
              baseColor: Colors.black,
              // Mask color with transparency
              maskColor: Colors.black.withValues(alpha: 0.7),
              // Corner dot styling (invisible for circle mode)
              cornerDotBuilder: (size, edgeAlignment) => const SizedBox.shrink(),
              // Interactive settings
              interactive: true,
              // Fix crop area, allow moving image
              fixCropRect: true,
            ),
          ),
          // Instructions
          Container(
            padding: const EdgeInsets.all(16),
            child: Text(
              'Pinch to zoom, drag to position',
              style: theme.textTheme.bodyMedium?.copyWith(
                color: Colors.white70,
              ),
              textAlign: TextAlign.center,
            ),
          ),
        ],
      ),
    );
  }
}
