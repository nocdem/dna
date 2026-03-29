// Voice Record Sheet — bottom sheet for recording voice messages.
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:record/record.dart';

import '../l10n/app_localizations.dart';
import '../design_system/design_system.dart';
import '../utils/logger.dart';

const String _tag = 'VOICE_REC';

/// Result returned from a successful voice recording.
class VoiceRecordResult {
  final Uint8List audioBytes;
  final int durationSeconds;
  VoiceRecordResult(this.audioBytes, this.durationSeconds);
}

/// Bottom sheet widget for recording voice messages.
class VoiceRecordSheet extends StatefulWidget {
  const VoiceRecordSheet({super.key});

  @override
  State<VoiceRecordSheet> createState() => _VoiceRecordSheetState();
}

class _VoiceRecordSheetState extends State<VoiceRecordSheet> {
  final AudioRecorder _recorder = AudioRecorder();
  bool _isRecording = false;
  bool _hasRecording = false;
  int _elapsedSeconds = 0;
  Timer? _timer;
  String? _recordingPath;

  static const int _maxDurationSeconds = 180; // 3 minutes

  @override
  void dispose() {
    _timer?.cancel();
    _recorder.dispose();
    // Clean up temp file if cancelled
    if (_recordingPath != null && !_hasRecording) {
      try {
        File(_recordingPath!).deleteSync();
      } catch (_) {}
    }
    super.dispose();
  }

  Future<void> _startRecording() async {
    try {
      if (!await _recorder.hasPermission()) {
        log(_tag, 'Microphone permission denied');
        return;
      }

      final tempDir = Directory.systemTemp;
      final timestamp = DateTime.now().millisecondsSinceEpoch;
      _recordingPath = '${tempDir.path}/dna_voice_$timestamp.m4a';

      await _recorder.start(
        const RecordConfig(encoder: AudioEncoder.aacLc),
        path: _recordingPath!,
      );

      setState(() {
        _isRecording = true;
        _elapsedSeconds = 0;
      });

      _timer = Timer.periodic(const Duration(seconds: 1), (timer) {
        if (!mounted) {
          timer.cancel();
          return;
        }
        setState(() {
          _elapsedSeconds++;
        });
        // Auto-stop at max duration
        if (_elapsedSeconds >= _maxDurationSeconds) {
          _stopRecording();
        }
      });

      log(_tag, 'Recording started: $_recordingPath');
    } catch (e) {
      log(_tag, 'Failed to start recording: $e');
    }
  }

  Future<void> _stopRecording() async {
    _timer?.cancel();
    try {
      final path = await _recorder.stop();
      if (path != null) {
        _recordingPath = path;
        setState(() {
          _isRecording = false;
          _hasRecording = true;
        });
        log(_tag, 'Recording stopped: ${_elapsedSeconds}s');
      }
    } catch (e) {
      log(_tag, 'Failed to stop recording: $e');
      setState(() {
        _isRecording = false;
      });
    }
  }

  Future<void> _sendRecording() async {
    if (_recordingPath == null) return;

    try {
      final file = File(_recordingPath!);
      final bytes = await file.readAsBytes();
      final result = VoiceRecordResult(bytes, _elapsedSeconds);
      if (mounted) {
        Navigator.pop(context, result);
      }
      // Clean up temp file after reading
      try {
        await file.delete();
      } catch (_) {}
    } catch (e) {
      log(_tag, 'Failed to read recording: $e');
    }
  }

  void _cancelRecording() {
    // Clean up temp file
    if (_recordingPath != null) {
      try {
        File(_recordingPath!).deleteSync();
      } catch (_) {}
    }
    Navigator.pop(context, null);
  }

  String _formatDuration(int seconds) {
    final m = seconds ~/ 60;
    final s = seconds % 60;
    return '${m.toString().padLeft(2, '0')}:${s.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Timer display
            Text(
              _formatDuration(_elapsedSeconds),
              style: theme.textTheme.headlineMedium?.copyWith(
                fontFeatures: [const FontFeature.tabularFigures()],
              ),
            ),
            const SizedBox(height: 8),

            // Status text
            Text(
              _isRecording
                  ? l10n.chatRecordingRelease
                  : (_hasRecording
                      ? l10n.chatVoiceMessage
                      : l10n.chatRecordingHold),
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurface.withAlpha(150),
              ),
            ),
            const SizedBox(height: 24),

            if (_hasRecording)
              // Send / Cancel buttons after recording
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  // Cancel button
                  IconButton(
                    onPressed: _cancelRecording,
                    icon: const FaIcon(FontAwesomeIcons.xmark),
                    iconSize: 28,
                    style: IconButton.styleFrom(
                      backgroundColor: DnaColors.error.withAlpha(30),
                      foregroundColor: DnaColors.error,
                      padding: const EdgeInsets.all(16),
                    ),
                  ),
                  const SizedBox(width: 48),
                  // Send button
                  IconButton(
                    onPressed: _sendRecording,
                    icon: const FaIcon(FontAwesomeIcons.solidPaperPlane),
                    iconSize: 28,
                    style: IconButton.styleFrom(
                      backgroundColor:
                          theme.colorScheme.primary.withAlpha(30),
                      foregroundColor: theme.colorScheme.primary,
                      padding: const EdgeInsets.all(16),
                    ),
                  ),
                ],
              )
            else
              // Mic button — long press to record
              GestureDetector(
                onLongPressStart: (_) => _startRecording(),
                onLongPressEnd: (_) {
                  if (_isRecording) {
                    _stopRecording();
                  }
                },
                child: Container(
                  width: 80,
                  height: 80,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: _isRecording
                        ? DnaColors.error
                        : theme.colorScheme.primary,
                  ),
                  child: Center(
                    child: FaIcon(
                      FontAwesomeIcons.microphone,
                      size: 32,
                      color: _isRecording
                          ? Colors.white
                          : theme.colorScheme.onPrimary,
                    ),
                  ),
                ),
              ),

            const SizedBox(height: 16),
          ],
        ),
      ),
    );
  }
}
