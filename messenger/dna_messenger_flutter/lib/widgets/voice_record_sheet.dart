// Voice Record Sheet — bottom sheet for recording voice messages.
// Tap-to-record, live waveform, listen/send/delete after recording.
import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:just_audio/just_audio.dart';
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

enum _RecordState { idle, recording, recorded, playing }

class _VoiceRecordSheetState extends State<VoiceRecordSheet> {
  final AudioRecorder _recorder = AudioRecorder();
  AudioPlayer? _player;
  _RecordState _state = _RecordState.idle;
  int _elapsedSeconds = 0;
  Timer? _timer;
  Timer? _amplitudeTimer;
  String? _recordingPath;

  // Waveform data — normalized 0.0..1.0 amplitude samples
  final List<double> _amplitudes = [];
  // Max visible bars in waveform
  static const int _maxVisibleBars = 60;
  static const int _maxDurationSeconds = 180; // 3 minutes

  // Playback position for waveform highlight
  Duration _playbackPosition = Duration.zero;
  Duration _playbackDuration = Duration.zero;

  @override
  void dispose() {
    _timer?.cancel();
    _amplitudeTimer?.cancel();
    _player?.dispose();
    _recorder.dispose();
    // Clean up temp file if not sent
    if (_recordingPath != null && _state != _RecordState.recorded) {
      try {
        File(_recordingPath!).deleteSync();
      } catch (_) {}
    }
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Recording
  // ---------------------------------------------------------------------------

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
        _state = _RecordState.recording;
        _elapsedSeconds = 0;
        _amplitudes.clear();
      });

      // Elapsed timer (1s)
      _timer = Timer.periodic(const Duration(seconds: 1), (timer) {
        if (!mounted) {
          timer.cancel();
          return;
        }
        setState(() {
          _elapsedSeconds++;
        });
        if (_elapsedSeconds >= _maxDurationSeconds) {
          _stopRecording();
        }
      });

      // Amplitude polling (100ms) for waveform
      _amplitudeTimer =
          Timer.periodic(const Duration(milliseconds: 100), (_) async {
        if (!mounted || _state != _RecordState.recording) return;
        try {
          final amp = await _recorder.getAmplitude();
          // amp.current is in dB (-160 to 0). Normalize to 0.0..1.0
          final db = amp.current;
          final normalized = db.isFinite ? ((db + 60) / 60).clamp(0.0, 1.0) : 0.0;
          if (mounted) {
            setState(() {
              _amplitudes.add(normalized);
            });
          }
        } catch (_) {}
      });

      log(_tag, 'Recording started: $_recordingPath');
    } catch (e) {
      log(_tag, 'Failed to start recording: $e');
    }
  }

  Future<void> _stopRecording() async {
    _timer?.cancel();
    _amplitudeTimer?.cancel();
    try {
      final path = await _recorder.stop();
      if (path != null) {
        _recordingPath = path;
        setState(() {
          _state = _RecordState.recorded;
        });
        log(_tag, 'Recording stopped: ${_elapsedSeconds}s');
      }
    } catch (e) {
      log(_tag, 'Failed to stop recording: $e');
      setState(() {
        _state = _RecordState.idle;
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Playback (Listen)
  // ---------------------------------------------------------------------------

  Future<void> _startPlayback() async {
    if (_recordingPath == null) return;

    try {
      _player?.dispose();
      _player = AudioPlayer();

      _player!.positionStream.listen((pos) {
        if (mounted) {
          setState(() {
            _playbackPosition = pos;
          });
        }
      });

      _player!.durationStream.listen((dur) {
        if (dur != null && mounted) {
          setState(() {
            _playbackDuration = dur;
          });
        }
      });

      _player!.playerStateStream.listen((state) {
        if (mounted && state.processingState == ProcessingState.completed) {
          setState(() {
            _state = _RecordState.recorded;
            _playbackPosition = Duration.zero;
          });
        }
      });

      await _player!.setFilePath(_recordingPath!);
      await _player!.play();

      setState(() {
        _state = _RecordState.playing;
      });
    } catch (e) {
      log(_tag, 'Playback failed: $e');
    }
  }

  Future<void> _stopPlayback() async {
    await _player?.pause();
    setState(() {
      _state = _RecordState.recorded;
    });
  }

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  Future<void> _sendRecording() async {
    if (_recordingPath == null) return;
    await _player?.stop();

    try {
      final file = File(_recordingPath!);
      final bytes = await file.readAsBytes();
      final result = VoiceRecordResult(bytes, _elapsedSeconds);
      if (mounted) {
        Navigator.pop(context, result);
      }
      try {
        await file.delete();
      } catch (_) {}
    } catch (e) {
      log(_tag, 'Failed to read recording: $e');
    }
  }

  void _deleteRecording() {
    _player?.stop();
    if (_recordingPath != null) {
      try {
        File(_recordingPath!).deleteSync();
      } catch (_) {}
    }
    Navigator.pop(context, null);
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  String _formatDuration(int seconds) {
    final m = seconds ~/ 60;
    final s = seconds % 60;
    return '${m.toString().padLeft(2, '0')}:${s.toString().padLeft(2, '0')}';
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

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
                color: _state == _RecordState.recording
                    ? DnaColors.error
                    : null,
              ),
            ),
            const SizedBox(height: 4),

            // Status text
            Text(
              _statusText(l10n),
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurface.withAlpha(150),
              ),
            ),
            const SizedBox(height: 16),

            // Waveform (recording or recorded/playing)
            if (_state != _RecordState.idle)
              SizedBox(
                height: 48,
                child: CustomPaint(
                  size: const Size(double.infinity, 48),
                  painter: _WaveformPainter(
                    amplitudes: _amplitudes,
                    maxBars: _maxVisibleBars,
                    barColor: _state == _RecordState.recording
                        ? DnaColors.error
                        : theme.colorScheme.primary.withAlpha(100),
                    activeColor: theme.colorScheme.primary,
                    playbackProgress: _state == _RecordState.playing &&
                            _playbackDuration.inMilliseconds > 0
                        ? (_playbackPosition.inMilliseconds /
                                _playbackDuration.inMilliseconds)
                            .clamp(0.0, 1.0)
                        : (_state == _RecordState.recording ? 1.0 : 0.0),
                  ),
                ),
              ),

            const SizedBox(height: 20),

            // Controls
            _buildControls(theme),

            const SizedBox(height: 12),
          ],
        ),
      ),
    );
  }

  String _statusText(AppLocalizations l10n) {
    switch (_state) {
      case _RecordState.idle:
        return l10n.chatRecordingTap;
      case _RecordState.recording:
        return l10n.chatRecordingInProgress;
      case _RecordState.recorded:
        return l10n.chatVoiceMessage;
      case _RecordState.playing:
        return l10n.chatRecordingListening;
    }
  }

  Widget _buildControls(ThemeData theme) {
    switch (_state) {
      case _RecordState.idle:
        // Big mic button — tap to start
        return GestureDetector(
          onTap: _startRecording,
          child: Container(
            width: 72,
            height: 72,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: theme.colorScheme.primary,
            ),
            child: Center(
              child: FaIcon(
                FontAwesomeIcons.microphone,
                size: 28,
                color: theme.colorScheme.onPrimary,
              ),
            ),
          ),
        );

      case _RecordState.recording:
        // Stop button (pulsing red circle)
        return GestureDetector(
          onTap: _stopRecording,
          child: Container(
            width: 72,
            height: 72,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: DnaColors.error,
            ),
            child: const Center(
              child: FaIcon(
                FontAwesomeIcons.stop,
                size: 24,
                color: Colors.white,
              ),
            ),
          ),
        );

      case _RecordState.recorded:
      case _RecordState.playing:
        // Three buttons: Delete / Listen / Send
        return Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // Delete
            _actionButton(
              icon: FontAwesomeIcons.trashCan,
              color: DnaColors.error,
              onTap: _deleteRecording,
            ),
            const SizedBox(width: 32),
            // Listen / Pause
            _actionButton(
              icon: _state == _RecordState.playing
                  ? FontAwesomeIcons.pause
                  : FontAwesomeIcons.play,
              color: theme.colorScheme.secondary,
              onTap: _state == _RecordState.playing
                  ? _stopPlayback
                  : _startPlayback,
            ),
            const SizedBox(width: 32),
            // Send
            _actionButton(
              icon: FontAwesomeIcons.solidPaperPlane,
              color: theme.colorScheme.primary,
              onTap: _sendRecording,
            ),
          ],
        );
    }
  }

  Widget _actionButton({
    required IconData icon,
    required Color color,
    required VoidCallback onTap,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: 56,
        height: 56,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: color.withAlpha(25),
        ),
        child: Center(
          child: FaIcon(icon, size: 22, color: color),
        ),
      ),
    );
  }
}

// =============================================================================
// Waveform Painter
// =============================================================================

class _WaveformPainter extends CustomPainter {
  final List<double> amplitudes;
  final int maxBars;
  final Color barColor;
  final Color activeColor;
  final double playbackProgress; // 0.0..1.0

  _WaveformPainter({
    required this.amplitudes,
    required this.maxBars,
    required this.barColor,
    required this.activeColor,
    required this.playbackProgress,
  });

  @override
  void paint(Canvas canvas, Size size) {
    if (amplitudes.isEmpty) return;

    final barWidth = 3.0;
    final barGap = 2.0;
    final totalBarWidth = barWidth + barGap;
    final barsCanFit = (size.width / totalBarWidth).floor();
    final visibleBars = min(barsCanFit, maxBars);

    // Take last N amplitudes (scroll effect during recording)
    final startIdx =
        amplitudes.length > visibleBars ? amplitudes.length - visibleBars : 0;
    final visibleAmps = amplitudes.sublist(startIdx);

    // Center the bars horizontally
    final totalWidth = visibleAmps.length * totalBarWidth - barGap;
    final offsetX = (size.width - totalWidth) / 2;

    final activePaint = Paint()..color = activeColor;
    final inactivePaint = Paint()..color = barColor;

    final activeBarCount = (visibleAmps.length * playbackProgress).round();

    for (int i = 0; i < visibleAmps.length; i++) {
      final amp = visibleAmps[i];
      // Min bar height 3px, max = full height
      final barHeight = max(3.0, amp * size.height);
      final x = offsetX + i * totalBarWidth;
      final y = (size.height - barHeight) / 2;

      final paint = i < activeBarCount ? activePaint : inactivePaint;
      canvas.drawRRect(
        RRect.fromRectAndRadius(
          Rect.fromLTWH(x, y, barWidth, barHeight),
          const Radius.circular(1.5),
        ),
        paint,
      );
    }
  }

  @override
  bool shouldRepaint(_WaveformPainter old) => true;
}
