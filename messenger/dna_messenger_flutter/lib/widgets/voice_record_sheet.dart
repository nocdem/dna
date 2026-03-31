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

class _VoiceRecordSheetState extends State<VoiceRecordSheet>
    with SingleTickerProviderStateMixin {
  final AudioRecorder _recorder = AudioRecorder();
  AudioPlayer? _player;
  _RecordState _state = _RecordState.idle;
  int _elapsedSeconds = 0;
  Timer? _timer;
  Timer? _amplitudeTimer;
  String? _recordingPath;

  // Pulse animation for recording indicator
  late AnimationController _pulseController;
  late Animation<double> _pulseAnimation;

  // Waveform data — normalized 0.0..1.0 amplitude samples
  final List<double> _amplitudes = [];
  static const int _maxVisibleBars = 50;
  static const int _maxDurationSeconds = 180; // 3 minutes

  // Playback position for waveform highlight
  Duration _playbackPosition = Duration.zero;
  Duration _playbackDuration = Duration.zero;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1200),
    );
    _pulseAnimation = Tween<double>(begin: 1.0, end: 1.15).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );
  }

  @override
  void dispose() {
    _pulseController.dispose();
    _timer?.cancel();
    _amplitudeTimer?.cancel();
    _player?.dispose();
    _recorder.dispose();
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

      _pulseController.repeat(reverse: true);

      setState(() {
        _state = _RecordState.recording;
        _elapsedSeconds = 0;
        _amplitudes.clear();
      });

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

      _amplitudeTimer =
          Timer.periodic(const Duration(milliseconds: 80), (_) async {
        if (!mounted || _state != _RecordState.recording) return;
        try {
          final amp = await _recorder.getAmplitude();
          final db = amp.current;
          final normalized =
              db.isFinite ? ((db + 55) / 55).clamp(0.0, 1.0) : 0.0;
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
    _pulseController.stop();
    _pulseController.reset();
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
        if (mounted) setState(() => _playbackPosition = pos);
      });

      _player!.durationStream.listen((dur) {
        if (dur != null && mounted) setState(() => _playbackDuration = dur);
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

      setState(() => _state = _RecordState.playing);
    } catch (e) {
      log(_tag, 'Playback failed: $e');
    }
  }

  Future<void> _stopPlayback() async {
    await _player?.pause();
    setState(() => _state = _RecordState.recorded);
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
      if (mounted) Navigator.pop(context, result);
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
    final isDark = theme.brightness == Brightness.dark;

    return SafeArea(
      child: Container(
        padding: const EdgeInsets.fromLTRB(24, 20, 24, 24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Drag handle
            Container(
              width: 36,
              height: 4,
              margin: const EdgeInsets.only(bottom: 20),
              decoration: BoxDecoration(
                color: theme.colorScheme.onSurface.withAlpha(40),
                borderRadius: BorderRadius.circular(2),
              ),
            ),

            // Timer + recording dot
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                if (_state == _RecordState.recording) ...[
                  Container(
                    width: 8,
                    height: 8,
                    margin: const EdgeInsets.only(right: 10),
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: DnaColors.error,
                      boxShadow: [
                        BoxShadow(
                          color: DnaColors.error.withAlpha(100),
                          blurRadius: 8,
                          spreadRadius: 2,
                        ),
                      ],
                    ),
                  ),
                ],
                Text(
                  _formatDuration(_elapsedSeconds),
                  style: theme.textTheme.headlineMedium?.copyWith(
                    fontFeatures: [const FontFeature.tabularFigures()],
                    fontWeight: FontWeight.w300,
                    letterSpacing: 2,
                    color: _state == _RecordState.recording
                        ? DnaColors.error
                        : theme.colorScheme.onSurface,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 4),

            // Status text
            Text(
              _statusText(l10n),
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurface.withAlpha(120),
                letterSpacing: 0.5,
              ),
            ),
            const SizedBox(height: 20),

            // Waveform area
            Container(
              height: 64,
              decoration: BoxDecoration(
                color: isDark
                    ? Colors.white.withAlpha(8)
                    : Colors.black.withAlpha(8),
                borderRadius: BorderRadius.circular(16),
              ),
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              child: _state == _RecordState.idle
                  ? Center(
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: List.generate(
                          20,
                          (i) => Container(
                            width: 2.5,
                            height: 4,
                            margin: const EdgeInsets.symmetric(horizontal: 2),
                            decoration: BoxDecoration(
                              color:
                                  theme.colorScheme.onSurface.withAlpha(30),
                              borderRadius: BorderRadius.circular(1.5),
                            ),
                          ),
                        ),
                      ),
                    )
                  : CustomPaint(
                      size: const Size(double.infinity, 48),
                      painter: _WaveformPainter(
                        amplitudes: _amplitudes,
                        maxBars: _maxVisibleBars,
                        isRecording: _state == _RecordState.recording,
                        primaryColor: theme.colorScheme.primary,
                        errorColor: DnaColors.error,
                        inactiveColor: isDark
                            ? Colors.white.withAlpha(25)
                            : Colors.black.withAlpha(25),
                        playbackProgress:
                            _state == _RecordState.playing &&
                                    _playbackDuration.inMilliseconds > 0
                                ? (_playbackPosition.inMilliseconds /
                                        _playbackDuration.inMilliseconds)
                                    .clamp(0.0, 1.0)
                                : (_state == _RecordState.recording
                                    ? 1.0
                                    : 0.0),
                      ),
                    ),
            ),

            const SizedBox(height: 28),

            // Controls
            _buildControls(theme),

            const SizedBox(height: 8),
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
        return _buildMicButton(theme);

      case _RecordState.recording:
        return _buildStopButton();

      case _RecordState.recorded:
      case _RecordState.playing:
        return _buildActionRow(theme);
    }
  }

  Widget _buildMicButton(ThemeData theme) {
    return GestureDetector(
      onTap: _startRecording,
      child: Container(
        width: 72,
        height: 72,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          gradient: const LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [DnaColors.gradientStart, DnaColors.gradientEnd],
          ),
          boxShadow: [
            BoxShadow(
              color: DnaColors.gradientEnd.withAlpha(60),
              blurRadius: 16,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: const Center(
          child: FaIcon(
            FontAwesomeIcons.microphone,
            size: 26,
            color: Colors.white,
          ),
        ),
      ),
    );
  }

  Widget _buildStopButton() {
    return AnimatedBuilder(
      animation: _pulseAnimation,
      builder: (context, child) {
        return Transform.scale(
          scale: _pulseAnimation.value,
          child: GestureDetector(
            onTap: _stopRecording,
            child: Container(
              width: 72,
              height: 72,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: DnaColors.error,
                boxShadow: [
                  BoxShadow(
                    color: DnaColors.error.withAlpha(80),
                    blurRadius: 20,
                    spreadRadius: 2,
                  ),
                ],
              ),
              child: const Center(
                child: FaIcon(
                  FontAwesomeIcons.stop,
                  size: 22,
                  color: Colors.white,
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildActionRow(ThemeData theme) {
    final isDark = theme.brightness == Brightness.dark;

    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        // Delete
        _circleButton(
          icon: FontAwesomeIcons.trashCan,
          iconSize: 18,
          size: 52,
          color: DnaColors.error,
          bgColor: DnaColors.error.withAlpha(isDark ? 30 : 20),
          onTap: _deleteRecording,
          label: null,
        ),
        const SizedBox(width: 24),
        // Listen / Pause — larger, emphasized
        _circleButton(
          icon: _state == _RecordState.playing
              ? FontAwesomeIcons.pause
              : FontAwesomeIcons.play,
          iconSize: 22,
          size: 64,
          color: Colors.white,
          bgColor: theme.colorScheme.primary,
          onTap:
              _state == _RecordState.playing ? _stopPlayback : _startPlayback,
          label: null,
          elevated: true,
        ),
        const SizedBox(width: 24),
        // Send
        _circleButton(
          icon: FontAwesomeIcons.solidPaperPlane,
          iconSize: 18,
          size: 52,
          color: DnaColors.success,
          bgColor: DnaColors.success.withAlpha(isDark ? 30 : 20),
          onTap: _sendRecording,
          label: null,
        ),
      ],
    );
  }

  Widget _circleButton({
    required IconData icon,
    required double iconSize,
    required double size,
    required Color color,
    required Color bgColor,
    required VoidCallback onTap,
    required String? label,
    bool elevated = false,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: size,
        height: size,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: bgColor,
          boxShadow: elevated
              ? [
                  BoxShadow(
                    color: bgColor.withAlpha(80),
                    blurRadius: 12,
                    offset: const Offset(0, 3),
                  ),
                ]
              : null,
        ),
        child: Center(
          child: FaIcon(icon, size: iconSize, color: color),
        ),
      ),
    );
  }
}

// =============================================================================
// Waveform Painter — mirrored bars with gradient coloring
// =============================================================================

class _WaveformPainter extends CustomPainter {
  final List<double> amplitudes;
  final int maxBars;
  final bool isRecording;
  final Color primaryColor;
  final Color errorColor;
  final Color inactiveColor;
  final double playbackProgress;

  _WaveformPainter({
    required this.amplitudes,
    required this.maxBars,
    required this.isRecording,
    required this.primaryColor,
    required this.errorColor,
    required this.inactiveColor,
    required this.playbackProgress,
  });

  @override
  void paint(Canvas canvas, Size size) {
    if (amplitudes.isEmpty) return;

    final barWidth = 3.0;
    final barGap = 2.5;
    final totalBarWidth = barWidth + barGap;
    final barsCanFit = (size.width / totalBarWidth).floor();
    final visibleBars = min(barsCanFit, maxBars);

    final startIdx =
        amplitudes.length > visibleBars ? amplitudes.length - visibleBars : 0;
    final visibleAmps = amplitudes.sublist(startIdx);

    final totalWidth = visibleAmps.length * totalBarWidth - barGap;
    final offsetX = (size.width - totalWidth) / 2;
    final centerY = size.height / 2;

    final activeBarCount = (visibleAmps.length * playbackProgress).round();

    for (int i = 0; i < visibleAmps.length; i++) {
      final amp = visibleAmps[i];
      // Mirrored: bars extend both up and down from center
      final halfHeight = max(1.5, amp * centerY * 0.9);
      final x = offsetX + i * totalBarWidth;

      Color barColor;
      if (isRecording) {
        // Gradient from error color — recent bars brighter
        final recency = visibleAmps.length > 1
            ? i / (visibleAmps.length - 1)
            : 1.0;
        barColor = Color.lerp(
          errorColor.withAlpha(80),
          errorColor,
          recency,
        )!;
      } else if (i < activeBarCount) {
        barColor = primaryColor;
      } else {
        barColor = inactiveColor;
      }

      final paint = Paint()..color = barColor;

      // Top half
      canvas.drawRRect(
        RRect.fromRectAndRadius(
          Rect.fromLTWH(x, centerY - halfHeight, barWidth, halfHeight),
          const Radius.circular(1.5),
        ),
        paint,
      );
      // Bottom half (mirror)
      canvas.drawRRect(
        RRect.fromRectAndRadius(
          Rect.fromLTWH(x, centerY, barWidth, halfHeight),
          const Radius.circular(1.5),
        ),
        paint,
      );
    }
  }

  @override
  bool shouldRepaint(_WaveformPainter old) => true;
}
