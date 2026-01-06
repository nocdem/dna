/// Unified logger that writes to both stdout and dna.log file
///
/// Usage: Replace `print('[TAG] message')` with `log('TAG', 'message')`
/// Or use `logPrint('[TAG] message')` for drop-in replacement of print()

import 'dart:async';
import 'package:flutter/foundation.dart';
import '../ffi/dna_engine.dart';

DnaEngine? _engine;
final List<_BufferedLog> _bufferedLogs = [];

class _BufferedLog {
  final String tag;
  final String message;
  _BufferedLog(this.tag, this.message);
}

/// Set the engine instance for logging (call once at app startup)
void logSetEngine(DnaEngine engine) {
  _engine = engine;

  // Flush any buffered logs
  for (final log in _bufferedLogs) {
    _engine?.debugLog(log.tag, log.message);
  }
  _bufferedLogs.clear();
}

/// Log with explicit tag - writes to stdout AND dna.log
void log(String tag, String message) {
  print('[$tag] $message');

  if (_engine != null) {
    _engine!.debugLog(tag, message);
  } else {
    // Buffer until engine is ready
    _bufferedLogs.add(_BufferedLog(tag, message));
  }
}

/// Drop-in replacement for print() - parses [TAG] from message
/// If message starts with [TAG], extracts it; otherwise uses 'FLUTTER' tag
void logPrint(String message) {
  print(message);

  // Parse tag from message if present: "[TAG] rest of message"
  String tag = 'FLUTTER';
  String msg = message;

  if (message.startsWith('[')) {
    final closeBracket = message.indexOf(']');
    if (closeBracket > 1) {
      tag = message.substring(1, closeBracket);
      msg = message.substring(closeBracket + 1).trimLeft();
    }
  }

  if (_engine != null) {
    _engine!.debugLog(tag, msg);
  } else {
    _bufferedLogs.add(_BufferedLog(tag, msg));
  }
}

/// Log an error with stack trace - for exception handling
void logError(String tag, Object error, [StackTrace? stack]) {
  final message = stack != null
      ? '$error\n$stack'
      : error.toString();

  print('[$tag] ERROR: $message');

  if (_engine != null) {
    _engine!.debugLog(tag, 'ERROR: $message');
  } else {
    _bufferedLogs.add(_BufferedLog(tag, 'ERROR: $message'));
  }
}

/// Setup Flutter error handlers to capture exceptions to log file
void setupErrorHandlers() {
  // Handle Flutter framework errors
  FlutterError.onError = (details) {
    FlutterError.presentError(details);
    logError('FLUTTER_ERROR', details.exception, details.stack);
  };

  // Handle errors in async code
  PlatformDispatcher.instance.onError = (error, stack) {
    logError('PLATFORM_ERROR', error, stack);
    return true; // Handled
  };
}

/// Run app with error zone that captures uncaught exceptions
void runAppWithErrorLogging(FutureOr<void> Function() appRunner) {
  runZonedGuarded(
    appRunner,
    (error, stack) {
      logError('ZONE_ERROR', error, stack);
    },
  );
}
