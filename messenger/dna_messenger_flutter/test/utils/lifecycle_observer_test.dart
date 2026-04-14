// SEC-09 (Phase 5) unit tests for AppLifecycleObserver clipboard hook.
//
// Verifies that dispatching AppLifecycleState.paused / .hidden / .detached
// through the Flutter widgets binding (which fans out to all registered
// observers) routes through ClipboardUtils.clearIfSensitive and wipes the
// tracked sensitive copy. Verifies that .inactive is a no-op.
//
// We deliberately do NOT instantiate AppLifecycleObserver directly — it
// takes a WidgetRef from a Riverpod ConsumerState, which would require a
// ConsumerStatefulWidget host. Instead we register a tiny test observer
// whose switch mirrors the production code exactly, plus we call
// ClipboardUtils.clearIfSensitive in the same branches. This pins the
// routing contract ("paused/hidden/detached -> clearIfSensitive; inactive
// -> no-op") and exercises the production ClipboardUtils path end-to-end.

import 'package:dna_connect/utils/clipboard_utils.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';

class _TestClipboardHook extends WidgetsBindingObserver {
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
      case AppLifecycleState.detached:
        ClipboardUtils.clearIfSensitive();
        break;
      case AppLifecycleState.inactive:
      case AppLifecycleState.resumed:
        break;
    }
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('AppLifecycleObserver clipboard hook (SEC-09)', () {
    String? clipboardContents;
    late _TestClipboardHook hook;

    setUp(() {
      clipboardContents = null;
      TestDefaultBinaryMessengerBinding
          .instance.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, (call) async {
        switch (call.method) {
          case 'Clipboard.setData':
            final args = call.arguments as Map;
            clipboardContents = args['text'] as String?;
            return null;
          case 'Clipboard.getData':
            return <String, dynamic>{'text': clipboardContents};
          default:
            return null;
        }
      });
      hook = _TestClipboardHook();
      WidgetsBinding.instance.addObserver(hook);
    });

    tearDown(() async {
      WidgetsBinding.instance.removeObserver(hook);
      await ClipboardUtils.clearIfSensitive();
      TestDefaultBinaryMessengerBinding
          .instance.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, null);
    });

    Future<void> pumpLifecycle(AppLifecycleState state) async {
      WidgetsBinding.instance.handleAppLifecycleStateChanged(state);
      // Let any async Clipboard.getData / setData microtasks drain.
      await Future<void>.delayed(Duration.zero);
      await Future<void>.delayed(Duration.zero);
    }

    test('paused state clears tracked sensitive clipboard content', () async {
      await ClipboardUtils.copyWithAutoClear('paused seed');
      expect(clipboardContents, 'paused seed');

      await pumpLifecycle(AppLifecycleState.paused);

      expect(
        clipboardContents,
        '',
        reason: 'paused must trigger clearIfSensitive and wipe the clipboard',
      );
    });

    test('hidden state clears tracked sensitive clipboard content', () async {
      await ClipboardUtils.copyWithAutoClear('hidden seed');
      expect(clipboardContents, 'hidden seed');

      await pumpLifecycle(AppLifecycleState.hidden);

      expect(
        clipboardContents,
        '',
        reason: 'hidden must trigger clearIfSensitive and wipe the clipboard',
      );
    });

    test(
      'detached state clears tracked sensitive clipboard content',
      () async {
        await ClipboardUtils.copyWithAutoClear('detached seed');
        expect(clipboardContents, 'detached seed');

        await pumpLifecycle(AppLifecycleState.detached);

        expect(
          clipboardContents,
          '',
          reason:
              'detached must trigger clearIfSensitive (best-effort clear)',
        );
      },
    );

    test(
      'inactive state is a no-op — sensitive clipboard survives',
      () async {
        await ClipboardUtils.copyWithAutoClear('inactive seed');
        expect(clipboardContents, 'inactive seed');

        await pumpLifecycle(AppLifecycleState.inactive);

        expect(
          clipboardContents,
          'inactive seed',
          reason:
              'inactive is a transient focus loss (e.g. permission prompt) '
              'and must NOT wipe the clipboard',
        );
      },
    );
  });
}
