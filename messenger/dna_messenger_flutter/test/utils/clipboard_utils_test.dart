// SEC-09 (Phase 5) unit tests for ClipboardUtils.
//
// Verifies:
//   1. auto-clear fires exactly at the 10-second hardened default
//   2. non-match-guard: clipboard content copied by the user after a
//      sensitive copy is NOT wiped by the timer
//   3. lifecycle-clear: clearIfSensitive() wipes the clipboard synchronously
//      (plus microtasks) when the tracked value still matches
//   4. rapid-overwrite: second sensitive copy replaces the tracked value
//      (last-one-wins) and the single pending clear wipes the most recent
//
// Test harness: flutter_test with fake_async (transitive via flutter_test)
// and a mock SystemChannels.platform MethodCallHandler to back the clipboard
// with an in-memory String. Public API only.

import 'package:dna_connect/utils/clipboard_utils.dart';
// ignore: depend_on_referenced_packages
import 'package:fake_async/fake_async.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('ClipboardUtils.copyWithAutoClear', () {
    String? clipboardContents;

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
    });

    tearDown(() async {
      // Drain any tracking state between cases and detach mock handler.
      await ClipboardUtils.clearIfSensitive();
      TestDefaultBinaryMessengerBinding
          .instance.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, null);
    });

    test('auto-clear: clipboard is cleared after 10 seconds', () {
      fakeAsync((async) {
        ClipboardUtils.copyWithAutoClear('correct horse battery staple');
        async.flushMicrotasks();
        expect(clipboardContents, 'correct horse battery staple');

        async.elapse(const Duration(seconds: 9));
        async.flushMicrotasks();
        expect(
          clipboardContents,
          'correct horse battery staple',
          reason: 'must still be set before the 10 s window expires',
        );

        async.elapse(const Duration(seconds: 2));
        async.flushMicrotasks();
        expect(
          clipboardContents,
          '',
          reason: 'must be cleared once the 10 s window has expired',
        );
      });
    });

    test(
      'non-match-guard: user-copied content mid-window is NOT wiped',
      () {
        fakeAsync((async) {
          ClipboardUtils.copyWithAutoClear('seed phrase here');
          async.flushMicrotasks();

          // Simulate the user copying something unrelated after the sensitive
          // copy but before the auto-clear timer fires.
          clipboardContents = 'something the user copied';

          async.elapse(const Duration(seconds: 11));
          async.flushMicrotasks();

          expect(
            clipboardContents,
            'something the user copied',
            reason:
                'the non-match guard must leave unrelated clipboard content alone',
          );
        });
      },
    );

    test('lifecycle-clear: clearIfSensitive wipes tracked content', () async {
      await ClipboardUtils.copyWithAutoClear('lifecycle seed');
      expect(clipboardContents, 'lifecycle seed');

      await ClipboardUtils.clearIfSensitive();
      expect(
        clipboardContents,
        '',
        reason:
            'clearIfSensitive() must wipe the clipboard when it still holds '
            'the most recent sensitive copy',
      );
    });

    test(
      'lifecycle-clear: clearIfSensitive is a no-op when clipboard diverged',
      () async {
        await ClipboardUtils.copyWithAutoClear('lifecycle seed 2');
        // User copies something else.
        clipboardContents = 'user data';

        await ClipboardUtils.clearIfSensitive();
        expect(
          clipboardContents,
          'user data',
          reason:
              'clearIfSensitive() must not wipe clipboard content that no '
              'longer matches the tracked sensitive copy',
        );
      },
    );

    test(
      'rapid-overwrite: second copy replaces tracking (last-one-wins)',
      () {
        fakeAsync((async) {
          ClipboardUtils.copyWithAutoClear('first seed');
          async.flushMicrotasks();
          expect(clipboardContents, 'first seed');

          // Second sensitive copy within the window — the tracked value
          // should now point at the second string. Last-one-wins: the most
          // recent copy is what will be cleared next time any pending timer
          // fires (the first timer, since it fires sooner).
          async.elapse(const Duration(seconds: 3));
          ClipboardUtils.copyWithAutoClear('second seed');
          async.flushMicrotasks();
          expect(clipboardContents, 'second seed');

          // Before either timer has fired: 'second seed' is still in the
          // clipboard.
          async.elapse(const Duration(seconds: 6));
          async.flushMicrotasks();
          expect(
            clipboardContents,
            'second seed',
            reason:
                'neither the first nor the second timer has fired yet '
                '(9 s absolute elapsed, first timer at 10 s)',
          );

          // First timer fires at t=10 s absolute. Tracking now points at
          // 'second seed' and the clipboard still matches, so it clears
          // and drops the tracking slot — the second copy is protected by
          // the first, sooner-firing timer.
          async.elapse(const Duration(seconds: 2));
          async.flushMicrotasks();
          expect(
            clipboardContents,
            '',
            reason:
                'last-one-wins: the first timer (sooner) clears the most '
                'recent tracked value, which is the second sensitive copy',
          );

          // Second timer (scheduled at t=3+10=13 s absolute) still fires
          // later but must be a safe no-op — tracking was already dropped.
          async.elapse(const Duration(seconds: 5));
          async.flushMicrotasks();
          expect(
            clipboardContents,
            '',
            reason:
                'the second timer must be a no-op once tracking has been '
                'dropped by the earlier fire',
          );
        });
      },
    );
  });
}
