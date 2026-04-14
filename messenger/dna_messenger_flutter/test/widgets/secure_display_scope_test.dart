import 'package:dna_connect/widgets/secure_display_scope.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('enables on mount, disables on dismount', (tester) async {
    var enableCalls = 0;
    var disableCalls = 0;

    await tester.pumpWidget(MaterialApp(
      home: SecureDisplayScope(
        onEnable: () async => enableCalls++,
        onDisable: () async => disableCalls++,
        child: const Text('seed display'),
      ),
    ));

    expect(enableCalls, 1, reason: 'enable should fire exactly once on mount');
    expect(disableCalls, 0, reason: 'disable should not fire before dispose');
    expect(find.text('seed display'), findsOneWidget);

    // Replace the widget tree entirely — this disposes SecureDisplayScope.
    await tester
        .pumpWidget(const MaterialApp(home: Scaffold(body: Text('other'))));

    expect(disableCalls, 1, reason: 'disable should fire exactly once on dispose');
    expect(enableCalls, 1, reason: 'enable should not re-fire after dispose');
  });

  testWidgets('rebuild without remount does not re-fire callbacks',
      (tester) async {
    var enableCalls = 0;
    var disableCalls = 0;

    Widget buildTree(String label) => MaterialApp(
          home: SecureDisplayScope(
            key: const ValueKey('scope'),
            onEnable: () async => enableCalls++,
            onDisable: () async => disableCalls++,
            child: Text(label),
          ),
        );

    await tester.pumpWidget(buildTree('first'));
    expect(enableCalls, 1);
    expect(disableCalls, 0);

    // Rebuild with a new child but same scope key — state is preserved,
    // neither initState nor dispose should run again.
    await tester.pumpWidget(buildTree('second'));
    expect(find.text('second'), findsOneWidget);
    expect(enableCalls, 1, reason: 'enable must not re-fire on rebuild');
    expect(disableCalls, 0, reason: 'disable must not fire on rebuild');
  });

  testWidgets('renders the child widget', (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: SecureDisplayScope(
        onEnable: () async {},
        onDisable: () async {},
        child: const Text('sensitive content'),
      ),
    ));

    expect(find.text('sensitive content'), findsOneWidget);
  });
}
