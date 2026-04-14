// DNA Connect internal custom_lint rules.
//
// This package is wired into the Flutter app via a path dev_dependency in
// messenger/dna_messenger_flutter/pubspec.yaml and registered as an analyzer
// plugin in messenger/dna_messenger_flutter/analysis_options.yaml.
//
// STATUS: SCAFFOLD ONLY — the [AvoidDnaLogPrimitives] rule is DISABLED.
// The `_enabled` constant below is `false`, so `run()` returns immediately
// and no diagnostics are reported. Plan 04-03 Task 2 will:
//   1. Flip `_enabled` to `true`
//   2. Implement the real AST visitor that walks [MethodInvocation] nodes
//      looking for `debugPrint(`, `print(`, and `developer.log(` calls in
//      files under `lib/` (excluding `lib/l10n/` and generated files).
//
// Until then, `dart run custom_lint` exits 0 with zero issues — Wave 2 sweep
// plans can land without the analyzer blocking them.

import 'package:analyzer/error/error.dart';
import 'package:analyzer/error/listener.dart';
import 'package:custom_lint_builder/custom_lint_builder.dart';

/// custom_lint plugin entry point.
PluginBase createPlugin() => _DnaLintsPlugin();

class _DnaLintsPlugin extends PluginBase {
  @override
  List<LintRule> getLintRules(CustomLintConfigs configs) => [
        AvoidDnaLogPrimitives(),
      ];
}

/// Rule that forbids raw logging primitives (`debugPrint`, `print`,
/// `developer.log`) in `lib/`. DnaLogger (`lib/utils/logger.dart`) is the
/// project-sanctioned replacement per CLAUDE.md "ONE logging system" rule.
///
/// DISABLED until Plan 04-03 Task 2 sweep completes. See file header.
class AvoidDnaLogPrimitives extends DartLintRule {
  // Plan 04-03 Task 2 flips this to `true` after the sweep lands and
  // implements the real MethodInvocation visitor below.
  static const bool _enabled = false;

  AvoidDnaLogPrimitives()
      : super(
          code: const LintCode(
            name: 'avoid_dna_log_primitives',
            problemMessage:
                'Use DnaLogger (lib/utils/logger.dart) instead of '
                'debugPrint/print/developer.log in lib/.',
            errorSeverity: ErrorSeverity.ERROR,
          ),
        );

  @override
  void run(
    CustomLintResolver resolver,
    ErrorReporter reporter,
    CustomLintContext context,
  ) {
    if (!_enabled) {
      // Scaffold only — no diagnostics reported.
      return;
    }

    // Plan 04-03 Task 2 implements the real visitor here:
    //   context.registry.addMethodInvocation((node) {
    //     final name = node.methodName.name;
    //     if (name == 'debugPrint' || name == 'print') {
    //       reporter.atNode(node, code);
    //     } else if (name == 'log') {
    //       // check prefix/target == developer
    //     }
    //   });
  }
}
