import 'package:flutter/material.dart';
import '../theme/dna_spacing.dart';

/// Switch toggle with label and optional subtitle
class DnaSwitch extends StatelessWidget {
  final String label;
  final bool value;
  final ValueChanged<bool>? onChanged;
  final String? subtitle;

  const DnaSwitch({
    super.key,
    required this.label,
    required this.value,
    this.onChanged,
    this.subtitle,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return InkWell(
      onTap: onChanged != null ? () => onChanged!(!value) : null,
      child: Padding(
        padding: const EdgeInsets.symmetric(
          horizontal: DnaSpacing.lg,
          vertical: DnaSpacing.md,
        ),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(label, style: theme.textTheme.bodyLarge),
                  if (subtitle != null) ...[
                    const SizedBox(height: 2),
                    Text(subtitle!, style: theme.textTheme.bodySmall),
                  ],
                ],
              ),
            ),
            Switch(
              value: value,
              onChanged: onChanged,
            ),
          ],
        ),
      ),
    );
  }
}
