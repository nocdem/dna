// Legacy compatibility shim — re-exports from new design system
// All 23 screens import this file for DnaColors
// Will be removed after full migration to design_system imports
//
// This file re-exports DnaColors so existing screens keep working.
// New code should import from design_system/design_system.dart instead.

export '../design_system/theme/dna_colors.dart';
