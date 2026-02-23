import 'dart:async';
import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../theme/dna_spacing.dart';

/// Search bar with debounced callback and clear button
class DnaSearchBar extends StatefulWidget {
  final String hint;
  final ValueChanged<String>? onChanged;
  final int debounceMs;
  final TextEditingController? controller;

  const DnaSearchBar({
    super.key,
    this.hint = 'Search...',
    this.onChanged,
    this.debounceMs = 500,
    this.controller,
  });

  @override
  State<DnaSearchBar> createState() => _DnaSearchBarState();
}

class _DnaSearchBarState extends State<DnaSearchBar> {
  late final TextEditingController _controller;
  Timer? _debounce;

  @override
  void initState() {
    super.initState();
    _controller = widget.controller ?? TextEditingController();
  }

  @override
  void dispose() {
    _debounce?.cancel();
    if (widget.controller == null) _controller.dispose();
    super.dispose();
  }

  void _onChanged(String value) {
    _debounce?.cancel();
    _debounce = Timer(Duration(milliseconds: widget.debounceMs), () {
      widget.onChanged?.call(value);
    });
    setState(() {}); // Update clear button visibility
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(
        horizontal: DnaSpacing.lg,
        vertical: DnaSpacing.sm,
      ),
      child: TextField(
        controller: _controller,
        onChanged: _onChanged,
        decoration: InputDecoration(
          hintText: widget.hint,
          prefixIcon: const Padding(
            padding: EdgeInsets.only(left: 12, right: 8),
            child: FaIcon(FontAwesomeIcons.magnifyingGlass, size: 16),
          ),
          prefixIconConstraints: const BoxConstraints(minWidth: 40, minHeight: 40),
          suffixIcon: _controller.text.isNotEmpty
              ? IconButton(
                  icon: const FaIcon(FontAwesomeIcons.xmark, size: 14),
                  onPressed: () {
                    _controller.clear();
                    widget.onChanged?.call('');
                    setState(() {});
                  },
                )
              : null,
          isDense: true,
        ),
      ),
    );
  }
}
