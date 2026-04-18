// Delegation Screen — placeholder scaffold; filled in Task 74.
import 'package:flutter/material.dart';
import '../ffi/dnac_bindings.dart';

class DelegationScreen extends StatelessWidget {
  const DelegationScreen({super.key, required this.earner});
  final DnacValidator earner;

  @override
  Widget build(BuildContext context) {
    // Task 74 fills this out with the full delegate/undelegate form.
    return const Scaffold(body: SizedBox.shrink());
  }
}
