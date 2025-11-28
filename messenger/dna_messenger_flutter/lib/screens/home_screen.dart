// Home Screen - Routes to identity selection or contacts
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/providers.dart';
import 'identity/identity_selection_screen.dart';
import 'contacts/contacts_screen.dart';

class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final identityLoaded = ref.watch(identityLoadedProvider);

    // Show contacts if identity loaded, otherwise show identity selection
    if (identityLoaded) {
      return const ContactsScreen();
    } else {
      return const IdentitySelectionScreen();
    }
  }
}
