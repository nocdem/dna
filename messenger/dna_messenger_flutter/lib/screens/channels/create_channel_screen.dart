// Create Channel Screen - Form for creating new channels
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../l10n/app_localizations.dart';
import '../../providers/providers.dart';

class CreateChannelScreen extends ConsumerStatefulWidget {
  const CreateChannelScreen({super.key});

  @override
  ConsumerState<CreateChannelScreen> createState() =>
      _CreateChannelScreenState();
}

class _CreateChannelScreenState extends ConsumerState<CreateChannelScreen> {
  final _nameController = TextEditingController();
  final _descriptionController = TextEditingController();
  bool _isPublic = true;
  bool _isCreating = false;

  @override
  void dispose() {
    _nameController.dispose();
    _descriptionController.dispose();
    super.dispose();
  }

  bool get _canCreate =>
      _nameController.text.trim().isNotEmpty && !_isCreating;

  Future<void> _create() async {
    final name = _nameController.text.trim();
    final description = _descriptionController.text.trim();

    setState(() => _isCreating = true);

    try {
      await ref.read(channelListProvider.notifier).createChannel(
            name,
            description,
            isPublic: _isPublic,
          );
      if (mounted) {
        DnaSnackBar.success(context, AppLocalizations.of(context).channelCreated);
        Navigator.pop(context);
      }
    } catch (e) {
      if (mounted) {
        DnaSnackBar.error(context, 'Failed to create channel: $e');
        setState(() => _isCreating = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: DnaAppBar(title: AppLocalizations.of(context).channelsCreate),
      body: Padding(
        padding: const EdgeInsets.all(DnaSpacing.lg),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            DnaTextField(
              label: AppLocalizations.of(context).channelName,
              hint: 'Enter channel name',
              controller: _nameController,
              autofocus: true,
              prefixIcon: const SizedBox(
                width: 48,
                child: Center(
                  child: FaIcon(FontAwesomeIcons.hashtag, size: 18),
                ),
              ),
              onChanged: (_) => setState(() {}),
            ),
            const SizedBox(height: DnaSpacing.lg),
            DnaTextField(
              label: AppLocalizations.of(context).channelDescription,
              hint: 'What is this channel about? (optional)',
              controller: _descriptionController,
              maxLines: 3,
              prefixIcon: const SizedBox(
                width: 48,
                child: Center(
                  child: FaIcon(FontAwesomeIcons.alignLeft, size: 18),
                ),
              ),
            ),
            const SizedBox(height: DnaSpacing.lg),
            DnaSwitch(
              label: AppLocalizations.of(context).channelListPublicly,
              subtitle: AppLocalizations.of(context).channelListPubliclyHint,
              value: _isPublic,
              onChanged: (value) => setState(() => _isPublic = value),
            ),
            const SizedBox(height: DnaSpacing.xl),
            DnaButton(
              label: AppLocalizations.of(context).channelsCreate,
              icon: FontAwesomeIcons.plus,
              onPressed: _canCreate ? _create : null,
              loading: _isCreating,
              expand: true,
            ),
          ],
        ),
      ),
    );
  }
}
