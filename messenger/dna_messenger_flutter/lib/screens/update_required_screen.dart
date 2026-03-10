// Update Required Screen - blocks app when version is below DHT minimum
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:url_launcher/url_launcher.dart';
import '../design_system/theme/dna_colors.dart';

class UpdateRequiredScreen extends StatefulWidget {
  final String libraryMinimum;
  final String appMinimum;
  final String localLibraryVersion;

  const UpdateRequiredScreen({
    super.key,
    required this.libraryMinimum,
    required this.appMinimum,
    required this.localLibraryVersion,
  });

  @override
  State<UpdateRequiredScreen> createState() => _UpdateRequiredScreenState();
}

class _UpdateRequiredScreenState extends State<UpdateRequiredScreen> {
  String _localAppVersion = '...';

  @override
  void initState() {
    super.initState();
    PackageInfo.fromPlatform().then((info) {
      if (mounted) setState(() => _localAppVersion = info.version);
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              SvgPicture.asset(
                'assets/logo-icon.svg',
                width: 96,
                height: 96,
              ),
              const SizedBox(height: 32),
              FaIcon(
                FontAwesomeIcons.circleExclamation,
                size: 48,
                color: DnaColors.textWarning,
              ),
              const SizedBox(height: 16),
              Text(
                'Update Required',
                style: theme.textTheme.headlineSmall?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'Your version of DNA Messenger is outdated and can no longer be used. '
                'Please update to the latest version to continue.',
                style: theme.textTheme.bodyMedium,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Column(
                  children: [
                    _versionRow(theme, 'Library', widget.localLibraryVersion, widget.libraryMinimum),
                    const SizedBox(height: 8),
                    _versionRow(theme, 'App', _localAppVersion, widget.appMinimum),
                  ],
                ),
              ),
              const SizedBox(height: 32),
              if (Platform.isAndroid)
                FilledButton.icon(
                  onPressed: () {
                    launchUrl(
                      Uri.parse('https://play.google.com/store/apps/details?id=io.cpunk.messenger'),
                      mode: LaunchMode.externalApplication,
                    );
                  },
                  icon: const FaIcon(FontAwesomeIcons.googlePlay, size: 18),
                  label: const Text('Update on Play Store'),
                )
              else
                FilledButton.icon(
                  onPressed: () {
                    launchUrl(
                      Uri.parse('https://cpunk.io'),
                      mode: LaunchMode.externalApplication,
                    );
                  },
                  icon: const FaIcon(FontAwesomeIcons.download, size: 18),
                  label: const Text('Download Update'),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _versionRow(ThemeData theme, String label, String current, String minimum) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label, style: theme.textTheme.bodyMedium),
        Text(
          '$current (min: $minimum)',
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.error,
          ),
        ),
      ],
    );
  }
}
