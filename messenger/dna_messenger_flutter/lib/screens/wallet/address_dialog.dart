// Address Dialog - Add/edit wallet address
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../ffi/dna_engine.dart' show AddressBookEntry;
import '../../l10n/app_localizations.dart';

class AddressDialogResult {
  final String address;
  final String label;
  final String network;
  final String notes;

  AddressDialogResult({
    required this.address,
    required this.label,
    required this.network,
    required this.notes,
  });
}

class AddressDialog extends StatefulWidget {
  final AddressBookEntry? entry;
  final String? prefilledAddress;
  final String? prefilledNetwork;

  const AddressDialog({super.key, this.entry})
      : prefilledAddress = null,
        prefilledNetwork = null;

  const AddressDialog.prefilled({
    super.key,
    required String address,
    required String network,
  })  : entry = null,
        prefilledAddress = address,
        prefilledNetwork = network;

  @override
  State<AddressDialog> createState() => _AddressDialogState();
}

class _AddressDialogState extends State<AddressDialog> {
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _addressController;
  late final TextEditingController _labelController;
  late final TextEditingController _notesController;
  late String _selectedNetwork;

  bool get _isEditing => widget.entry != null;

  static const _networks = [
    ('cellframe', 'Cellframe (CF20)'),
    ('ethereum', 'Ethereum (ERC20)'),
    ('solana', 'Solana (SPL)'),
    ('tron', 'TRON (TRC20)'),
    ('bsc', 'BNB Smart Chain (BEP20)'),
  ];

  @override
  void initState() {
    super.initState();
    _addressController = TextEditingController(
      text: widget.entry?.address ?? widget.prefilledAddress ?? '',
    );
    _labelController = TextEditingController(text: widget.entry?.label ?? '');
    _notesController = TextEditingController(text: widget.entry?.notes ?? '');
    _selectedNetwork = widget.entry?.network ?? widget.prefilledNetwork ?? 'cellframe';
  }

  bool get _isPrefilled => widget.prefilledAddress != null;

  @override
  void dispose() {
    _addressController.dispose();
    _labelController.dispose();
    _notesController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(_isEditing ? AppLocalizations.of(context).walletEditAddress : AppLocalizations.of(context).walletAddAddress),
      content: SingleChildScrollView(
        child: Form(
          key: _formKey,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Network dropdown
              DropdownButtonFormField<String>(
                initialValue: _selectedNetwork,
                decoration: InputDecoration(
                  labelText: AppLocalizations.of(context).walletNetwork,
                  prefixIcon: Icon(Icons.layers),
                ),
                items: _networks.map((n) {
                  return DropdownMenuItem(
                    value: n.$1,
                    child: Text(n.$2),
                  );
                }).toList(),
                onChanged: _isPrefilled
                    ? null // Can't change network when prefilled (e.g., from send flow)
                    : (value) {
                        if (value != null) {
                          setState(() => _selectedNetwork = value);
                        }
                      },
              ),
              const SizedBox(height: 16),

              // Address input
              TextFormField(
                controller: _addressController,
                enabled: !_isPrefilled, // Editable in edit mode, locked only when prefilled from send flow
                decoration: InputDecoration(
                  labelText: AppLocalizations.of(context).walletAddress,
                  hintText: _getAddressHint(_selectedNetwork),
                  prefixIcon: const Icon(Icons.account_balance_wallet),
                  suffixIcon: !_isPrefilled
                      ? IconButton(
                          icon: const FaIcon(FontAwesomeIcons.paste, size: 16),
                          onPressed: _pasteAddress,
                          tooltip: 'Paste from clipboard',
                        )
                      : null,
                ),
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return 'Address is required';
                  }
                  if (!_validateAddress(value, _selectedNetwork)) {
                    return 'Invalid address format';
                  }
                  return null;
                },
                maxLines: 2,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
              const SizedBox(height: 16),

              // Label input
              TextFormField(
                controller: _labelController,
                decoration: InputDecoration(
                  labelText: AppLocalizations.of(context).walletLabel,
                  hintText: 'e.g., My Exchange, Friend',
                  prefixIcon: Icon(Icons.label),
                ),
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return 'Label is required';
                  }
                  if (value.length > 63) {
                    return 'Label must be 63 characters or less';
                  }
                  return null;
                },
                maxLength: 63,
                textCapitalization: TextCapitalization.words,
              ),
              const SizedBox(height: 8),

              // Notes input (optional)
              TextFormField(
                controller: _notesController,
                decoration: const InputDecoration(
                  labelText: 'Notes (optional)',
                  hintText: 'Any additional info...',
                  prefixIcon: Icon(Icons.note),
                ),
                maxLines: 2,
                maxLength: 255,
              ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(AppLocalizations.of(context).cancel),
        ),
        ElevatedButton(
          onPressed: _submit,
          child: Text(_isEditing ? AppLocalizations.of(context).save : AppLocalizations.of(context).walletAddAddress),
        ),
      ],
    );
  }

  String _getAddressHint(String network) {
    switch (network) {
      case 'cellframe':
        return 'Cellframe address...';
      case 'ethereum':
        return '0x...';
      case 'solana':
        return 'Base58 address...';
      case 'tron':
        return 'T...';
      case 'bsc':
        return '0x...';
      default:
        return 'Address...';
    }
  }

  bool _validateAddress(String address, String network) {
    switch (network) {
      case 'cellframe':
        // Cellframe: Base58, 30-60 chars
        return RegExp(r'^[1-9A-HJ-NP-Za-km-z]{30,60}$').hasMatch(address);
      case 'ethereum':
        // Ethereum: 0x + 40 hex chars
        return RegExp(r'^0x[a-fA-F0-9]{40}$').hasMatch(address);
      case 'solana':
        // Solana: Base58, 32-44 chars
        return RegExp(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$').hasMatch(address);
      case 'tron':
        // TRON: T + 33 Base58 chars
        return RegExp(r'^T[1-9A-HJ-NP-Za-km-z]{33}$').hasMatch(address);
      case 'bsc':
        // BSC: same format as ETH (0x + 40 hex)
        return RegExp(r'^0x[a-fA-F0-9]{40}$').hasMatch(address);
      default:
        return address.isNotEmpty;
    }
  }

  Future<void> _pasteAddress() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text != null) {
      _addressController.text = data!.text!.trim();
      // Auto-detect network from address format
      final detected = _detectNetwork(data.text!.trim());
      if (detected != null) {
        setState(() => _selectedNetwork = detected);
      }
    }
  }

  String? _detectNetwork(String address) {
    if (address.startsWith('0x') && address.length == 42) {
      return 'ethereum';
    }
    if (address.startsWith('T') && address.length == 34) {
      return 'tron';
    }
    if (RegExp(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$').hasMatch(address)) {
      // Could be Solana or Cellframe - guess based on length
      if (address.length >= 32 && address.length <= 44) {
        return 'solana';
      }
    }
    return null;
  }

  void _submit() {
    if (_formKey.currentState?.validate() ?? false) {
      Navigator.pop(
        context,
        AddressDialogResult(
          address: _addressController.text.trim(),
          label: _labelController.text.trim(),
          network: _selectedNetwork,
          notes: _notesController.text.trim(),
        ),
      );
    }
  }
}
