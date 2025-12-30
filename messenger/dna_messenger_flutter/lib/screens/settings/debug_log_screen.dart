// Debug Log Screen - In-app log viewer for mobile debugging
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';

/// Debug log screen for viewing native library logs
class DebugLogScreen extends ConsumerStatefulWidget {
  const DebugLogScreen({super.key});

  @override
  ConsumerState<DebugLogScreen> createState() => _DebugLogScreenState();
}

class _DebugLogScreenState extends ConsumerState<DebugLogScreen> {
  List<DebugLogEntry> _entries = [];
  Timer? _refreshTimer;
  bool _autoRefresh = true;
  DebugLogLevel? _filterLevel;
  final _scrollController = ScrollController();
  bool _scrollToBottom = true;

  @override
  void initState() {
    super.initState();
    _loadEntries();
    _startAutoRefresh();
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    _scrollController.dispose();
    super.dispose();
  }

  void _startAutoRefresh() {
    _refreshTimer?.cancel();
    if (_autoRefresh) {
      _refreshTimer = Timer.periodic(const Duration(seconds: 2), (_) {
        _loadEntries();
      });
    }
  }

  void _loadEntries() {
    final engineAsync = ref.read(engineProvider);
    engineAsync.whenData((engine) {
      final entries = engine.debugLogGetEntries();
      if (mounted) {
        setState(() {
          _entries = entries;
        });
        if (_scrollToBottom && entries.isNotEmpty) {
          WidgetsBinding.instance.addPostFrameCallback((_) {
            if (_scrollController.hasClients) {
              _scrollController.animateTo(
                _scrollController.position.maxScrollExtent,
                duration: const Duration(milliseconds: 200),
                curve: Curves.easeOut,
              );
            }
          });
        }
      }
    });
  }

  void _clearLogs() {
    final engineAsync = ref.read(engineProvider);
    engineAsync.whenData((engine) {
      engine.debugLogClear();
      if (mounted) {
        setState(() {
          _entries = [];
        });
      }
    });
  }

  void _copyAllLogs() {
    final text = _filteredEntries.map((e) => e.toString()).join('\n');
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Copied ${_filteredEntries.length} log entries'),
        backgroundColor: DnaColors.snackbarSuccess,
      ),
    );
  }

  List<DebugLogEntry> get _filteredEntries {
    if (_filterLevel == null) return _entries;
    return _entries.where((e) => e.level.index >= _filterLevel!.index).toList();
  }

  Color _levelColor(DebugLogLevel level) {
    switch (level) {
      case DebugLogLevel.debug:
        return DnaColors.textMuted;
      case DebugLogLevel.info:
        return DnaColors.textSuccess;
      case DebugLogLevel.warn:
        return DnaColors.textWarning;
      case DebugLogLevel.error:
        return Colors.red;
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final filteredEntries = _filteredEntries;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Debug Logs'),
        actions: [
          // Filter dropdown
          PopupMenuButton<DebugLogLevel?>(
            icon: FaIcon(
              FontAwesomeIcons.filter,
              color: _filterLevel != null ? theme.colorScheme.primary : null,
            ),
            tooltip: 'Filter by level',
            onSelected: (level) {
              setState(() {
                _filterLevel = level;
              });
            },
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: null,
                child: Text('All levels'),
              ),
              const PopupMenuItem(
                value: DebugLogLevel.debug,
                child: Text('DEBUG+'),
              ),
              const PopupMenuItem(
                value: DebugLogLevel.info,
                child: Text('INFO+'),
              ),
              const PopupMenuItem(
                value: DebugLogLevel.warn,
                child: Text('WARN+'),
              ),
              const PopupMenuItem(
                value: DebugLogLevel.error,
                child: Text('ERROR only'),
              ),
            ],
          ),
          // Auto-refresh toggle
          IconButton(
            icon: FaIcon(
              _autoRefresh ? FontAwesomeIcons.arrowsRotate : FontAwesomeIcons.stop,
              color: _autoRefresh ? theme.colorScheme.primary : null,
            ),
            tooltip: _autoRefresh ? 'Auto-refresh ON' : 'Auto-refresh OFF',
            onPressed: () {
              setState(() {
                _autoRefresh = !_autoRefresh;
              });
              _startAutoRefresh();
            },
          ),
          // More options
          PopupMenuButton(
            itemBuilder: (context) => [
              PopupMenuItem(
                onTap: _loadEntries,
                child: const Row(
                  children: [
                    FaIcon(FontAwesomeIcons.arrowsRotate, size: 20),
                    SizedBox(width: 12),
                    Text('Refresh now'),
                  ],
                ),
              ),
              PopupMenuItem(
                onTap: _copyAllLogs,
                child: const Row(
                  children: [
                    FaIcon(FontAwesomeIcons.copy, size: 20),
                    SizedBox(width: 12),
                    Text('Copy all'),
                  ],
                ),
              ),
              PopupMenuItem(
                onTap: _clearLogs,
                child: Row(
                  children: [
                    FaIcon(FontAwesomeIcons.trash, size: 20, color: DnaColors.textWarning),
                    const SizedBox(width: 12),
                    Text('Clear logs', style: TextStyle(color: DnaColors.textWarning)),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
      body: Column(
        children: [
          // Status bar
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            color: theme.colorScheme.surface,
            child: Row(
              children: [
                FaIcon(
                  FontAwesomeIcons.circle,
                  size: 8,
                  color: _autoRefresh ? DnaColors.textSuccess : DnaColors.textMuted,
                ),
                const SizedBox(width: 8),
                Text(
                  '${filteredEntries.length} entries',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: DnaColors.textMuted,
                  ),
                ),
                if (_filterLevel != null) ...[
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                    decoration: BoxDecoration(
                      color: theme.colorScheme.primary.withAlpha(26),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Text(
                      _filterLevel!.name.toUpperCase(),
                      style: theme.textTheme.labelSmall?.copyWith(
                        color: theme.colorScheme.primary,
                      ),
                    ),
                  ),
                ],
                const Spacer(),
                // Scroll to bottom toggle
                IconButton(
                  icon: FaIcon(
                    FontAwesomeIcons.arrowDown,
                    size: 20,
                    color: _scrollToBottom ? theme.colorScheme.primary : DnaColors.textMuted,
                  ),
                  tooltip: 'Auto-scroll to bottom',
                  onPressed: () {
                    setState(() {
                      _scrollToBottom = !_scrollToBottom;
                    });
                  },
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          // Log entries
          Expanded(
            child: filteredEntries.isEmpty
                ? Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        FaIcon(
                          FontAwesomeIcons.fileLines,
                          size: 64,
                          color: DnaColors.textMuted.withAlpha(102),
                        ),
                        const SizedBox(height: 16),
                        Text(
                          'No log entries',
                          style: theme.textTheme.titleMedium?.copyWith(
                            color: DnaColors.textMuted,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Logs will appear here when debug logging is enabled',
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: DnaColors.textMuted,
                          ),
                        ),
                      ],
                    ),
                  )
                : ListView.builder(
                    controller: _scrollController,
                    itemCount: filteredEntries.length,
                    itemBuilder: (context, index) {
                      final entry = filteredEntries[index];
                      return _LogEntryTile(
                        entry: entry,
                        levelColor: _levelColor(entry.level),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}

class _LogEntryTile extends StatelessWidget {
  final DebugLogEntry entry;
  final Color levelColor;

  const _LogEntryTile({
    required this.entry,
    required this.levelColor,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final time = entry.timestamp;
    final timeStr = '${time.hour.toString().padLeft(2, '0')}:'
        '${time.minute.toString().padLeft(2, '0')}:'
        '${time.second.toString().padLeft(2, '0')}.'
        '${(time.millisecond ~/ 10).toString().padLeft(2, '0')}';

    return InkWell(
      onLongPress: () {
        Clipboard.setData(ClipboardData(text: entry.toString()));
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Log entry copied')),
        );
      },
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(
          border: Border(
            left: BorderSide(color: levelColor, width: 3),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header row: time, level, tag
            Row(
              children: [
                Text(
                  timeStr,
                  style: theme.textTheme.labelSmall?.copyWith(
                    fontFamily: 'monospace',
                    color: DnaColors.textMuted,
                  ),
                ),
                const SizedBox(width: 8),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                  decoration: BoxDecoration(
                    color: levelColor.withAlpha(26),
                    borderRadius: BorderRadius.circular(2),
                  ),
                  child: Text(
                    entry.levelString,
                    style: theme.textTheme.labelSmall?.copyWith(
                      color: levelColor,
                      fontWeight: FontWeight.w600,
                      fontSize: 10,
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  entry.tag,
                  style: theme.textTheme.labelSmall?.copyWith(
                    color: theme.colorScheme.primary,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 2),
            // Message
            Text(
              entry.message,
              style: theme.textTheme.bodySmall?.copyWith(
                fontFamily: 'monospace',
                fontSize: 12,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
