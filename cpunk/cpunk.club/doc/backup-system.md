# CPUNK Backup System

## Overview

The CPUNK project includes an automated backup system that creates timestamped backups of files before editing. This provides a safety net for code changes and allows easy recovery from unintended modifications.

## Features

- **Automatic Backups**: Creates backup before any file edit
- **Timestamped Files**: Each backup includes date and time
- **Retention Policy**: Keeps last 5 backups per file
- **Organized Structure**: Maintains directory structure in backup folder
- **Git Ignored**: Backups are excluded from version control and deployment

## Directory Structure

```
cpunk.club/
├── backup/                          # Main backup directory (git ignored)
│   ├── js/
│   │   ├── settings.js.backup.20250526_143022
│   │   ├── settings.js.backup.20250526_142815
│   │   └── ...
│   ├── css/
│   └── ...
├── backup-system.sh                 # Backup management script
└── doc/
    └── backup-system.md             # This documentation
```

## Usage

### Command Line Interface

```bash
# Create backup of a file
./backup-system.sh backup /path/to/file.js

# List all backups for a file
./backup-system.sh list /path/to/file.js

# Restore file from specific backup
./backup-system.sh restore /path/to/backup.file.backup.20250526_143022 /path/to/file.js
```

### Integration with Claude Code

The backup system is integrated into the project workflow. Claude Code should:

1. **Before any file edit**: Call `backup_file()` function
2. **Use absolute paths**: Always provide full file paths
3. **Verify backup creation**: Check return status

#### Example Integration

```bash
# Before editing settings.js
./backup-system.sh backup /home/nocdem/projects/cpunk.club/js/settings.js

# Then proceed with edit
# Edit file using Edit tool...

# Verify backup was created
./backup-system.sh list /home/nocdem/projects/cpunk.club/js/settings.js
```

## Backup File Naming Convention

Backup files follow this naming pattern:
```
{original_filename}.backup.{timestamp}
```

Where:
- `original_filename`: The name of the original file
- `timestamp`: Format YYYYMMDD_HHMMSS (e.g., 20250526_143022)

## Retention Policy

- **Maximum backups per file**: 5
- **Cleanup**: Automatic removal of oldest backups when limit exceeded
- **Sort order**: Most recent backup kept, oldest removed first

## Git and Deployment Exclusions

### .gitignore
```
# Backup directories
backup/
*.backup
```

### Deployment Exclusions
Backups are excluded from deployment via rsync:
```bash
--exclude-from=<(echo -e "*.txt\n/doc/\n/devel/\n/configs/\n/certs/\n/backup/\n/js/unused/")
```

## Recovery Procedures

### Quick Recovery (Last Edit)
```bash
# Find most recent backup
./backup-system.sh list /path/to/file.js

# Restore from most recent
./backup-system.sh restore /path/to/most/recent/backup /path/to/file.js
```

### Selective Recovery
```bash
# List all backups with timestamps
ls -la backup/js/settings.js.backup.*

# Choose specific backup by timestamp
./backup-system.sh restore backup/js/settings.js.backup.20250526_142815 /path/to/settings.js
```

## Best Practices

1. **Always backup before editing**: Never skip the backup step
2. **Verify backup creation**: Check that backup was created successfully
3. **Use absolute paths**: Avoid relative paths in backup commands
4. **Document major changes**: Note significant edits in commit messages
5. **Test restoration**: Periodically verify backup restoration works

## Troubleshooting

### Common Issues

#### Permission Denied
```bash
chmod +x backup-system.sh
```

#### Backup Directory Missing
The script automatically creates necessary directories.

#### File Not Found
Verify the file path is correct and file exists before backup.

### Error Messages

- **"File does not exist"**: Check file path spelling and existence
- **"No backups found"**: File has never been backed up
- **"Backup file does not exist"**: Backup path is incorrect

## Integration with CLAUDE.md

This backup system is referenced in the main project instructions at `/home/nocdem/projects/CLAUDE.md` for automated usage by Claude Code during development sessions.