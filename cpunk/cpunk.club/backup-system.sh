#!/bin/bash

# CPUNK Backup System
# Creates timestamped backups of files before editing
# Maintains last 5 backups per file

BACKUP_DIR="/home/nocdem/projects/cpunk.club/backup"
MAX_BACKUPS=5

# Function to create backup of a file
backup_file() {
    local file_path="$1"
    
    # Check if file exists
    if [[ ! -f "$file_path" ]]; then
        echo "Warning: File $file_path does not exist, skipping backup"
        return 1
    fi
    
    # Get relative path from cpunk.club directory
    local rel_path="${file_path#/home/nocdem/projects/cpunk.club/}"
    
    # Create backup directory structure
    local backup_subdir="$BACKUP_DIR/$(dirname "$rel_path")"
    mkdir -p "$backup_subdir"
    
    # Get filename without path
    local filename=$(basename "$file_path")
    
    # Create timestamp
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    
    # Create backup filename
    local backup_filename="${filename}.backup.${timestamp}"
    local backup_path="$backup_subdir/$backup_filename"
    
    # Copy file to backup
    cp "$file_path" "$backup_path"
    echo "Backup created: $backup_path"
    
    # Clean old backups (keep only last 5)
    cleanup_old_backups "$backup_subdir" "$filename"
    
    return 0
}

# Function to clean up old backups
cleanup_old_backups() {
    local backup_subdir="$1"
    local filename="$2"
    
    # Find all backups for this file and sort by modification time
    local backup_files=($(ls -t "$backup_subdir"/${filename}.backup.* 2>/dev/null))
    
    # If we have more than MAX_BACKUPS, remove the oldest ones
    if [[ ${#backup_files[@]} -gt $MAX_BACKUPS ]]; then
        for ((i=$MAX_BACKUPS; i<${#backup_files[@]}; i++)); do
            rm -f "${backup_files[i]}"
            echo "Removed old backup: ${backup_files[i]}"
        done
    fi
}

# Function to list backups for a file
list_backups() {
    local file_path="$1"
    local rel_path="${file_path#/home/nocdem/projects/cpunk.club/}"
    local backup_subdir="$BACKUP_DIR/$(dirname "$rel_path")"
    local filename=$(basename "$file_path")
    
    echo "Backups for $file_path:"
    ls -la "$backup_subdir"/${filename}.backup.* 2>/dev/null || echo "No backups found"
}

# Function to restore from backup
restore_backup() {
    local backup_path="$1"
    local original_path="$2"
    
    if [[ ! -f "$backup_path" ]]; then
        echo "Error: Backup file $backup_path does not exist"
        return 1
    fi
    
    # Create backup of current file before restoring
    backup_file "$original_path"
    
    # Restore from backup
    cp "$backup_path" "$original_path"
    echo "Restored $original_path from $backup_path"
}

# Main function
main() {
    case "$1" in
        "backup")
            backup_file "$2"
            ;;
        "list")
            list_backups "$2"
            ;;
        "restore")
            restore_backup "$2" "$3"
            ;;
        *)
            echo "Usage: $0 {backup|list|restore} <file_path> [backup_path]"
            echo "  backup <file_path>           - Create backup of file"
            echo "  list <file_path>             - List backups for file"
            echo "  restore <backup_path> <file_path> - Restore file from backup"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"