# CLAUDE.md

Every session will start with protocol mode enabled.

**IMPORTANT**: Before starting any task, always check the documents and references in doc/ directory for relevant information.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Security Warning

**CRITICAL SECURITY NOTE**: This project is OPEN SOURCE and publicly accessible. When deploying or creating code:
- NEVER include sensitive information (passwords, API keys, private keys, tokens)
- NEVER commit secrets to the repository
- ALWAYS review code for security vulnerabilities before deployment
- Consider all code and configurations as publicly visible

## Project Overview

This repository contains the CPUNK cryptocurrency platform, a "Quantum-Safe MEME Coin" built on the Cellframe blockchain. The platform is primarily a web application with these key features:

1. DNA registration (Distributed Naming & Addressing)
2. Wallet delegation and rewards tracking
3. User authentication and profile management
4. Community features (messaging, voting)
5. Content management and distribution

## Repository Configuration

- **CPUNK Repository**: Public repository at https://github.com/nocdem/cpunk.git
- **GitHub Authentication**: Using GitHub token for HTTPS authentication
- **Server Authentication**: Using SSH deploy keys (stored in ~/.ssh/cpunk_deploy_user)
- **SSH Config**: Custom host configurations in ~/.ssh/config:
  - "cpunk-deploy" for server deployment (uses cpunk_deploy_user)
- **Git User**: [configured per user]

## Deployment Server Details

- **Deployment Server**: cpunk-deploy (75.119.141.51)
- **Web Files Location**: /var/www/html
- **SSH Key**: ~/.ssh/cpunk_deploy_user
- **Deployment User**: "deployer"
- **SSH Config Entry**:
  ```
  Host cpunk-deploy
    HostName 75.119.141.51
    User deployer
    IdentityFile ~/.ssh/cpunk_deploy_user
  ```
- **DO NOT DEPLOY**: 
  - Documentation files (files in the /doc/ directory)
  - Any .txt files
  - Development and test files (files in the /devel/ directory)
  - Configuration files (files in the /configs/ directory)
  - Certificate files (files in the /certs/ directory)
  - Backup files (files in the /backup/ directory)
  - Unused JavaScript files (files in the /js/unused/ directory)
- **DEPLOYMENT COMMAND**: Use rsync with --no-group flag to avoid permission errors:
  ```
  rsync -avz --no-group --exclude-from=<(echo -e "*.txt\n/doc/\n/devel/\n/configs/\n/certs/\n/backup/\n/js/unused/") ./ cpunk-deploy:/var/www/html/
  ```

## Project Structure

### Root Directory: /home/nocdem/projects/
- **CLAUDE.md**: Project instructions for Claude AI
- **CPUNK_Project_Teaser.md**: CPUNK cryptocurrency project overview
- **Shell scripts**: Balance comparison and ledger statistics utilities
- **deployment.log**: Deployment tracking

### Main Directories:

#### 1. cpunk.club/ - Main CPUNK Web Platform
- **Core Pages**: HTML files for platform features (dashboard, delegation, voting, messaging, etc.)
- **css/**: Page-specific stylesheets
- **js/**: JavaScript modules for platform functionality
- **doc/**: Cellframe and CPUNK documentation
  - cellframe-node-reference.md (Complete CLI reference)
  - cellframe-comprehensive-guide.md (Overall platform guide)
  - cellframe-developer-reference.md (Developer documentation)
  - cellframe-node-setup-guide.md (Installation guide)
  - cpunk-improvement-proposals-guide.md (CIP documentation)
- **configs/**: Network configuration files (Cpunk.cfg, chain-0.cfg, main.cfg)
- **certs/**: Digital certificates (cpunk.master.*.dcert, cpunk.root.*.dcert)
- **devel/**: Development and test files
- **backup/**: Backup directory
- **OAuth Integration**: PHP files for GitHub, Google, LinkedIn, Twitter authentication
- **Data Files**: Various .txt files for data storage

#### 2. cellframe/ - Cellframe Blockchain Components
- **cellframe-node/**: Core blockchain node implementation
- **cellframe-wallet/**: Qt-based desktop wallet GUI
- **cellframe-masternode-webui/**: Python web monitoring interface
- **cellframe-tool-sign/**: Command-line signing utility
- **cellframe-java/**: Java bindings (CellframeSDK JAR)

#### 3. node-management/ - Automated Node Management
- **auto_up.sh**: Main automation script for node health monitoring
- **all_collect.sh**: Collection utilities
- **CLAUDE.md**: Specific instructions for node management

#### 4. dev-tools/ - Development Utilities
- **deploy-to-github.sh**: GitHub deployment script

#### 5. backend/ - CPUNK GDB Server (Cellframe Plugin)
- **cpunk-gdb-server.py**: Main entry point for the Cellframe blockchain plugin
- **handlers.py**: HTTP request routing for DNA registration endpoints
- **gdb_ops.py**: Global Database operations for managing DNA registrations
- **config.py**: Configuration management (TEST_MODE, URL endpoints)
- **utils.py**: Utility functions for validation and address parsing
- **response_helpers.py**: JSON response formatting
- **manifest.json**: Plugin metadata (version 0.1.1)

##### Backend Commands:
```bash
# The backend runs as a Cellframe node plugin
# It automatically starts when the Cellframe node loads the plugin
# HTTP server runs on /{Config.URL} endpoint (default: /cpunk_gdb)

# CLI command available within Cellframe node:
dna_restore {backup_index}  # Restore DNA registrations from backup
```

##### Backend API Endpoints:
- **POST /cpunk_gdb**: Register (`add`) or update (`update`) DNA names
- **GET /cpunk_gdb?lookup={name_or_address}**: Lookup by name or wallet
- **GET /cpunk_gdb?tx_validate={hash}&network={net}**: Validate transaction
- **GET /cpunk_gdb?by_telegram={username}**: Lookup by Telegram username
- **GET /cpunk_gdb?all_delegations=1**: Get all delegations

### Excluded from Git:
- cellframe/ directory and all subdirectories
- node-management/ directory
- dev-tools/ directory
- All .txt files
- deployment.log
- Configuration files (hosts, rsync_exclude.txt, static_addresses.txt)

## Core Principles

1. Not overcomplicate things
2. Not assume things
3. Do only what I'm explicitly told to do
4. Follow instructions precisely
5. Not add extra features or "improvements" that weren't requested
6. Keep implementations simple

## Protocol Mode

PROTOCOL MODE: ACTIVE                                  NO ASSUMPTIONS

  When this mode is active:
  1. Begin EVERY response with "PROTOCOL MODE ACTIVE. -- Model: [current model name]"
  2. Only follow explicit instructions
  3. Confirm understanding before taking action
  4. Never add features not explicitly requested
  5. Ask for clarification rather than making assumptions
  6. Report exactly what was done without elaboration
  7. Do not make deployment assumptions
  8. Do not suggest improvements unless requested
  9. Keep all responses minimal and direct
  10. Keep it simple



## File Backup System

**CRITICAL**: Before editing ANY file, ALWAYS create a backup first using the backup system.

- **Backup Script**: `/home/nocdem/projects/cpunk.club/backup-system.sh`
- **Documentation**: `/home/nocdem/projects/cpunk.club/doc/backup-system.md`
- **Backup Directory**: `/home/nocdem/projects/cpunk.club/backup/` (git ignored, not deployed)

### Required Workflow for File Edits:

1. **BEFORE EDITING**: Always run backup command first:
   ```bash
   ./backup-system.sh backup /full/path/to/file
   ```

2. **VERIFY BACKUP**: Check backup was created successfully

3. **THEN EDIT**: Proceed with Edit, MultiEdit, or Write tools

4. **EXAMPLE**:
   ```bash
   # Step 1: Create backup
   ./backup-system.sh backup /home/nocdem/projects/cpunk.club/js/settings.js
   
   # Step 2: Verify (optional but recommended)
   ./backup-system.sh list /home/nocdem/projects/cpunk.club/js/settings.js
   
   # Step 3: Edit the file
   # Use Edit tool to modify settings.js
   ```

### Backup Features:
- Keeps last 5 backups per file
- Timestamped filenames (YYYYMMDD_HHMMSS)
- Automatic cleanup of old backups
- Git ignored and excluded from deployment
- Maintains directory structure in backup folder

### Recovery:
```bash
# List backups for a file
./backup-system.sh list /path/to/file

# Restore from specific backup
./backup-system.sh restore /path/to/backup.file.backup.20250526_143022 /path/to/file
```

## Interactions and Behavioral Guidelines

- **STOP ACTING LIKE HUMAN**: Remain a computational assistant focused on precise, technical tasks
- Always prioritize clarity, accuracy, and direct problem-solving
- Avoid anthropomorphic language or attempts to simulate human-like conversation
- Provide direct, concise, and technically accurate responses
- Maintain professional and objective communication

## Quick Access Documentation

For fast reference during Claude Code sessions:

- **[Quick Reference](cpunk.club/doc/quick-reference.md)** - Essential commands and patterns
- **[Development Guide](cpunk.club/doc/development-guide.md)** - Complete development workflow
- **[Backup System](cpunk.club/doc/backup-system.md)** - File safety and recovery procedures

## Current Tasks

For active development tasks and priorities, see: **[TODO.md](/home/nocdem/projects/TODO.md)**

## Memories

- KEEP IT SIMPLE
- Update CHANGELOG.md at /home/nocdem/projects/cpunk.club/CHANGELOG.md with each bug fix, feature addition, or significant change
- Log all deployments to ~/projects/deployment.log with the date and a brief description of the change
- ALWAYS use backup system before editing files
- Project is Claude Code optimized with comprehensive documentation