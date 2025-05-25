# CPUNK Platform

A "Quantum-Safe MEME Coin" web platform built on the Cellframe blockchain.

## 🚀 Quick Start for Claude Code

This project is optimized for Claude Code development. All necessary instructions and documentation are available in:

- **[CLAUDE.md](CLAUDE.md)** - Main instructions for Claude Code sessions
- **[cpunk.club/doc/](cpunk.club/doc/)** - Technical documentation

## 📁 Project Structure

```
cpunk.club/                    # Main web platform
├── *.html                     # Core pages (index, voting, messaging, etc.)
├── css/                       # Stylesheets (minified for production)
├── js/                        # JavaScript modules
│   ├── unused/               # Moved unused files
│   └── *.js                  # Active modules
├── doc/                      # Documentation (not deployed)
│   ├── backup-system.md      # File backup system guide
│   ├── cellframe-*.md        # Cellframe blockchain docs
│   └── *.md                  # Other guides
├── backup/                   # Automated backups (git ignored)
├── backup-system.sh          # Backup management script
└── CHANGELOG.md              # Version history

cellframe/                    # Blockchain components (git ignored)
node-management/              # Automation scripts (git ignored)
dev-tools/                    # Development utilities (git ignored)
```

## 🔧 Development Workflow

### For Claude Code Sessions:

1. **Read CLAUDE.md first** - Contains all project instructions
2. **Use backup system** - Required before any file edits:
   ```bash
   ./backup-system.sh backup /path/to/file
   ```
3. **Update CHANGELOG.md** - Document all changes
4. **Deploy when ready** - Use provided rsync command

### Key Features:

- **DNA Registration** - Distributed naming system
- **Wallet Delegation** - Reward tracking and management  
- **Community Features** - Messaging, voting, proposals
- **OAuth Integration** - GitHub, Google, LinkedIn, Twitter
- **Content Management** - User profiles and content distribution

## 📖 Documentation Index

### Core Guides
- [Backup System](cpunk.club/doc/backup-system.md) - File safety and recovery
- [Cellframe Comprehensive Guide](cpunk.club/doc/cellframe-comprehensive-guide.md) - Platform overview
- [Cellframe Developer Reference](cpunk.club/doc/cellframe-developer-reference.md) - API documentation
- [Cellframe Node Reference](cpunk.club/doc/cellframe-node-reference.md) - CLI commands
- [CPUNK Improvement Proposals](cpunk.club/doc/cpunk-improvement-proposals-guide.md) - CIP system

### Technical Docs
- [Dashboard Connector](cpunk.club/doc/dashboardConnector.md) - Wallet integration
- [OAuth Implementation](cpunk.club/doc/oauth_implementation_guide.md) - Authentication
- [Deployment Guide](cpunk.club/doc/deployment-guide.md) - Server deployment

## 🔐 Security & Deployment

- **Server**: cpunk-deploy (75.119.141.51)
- **SSH Keys**: Configured in ~/.ssh/config
- **Exclusions**: Documentation, configs, certs, backups not deployed
- **Git Ignore**: Data files, logs, backups, development files

## 📝 Protocol Mode

This project uses Protocol Mode for Claude Code sessions:
- Follow explicit instructions only
- No assumptions or improvements without request
- Keep implementations simple
- Always create backups before edits

## 📊 Current Status

**Version**: 0.1.5  
**Last Updated**: 2025-05-26

### Recent Improvements:
- ✅ Console.log cleanup across all JS files
- ✅ CSS minification (27% size reduction)
- ✅ Viewport accessibility improvements
- ✅ Unused file cleanup and organization
- ✅ Automated backup system implementation
- ✅ Settings.js modularization (social + wallet integration)

### Ready for Development:
- All core features functional
- Clean, optimized codebase
- Comprehensive documentation
- Safety systems in place
- Claude Code optimized workflow

---

**Need Help?** Start with [CLAUDE.md](CLAUDE.md) for complete instructions and project context.