# CPUNK Platform

A "Quantum-Safe MEME Coin" web platform built on the Cellframe blockchain.

## 🚀 Quick Start for Claude Code

This project is optimized for Claude Code development. All necessary instructions and documentation are available in:

- **[CLAUDE.md](CLAUDE.md)** - Main instructions for Claude Code sessions
- **[cpunk.club/doc/](cpunk.club/doc/)** - Technical documentation

## 📁 Project Structure

```
cpunk.club/                    # Main web platform
├── *.html                     # Core pages (20+ pages)
├── css/                       # Stylesheets (minified for production)
├── js/                        # JavaScript modules
│   ├── authentication.js      # Centralized auth module
│   ├── sso.js                # Single Sign-On system
│   ├── translation.js        # Multi-language support
│   ├── dashboardConnector.js # Cellframe API client
│   ├── board.js              # Community board
│   ├── unused/               # Deprecated files
│   └── *.js                  # Other modules
├── lang/                      # Translation files (8 languages)
├── doc/                       # Documentation (not deployed)
├── backup/                    # Automated backups (git ignored)
├── OAuth/                     # Social auth endpoints
├── configs/                   # Network configurations
├── certs/                     # Digital certificates
└── CHANGELOG.md              # Version history

backend/                       # Cellframe plugin (Python)
├── cpunk-gdb-server.py       # Main plugin entry
├── handlers.py               # HTTP routing
├── gdb_ops.py               # Database operations
└── manifest.json            # Plugin metadata

docs/                         # Platform documentation
├── API_REFERENCE.md         # API endpoints
├── PLATFORM_FEATURES.md     # Feature overview
└── *.md                     # Various guides

cellframe/                    # Blockchain components (git ignored)
dev-tools/                    # Development utilities
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
- **Wallet Delegation** - Validator-based staking model
- **Community Features** - Messaging, voting, proposals, board
- **OAuth Integration** - GitHub, Google, LinkedIn, Twitter
- **Content Management** - User profiles and content distribution
- **Multilingual Support** - 8 languages (EN, ES, IT, RU, TR, AR, FR, ZH)
- **Single Sign-On** - Unified authentication across all pages
- **Network Statistics** - Real-time blockchain monitoring
- **CPUNK Improvement Proposals** - Community governance (CIP system)
- **Mainnet Party** - Event registration with invitation codes

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

**Version**: 0.1.14  
**Last Updated**: 2025-05-31

### Recent Improvements:
- ✅ Full multilingual support (8 languages)
- ✅ Quantum apocalypse awareness messaging
- ✅ Community board with DNA verification
- ✅ SSO system implementation
- ✅ Validator delegation model
- ✅ Network statistics page
- ✅ CPUNK Improvement Proposals system
- ✅ Mainnet party event management
- ✅ OAuth social authentication
- ✅ Automated backup system

### Platform Highlights:
- **Quantum-Safe**: Built on Cellframe's quantum-resistant blockchain
- **Community-Driven**: Governance through CIP proposals
- **Global Reach**: 8 language support
- **Developer-Friendly**: Comprehensive documentation and APIs
- **Production-Ready**: Live at https://cpunk.club

### Technical Stack:
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Backend**: PHP 7.4+, Python 3.8+ (Cellframe plugin)
- **Blockchain**: Cellframe Network
- **Database**: Cellframe Global Database (GDB)
- **Authentication**: OAuth 2.0, Cellframe Wallet

## 🚀 Getting Started

### For Users:
1. Visit https://cpunk.club
2. Click "Login" to authenticate with your Cellframe wallet
3. Register your DNA (Distributed Name Address)
4. Explore features: delegation, voting, messaging, etc.

### For Developers:
1. Read [CLAUDE.md](CLAUDE.md) for development guidelines
2. Check [docs/](docs/) for API documentation
3. Use the backup system before editing files
4. Follow the Protocol Mode guidelines

### For Node Operators:
1. Install Cellframe node: [Installation Guide](cpunk.club/doc/cellframe-node-setup-guide.md)
2. Download CPUNK network configs from https://cpunk.club/network.html
3. Join the network and start earning rewards

---

**Need Help?** Start with [CLAUDE.md](CLAUDE.md) for complete instructions and project context.