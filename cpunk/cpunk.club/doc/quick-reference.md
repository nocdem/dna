# CPUNK Quick Reference

## Essential Commands

### Backup System
```bash
# Create backup before editing
./backup-system.sh backup /path/to/file

# List backups for file
./backup-system.sh list /path/to/file

# Restore from backup
./backup-system.sh restore /path/to/backup /path/to/original
```

### Deployment
```bash
cd /home/nocdem/projects/cpunk.club
rsync -avz --no-group --exclude-from=<(echo -e "*.txt\n/doc/\n/devel/\n/configs/\n/certs/\n/backup/\n/js/unused/") ./ cpunk-deploy:/var/www/html/
```

### CSS Minification
```bash
cleancss -o filename.css filename.css
```

## File Locations

### Key Files
- **Main Instructions**: `/home/nocdem/projects/CLAUDE.md`
- **Backup Script**: `/home/nocdem/projects/cpunk.club/backup-system.sh`
- **Changelog**: `/home/nocdem/projects/cpunk.club/CHANGELOG.md`
- **Project Root**: `/home/nocdem/projects/cpunk.club/`

### Important Directories
```
cpunk.club/
├── backup/           # Automated backups (git ignored)
├── css/              # Stylesheets (minified)
├── js/               # JavaScript modules
│   └── unused/       # Moved unused files
├── doc/              # Documentation (not deployed)
├── devel/            # Development files (not deployed)
├── configs/          # Config files (not deployed)
└── certs/            # Certificates (not deployed)
```

## Development Workflow

### Standard Process
1. **Read CLAUDE.md** - Project instructions
2. **Create Backup** - Before any file edit
3. **Make Changes** - Using Claude Code tools
4. **Update Changelog** - Document changes
5. **Deploy** - Using rsync command

### File Edit Process
```bash
# 1. Backup
./backup-system.sh backup /path/to/file

# 2. Edit (using Claude Code tools)
# Edit tool, MultiEdit tool, etc.

# 3. Verify backup
./backup-system.sh list /path/to/file
```

## Code Patterns

### JavaScript Module Structure
```javascript
// Module pattern
const ModuleName = (function() {
    // Private variables
    let privateVar = null;
    
    // Private functions
    function privateFunction() { }
    
    // Public API
    return {
        init: function() { },
        publicFunction: function() { }
    };
})();
```

### Dashboard Connector Usage
```javascript
// Initialize
CpunkDashboard.init({
    onConnected: function(sessionId) { },
    onWalletSelected: function(wallet) { },
    onDnaSelected: function(dna) { }
});

// Connect
await CpunkDashboard.connectToDashboard();
```

### Error Handling
```javascript
try {
    const result = await apiCall();
    // Handle success
} catch (error) {
    console.error('Error:', error);
    // Handle error appropriately
}
```

## API Endpoints

### Cellframe Dashboard
- **Connect**: `GET /?method=Connect`
- **GetWallets**: `GET /?method=GetWallets&id={sessionId}`
- **GetDataWallet**: `GET /?method=GetDataWallet&id={sessionId}&walletName={name}`

### OAuth Endpoints
- **GitHub**: `/github_oauth.php`
- **Google**: `/google_oauth.php`
- **LinkedIn**: `/linkedin_oauth.php`
- **Twitter**: `/twitter_oauth.php`

### DNA Proxy
- **Lookup**: `/dna-proxy.php?lookup={address}`

## CSS Classes

### Common Patterns
```css
/* Cards */
.wallet-card { }
.wallet-card.selected { }
.dna-card { }

/* Status indicators */
.status-indicator { }
.status-connected { }
.status-disconnected { }

/* Navigation */
.navbar { }
.nav-links { }
.nav-link { }
```

## HTML Structure

### Page Template
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page Title - CPUNK</title>
    <link rel="stylesheet" href="css/main.css">
    <link rel="stylesheet" href="css/page-specific.css">
</head>
<body>
    <!-- Navigation -->
    <nav id="navbar-placeholder"></nav>
    
    <!-- Main content -->
    <main role="main">
        <!-- Page content -->
    </main>
    
    <!-- Scripts -->
    <script src="js/navbar.js"></script>
    <script src="js/page-specific.js"></script>
</body>
</html>
```

### Dashboard Connection Elements
```html
<!-- Status indicator -->
<div id="statusIndicator" class="status-indicator">Disconnected</div>

<!-- Connect button -->
<button id="connectButton">Connect to Dashboard</button>

<!-- Error display -->
<div id="connectionError" style="display: none;"></div>

<!-- Wallet selection -->
<div id="walletSection" style="display: none;">
    <div id="walletsList"></div>
</div>

<!-- DNA selection -->
<div id="dnaSection" style="display: none;">
    <div id="dnaList"></div>
</div>
```

## Git Ignore Patterns

### Excluded from Git
```
*.txt                 # Data files
*.log                 # Log files
backup/               # Backup directory
*.backup              # Backup files
devel/                # Development files
configs/*.cfg         # Config files
*.dcert              # Certificates
node_modules/         # NPM packages
```

## Deployment Exclusions

### Not Deployed to Server
- Documentation (`/doc/`)
- Development files (`/devel/`)
- Configuration files (`/configs/`)
- Certificates (`/certs/`)
- Backup files (`/backup/`)
- Unused JavaScript (`/js/unused/`)
- Data files (`*.txt`)

## Troubleshooting

### Common Issues
```bash
# Permission denied on backup script
chmod +x backup-system.sh

# Backup not found
./backup-system.sh list /path/to/file

# Deployment permission errors (non-fatal)
# These are warnings, deployment still works

# JavaScript errors
# Check browser console
# Verify file paths
# Check API connectivity
```

### Recovery Procedures
```bash
# Find recent backup
./backup-system.sh list /path/to/file

# Restore from backup
./backup-system.sh restore /path/to/backup.file /path/to/original

# Check file was restored
ls -la /path/to/original
```

## Version Information

- **Current Version**: 0.1.5
- **Last Updated**: 2025-05-26
- **Protocol Mode**: Active
- **Backup System**: Implemented

## Quick Links

- [Main Instructions](../CLAUDE.md)
- [Development Guide](development-guide.md)
- [Backup System](backup-system.md)
- [Changelog](../CHANGELOG.md)
- [Project README](../../README.md)