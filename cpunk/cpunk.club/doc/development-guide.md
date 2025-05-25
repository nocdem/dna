# CPUNK Development Guide

## Overview

This guide provides comprehensive instructions for developing and maintaining the CPUNK platform using Claude Code.

## Prerequisites

### Required Knowledge
- HTML, CSS, JavaScript fundamentals
- Basic understanding of blockchain concepts
- Familiarity with Cellframe platform
- Web development best practices

### Required Tools
- Claude Code CLI
- SSH access to deployment server
- Git for version control
- Text editor (optional, Claude Code handles file editing)

## Getting Started

### 1. First Session Setup

```bash
# Navigate to project root
cd /home/nocdem/projects/

# Read main instructions
cat CLAUDE.md

# Explore project structure
ls -la cpunk.club/
```

### 2. Understanding the Architecture

#### Core Components:
- **Frontend**: HTML pages with CSS styling and JavaScript functionality
- **Backend**: PHP scripts for OAuth and API proxy functionality
- **Blockchain**: Cellframe node integration via dashboard connector
- **Storage**: File-based data storage (not database)

#### Key Files:
- `index.html` - Main landing page
- `settings.html` - User profile and wallet management
- `voting.html` - Community voting interface
- `messaging.html` - Inter-user communication
- `proposals.html` - CPUNK Improvement Proposals (CIPs)
- `delegate.html` - Wallet delegation interface

## Development Workflow

### Standard Workflow for Any Changes:

1. **Start with Backup**
   ```bash
   cd /home/nocdem/projects/cpunk.club
   ./backup-system.sh backup /path/to/file
   ```

2. **Make Changes**
   - Use Claude Code Edit/MultiEdit tools
   - Follow existing code conventions
   - Test changes locally if possible

3. **Document Changes**
   ```bash
   # Update changelog
   ./backup-system.sh backup /home/nocdem/projects/cpunk.club/CHANGELOG.md
   # Edit CHANGELOG.md with new version info
   ```

4. **Deploy to Server**
   ```bash
   cd /home/nocdem/projects/cpunk.club
   rsync -avz --no-group --exclude-from=<(echo -e "*.txt\n/doc/\n/devel/\n/configs/\n/certs/\n/backup/\n/js/unused/") ./ cpunk-deploy:/var/www/html/
   ```

### File Editing Guidelines

#### Before Editing ANY File:
```bash
# ALWAYS create backup first
./backup-system.sh backup /full/path/to/file

# Verify backup created
./backup-system.sh list /full/path/to/file
```

#### CSS Changes:
- Edit source CSS files (not minified versions)
- After changes, re-minify if needed:
  ```bash
  cleancss -o filename.css filename.css
  ```

#### JavaScript Changes:
- Maintain modular structure
- Avoid console.log in production code
- Use window.logAPI for debugging when available
- Follow existing naming conventions

#### HTML Changes:
- Maintain semantic structure
- Keep accessibility standards (viewport meta tags)
- Update navigation consistently across pages

## Code Conventions

### JavaScript
```javascript
// Use camelCase for variables and functions
const selectedWallet = null;
function connectToDashboard() { }

// Use descriptive names
function updateUserProfile(userData) {
    // Implementation
}

// Consistent error handling
try {
    const result = await apiCall();
} catch (error) {
    console.error('API call failed:', error);
    // Handle error appropriately
}
```

### CSS
```css
/* Use BEM-like naming */
.wallet-card { }
.wallet-card--selected { }
.wallet-card__name { }

/* Consistent spacing */
.section {
    padding: 20px;
    margin-bottom: 30px;
}
```

### HTML
```html
<!-- Semantic structure -->
<main role="main">
    <section class="user-dashboard">
        <h2>Dashboard</h2>
        <!-- Content -->
    </section>
</main>

<!-- Accessibility -->
<button aria-label="Connect to dashboard" id="connectButton">
    Connect
</button>
```

## API Integration

### Dashboard Connector
The `dashboardConnector.js` module handles all Cellframe dashboard communication:

```javascript
// Initialize connector
CpunkDashboard.init({
    onConnected: function(sessionId) {
        console.log('Connected:', sessionId);
    },
    onWalletSelected: function(wallet) {
        console.log('Selected:', wallet);
    }
});

// Connect to dashboard
await CpunkDashboard.connectToDashboard();
```

### OAuth Integration
PHP scripts handle OAuth flows:
- `github_oauth.php` - GitHub authentication
- `google_oauth.php` - Google authentication
- `linkedin_oauth.php` - LinkedIn authentication
- `twitter_oauth.php` - Twitter authentication

## Testing

### Manual Testing Checklist:
- [ ] All pages load without JavaScript errors
- [ ] Navigation works consistently
- [ ] Forms submit properly
- [ ] OAuth flows complete successfully
- [ ] Dashboard connection works
- [ ] Wallet selection functions
- [ ] DNA registration process works
- [ ] Voting system operates correctly

### Cross-Browser Testing:
- [ ] Chrome/Chromium
- [ ] Firefox
- [ ] Safari (if available)
- [ ] Mobile browsers

## Deployment

### Deployment Process:
1. **Test Locally**: Verify changes work as expected
2. **Create Backups**: Ensure all edited files are backed up
3. **Update Documentation**: Update CHANGELOG.md and relevant docs
4. **Deploy Files**: Use rsync command from CLAUDE.md
5. **Verify Deployment**: Check live site functionality

### Deployment Command:
```bash
cd /home/nocdem/projects/cpunk.club
rsync -avz --no-group --exclude-from=<(echo -e "*.txt\n/doc/\n/devel/\n/configs/\n/certs/\n/backup/\n/js/unused/") ./ cpunk-deploy:/var/www/html/
```

### What Gets Deployed:
- HTML files
- CSS files (minified)
- JavaScript files (production)
- PHP files
- Images and assets

### What Does NOT Get Deployed:
- Documentation (doc/ folder)
- Configuration files (configs/ folder)
- Certificates (certs/ folder)
- Backup files (backup/ folder)
- Development files (devel/ folder)
- Unused JavaScript (js/unused/ folder)
- Data files (*.txt files)

## Troubleshooting

### Common Issues:

#### Backup System:
```bash
# Permission denied
chmod +x backup-system.sh

# Backup not found
./backup-system.sh list /path/to/file
```

#### Deployment:
```bash
# Permission errors (non-fatal)
# Add --no-group flag to rsync command

# Files not deploying
# Check exclusion patterns in rsync command
```

#### JavaScript Errors:
```javascript
// Check console for errors
// Verify all dependencies are loaded
// Check API endpoints are accessible
```

## Security Considerations

### Never Commit:
- OAuth credentials
- Private keys
- User data files
- Configuration secrets

### Safe Practices:
- Always backup before changes
- Test changes before deployment
- Keep credentials external
- Regular backup rotation

## Documentation Maintenance

### Keep Updated:
- CHANGELOG.md for all changes
- README.md for project overview
- Technical docs in doc/ folder
- Code comments for complex functions

### Documentation Standards:
- Clear, concise explanations
- Step-by-step instructions
- Examples for complex procedures
- Cross-references between related docs

## Getting Help

### Resources:
1. **CLAUDE.md** - Main project instructions
2. **This Guide** - Development procedures
3. **doc/ folder** - Technical documentation
4. **CHANGELOG.md** - Recent changes and history

### Support:
- Refer to existing documentation first
- Check backup system for file recovery
- Review git history for change context
- Use backup-system.sh for file recovery if needed

---

This guide should be updated whenever significant changes are made to the development process or project structure.