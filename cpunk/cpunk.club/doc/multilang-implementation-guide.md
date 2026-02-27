# CPUNK Multilang Implementation Guide

## Overview

The CPUNK platform uses a JSON-based translation system for internationalization (i18n). This guide explains how to implement new languages and add translatable text throughout the platform.

## Core System Architecture

### Translation System (`js/translation.js`)
- **Automatic language detection** from browser settings
- **Local storage persistence** for user language preference
- **Dynamic language loading** via AJAX
- **Fallback system** to English for missing translations
- **Event system** for language change notifications

### Language Files (`/lang/`)
- `en.json` - English (default/fallback)
- `es.json` - Spanish
- Additional languages: `fr.json`, `de.json`, etc.

## Implementation Rules

### ⚠️ CRITICAL RULE: Use Translation Keys for ALL Text

**NEVER hardcode text strings in HTML or JavaScript files.**

❌ **WRONG:**
```javascript
alert('Connection failed');
statusDiv.textContent = 'Loading...';
```

✅ **CORRECT:**
```javascript
alert(t('errors.connectionFailed'));
statusDiv.textContent = t('common.loading');
```

## Adding New Languages

### Step 1: Create Language File

Create `/lang/[language-code].json` using ISO 639-1 codes:

```json
{
  "nav": {
    "home": "Accueil",
    "about": "À propos"
  },
  "common": {
    "loading": "Chargement...",
    "error": "Erreur"
  }
}
```

### Step 2: Add to Language Switcher

Update `navbar-template.html`:

```html
<ul class="dropdown-menu">
    <li><a href="#" data-lang="en">🇺🇸 English</a></li>
    <li><a href="#" data-lang="es">🇪🇸 Español</a></li>
    <li><a href="#" data-lang="fr">🇫🇷 Français</a></li>
</ul>
```

### Step 3: Deploy

```bash
rsync -avz --no-group lang/ cpunk-deploy:/var/www/html/lang/
```

## Adding New Translatable Text

### HTML Elements

Use data attributes for static content:

```html
<!-- Text content -->
<h1 data-i18n="page.title">Title</h1>
<p data-i18n="page.description">Description</p>

<!-- Placeholders -->
<input data-i18n="common.search" placeholder="Search">

<!-- Attributes -->
<img data-i18n-alt="nav.logoAlt" alt="Logo">
<button data-i18n-title="common.help" title="Help">?</button>

<!-- HTML content -->
<div data-i18n-html="page.richContent">Rich <strong>content</strong></div>
```

### JavaScript Dynamic Content

Use the `t()` function with translation keys:

```javascript
// Simple translation
element.textContent = t('common.loading');

// With parameters
const message = t('register.insufficientBalance', {
    price: 100,
    currency: 'CPUNK'
});

// Error messages
showError(t('errors.connectionFailed'));

// Status updates
updateStatus(t('dashboard.connected'));
```

### Adding New Translation Keys

#### 1. Add to English file (`lang/en.json`):

```json
{
  "newFeature": {
    "title": "New Feature",
    "description": "This is a new feature with {{param}} parameter",
    "button": "Click Here"
  }
}
```

#### 2. Add to ALL other language files:

```json
{
  "newFeature": {
    "title": "Nueva Función",
    "description": "Esta es una nueva función con parámetro {{param}}",
    "button": "Haz Clic Aquí"
  }
}
```

#### 3. Use in code:

```javascript
// HTML
document.getElementById('title').textContent = t('newFeature.title');

// With parameters
const desc = t('newFeature.description', {param: 'example'});

// Or use data-i18n in HTML
<h2 data-i18n="newFeature.title">New Feature</h2>
```

## Translation Key Organization

### Naming Convention

Use hierarchical dot notation:

```json
{
  "nav": {
    "home": "Home",
    "services": "Services"
  },
  "dashboard": {
    "title": "Dashboard",
    "connectionStatus": "Connection Status"
  },
  "errors": {
    "connectionFailed": "Connection Failed",
    "invalidInput": "Invalid Input"
  },
  "common": {
    "loading": "Loading...",
    "save": "Save",
    "cancel": "Cancel"
  }
}
```

### Categories

- **`nav`** - Navigation menu items
- **`common`** - Shared UI elements (buttons, status messages)
- **`errors`** - Error messages
- **`messages`** - Success/info messages
- **`dashboard`** - Dashboard-specific content
- **`register`** - Registration page content
- **`login`** - Authentication content
- **`[page-name]`** - Page-specific content

## Parameter Substitution

Use `{{parameter}}` syntax for dynamic content:

### JSON:
```json
{
  "user": {
    "welcome": "Welcome back, {{username}}!",
    "balance": "Your balance is {{amount}} {{currency}}"
  }
}
```

### JavaScript:
```javascript
const welcome = t('user.welcome', {username: 'John'});
const balance = t('user.balance', {amount: 100, currency: 'CPUNK'});
```

## File Integration Checklist

### For New HTML Pages:

1. ✅ Include translation.js before navbar.js:
```html
<script src="js/translation.js"></script>
<script src="js/navbar.js"></script>
```

2. ✅ Add data-i18n attributes to text elements
3. ✅ Test language switching

### For New JavaScript Files:

1. ✅ Replace all hardcoded strings with `t()` calls
2. ✅ Add corresponding keys to ALL language files
3. ✅ Test with different languages

### For Existing Files:

1. ✅ Backup file: `./backup-system.sh backup /path/to/file`
2. ✅ Replace hardcoded strings
3. ✅ Add translation keys
4. ✅ Deploy and test

## Testing Translation Implementation

### 1. Manual Testing
- Switch languages using navbar dropdown
- Verify all text changes
- Check for missing translations (fallback to English)

### 2. Console Debugging
Translation system logs missing keys:
```
Translation key 'missing.key' not found for language 'es'
```

### 3. Validation Checklist
- [ ] All user-facing text uses translation keys
- [ ] Keys exist in ALL language files
- [ ] Parameters work correctly
- [ ] Language switcher functions
- [ ] Fallback to English works

## Deployment Workflow

### 1. Update Language Files:
```bash
# Add new keys to all language files
vim lang/en.json
vim lang/es.json
# ... other languages
```

### 2. Update Code:
```bash
# Replace hardcoded strings with t() calls
vim js/[filename].js
# Or add data-i18n attributes to HTML
vim [page].html
```

### 3. Deploy:
```bash
rsync -avz --no-group lang/ js/ *.html cpunk-deploy:/var/www/html/
```

## Common Patterns

### Form Validation:
```javascript
if (!input.value) {
    showError(t('errors.fieldRequired'));
}
if (input.value.length < 3) {
    showError(t('validation.minLength', {min: 3}));
}
```

### Loading States:
```javascript
button.textContent = t('common.loading');
statusDiv.textContent = t('dashboard.connecting');
```

### Success Messages:
```javascript
showSuccess(t('messages.settingsSaved'));
showSuccess(t('messages.transactionComplete'));
```

### Error Handling:
```javascript
catch (error) {
    showError(t('errors.networkError'));
    console.error(error);
}
```

## Best Practices

### 1. Always Use Keys
Never hardcode text strings. Create translation keys even for temporary content.

### 2. Consistent Naming
Follow the established naming convention for translation keys.

### 3. Parameter Usage
Use parameters for dynamic content instead of string concatenation.

### 4. Fallback Planning
Always ensure English translations exist as fallback.

### 5. Context Awareness
Group related translations under appropriate categories.

### 6. Testing Requirement
Test all new translations with language switching.

## Maintenance

### Adding New Features:
1. Design translation key structure
2. Add keys to all language files
3. Implement using t() function
4. Test language switching
5. Deploy

### Updating Existing Text:
1. Update all language files simultaneously
2. Deploy language files first
3. Verify changes across all languages

### Adding New Languages:
1. Create new language file
2. Translate all existing keys
3. Add to language switcher
4. Test thoroughly
5. Deploy

## Summary

The CPUNK translation system provides:
- ✅ Automatic language detection
- ✅ Dynamic language switching
- ✅ Parameter substitution
- ✅ Fallback mechanism
- ✅ Event-driven updates

**Remember:** Always use `t()` function and data-i18n attributes. Never hardcode text strings.