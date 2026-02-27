# CSS Structure

## Overview

The CSS for the CPUNK platform has been reorganized to improve maintainability and performance. The structure now follows a modular approach with:

1. A main shared CSS file containing common styles
2. Page-specific CSS files containing only styles unique to each page

## Files

- `main.css`: Contains all shared styles (colors, typography, common components)
- Page-specific files:
  - `register-page.css`: Styles for the DNA registration page
  - `delegation-page.css`: Styles for the delegation page
  - `messaging-page.css`: Styles for the messaging page
  - `voting-page.css`: Styles for the voting page
  - `user-settings-page.css`: Styles for the user settings page
  - `mainnet-party-page.css`: Styles for the mainnet party page

## How to Update HTML Files

To update HTML files to use the new CSS structure, follow this pattern:

```html
<head>
    <!-- Other head elements -->
    
    <!-- First include the main CSS -->
    <link rel="stylesheet" href="css/main.css">
    
    <!-- Then include the page-specific CSS -->
    <link rel="stylesheet" href="css/page-name-page.css">
</head>
```

Replace `page-name-page.css` with the appropriate page-specific CSS file.

## Page to CSS File Mapping

- `register.html` → `main.css` + `register-page.css`
- `delegate.html` → `main.css` + `delegation-page.css`
- `messaging.html` → `main.css` + `messaging-page.css`
- `voting.html` → `main.css` + `voting-page.css`
- `user_settings.html` → `main.css` + `user-settings-page.css`
- `mainnet_party.html` → `main.css` + `mainnet-party-page.css`

## Benefits

This CSS restructuring provides several benefits:

1. **Faster Loading**: The browser can cache the shared `main.css` file, reducing page load times
2. **Better Maintenance**: Common styles are defined in one place, making updates easier
3. **Reduced Code Duplication**: Eliminates repeated style definitions across files
4. **Clearer Organization**: Easier to find and modify page-specific styles

## Implementation Notes

When implementing this in production:

1. First add both CSS files to the HTML (as shown above)
2. Then test each page to ensure styles are properly applied
3. Only after thorough testing, remove the original CSS files

This approach ensures a smooth transition with minimal risk to the live environment.