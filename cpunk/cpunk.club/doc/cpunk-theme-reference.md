# CPUNK Theme Reference

## Color Variables

The CPUNK platform uses a consistent dark theme with orange accents. All colors are defined in `css/main.css`:

### Primary Colors
- `--primary: #f97834` - Main orange color (buttons, headers, links)
- `--primary-hover: #ff9055` - Hover state for primary elements
- `--primary-dim: rgba(249, 120, 52, 0.3)` - Dimmed primary for shadows
- `--primary-bg: rgba(249, 120, 52, 0.1)` - Very light primary for backgrounds

### Background Colors
- `--dark-bg: #0a0a0a` - Main dark background
- `--card-bg: #2b1816` - Card/container backgrounds
- `--section-bg: #1a0f0e` - Section backgrounds
- `--secondary-bg: #3b1d1d` - Alternative backgrounds

### Text Colors
- `--text: #ffffff` - Primary text color
- `--text-dim: #cccccc` - Secondary text
- `--text-dimmer: #888888` - Tertiary text

### Status Colors
- `--error: #ff4444` - Error states
- `--success: #00c851` - Success states
- `--warning: #ffbb33` - Warning states

## Common Patterns

### Container Style
```css
.container {
    background-color: var(--card-bg);
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0,0,0,.4), 0 0 0 1px rgba(249,120,52,.1);
    max-width: 1400px;
    margin: 20px auto;
    position: relative;
    overflow: hidden;
}

.container::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(90deg, var(--primary), transparent);
}
```

### Card Style
```css
.card {
    background-color: var(--section-bg);
    border: 1px solid #444;
    border-radius: 8px;
    padding: 20px;
    transition: all 0.3s ease;
    box-shadow: 0 2px 8px rgba(0,0,0,.2);
}

.card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 16px rgba(249,120,52,.2);
    border-color: var(--primary);
}
```

### Button Style
```css
.button {
    background-color: var(--primary);
    color: var(--text);
    padding: 14px 20px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 700;
    transition: all 0.3s ease;
}

.button:hover {
    background-color: var(--primary-hover);
    box-shadow: 0 0 20px var(--primary-dim);
    transform: translateY(-2px);
}
```

### Form Input Style
```css
input, textarea {
    width: 100%;
    padding: 14px;
    border: 1px solid var(--text-dimmer);
    border-radius: 6px;
    background-color: var(--dark-bg);
    color: var(--text);
    font-size: 1em;
    transition: all 0.3s ease;
}

input:focus, textarea:focus {
    outline: 0;
    border-color: var(--primary);
    box-shadow: 0 0 0 2px var(--primary-bg);
}
```

### Info Section Style
```css
.info-section {
    background-color: var(--section-bg);
    border: 1px solid var(--primary-dim);
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 4px 16px rgba(0,0,0,.2);
    position: relative;
}

.info-section::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    width: 4px;
    height: 100%;
    background: var(--primary);
}
```

## Typography

- Font family: `'Courier New', monospace`
- Base font size: `1em`
- Line height: `1.6`
- Headers use orange color (`var(--primary)`)
- Headers often have underline gradient effect

## Layout Guidelines

- Max container width: `1400px` for wide layouts
- Standard container width: `800px` for forms/content
- Consistent padding: `20px` mobile, `30px` desktop
- Border radius: `6px` for buttons/inputs, `8px` for cards, `12px` for main containers
- Box shadows: Dark shadows with orange tint on hover

## Animation Patterns

- Hover transitions: `all 0.3s ease`
- Transform on hover: `translateY(-2px)`
- Shadow expansion on hover
- Gradient animations for loading states

## Best Practices

1. Always use CSS variables for colors
2. Maintain consistent spacing and border radius
3. Add hover states to interactive elements
4. Use box shadows for depth
5. Apply gradient accents sparingly
6. Keep dark background with orange highlights
7. Ensure sufficient contrast for readability