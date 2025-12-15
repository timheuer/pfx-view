# Copilot Instructions for PFX/P12 Viewer

## Project Overview
VS Code extension that provides a read-only viewer for PFX/P12 certificate files using the Custom Editor API.

## Architecture
- **CustomReadonlyEditorProvider pattern**: `PfxEditorProvider` implements `vscode.CustomReadonlyEditorProvider<PfxDocument>` for binary file viewing
- **Webview-based UI**: HTML/CSS/JS rendered in webview panel with VS Code theme integration
- **node-forge library**: Used for PKCS#12 parsing (`forge.pkcs12.pkcs12FromAsn1`)

## Key Files
- `src/pfxEditorProvider.ts` - Core editor provider with PFX parsing and webview rendering
- `src/extension.ts` - Extension entry point, registers the provider
- `package.json` - Extension manifest with `customEditors` contribution

## Development Workflow
```bash
npm install          # Install dependencies
npm run compile      # Type-check + lint + build
npm run watch        # Watch mode (F5 to debug)
npm run package      # Production build
```

## Conventions
- **Styling**: Use VS Code CSS variables (e.g., `var(--vscode-foreground)`, `var(--vscode-editor-background)`)
- **Icons**: Use `@vscode/codicons` with `<i class="codicon codicon-*">` syntax
- **CSP**: All webview content must respect Content Security Policy with nonces
- **HTML generation**: Use template literals with `/* html */` comment for syntax highlighting

## Testing
- Sample certificates in `samples/` directory (with/without password, certificate chains)
- Run extension with F5, open any `.pfx` or `.p12` file

## Build & Release
- NBGV for versioning (see `version.json`)
- GitHub Actions workflow builds and publishes to VS Code Marketplace
