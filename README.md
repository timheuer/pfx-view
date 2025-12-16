# Certificate Viewer

A Visual Studio Code extension that provides a beautiful, read-only viewer for certificate files including PFX, P12, PEM, CER, CRT, and DER formats.

![Certificate Viewer Screenshot](samples/screenshot.png)

## Features

- **🔐 View Certificate Details**: Open certificate files directly in VS Code to see certificate information
- **📋 Certificate Information**: View subject, issuer, validity dates, serial number, thumbprint, and more
- **🔑 Private Key Detection**: See if the file contains a private key and its type
- **📅 Expiry Status**: Visual indicators for valid, expiring soon, or expired certificates
- **🔌 Extensions**: View certificate extensions like Key Usage, Subject Alternative Names, and more
- **🔒 Password Support**: Automatically prompts for password when opening password-protected PFX/P12 files
- **📋 Copy to Clipboard**: Click on values like thumbprint or serial number to copy them
- **🔗 Certificate Chains**: View all certificates in a chain (PEM and PFX files)

## Supported File Types

| Extension | Format | Description |
|-----------|--------|-------------|
| `.pfx` | PKCS#12 | Personal Information Exchange (may contain private key) |
| `.p12` | PKCS#12 | PKCS #12 Archive (may contain private key) |
| `.pem` | PEM | Base64-encoded certificate(s), may include private key |
| `.cer` | DER/PEM | Certificate file (auto-detects format) |
| `.crt` | DER/PEM | Certificate file (auto-detects format) |
| `.der` | DER | Binary X.509 certificate |

## Usage

Simply open any supported certificate file in VS Code. The extension will automatically display the certificate information in a formatted viewer.

- **PFX/P12 files**: May prompt for password if the file is encrypted
- **PEM/CER/CRT/DER files**: Opens directly without password prompt

### Certificate Overview
The viewer shows a summary of all certificates in the file, including:
- Number of certificates
- Whether a private key is present
- Key type and size

### Certificate Details
Expand each certificate to see:
- Subject information (Common Name, Organization, etc.)
- Issuer information
- Validity period with expiry status
- Technical details (Serial Number, Thumbprint, Signature Algorithm, Public Key)
- Extensions (Key Usage, Extended Key Usage, Subject Alternative Names, etc.)

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `pfx-view.logLevel` | `info` | Controls the log level for the extension. Options: `off`, `error`, `warn`, `info`, `debug`, `trace` |

## Requirements

No additional requirements. The extension bundles all necessary dependencies.

## Known Issues

- Some exotic certificate extensions may not be fully parsed and will display as raw values
- Encrypted private keys in PEM files are detected but not decrypted (password prompt not yet supported for PEM)
