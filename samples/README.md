# Sample Certificate Files

This directory contains sample PFX/P12 files for testing the PFX Viewer extension.

## Files

| File | Password | Description |
|------|----------|-------------|
| `sample-no-password.pfx` | *(none)* | PFX file with no password protection |
| `sample-with-password.pfx` | `password` | PFX file with password protection |
| `sample-with-password.p12` | `password` | P12 file with password protection |
| `sample-chain-no-password.pfx` | *(none)* | PFX file with 2 certificates (leaf + root CA) |

## Certificate Details

### Single Certificate Files
- **Subject**: CN=test.example.com
- **Validity**: 1 year from creation date

### Certificate Chain File (`sample-chain-no-password.pfx`)
Contains 2 certificates forming a chain:

1. **Root CA**: CN=Root CA (valid 5 years)
2. **Leaf Certificate**: CN=leaf.example.com (valid 1 year)

## Usage

Open any of these files in VS Code with the PFX Viewer extension installed to test the viewer functionality.
