# Sample Certificate Files

This directory contains sample PFX/P12 files for testing the PFX Viewer extension.

## Files

| File | Password | Description |
|------|----------|-------------|
| `sample-no-password.pfx` | *(none)* | PFX file with no password protection |
| `sample-with-password.pfx` | `pass@word123` | PFX file with password protection |
| `sample-with-password.p12` | `pass@word123` | P12 file with password protection |
| `sample-chain-no-password.pfx` | *(none)* | PFX file with 3 certificates (certificate chain) |

## Certificate Details

### Single Certificate Files
All single certificates are self-signed with the following properties:
- **Subject**: CN=PFX Viewer TEST
- **Key Algorithm**: RSA 2048-bit
- **Signature Algorithm**: SHA256
- **Validity**: 1 year from creation date

### Certificate Chain File (`sample-chain-no-password.pfx`)
Contains 3 certificates forming a chain:

1. **Root CA**: CN=Contoso Root CA, O=Contoso Ltd, C=US (valid 10 years)
2. **Intermediate CA**: CN=Contoso Intermediate CA, O=Contoso Ltd, C=US (valid 5 years)
3. **End Entity**: CN=api.contoso.com, O=Contoso Ltd, C=US (valid 1 year)
   - SAN: api.contoso.com, www.contoso.com

## Usage

Open any of these files in VS Code with the PFX Viewer extension installed to test the viewer functionality.
