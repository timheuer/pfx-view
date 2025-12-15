import * as vscode from 'vscode';
import * as forge from 'node-forge';
import { logger } from './extension';

/**
 * Parsed certificate information for display
 */
interface CertificateInfo {
    subject: { [key: string]: string };
    issuer: { [key: string]: string };
    serialNumber: string;
    validFrom: string;
    validTo: string;
    thumbprint: string;
    signatureAlgorithm: string;
    publicKeyInfo: string;
    extensions: { name: string; value: string }[];
    isExpired: boolean;
    daysUntilExpiry: number;
}

/**
 * Parsed PFX file contents
 */
interface PfxContents {
    certificates: CertificateInfo[];
    hasPrivateKey: boolean;
    privateKeyInfo?: string;
    error?: string;
    isPasswordProtected?: boolean;
}

/**
 * Provider for PFX/P12 file viewer.
 * This is a readonly custom editor that displays certificate information.
 */
export class PfxEditorProvider implements vscode.CustomReadonlyEditorProvider<PfxDocument> {

    public static readonly viewType = 'pfx-view.pfxViewer';

    public static register(context: vscode.ExtensionContext): vscode.Disposable {
        const provider = new PfxEditorProvider(context);
        return vscode.window.registerCustomEditorProvider(
            PfxEditorProvider.viewType,
            provider,
            {
                webviewOptions: {
                    retainContextWhenHidden: true,
                },
                supportsMultipleEditorsPerDocument: false,
            }
        );
    }

    constructor(private readonly context: vscode.ExtensionContext) {}

    async openCustomDocument(
        uri: vscode.Uri,
        _openContext: vscode.CustomDocumentOpenContext,
        _token: vscode.CancellationToken
    ): Promise<PfxDocument> {
        logger.info('Opening PFX document', { path: uri.fsPath });
        const data = await vscode.workspace.fs.readFile(uri);
        logger.debug('File read successfully', { size: data.length });
        return new PfxDocument(uri, data);
    }

    async resolveCustomEditor(
        document: PfxDocument,
        webviewPanel: vscode.WebviewPanel,
        _token: vscode.CancellationToken
    ): Promise<void> {
        logger.debug('Resolving custom editor for document');
        webviewPanel.webview.options = {
            enableScripts: true,
        };

        // Try to parse without password first
        logger.debug('Attempting to parse PFX without password');
        let pfxContents = this.parsePfx(document.data, '');
        let isPasswordProtected = false;
        
        // If parsing failed (likely password protected), prompt for password
        if (pfxContents.error && pfxContents.error.includes('password')) {
            logger.info('PFX file is password protected, prompting user');
            isPasswordProtected = true;
            const password = await vscode.window.showInputBox({
                prompt: 'Enter the password for this PFX/P12 file',
                password: true,
                placeHolder: 'Password',
                ignoreFocusOut: true,
            });

            if (password !== undefined) {
                pfxContents = this.parsePfx(document.data, password);
                pfxContents.isPasswordProtected = true;
            }
        }

        if (pfxContents.error) {
            logger.warn('Failed to parse PFX file', { error: pfxContents.error });
        } else {
            logger.info('PFX parsed successfully', { 
                certificateCount: pfxContents.certificates.length,
                hasPrivateKey: pfxContents.hasPrivateKey 
            });
        }

        webviewPanel.webview.html = this.getHtmlForWebview(webviewPanel.webview, pfxContents, document.uri);

        // Handle messages from the webview
        webviewPanel.webview.onDidReceiveMessage(async (message) => {
            logger.debug('Received webview message', { type: message.type });
            if (message.type === 'retry-password') {
                logger.info('User retrying password entry');
                const password = await vscode.window.showInputBox({
                    prompt: 'Enter the password for this PFX/P12 file',
                    password: true,
                    placeHolder: 'Password',
                    ignoreFocusOut: true,
                });

                if (password !== undefined) {
                    const newContents = this.parsePfx(document.data, password);
                    newContents.isPasswordProtected = true;
                    if (newContents.error) {
                        logger.warn('Password retry failed', { error: newContents.error });
                    } else {
                        logger.info('Password retry successful');
                    }
                    webviewPanel.webview.html = this.getHtmlForWebview(webviewPanel.webview, newContents, document.uri);
                } else {
                    logger.debug('User cancelled password entry');
                }
            } else if (message.type === 'copy-to-clipboard') {
                logger.debug('Copying value to clipboard');
                await vscode.env.clipboard.writeText(message.value);
                vscode.window.showInformationMessage('Copied to clipboard!');
            }
        });

        // Log when panel is disposed
        webviewPanel.onDidDispose(() => {
            logger.debug('Webview panel disposed');
        });
    }

    /**
     * Parse a PFX file and extract certificate information
     */
    private parsePfx(data: Uint8Array, password: string): PfxContents {
        try {
            logger.trace('Converting binary data for forge');
            // Convert Uint8Array to binary string for forge
            let binary = '';
            for (let i = 0; i < data.length; i++) {
                binary += String.fromCharCode(data[i]);
            }
            const derBuffer = forge.util.createBuffer(binary, 'raw');
            
            logger.trace('Parsing ASN.1 structure');
            const asn1 = forge.asn1.fromDer(derBuffer);
            
            let p12: forge.pkcs12.Pkcs12Pfx;
            try {
                logger.trace('Attempting PKCS12 parse (non-strict mode)');
                p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password);
            } catch (e) {
                // Try with strict mode
                logger.trace('Non-strict failed, trying strict mode');
                p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password);
            }

            const certificates: CertificateInfo[] = [];
            let hasPrivateKey = false;
            let privateKeyInfo: string | undefined;

            // Get certificate bags
            const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
            const certBagArray = certBags[forge.pki.oids.certBag] || [];
            logger.debug('Found certificate bags', { count: certBagArray.length });

            for (const bag of certBagArray) {
                if (bag.cert) {
                    const certInfo = this.extractCertInfo(bag.cert);
                    logger.debug('Extracted certificate', { 
                        cn: certInfo.subject['CN'] || 'N/A',
                        thumbprint: certInfo.thumbprint.substring(0, 16) + '...',
                        isExpired: certInfo.isExpired
                    });
                    certificates.push(certInfo);
                }
            }

            // Get private key bags
            const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
            const keyBagArray = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag] || [];
            logger.debug('Found shrouded key bags', { count: keyBagArray.length });

            if (keyBagArray.length > 0) {
                hasPrivateKey = true;
                const keyBag = keyBagArray[0];
                if (keyBag.key) {
                    const rsaKey = keyBag.key as forge.pki.rsa.PrivateKey;
                    privateKeyInfo = `RSA ${(rsaKey.n.bitLength())} bits`;
                    logger.debug('Found private key', { type: 'RSA', bits: rsaKey.n.bitLength() });
                } else {
                    privateKeyInfo = 'Private key present (encrypted)';
                    logger.debug('Found encrypted private key');
                }
            }

            // Also check for unencrypted key bags
            const plainKeyBags = p12.getBags({ bagType: forge.pki.oids.keyBag });
            const plainKeyBagArray = plainKeyBags[forge.pki.oids.keyBag] || [];
            logger.debug('Found plain key bags', { count: plainKeyBagArray.length });

            if (plainKeyBagArray.length > 0) {
                hasPrivateKey = true;
                const keyBag = plainKeyBagArray[0];
                if (keyBag.key) {
                    const rsaKey = keyBag.key as forge.pki.rsa.PrivateKey;
                    privateKeyInfo = `RSA ${(rsaKey.n.bitLength())} bits`;
                }
            }

            return { certificates, hasPrivateKey, privateKeyInfo };
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            logger.error('PFX parsing failed', { error: errorMessage });
            
            // Check if it's a password error
            if (errorMessage.toLowerCase().includes('invalid password') ||
                errorMessage.toLowerCase().includes('mac') ||
                errorMessage.toLowerCase().includes('pkcs12') ||
                errorMessage.toLowerCase().includes('decrypt')) {
                logger.debug('Error appears to be password-related');
                return {
                    certificates: [],
                    hasPrivateKey: false,
                    error: `Invalid password or corrupted file. Please try again with the correct password.`
                };
            }

            return {
                certificates: [],
                hasPrivateKey: false,
                error: `Failed to parse PFX file: ${errorMessage}`
            };
        }
    }

    /**
     * Extract certificate information from a forge certificate
     */
    private extractCertInfo(cert: forge.pki.Certificate): CertificateInfo {
        const subject: { [key: string]: string } = {};
        const issuer: { [key: string]: string } = {};

        // Extract subject attributes
        for (const attr of cert.subject.attributes) {
            const name = attr.shortName || attr.name || attr.type || 'unknown';
            subject[name] = attr.value as string;
        }

        // Extract issuer attributes
        for (const attr of cert.issuer.attributes) {
            const name = attr.shortName || attr.name || attr.type || 'unknown';
            issuer[name] = attr.value as string;
        }

        // Calculate thumbprint (SHA-1 hash of DER-encoded certificate)
        const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
        const md = forge.md.sha1.create();
        md.update(certDer);
        const thumbprint = md.digest().toHex().toUpperCase();

        // Get validity dates
        const validFrom = cert.validity.notBefore;
        const validTo = cert.validity.notAfter;
        const now = new Date();
        const isExpired = validTo < now;
        const daysUntilExpiry = Math.ceil((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

        // Get public key info
        let publicKeyInfo = 'Unknown';
        try {
            const pubKey = cert.publicKey as forge.pki.rsa.PublicKey;
            if (pubKey && pubKey.n) {
                publicKeyInfo = `RSA ${pubKey.n.bitLength()} bits`;
            }
        } catch {
            // Ignore errors in getting public key info
        }

        // Get signature algorithm
        let signatureAlgorithm = cert.signatureOid;
        const sigOidMap: { [key: string]: string } = {
            '1.2.840.113549.1.1.5': 'SHA-1 with RSA',
            '1.2.840.113549.1.1.11': 'SHA-256 with RSA',
            '1.2.840.113549.1.1.12': 'SHA-384 with RSA',
            '1.2.840.113549.1.1.13': 'SHA-512 with RSA',
            '1.2.840.10045.4.3.2': 'ECDSA with SHA-256',
            '1.2.840.10045.4.3.3': 'ECDSA with SHA-384',
            '1.2.840.10045.4.3.4': 'ECDSA with SHA-512',
        };
        if (sigOidMap[cert.signatureOid]) {
            signatureAlgorithm = sigOidMap[cert.signatureOid];
        }

        // Extract extensions
        const extensions: { name: string; value: string }[] = [];
        if (cert.extensions) {
            for (const ext of cert.extensions) {
                let value = '';
                
                if (ext.name === 'subjectAltName' && ext.altNames) {
                    value = ext.altNames.map((an: { type: number; value: string }) => {
                        if (an.type === 2) { return `DNS: ${an.value}`; }
                        if (an.type === 7) { return `IP: ${an.value}`; }
                        return an.value;
                    }).join(', ');
                } else if (ext.name === 'keyUsage') {
                    const usages: string[] = [];
                    if (ext.digitalSignature) { usages.push('Digital Signature'); }
                    if (ext.keyEncipherment) { usages.push('Key Encipherment'); }
                    if (ext.dataEncipherment) { usages.push('Data Encipherment'); }
                    if (ext.keyAgreement) { usages.push('Key Agreement'); }
                    if (ext.keyCertSign) { usages.push('Certificate Signing'); }
                    if (ext.cRLSign) { usages.push('CRL Signing'); }
                    value = usages.join(', ');
                } else if (ext.name === 'extKeyUsage') {
                    const usages: string[] = [];
                    if (ext.serverAuth) { usages.push('Server Authentication'); }
                    if (ext.clientAuth) { usages.push('Client Authentication'); }
                    if (ext.codeSigning) { usages.push('Code Signing'); }
                    if (ext.emailProtection) { usages.push('Email Protection'); }
                    if (ext.timeStamping) { usages.push('Time Stamping'); }
                    value = usages.join(', ');
                } else if (ext.name === 'basicConstraints') {
                    value = ext.cA ? `CA: true${ext.pathLenConstraint !== undefined ? `, Path Length: ${ext.pathLenConstraint}` : ''}` : 'CA: false';
                } else if (typeof ext.value === 'string') {
                    value = ext.value;
                } else {
                    value = JSON.stringify(ext.value || '(complex value)');
                }

                extensions.push({
                    name: ext.name || ext.id,
                    value: value || '(empty)',
                });
            }
        }

        return {
            subject,
            issuer,
            serialNumber: cert.serialNumber,
            validFrom: validFrom.toISOString(),
            validTo: validTo.toISOString(),
            thumbprint,
            signatureAlgorithm,
            publicKeyInfo,
            extensions,
            isExpired,
            daysUntilExpiry,
        };
    }

    /**
     * Generate the HTML for the webview
     */
    private getHtmlForWebview(webview: vscode.Webview, contents: PfxContents, uri: vscode.Uri): string {
        const nonce = getNonce();

        const fileName = uri.path.split('/').pop() || 'Unknown';

        // Get codicons stylesheet URI
        const codiconsUri = webview.asWebviewUri(vscode.Uri.joinPath(
            this.context.extensionUri, 'node_modules', '@vscode/codicons', 'dist', 'codicon.css'
        ));

        // Get certificate icon URI
        const certIconUri = webview.asWebviewUri(vscode.Uri.joinPath(
            this.context.extensionUri, 'dist', 'assets', 'cert.svg'
        ));

        return /* html */`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}'; font-src ${webview.cspSource}; img-src ${webview.cspSource};">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>PFX Viewer</title>
                <link href="${codiconsUri}" rel="stylesheet" />
                <style>
                    :root {
                        --container-padding: 20px;
                        --section-gap: 16px;
                    }
                    
                    body {
                        padding: var(--container-padding);
                        font-family: var(--vscode-font-family);
                        font-size: var(--vscode-font-size);
                        color: var(--vscode-foreground);
                        background-color: var(--vscode-editor-background);
                        line-height: 1.5;
                    }

                    .header {
                        display: flex;
                        align-items: center;
                        gap: 12px;
                        margin-bottom: 24px;
                        padding-bottom: 16px;
                        border-bottom: 1px solid var(--vscode-panel-border);
                    }

                    .header-icon {
                        font-size: 32px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }

                    .header-icon-svg {
                        max-width: 48px;
                        max-height: 48px;
                        width: 48px;
                        height: 48px;
                    }

                    .header-info h1 {
                        margin: 0;
                        font-size: 1.4em;
                        font-weight: 600;
                    }

                    .header-info .file-path {
                        color: var(--vscode-descriptionForeground);
                        font-size: 0.9em;
                        margin-top: 4px;
                    }

                    .summary {
                        display: flex;
                        gap: 24px;
                        margin-bottom: 24px;
                        flex-wrap: wrap;
                    }

                    .summary-card {
                        background: var(--vscode-editor-inactiveSelectionBackground);
                        border-radius: 6px;
                        padding: 16px 20px;
                        min-width: 150px;
                    }

                    .summary-card .label {
                        font-size: 0.85em;
                        color: var(--vscode-descriptionForeground);
                        margin-bottom: 4px;
                    }

                    .summary-card .value {
                        font-size: 1.3em;
                        font-weight: 600;
                    }

                    .summary-card .value.has-key {
                        color: var(--vscode-charts-green);
                    }

                    .summary-card .value.no-key {
                        color: var(--vscode-descriptionForeground);
                    }

                    .certificate {
                        background: var(--vscode-editor-inactiveSelectionBackground);
                        border-radius: 8px;
                        margin-bottom: var(--section-gap);
                        overflow: hidden;
                    }

                    .cert-header {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 16px 20px;
                        background: var(--vscode-sideBarSectionHeader-background);
                        cursor: pointer;
                    }

                    .cert-header:hover {
                        background: var(--vscode-list-hoverBackground);
                    }

                    .cert-title {
                        display: flex;
                        align-items: center;
                        gap: 12px;
                    }

                    .cert-title .cert-icon {
                        font-size: 20px;
                    }

                    .cert-title h3 {
                        margin: 0;
                        font-weight: 500;
                    }

                    .cert-title .cert-cn {
                        color: var(--vscode-descriptionForeground);
                        font-size: 0.9em;
                    }

                    .status-badge {
                        padding: 4px 10px;
                        border-radius: 12px;
                        font-size: 0.8em;
                        font-weight: 500;
                    }

                    .status-badge.valid {
                        background: var(--vscode-testing-iconPassed);
                        color: white;
                    }

                    .status-badge.expired {
                        background: var(--vscode-testing-iconFailed);
                        color: white;
                    }

                    .status-badge.expiring-soon {
                        background: var(--vscode-editorWarning-foreground);
                        color: white;
                    }

                    .cert-body {
                        padding: 20px;
                        display: none;
                    }

                    .cert-body.expanded {
                        display: block;
                    }

                    .section {
                        margin-bottom: 20px;
                    }

                    .section:last-child {
                        margin-bottom: 0;
                    }

                    .section-title {
                        font-weight: 600;
                        font-size: 0.95em;
                        margin-bottom: 12px;
                        color: var(--vscode-foreground);
                        display: flex;
                        align-items: center;
                        gap: 8px;
                    }

                    .property-grid {
                        display: grid;
                        grid-template-columns: minmax(150px, auto) 1fr;
                        gap: 8px 16px;
                    }

                    .property-label {
                        color: var(--vscode-descriptionForeground);
                        font-size: 0.9em;
                    }

                    .property-value {
                        font-family: var(--vscode-editor-font-family);
                        font-size: 0.9em;
                        word-break: break-all;
                    }

                    .property-value.copyable {
                        cursor: pointer;
                        display: inline-flex;
                        align-items: center;
                        gap: 6px;
                    }

                    .property-value.copyable:hover {
                        color: var(--vscode-textLink-foreground);
                    }

                    .property-value.copyable .copy-icon {
                        opacity: 0;
                        transition: opacity 0.15s, color 0.15s;
                        font-size: 14px;
                        color: var(--vscode-descriptionForeground);
                    }

                    .property-value.copyable:hover .copy-icon {
                        opacity: 1;
                        color: var(--vscode-textLink-foreground);
                    }

                    .property-value.copyable .copy-icon.copied {
                        opacity: 1;
                        color: var(--vscode-charts-green, #89d185);
                    }

                    .thumbprint {
                        font-family: var(--vscode-editor-font-family);
                        font-size: 0.85em;
                        background: var(--vscode-textCodeBlock-background);
                        padding: 2px 6px;
                        border-radius: 3px;
                    }

                    .extensions-list {
                        list-style: none;
                        padding: 0;
                        margin: 0;
                    }

                    .extensions-list li {
                        padding: 8px 0;
                        border-bottom: 1px solid var(--vscode-panel-border);
                    }

                    .extensions-list li:last-child {
                        border-bottom: none;
                    }

                    .ext-name {
                        font-weight: 500;
                        margin-bottom: 4px;
                    }

                    .ext-value {
                        color: var(--vscode-descriptionForeground);
                        font-size: 0.9em;
                        font-family: var(--vscode-editor-font-family);
                    }

                    .error-container {
                        background: var(--vscode-inputValidation-errorBackground);
                        border: 1px solid var(--vscode-inputValidation-errorBorder);
                        border-radius: 6px;
                        padding: 20px;
                        text-align: center;
                    }

                    .error-container h2 {
                        margin: 0 0 12px 0;
                        color: var(--vscode-errorForeground);
                    }

                    .error-container p {
                        margin: 0 0 16px 0;
                    }

                    .retry-button {
                        background: var(--vscode-button-background);
                        color: var(--vscode-button-foreground);
                        border: none;
                        padding: 8px 16px;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 0.95em;
                    }

                    .retry-button:hover {
                        background: var(--vscode-button-hoverBackground);
                    }

                    .toggle-icon {
                        font-size: 16px;
                        display: inline-flex;
                        align-items: center;
                        justify-content: center;
                        width: 16px;
                        height: 16px;
                    }

                    .toggle-icon .chevron-right {
                        display: inline;
                    }

                    .toggle-icon .chevron-down {
                        display: none;
                    }

                    .toggle-icon.expanded .chevron-right {
                        display: none;
                    }

                    .toggle-icon.expanded .chevron-down {
                        display: inline;
                    }

                    .private-key-info {
                        display: flex;
                        align-items: center;
                        gap: 8px;
                        padding: 12px 16px;
                        background: var(--vscode-editor-inactiveSelectionBackground);
                        border-radius: 6px;
                        margin-bottom: 24px;
                    }

                    .private-key-info .key-icon {
                        color: var(--vscode-charts-green);
                    }
                </style>
            </head>
            <body>
                ${this.renderContent(contents, fileName, certIconUri.toString())}
                
                <script nonce="${nonce}">
                    const vscode = acquireVsCodeApi();

                    // Toggle certificate expansion
                    document.querySelectorAll('.cert-header').forEach(header => {
                        header.addEventListener('click', () => {
                            const body = header.nextElementSibling;
                            const icon = header.querySelector('.toggle-icon');
                            body.classList.toggle('expanded');
                            icon.classList.toggle('expanded');
                        });
                    });

                    // Copy to clipboard
                    document.querySelectorAll('.copyable').forEach(el => {
                        el.addEventListener('click', () => {
                            const value = el.dataset.value || el.textContent;
                            vscode.postMessage({ type: 'copy-to-clipboard', value });
                            
                            // Show green checkmark temporarily
                            const icon = el.querySelector('.copy-icon');
                            if (icon) {
                                icon.classList.remove('codicon-copy');
                                icon.classList.add('codicon-check', 'copied');
                                
                                setTimeout(() => {
                                    icon.classList.remove('codicon-check', 'copied');
                                    icon.classList.add('codicon-copy');
                                }, 1500);
                            }
                        });
                    });

                    // Retry password
                    const retryBtn = document.querySelector('.retry-button');
                    if (retryBtn) {
                        retryBtn.addEventListener('click', () => {
                            vscode.postMessage({ type: 'retry-password' });
                        });
                    }

                    // Expand first certificate by default
                    const firstCert = document.querySelector('.cert-body');
                    const firstIcon = document.querySelector('.toggle-icon');
                    if (firstCert) {
                        firstCert.classList.add('expanded');
                        if (firstIcon) firstIcon.classList.add('expanded');
                    }
                </script>
            </body>
            </html>
        `;
    }

    private renderContent(contents: PfxContents, fileName: string, certIconUri: string): string {
        // Certificate icon from SVG file, lock emoji for password-protected
        const certIcon = `<img class="header-icon-svg" src="${certIconUri}" alt="Certificate" />`;
        const lockIcon = '🔐';
        const headerIcon = contents.isPasswordProtected ? lockIcon : certIcon;

        if (contents.error) {
            return /* html */`
                <div class="header">
                    <span class="header-icon">${lockIcon}</span>
                    <div class="header-info">
                        <h1>${this.escapeHtml(fileName)}</h1>
                    </div>
                </div>
                <div class="error-container">
                    <h2>⚠️ Unable to Read Certificate</h2>
                    <p>${this.escapeHtml(contents.error)}</p>
                    <button class="retry-button">Enter Password</button>
                </div>
            `;
        }

        const certCount = contents.certificates.length;
        
        return /* html */`
            <div class="header">
                <span class="header-icon">${headerIcon}</span>
                <div class="header-info">
                    <h1>${this.escapeHtml(fileName)}</h1>
                </div>
            </div>

            <div class="summary">
                <div class="summary-card">
                    <div class="label">Certificates</div>
                    <div class="value">${certCount}</div>
                </div>
                <div class="summary-card">
                    <div class="label">Private Key</div>
                    <div class="value ${contents.hasPrivateKey ? 'has-key' : 'no-key'}">
                        ${contents.hasPrivateKey ? '✓ Present' : '✗ None'}
                    </div>
                </div>
                ${contents.privateKeyInfo ? `
                <div class="summary-card">
                    <div class="label">Key Type</div>
                    <div class="value">${this.escapeHtml(contents.privateKeyInfo)}</div>
                </div>
                ` : ''}
            </div>

            ${contents.hasPrivateKey ? `
            <div class="private-key-info">
                <span class="key-icon">🔑</span>
                <span>This file contains a private key (${this.escapeHtml(contents.privateKeyInfo || 'unknown type')})</span>
            </div>
            ` : ''}

            ${contents.certificates.map((cert, index) => this.renderCertificate(cert, index)).join('')}
        `;
    }

    private renderCertificate(cert: CertificateInfo, index: number): string {
        const cn = cert.subject['CN'] || cert.subject['O'] || 'Certificate';
        const statusClass = cert.isExpired ? 'expired' : (cert.daysUntilExpiry <= 30 ? 'expiring-soon' : 'valid');
        const statusText = cert.isExpired ? 'Expired' : (cert.daysUntilExpiry <= 30 ? `Expires in ${cert.daysUntilExpiry} days` : 'Valid');

        return /* html */`
            <div class="certificate">
                <div class="cert-header">
                    <div class="cert-title">
                        <span class="toggle-icon"><i class="chevron-right codicon codicon-chevron-right"></i><i class="chevron-down codicon codicon-chevron-down"></i></span>
                        <span class="cert-icon">📜</span>
                        <div>
                            <h3>Certificate ${index + 1}</h3>
                            <div class="cert-cn">${this.escapeHtml(cn)}</div>
                        </div>
                    </div>
                    <span class="status-badge ${statusClass}">${statusText}</span>
                </div>
                <div class="cert-body">
                    <div class="section">
                        <div class="section-title">📋 Subject</div>
                        <div class="property-grid">
                            ${Object.entries(cert.subject).map(([key, value]) => `
                                <div class="property-label">${this.escapeHtml(this.formatAttributeName(key))}</div>
                                <div class="property-value">${this.escapeHtml(value)}</div>
                            `).join('')}
                        </div>
                    </div>

                    <div class="section">
                        <div class="section-title">🏛️ Issuer</div>
                        <div class="property-grid">
                            ${Object.entries(cert.issuer).map(([key, value]) => `
                                <div class="property-label">${this.escapeHtml(this.formatAttributeName(key))}</div>
                                <div class="property-value">${this.escapeHtml(value)}</div>
                            `).join('')}
                        </div>
                    </div>

                    <div class="section">
                        <div class="section-title">📅 Validity</div>
                        <div class="property-grid">
                            <div class="property-label">Valid From</div>
                            <div class="property-value">${this.formatDate(cert.validFrom)}</div>
                            <div class="property-label">Valid To</div>
                            <div class="property-value">${this.formatDate(cert.validTo)}</div>
                        </div>
                    </div>

                    <div class="section">
                        <div class="section-title">🔧 Technical Details</div>
                        <div class="property-grid">
                            <div class="property-label">Serial Number</div>
                            <div class="property-value copyable" data-value="${this.escapeHtml(cert.serialNumber)}">
                                <span>${this.escapeHtml(cert.serialNumber)}</span>
                                <i class="copy-icon codicon codicon-copy"></i>
                            </div>
                            <div class="property-label">Thumbprint (SHA-1)</div>
                            <div class="property-value copyable" data-value="${this.escapeHtml(cert.thumbprint)}">
                                <span class="thumbprint">${this.formatThumbprint(cert.thumbprint)}</span>
                                <i class="copy-icon codicon codicon-copy"></i>
                            </div>
                            <div class="property-label">Signature Algorithm</div>
                            <div class="property-value">${this.escapeHtml(cert.signatureAlgorithm)}</div>
                            <div class="property-label">Public Key</div>
                            <div class="property-value">${this.escapeHtml(cert.publicKeyInfo)}</div>
                        </div>
                    </div>

                    ${cert.extensions.length > 0 ? `
                    <div class="section">
                        <div class="section-title">🔌 Extensions</div>
                        <ul class="extensions-list">
                            ${cert.extensions.map(ext => `
                                <li>
                                    <div class="ext-name">${this.escapeHtml(this.formatExtensionName(ext.name))}</div>
                                    <div class="ext-value">${this.escapeHtml(ext.value)}</div>
                                </li>
                            `).join('')}
                        </ul>
                    </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    private formatAttributeName(name: string): string {
        const nameMap: { [key: string]: string } = {
            'CN': 'Common Name',
            'O': 'Organization',
            'OU': 'Organizational Unit',
            'L': 'Locality',
            'ST': 'State/Province',
            'C': 'Country',
            'E': 'Email',
            'emailAddress': 'Email',
        };
        return nameMap[name] || name;
    }

    private formatExtensionName(name: string): string {
        const nameMap: { [key: string]: string } = {
            'subjectAltName': 'Subject Alternative Names',
            'keyUsage': 'Key Usage',
            'extKeyUsage': 'Extended Key Usage',
            'basicConstraints': 'Basic Constraints',
            'subjectKeyIdentifier': 'Subject Key Identifier',
            'authorityKeyIdentifier': 'Authority Key Identifier',
            'cRLDistributionPoints': 'CRL Distribution Points',
            'authorityInfoAccess': 'Authority Information Access',
            'certificatePolicies': 'Certificate Policies',
        };
        return nameMap[name] || name;
    }

    private formatThumbprint(thumbprint: string): string {
        // Format as XX:XX:XX:XX...
        return thumbprint.match(/.{2}/g)?.join(':') || thumbprint;
    }

    private formatDate(isoDate: string): string {
        try {
            const date = new Date(isoDate);
            return date.toLocaleString(undefined, {
                year: 'numeric',
                month: 'long',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                timeZoneName: 'short'
            });
        } catch {
            return isoDate;
        }
    }

    private escapeHtml(text: string): string {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
}

/**
 * Represents a PFX document
 */
class PfxDocument implements vscode.CustomDocument {
    constructor(
        public readonly uri: vscode.Uri,
        public readonly data: Uint8Array
    ) {}

    dispose(): void {
        // Nothing to dispose
    }
}

/**
 * Generate a nonce for Content Security Policy
 */
function getNonce(): string {
    let text = '';
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 32; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}
