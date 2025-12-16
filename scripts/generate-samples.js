/**
 * Generate sample certificate files in various formats for testing
 * Run with: node scripts/generate-samples.js
 */
const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

const samplesDir = path.join(__dirname, '..', 'samples');

// Generate a self-signed certificate
function generateCertificate(cn, org, days = 365) {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    
    cert.publicKey = keys.publicKey;
    cert.serialNumber = Date.now().toString(16);
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + days);
    
    const attrs = [
        { name: 'commonName', value: cn },
        { name: 'organizationName', value: org },
        { name: 'countryName', value: 'US' }
    ];
    
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    
    // Add extensions
    cert.setExtensions([
        { name: 'basicConstraints', cA: false },
        { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
        { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
        { name: 'subjectAltName', altNames: [
            { type: 2, value: 'localhost' },
            { type: 2, value: 'example.com' },
            { type: 7, ip: '127.0.0.1' }
        ]},
        { name: 'subjectKeyIdentifier' }
    ]);
    
    // Self-sign
    cert.sign(keys.privateKey, forge.md.sha256.create());
    
    return { cert, keys };
}

// Generate an expired certificate
function generateExpiredCertificate(cn, org) {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    
    cert.publicKey = keys.publicKey;
    cert.serialNumber = Date.now().toString(16);
    
    // Set dates in the past
    cert.validity.notBefore = new Date();
    cert.validity.notBefore.setFullYear(cert.validity.notBefore.getFullYear() - 2);
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() - 1);
    
    const attrs = [
        { name: 'commonName', value: cn },
        { name: 'organizationName', value: org },
        { name: 'countryName', value: 'US' }
    ];
    
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    
    cert.setExtensions([
        { name: 'basicConstraints', cA: false },
        { name: 'keyUsage', digitalSignature: true }
    ]);
    
    cert.sign(keys.privateKey, forge.md.sha256.create());
    
    return { cert, keys };
}

console.log('Generating sample certificates...\n');

// 1. PEM certificate only
console.log('1. Creating sample-cert.pem (certificate only)');
const { cert: cert1 } = generateCertificate('Sample PEM Certificate', 'PFX Viewer Test');
const pemCert = forge.pki.certificateToPem(cert1);
fs.writeFileSync(path.join(samplesDir, 'sample-cert.pem'), pemCert);

// 2. PEM certificate with private key
console.log('2. Creating sample-cert-with-key.pem (certificate + private key)');
const { cert: cert2, keys: keys2 } = generateCertificate('Sample PEM with Key', 'PFX Viewer Test');
const pemWithKey = forge.pki.certificateToPem(cert2) + forge.pki.privateKeyToPem(keys2.privateKey);
fs.writeFileSync(path.join(samplesDir, 'sample-cert-with-key.pem'), pemWithKey);

// 3. DER certificate (binary)
console.log('3. Creating sample-cert.der (DER binary format)');
const { cert: cert3 } = generateCertificate('Sample DER Certificate', 'PFX Viewer Test');
const derCert = forge.asn1.toDer(forge.pki.certificateToAsn1(cert3)).getBytes();
fs.writeFileSync(path.join(samplesDir, 'sample-cert.der'), Buffer.from(derCert, 'binary'));

// 4. CER certificate (DER format with .cer extension)
console.log('4. Creating sample-cert.cer (CER/DER format)');
const { cert: cert4 } = generateCertificate('Sample CER Certificate', 'PFX Viewer Test');
const cerCert = forge.asn1.toDer(forge.pki.certificateToAsn1(cert4)).getBytes();
fs.writeFileSync(path.join(samplesDir, 'sample-cert.cer'), Buffer.from(cerCert, 'binary'));

// 5. CRT certificate (PEM format with .crt extension - common on Linux)
console.log('5. Creating sample-cert.crt (CRT/PEM format)');
const { cert: cert5 } = generateCertificate('Sample CRT Certificate', 'PFX Viewer Test');
const crtCert = forge.pki.certificateToPem(cert5);
fs.writeFileSync(path.join(samplesDir, 'sample-cert.crt'), crtCert);

// 6. Certificate chain in PEM
console.log('6. Creating sample-chain.pem (certificate chain)');
const { cert: rootCert, keys: rootKeys } = generateCertificate('Sample Root CA', 'PFX Viewer Test CA', 3650);
const { cert: leafCert } = generateCertificate('Sample Leaf Certificate', 'PFX Viewer Test');
// Re-sign leaf with root (make it a real chain)
leafCert.setIssuer(rootCert.subject.attributes);
leafCert.sign(rootKeys.privateKey, forge.md.sha256.create());
const chainPem = forge.pki.certificateToPem(leafCert) + forge.pki.certificateToPem(rootCert);
fs.writeFileSync(path.join(samplesDir, 'sample-chain.pem'), chainPem);

// 7. Expired certificate
console.log('7. Creating sample-expired.cer (expired certificate)');
const { cert: expiredCert } = generateExpiredCertificate('Expired Certificate', 'PFX Viewer Test');
const expiredDer = forge.asn1.toDer(forge.pki.certificateToAsn1(expiredCert)).getBytes();
fs.writeFileSync(path.join(samplesDir, 'sample-expired.cer'), Buffer.from(expiredDer, 'binary'));

console.log('\nDone! Generated 7 sample certificate files in samples/');
