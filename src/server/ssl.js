var settings = require('./settings'),
    forge = require('node-forge'),
    pki = forge.pki,
    certificate = settings.read('ssl-certificate')

forge.options.usePureJavaScript = true

const fs = require('fs');
const path = require('path');

// Generate a random Serial number for the certificate
// matth-c3 @ https://github.com/digitalbazaar/forge/issues/673#issuecomment-500900852
function randomSerialNumber() {
    var hexString = forge.util.bytesToHex(forge.random.getBytesSync(16))

    var mostSiginficativeHexAsInt = parseInt(hexString[0], 16)
    if (mostSiginficativeHexAsInt < 8) {
        return hexString
    }

    mostSiginficativeHexAsInt -= 8
    return mostSiginficativeHexAsInt.toString() + hexString.substring(1)
}

function loadCertificateFromFile() {
    const certDir = path.join(__dirname, '..', '..', 'certs');
    const certPath = path.join(certDir, 'certificate.crt');
    const privateKeyPath = path.join(certDir, 'private.key');

    if (fs.existsSync(certPath) && fs.existsSync(privateKeyPath)) {
        try {
            const cert = fs.readFileSync(certPath, 'utf8');
            const key = fs.readFileSync(privateKeyPath, 'utf8');

            // Verify the certificate and key
            const certObj = pki.certificateFromPem(cert);
            const keyObj = pki.privateKeyFromPem(key);

            // Check if the certificate is valid
            const now = new Date();
            if (now < certObj.validity.notBefore || now > certObj.validity.notAfter) {
                console.log('(INFO) Certificate is expierd, creating a new one.');
                return createCertificate();
            }

            console.log('(INFO) If it crashes now the certificate is invalid ');
            return settings.write('ssl-certificate', { cert, key });
        } catch (error) {
            console.error('(ERROR) Failed to load certificate from files:', error);
            
            return createCertificate();
        }
    } else {
        console.log('(INFO) Certificate or key file not found. Creating a new self-signed certificate.');
        return createCertificate();
    }
}

function createCertificate() {

    console.log('(INFO) Creating self signed ssl certificate...')

    var keys = pki.rsa.generateKeyPair(2048),
        cert = pki.createCertificate()

    cert.publicKey = keys.publicKey
    cert.validity.notBefore = new Date()
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)
    cert.serialNumber = randomSerialNumber()

    var attrs = [
        {name:'commonName',value: settings.infos.name},
        {name:'subjectAltName',value: settings.infos.productName}
    ]

    cert.setSubject(attrs)
    cert.setIssuer(attrs)
    cert.sign(keys.privateKey)

    settings.write('ssl-certificate', {
        key:  pki.privateKeyToPem(keys.privateKey),
        cert: pki.certificateToPem(cert)
    })

    const certDir = path.join(__dirname, '..', '..', 'certs');
    if (!fs.existsSync(certDir)){
        fs.mkdirSync(certDir, { recursive: true });
    }

    fs.writeFileSync(path.join(certDir, 'certificate.crt'), pki.certificateToPem(cert));
    fs.writeFileSync(path.join(certDir, 'private.key'), pki.privateKeyToPem(keys.privateKey));
    fs.writeFileSync(path.join(certDir, 'public.key'), pki.publicKeyToPem(keys.publicKey));

}

if (!certificate) {
    loadCertificateFromFile();

    // createCertificate()

} else {

    var cert = pki.certificateFromPem(certificate.cert)

    if (
        cert.serialNumber === '00' ||
        new Date() > new Date(cert.validity.notAfter) ||
        cert.subject.attributes[1].value !== settings.infos.productName
    ) {
        console.log('(INFO) Self-signed ssl certificate in cache has expired or is invalid')
        createCertificate()
    } else {
        console.log('(INFO) Using self-signed ssl certificate in cache')
    }


}
