import {X509Certificate} from "node:crypto";

/**
 * Checks whether the certificate validity window includes the current time.
 */
export const certificateTimeValid = (certificate: X509Certificate): boolean => {
    const now = Date.now();
    return now >= new Date(certificate.validFrom).getTime() && now <= new Date(certificate.validTo).getTime();
};

const getLegacyCertificateData = (certificate: X509Certificate) =>
    certificate.toLegacyObject() as {
        readonly ca?: boolean;
    };

export const isCertificateAuthority = (certificate: X509Certificate): boolean =>
    getLegacyCertificateData(certificate).ca === true;

export const allowsCertificateSigning = (certificate: X509Certificate): boolean => {
    const usage = certificate.keyUsage;
    return !usage || usage.includes("keyCertSign");
};

/**
 * Verifies a certificate path against one or more trust anchors.
 */
export const verifyCertificatePath = (
    certificates: readonly X509Certificate[],
    trustAnchors: ReadonlyArray<string | Buffer | Uint8Array>
): boolean => {
    const chain = [...certificates];
    if (chain.length === 0) {
        return false;
    }

    if (chain.some(certificate => !certificateTimeValid(certificate))) {
        return false;
    }

    for (let index = 0; index < chain.length - 1; index += 1) {
        const subject = chain[index];
        const issuer = chain[index + 1];

        if (!isCertificateAuthority(issuer) || !allowsCertificateSigning(issuer)) {
            return false;
        }

        if (!subject.checkIssued(issuer) || !subject.verify(issuer.publicKey)) {
            return false;
        }
    }

    const finalCertificate = chain[chain.length - 1];
    const anchors = trustAnchors.map(anchor => new X509Certificate(Buffer.from(anchor)));

    return anchors.some(anchor => (
        certificateTimeValid(anchor) && (
            finalCertificate.fingerprint256 === anchor.fingerprint256 ||
            (
                isCertificateAuthority(anchor) &&
                allowsCertificateSigning(anchor) &&
                finalCertificate.checkIssued(anchor) &&
                finalCertificate.verify(anchor.publicKey)
            )
        )
    ));
};
