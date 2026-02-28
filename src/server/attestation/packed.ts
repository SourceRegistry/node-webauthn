import {coseToPublicKey} from "../keys";
import {AttestationVerificationInput} from "./utils";
import {
    resolveAttestationTrust,
    resolveMetadata,
    toCertificates,
    validatePackedAttestationCertificate,
    verifySignatureByCoseAlgorithm
} from "./utils";
import {fail} from "../errors";

export const verifyPackedAttestation = (input: AttestationVerificationInput) => {
    const algorithmNode = input.attestationObject.attStmt.alg;
    const signatureNode = input.attestationObject.attStmt.sig;

    if (typeof algorithmNode !== "number" || !(signatureNode instanceof Uint8Array)) {
        fail("ERR_INVALID_ATTESTATION", "Packed attestation requires numeric alg and binary sig fields");
    }

    const algorithm = algorithmNode as number;
    const signature = signatureNode as Uint8Array;
    const signatureBase = Buffer.concat([input.authDataBytes, input.clientDataHash]);
    const x5c = input.attestationObject.attStmt.x5c;

    if (x5c) {
        const certificates = toCertificates(x5c);
        const leaf = certificates[0];
        validatePackedAttestationCertificate(leaf);

        if (!verifySignatureByCoseAlgorithm({
            algorithm,
            verifierKey: leaf.publicKey,
            data: signatureBase,
            signature
        })) {
            fail("ERR_INVALID_ATTESTATION", "Packed attestation signature verification failed");
        }

        const trust = resolveAttestationTrust(certificates, input.policy);
        return resolveMetadata({
            format: "packed",
            type: "basic",
            trusted: trust.trusted,
            policyAccepted: trust.policyAccepted
        }, input, certificates);
    }

    if (input.authData.publicKeyAlgorithm !== algorithm) {
        fail("ERR_INVALID_ATTESTATION", "Packed self attestation algorithm must match the credential public key algorithm");
    }

    if (!verifySignatureByCoseAlgorithm({
        algorithm,
        verifierKey: coseToPublicKey(input.authData.publicKey),
        data: signatureBase,
        signature
    })) {
        fail("ERR_INVALID_ATTESTATION", "Packed self attestation signature verification failed");
    }

    return resolveMetadata({
        format: "packed",
        type: "self",
        trusted: false,
        policyAccepted: true
    }, input);
};
