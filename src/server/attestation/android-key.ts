import {collectDerChildren, findCertificateExtensionValue} from "../der";
import {fail} from "../errors";
import {coseToPublicKey} from "../keys";
import {AttestationVerificationInput, resolveAttestationTrust, resolveMetadata, toCertificates, verifySignatureByCoseAlgorithm} from "./utils";

const ANDROID_KEY_OID = "1.3.6.1.4.1.11129.2.1.17";

const readAndroidKeyAttestationChallenge = (extension: Buffer): Buffer => {
    const outer = collectDerChildren(extension);
    if (outer.length !== 1 || outer[0].tag !== 0x30) {
        fail("ERR_INVALID_ATTESTATION", "android-key attestation extension must be a DER sequence");
    }

    const fields = collectDerChildren(extension.subarray(outer[0].start, outer[0].end));
    if (fields.length < 5 || fields[4].tag !== 0x04) {
        fail("ERR_INVALID_ATTESTATION", "android-key attestation extension is missing attestationChallenge");
    }

    return extension.subarray(fields[4].start + outer[0].start, fields[4].end + outer[0].start);
};

/**
 * Verifies Android Key attestation.
 */
export const verifyAndroidKeyAttestation = (input: AttestationVerificationInput) => {
    const algorithmNode = input.attestationObject.attStmt.alg;
    const signatureNode = input.attestationObject.attStmt.sig;
    const x5c = input.attestationObject.attStmt.x5c;

    if (typeof algorithmNode !== "number" || !(signatureNode instanceof Uint8Array)) {
        fail("ERR_INVALID_ATTESTATION", "android-key attestation requires numeric alg and binary sig fields");
    }

    const certificates = toCertificates(x5c as Uint8Array[]);
    const leaf = certificates[0];
    const signatureBase = Buffer.concat([input.authDataBytes, input.clientDataHash]);

    if (!verifySignatureByCoseAlgorithm({
        algorithm: algorithmNode as number,
        verifierKey: leaf.publicKey,
        data: signatureBase,
        signature: signatureNode as Uint8Array
    })) {
        fail("ERR_INVALID_ATTESTATION", "android-key attestation signature verification failed");
    }

    const extension = findCertificateExtensionValue(leaf, ANDROID_KEY_OID);
    if (!extension) {
        fail("ERR_INVALID_ATTESTATION", "android-key certificate is missing the Android key attestation extension");
    }
    const extensionValue = extension as Buffer;

    const challenge = readAndroidKeyAttestationChallenge(extensionValue);
    if (!Buffer.from(challenge).equals(input.clientDataHash)) {
        fail("ERR_INVALID_ATTESTATION", "android-key attestation challenge did not match clientDataHash");
    }

    const credentialSpki = coseToPublicKey(input.authData.publicKey).export({format: "der", type: "spki"}) as Buffer;
    const certificateSpki = leaf.publicKey.export({format: "der", type: "spki"});
    if (!Buffer.from(certificateSpki).equals(Buffer.from(credentialSpki))) {
        fail("ERR_INVALID_ATTESTATION", "android-key certificate public key did not match the credential public key");
    }

    const trust = resolveAttestationTrust(certificates, input.policy);
    return resolveMetadata({
        format: "android-key",
        type: "basic",
        trusted: trust.trusted,
        policyAccepted: trust.policyAccepted
    }, input, certificates);
};
