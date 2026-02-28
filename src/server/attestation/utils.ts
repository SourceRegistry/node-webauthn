import {createHash, createVerify, KeyObject, X509Certificate} from "node:crypto";
import {fromBase64Url} from "../base64url";
import {decodeCbor} from "../cbor";
import {findCertificateExtensionValue, findDerOctetString} from "../der";
import {fail} from "../errors";
import {coseEc2ToUncompressedPoint, coseToPublicKey} from "../keys";
import {certificateTimeValid, verifyCertificatePath} from "../trust";
import {AttestationPolicyInput, CborNode, ParsedRegistrationAuthenticatorData, VerifiedAttestation} from "../types";
import {createExpectedRpIdHash} from "../authenticator-data";

export type ParsedAttestationObject = {
    readonly fmt: string;
    readonly attStmt: Record<string, CborNode>;
    readonly authData: Uint8Array;
};

export type AttestationVerificationInput = {
    readonly attestationObject: ParsedAttestationObject;
    readonly authData: ParsedRegistrationAuthenticatorData;
    readonly authDataBytes: Buffer;
    readonly clientDataHash: Buffer;
    readonly rpId: string;
    readonly credentialId: string;
    readonly policy: AttestationPolicyInput;
};

export const digestForCoseAlgorithm = (algorithm: number): string => {
    const digest = ({
        [-7]: "SHA256",
        [-35]: "SHA384",
        [-36]: "SHA512",
        [-257]: "SHA256",
        [-258]: "SHA384",
        [-259]: "SHA512",
        [-37]: "SHA256",
        [-38]: "SHA384",
        [-39]: "SHA512"
    } as Record<number, string>)[algorithm];

    if (!digest) {
        fail("ERR_UNSUPPORTED_ALGORITHM", `Unsupported COSE algorithm: ${algorithm}`);
    }

    return digest;
};

export const verifySignatureByCoseAlgorithm = (input: {
    readonly algorithm: number;
    readonly verifierKey: KeyObject;
    readonly data: Buffer;
    readonly signature: Uint8Array;
}): boolean => {
    const verifier = createVerify(digestForCoseAlgorithm(input.algorithm));
    verifier.update(input.data);
    verifier.end();
    return verifier.verify(input.verifierKey, Buffer.from(input.signature));
};

export const toCertificates = (x5c: CborNode): X509Certificate[] => {
    if (!Array.isArray(x5c) || x5c.length === 0) {
        fail("ERR_INVALID_ATTESTATION", "Attestation x5c must be a non-empty certificate array");
    }

    return (x5c as CborNode[]).map((item: CborNode) => {
        if (!(item instanceof Uint8Array)) {
            fail("ERR_INVALID_ATTESTATION", "Attestation certificates must be byte strings");
        }
        return new X509Certificate(Buffer.from(item as Uint8Array));
    });
};

export const validatePackedAttestationCertificate = (certificate: X509Certificate) => {
    const legacy = certificate.toLegacyObject() as {
        readonly subject?: Record<string, string>;
        readonly ca?: boolean;
    };
    const subject = legacy.subject ?? {};

    if (!certificateTimeValid(certificate)) {
        fail("ERR_INVALID_ATTESTATION", "Packed attestation certificate is not currently valid");
    }

    if (legacy.ca) {
        fail("ERR_INVALID_ATTESTATION", "Packed attestation certificate must not be a CA certificate");
    }

    if (subject.OU !== "Authenticator Attestation") {
        fail("ERR_INVALID_ATTESTATION", "Packed attestation certificate must include OU=Authenticator Attestation");
    }

    if (!subject.CN || !subject.O || !subject.C) {
        fail("ERR_INVALID_ATTESTATION", "Packed attestation certificate is missing required subject fields");
    }
};

export const resolveAttestationTrust = (
    certificates: readonly X509Certificate[] | undefined,
    policy: AttestationPolicyInput
): {trusted: boolean; policyAccepted: boolean} => {
    const trustMode = policy.trust_mode ?? (policy.require_trusted_attestation ? "strict" : "permissive");
    const trusted = certificates && policy.trust_anchors
        ? verifyCertificatePath(certificates, policy.trust_anchors)
        : false;

    if (trustMode === "strict" && !trusted) {
        fail("ERR_UNTRUSTED_ATTESTATION", "Attestation certificate chain is not trusted");
    }

    return {
        trusted,
        policyAccepted: trustMode === "none" || trustMode === "permissive" || trusted
    };
};

export const resolveMetadata = (
    verification: VerifiedAttestation,
    input: AttestationVerificationInput,
    certificates?: readonly X509Certificate[]
): VerifiedAttestation => {
    const metadata = input.policy.metadata_provider?.getEntry?.({
        aaguid: input.authData.aaguid,
        format: verification.format,
        certificates: certificates?.map(certificate => certificate.raw.toString("base64"))
    });

    if (!metadata) {
        return verification;
    }

    if (metadata.revoked || metadata.allow === false) {
        fail("ERR_ATTESTATION_METADATA_REJECTED", metadata.reason ?? "Attestation metadata policy rejected the credential");
    }

    return {
        ...verification,
        trusted: verification.trusted || metadata.trusted === true,
        policyAccepted: verification.policyAccepted ?? metadata.allow !== false,
        metadataStatus: metadata.status
    };
};

export const verifyNoneAttestation = (): VerifiedAttestation => ({
    format: "none",
    type: "none",
    trusted: false,
    policyAccepted: true
});

export const verifyFidoU2fCore = (input: AttestationVerificationInput, certificates: readonly X509Certificate[], signature: Uint8Array): VerifiedAttestation => {
    if (certificates.length !== 1) {
        fail("ERR_INVALID_ATTESTATION", "FIDO U2F attestation requires exactly one attestation certificate");
    }

    const verifier = createVerify("SHA256");
    verifier.update(Buffer.concat([
        Buffer.from([0x00]),
        createExpectedRpIdHash(input.rpId),
        input.clientDataHash,
        fromBase64Url(input.credentialId),
        coseEc2ToUncompressedPoint(input.authData.publicKey)
    ]));
    verifier.end();

    if (!verifier.verify(certificates[0].publicKey, Buffer.from(signature))) {
        fail("ERR_INVALID_ATTESTATION", "FIDO U2F attestation signature verification failed");
    }

    const trust = resolveAttestationTrust(certificates, input.policy);
    return resolveMetadata({
        format: "fido-u2f",
        type: "basic",
        trusted: trust.trusted,
        policyAccepted: trust.policyAccepted
    }, input, certificates);
};

export const verifyAppleCore = (input: AttestationVerificationInput, certificates: readonly X509Certificate[]): VerifiedAttestation => {
    if (certificates.length === 0) {
        fail("ERR_INVALID_ATTESTATION", "Apple attestation requires an x5c certificate chain");
    }

    const leaf = certificates[0];
    const nonceExtension = findCertificateExtensionValue(leaf, "1.2.840.113635.100.8.2");
    if (!nonceExtension) {
        fail("ERR_INVALID_ATTESTATION", "Apple attestation certificate is missing the nonce extension");
    }
    const nonceExtensionValue = nonceExtension as Buffer;

    const nonce = findDerOctetString(nonceExtensionValue, 32);
    if (!nonce) {
        fail("ERR_INVALID_ATTESTATION", "Apple attestation nonce extension does not contain a 32-byte nonce");
    }
    const nonceValue = nonce as Buffer;

    const expectedNonce = createHash("sha256").update(Buffer.concat([input.authDataBytes, input.clientDataHash])).digest();
    if (!Buffer.from(nonceValue).equals(expectedNonce)) {
        fail("ERR_INVALID_ATTESTATION", "Apple attestation nonce did not match authData and clientDataHash");
    }

    const credentialSpki = coseToPublicKey(input.authData.publicKey).export({format: "der", type: "spki"}) as Buffer;
    const certificateSpki = leaf.publicKey.export({format: "der", type: "spki"});
    if (!Buffer.from(certificateSpki).equals(Buffer.from(credentialSpki))) {
        fail("ERR_INVALID_ATTESTATION", "Apple attestation certificate public key did not match the credential public key");
    }

    const trust = resolveAttestationTrust(certificates, input.policy);
    return resolveMetadata({
        format: "apple",
        type: "anonca",
        trusted: trust.trusted,
        policyAccepted: trust.policyAccepted
    }, input, certificates);
};

export const validateAttestationObject = (attestationObject: string): ParsedAttestationObject => {
    const decoded = decodeCbor(fromBase64Url(attestationObject));
    const value = decoded.value as Record<string, CborNode>;
    const fmtNode = value.fmt;
    const authDataNode = value.authData;
    const attStmtNode = value.attStmt;

    if (typeof fmtNode !== "string" || fmtNode.length === 0) {
        fail("ERR_INVALID_ATTESTATION", "Attestation object is missing fmt");
    }

    if (!(authDataNode instanceof Uint8Array)) {
        fail("ERR_INVALID_ATTESTATION", "Attestation object is missing authData");
    }

    const attStmt = attStmtNode instanceof Uint8Array ? decodeCbor(attStmtNode).value : attStmtNode;
    if (!attStmt || Array.isArray(attStmt) || attStmt instanceof Uint8Array || typeof attStmt !== "object") {
        fail("ERR_INVALID_ATTESTATION", "Attestation object is missing attStmt");
    }

    const fmt = fmtNode as string;
    const authData = authDataNode as Uint8Array;

    if (
        fmt !== "none" &&
        fmt !== "packed" &&
        fmt !== "fido-u2f" &&
        fmt !== "apple" &&
        fmt !== "android-key" &&
        fmt !== "android-safetynet" &&
        fmt !== "tpm"
    ) {
        fail("ERR_UNSUPPORTED_ATTESTATION", `Unsupported attestation format: ${fmt}`);
    }

    if (fmt === "none" && Object.keys(attStmt as Record<string, unknown>).length > 0) {
        fail("ERR_INVALID_ATTESTATION", "The 'none' attestation format requires an empty attStmt");
    }

    return {
        fmt,
        attStmt: attStmt as Record<string, CborNode>,
        authData
    };
};
