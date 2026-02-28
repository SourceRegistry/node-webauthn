import {createHash} from "node:crypto";
import {fromBase64Url} from "../base64url";
import {decodeCbor} from "../cbor";
import {fail} from "../errors";
import {AttestationVerificationInput, digestForCoseAlgorithm, resolveAttestationTrust, resolveMetadata, toCertificates, verifySignatureByCoseAlgorithm} from "./utils";

const TPM_GENERATED_VALUE = 0xff544347;
const TPM_ST_ATTEST_CERTIFY = 0x8017;
const TPM_ALG_RSA = 0x0001;
const TPM_ALG_ECC = 0x0023;
const TPM_ALG_SHA256 = 0x000b;
const TPM_ECC_NIST_P256 = 0x0003;

const readU16 = (buffer: Buffer, offset: number) => buffer.readUInt16BE(offset);
const readU32 = (buffer: Buffer, offset: number) => buffer.readUInt32BE(offset);

const readSizedBytes = (buffer: Buffer, offset: number): { value: Buffer; offset: number } => {
    const size = readU16(buffer, offset);
    const start = offset + 2;
    const end = start + size;
    if (end > buffer.length) {
        fail("ERR_INVALID_ATTESTATION", "TPM structure is truncated");
    }
    return {
        value: buffer.subarray(start, end),
        offset: end
    };
};

const parsePubArea = (pubArea: Buffer): { unique: Buffer; type: number; curveId?: number } => {
    let offset = 0;
    const type = readU16(pubArea, offset);
    offset += 2;
    const nameAlg = readU16(pubArea, offset);
    offset += 2;
    if (nameAlg !== TPM_ALG_SHA256) {
        fail("ERR_INVALID_ATTESTATION", "TPM attestation currently requires pubArea nameAlg SHA-256");
    }

    offset += 4;
    const authPolicy = readSizedBytes(pubArea, offset);
    offset = authPolicy.offset;

    if (type === TPM_ALG_RSA) {
        offset += 2 + 2 + 4;
        const exponent = readU32(pubArea, offset);
        offset += 4;
        const unique = readSizedBytes(pubArea, offset);
        return {type, unique: unique.value};
    }

    if (type === TPM_ALG_ECC) {
        offset += 2 + 2;
        const curveId = readU16(pubArea, offset);
        offset += 2;
        offset += 2;
        const x = readSizedBytes(pubArea, offset);
        offset = x.offset;
        const y = readSizedBytes(pubArea, offset);
        return {type, curveId, unique: Buffer.concat([x.value, y.value])};
    }

    return fail("ERR_INVALID_ATTESTATION", "Unsupported TPM public area type");
};

const parseCertInfo = (certInfo: Buffer): { extraData: Buffer; name: Buffer } => {
    let offset = 0;
    const magic = readU32(certInfo, offset);
    offset += 4;
    const type = readU16(certInfo, offset);
    offset += 2;

    if (magic !== TPM_GENERATED_VALUE || type !== TPM_ST_ATTEST_CERTIFY) {
        fail("ERR_INVALID_ATTESTATION", "TPM certInfo magic or type was invalid");
    }

    offset = readSizedBytes(certInfo, offset).offset;
    const extraData = readSizedBytes(certInfo, offset);
    offset = extraData.offset;
    offset += 17 + 8;
    const name = readSizedBytes(certInfo, offset);

    return {extraData: extraData.value, name: name.value};
};

const cosePublicKeyMatchesPubArea = (publicKey: string, pubArea: Buffer): boolean => {
    const key = decodeCbor(fromBase64Url(publicKey)).value as Record<number, Uint8Array | number>;
    const parsedPubArea = parsePubArea(pubArea);

    if (parsedPubArea.type === TPM_ALG_RSA) {
        return key[1] === 3 && key[-1] instanceof Uint8Array && Buffer.from(key[-1] as Uint8Array).equals(parsedPubArea.unique);
    }

    if (parsedPubArea.type === TPM_ALG_ECC) {
        return (
            key[1] === 2 &&
            key[-1] === 1 &&
            parsedPubArea.curveId === TPM_ECC_NIST_P256 &&
            key[-2] instanceof Uint8Array &&
            key[-3] instanceof Uint8Array &&
            Buffer.concat([Buffer.from(key[-2] as Uint8Array), Buffer.from(key[-3] as Uint8Array)]).equals(parsedPubArea.unique)
        );
    }

    return false;
};

/**
 * Verifies TPM attestation.
 */
export const verifyTpmAttestation = (input: AttestationVerificationInput) => {
    const algorithmNode = input.attestationObject.attStmt.alg;
    const signatureNode = input.attestationObject.attStmt.sig;
    const x5c = input.attestationObject.attStmt.x5c;
    const certInfoNode = input.attestationObject.attStmt.certInfo;
    const pubAreaNode = input.attestationObject.attStmt.pubArea;

    if (
        typeof algorithmNode !== "number" ||
        !(signatureNode instanceof Uint8Array) ||
        !(certInfoNode instanceof Uint8Array) ||
        !(pubAreaNode instanceof Uint8Array)
    ) {
        fail("ERR_INVALID_ATTESTATION", "TPM attestation requires alg, sig, certInfo, and pubArea");
    }

    const certificates = toCertificates(x5c as Uint8Array[]);
    const leaf = certificates[0];

    if (!verifySignatureByCoseAlgorithm({
        algorithm: algorithmNode as number,
        verifierKey: leaf.publicKey,
        data: Buffer.from(certInfoNode as Uint8Array),
        signature: signatureNode as Uint8Array
    })) {
        fail("ERR_INVALID_ATTESTATION", "TPM attestation signature verification failed");
    }

    const attToBeSigned = Buffer.concat([input.authDataBytes, input.clientDataHash]);
    const digest = createHash(digestForCoseAlgorithm(algorithmNode as number).toLowerCase()).update(attToBeSigned).digest();
    const certInfo = parseCertInfo(Buffer.from(certInfoNode as Uint8Array));
    if (!certInfo.extraData.equals(digest)) {
        fail("ERR_INVALID_ATTESTATION", "TPM certInfo extraData did not match the attested data hash");
    }

    const pubArea = Buffer.from(pubAreaNode as Uint8Array);
    const pubAreaName = Buffer.concat([Buffer.from([0x00, TPM_ALG_SHA256]), createHash("sha256").update(pubArea).digest()]);
    if (!certInfo.name.equals(pubAreaName)) {
        fail("ERR_INVALID_ATTESTATION", "TPM certInfo name did not match pubArea");
    }

    const parsedPubArea = parsePubArea(pubArea);
    if (parsedPubArea.type === TPM_ALG_ECC && parsedPubArea.curveId !== TPM_ECC_NIST_P256) {
        fail("ERR_INVALID_ATTESTATION", "TPM ECC attestation currently requires the NIST P-256 curve");
    }

    if (!cosePublicKeyMatchesPubArea(input.authData.publicKey, pubArea)) {
        fail("ERR_INVALID_ATTESTATION", "TPM pubArea did not match the credential public key");
    }

    const trust = resolveAttestationTrust(certificates, input.policy);
    return resolveMetadata({
        format: "tpm",
        type: "basic",
        trusted: trust.trusted,
        policyAccepted: trust.policyAccepted
    }, input, certificates);
};
