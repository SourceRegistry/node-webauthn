import {createHash} from "node:crypto";
import {assertBufferLength} from "./assert";
import {decodeCbor} from "./cbor";
import {
    ATTESTED_CREDENTIAL_DATA_FLAG,
    BACKUP_ELIGIBLE_FLAG,
    BACKUP_STATE_FLAG,
    EXTENSION_DATA_FLAG,
    USER_PRESENT_FLAG,
    USER_VERIFIED_FLAG
} from "./constants";
import {toBase64Url} from "./base64url";
import {fail} from "./errors";
import {parseExtensionData} from "./extensions";
import {
    ParsedAssertionAuthenticatorData,
    ParsedAuthenticatorFlags,
    ParsedRegistrationAuthenticatorData
} from "./types";

/**
 * Returns the SHA-256 hash of the RP ID used in authenticator data.
 */
export const createExpectedRpIdHash = (rpId: string) =>
    createHash("sha256").update(rpId).digest();

/**
 * Parses authenticator flags from authenticator data.
 */
export const parseFlags = (flags: number): ParsedAuthenticatorFlags => {
    const backupEligible = (flags & BACKUP_ELIGIBLE_FLAG) !== 0;
    const backupState = (flags & BACKUP_STATE_FLAG) !== 0;

    if (backupState && !backupEligible) {
        fail("ERR_INVALID_AUTHENTICATOR_DATA", "Backup state cannot be set when backup eligibility is unset");
    }

    return {
        raw: flags,
        userPresent: (flags & USER_PRESENT_FLAG) !== 0,
        userVerified: (flags & USER_VERIFIED_FLAG) !== 0,
        backupEligible,
        backupState,
        hasAttestedCredentialData: (flags & ATTESTED_CREDENTIAL_DATA_FLAG) !== 0,
        hasExtensionData: (flags & EXTENSION_DATA_FLAG) !== 0
    };
};

/**
 * Parses registration authenticator data and extracts attested credential details.
 */
export const parseRegistrationAuthenticatorData = (
    authData: Buffer,
    rpId: string
): ParsedRegistrationAuthenticatorData => {
    assertBufferLength(authData, 55, "Authenticator data");

    const expectedRpIdHash = createExpectedRpIdHash(rpId);
    const rpIdHash = authData.subarray(0, 32);
    if (!rpIdHash.equals(expectedRpIdHash)) {
        fail("ERR_RP_ID_HASH_MISMATCH", "Invalid RP ID hash");
    }

    const flags = parseFlags(authData[32]);
    const signCount = authData.readUInt32BE(33);

    if (!flags.hasAttestedCredentialData) {
        fail("ERR_MISSING_ATTESTED_DATA", "Missing attested credential data");
    }

    let offset = 37;
    const aaguid = authData.subarray(offset, offset + 16);
    offset += 16;
    const credentialIdLength = authData.readUInt16BE(offset);
    offset += 2;

    assertBufferLength(authData.subarray(offset), credentialIdLength, "Credential ID");
    const credentialId = authData.subarray(offset, offset + credentialIdLength);
    offset += credentialIdLength;

    const cose = decodeCbor(authData, offset);
    const publicKeyBytes = authData.subarray(offset, cose.offset);
    const parsedPublicKey = cose.value as Record<number, Uint8Array | number>;
    let extensions: Record<string, unknown> | undefined;
    let finalOffset = cose.offset;

    if (flags.hasExtensionData) {
        const parsedExtensions = parseExtensionData(authData, cose.offset);
        extensions = parsedExtensions.extensions;
        finalOffset = parsedExtensions.offset;
    }

    if (finalOffset !== authData.length) {
        fail("ERR_INVALID_AUTHENTICATOR_DATA", "Unexpected trailing bytes in registration authenticator data");
    }

    return {
        flags,
        signCount,
        aaguid: toBase64Url(aaguid),
        credentialId: toBase64Url(credentialId),
        publicKey: toBase64Url(publicKeyBytes),
        publicKeyAlgorithm: typeof parsedPublicKey[3] === "number" ? parsedPublicKey[3] : undefined,
        extensions
    };
};

/**
 * Parses assertion authenticator data and validates the RP ID hash against one or more accepted RP IDs.
 */
export const parseAssertionAuthenticatorData = (
    authData: Buffer,
    rpIds: readonly string[]
): ParsedAssertionAuthenticatorData => {
    assertBufferLength(authData, 37, "Authenticator data");

    const rpIdHash = authData.subarray(0, 32);
    const rpIdValid = rpIds.some(rpId => rpIdHash.equals(createExpectedRpIdHash(rpId)));
    if (!rpIdValid) {
        fail("ERR_RP_ID_HASH_MISMATCH", "Invalid RP ID hash");
    }

    const flags = parseFlags(authData[32]);
    const signCount = authData.readUInt32BE(33);
    let extensions: Record<string, unknown> | undefined;
    let finalOffset = 37;

    if (flags.hasExtensionData) {
        const parsedExtensions = parseExtensionData(authData, 37);
        extensions = parsedExtensions.extensions;
        finalOffset = parsedExtensions.offset;
    }

    if (finalOffset !== authData.length) {
        fail("ERR_INVALID_AUTHENTICATOR_DATA", "Unexpected trailing bytes in assertion authenticator data");
    }

    return {
        flags,
        signCount,
        extensions
    };
};
