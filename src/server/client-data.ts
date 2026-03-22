import {assertString} from "./assert";
import {fromBase64Url} from "./base64url";
import {fail} from "./errors";
import {CollectedClientData} from "./types";

const textDecoder = new TextDecoder();

const validateOrigin = (origin: string, allowedOrigins: readonly string[]) => {
    if (!allowedOrigins.includes(origin)) {
        fail("ERR_ORIGIN_MISMATCH", "Origin mismatch");
    }
};

/**
 * Decodes `clientDataJSON` into its raw bytes and parsed structure.
 */
export const decodeClientData = (clientDataJson: string): { buffer: Buffer; data: CollectedClientData } => {
    const buffer = fromBase64Url(assertString(clientDataJson, "client_data_json"));
    let data: CollectedClientData | undefined;

    try {
        data = JSON.parse(textDecoder.decode(buffer)) as CollectedClientData;
    } catch {
        fail("ERR_INVALID_CLIENT_DATA", "clientDataJSON must be valid JSON");
    }

    if (!data || typeof data !== "object" || Array.isArray(data)) {
        fail("ERR_INVALID_CLIENT_DATA", "clientDataJSON must decode to an object");
    }

    const parsedData = data;
    if (parsedData === undefined) {
        fail("ERR_INVALID_CLIENT_DATA", "clientDataJSON could not be decoded");
    }

    return {
        buffer,
        data: parsedData as CollectedClientData
    };
};

/**
 * Validates collected client data for a registration or authentication ceremony.
 */
export const validateCollectedClientData = (input: {
    readonly expectedType: "webauthn.create" | "webauthn.get";
    readonly expectedChallenge: string;
    readonly allowedOrigins: readonly string[];
    readonly clientDataJson: string;
}): Buffer => {
    const {buffer, data} = decodeClientData(input.clientDataJson);

    if (data.type !== input.expectedType) {
        fail("ERR_INVALID_CEREMONY", "Invalid WebAuthn ceremony type");
    }

    if (data.challenge !== input.expectedChallenge) {
        fail("ERR_CHALLENGE_MISMATCH", "Challenge mismatch");
    }

    validateOrigin(assertString(data.origin, "clientData.origin"), input.allowedOrigins);

    if (data.crossOrigin === true) {
        fail("ERR_CROSS_ORIGIN_NOT_SUPPORTED", "Cross-origin ceremonies are not supported by this library");
    }

    return buffer;
};
