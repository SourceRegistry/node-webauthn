import {randomBytes} from "node:crypto";
import {DEFAULT_CHALLENGE_BYTES} from "./constants";
import {fail} from "./errors";
import {toBase64Url} from "./base64url";

/**
 * Generates a base64url challenge suitable for WebAuthn ceremonies.
 */
export const generateChallenge = (bytes = DEFAULT_CHALLENGE_BYTES): string => {
    if (!Number.isInteger(bytes) || bytes < 16) {
        fail("ERR_INVALID_INPUT", "Challenge byte length must be an integer >= 16");
    }

    return toBase64Url(randomBytes(bytes));
};
