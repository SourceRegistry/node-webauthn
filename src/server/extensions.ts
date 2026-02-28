import {decodeCbor} from "./cbor";
import {toBase64Url} from "./base64url";
import {fail} from "./errors";
import {CborNode} from "./types";

/**
 * Converts decoded CBOR values into JSON-safe extension data.
 */
export const cborNodeToJson = (value: CborNode): unknown => {
    if (value instanceof Uint8Array) {
        return toBase64Url(value);
    }

    if (Array.isArray(value)) {
        return value.map(cborNodeToJson);
    }

    if (value && typeof value === "object") {
        const result: Record<string, unknown> = {};
        for (const [key, entry] of Object.entries(value)) {
            result[key] = cborNodeToJson(entry);
        }
        return result;
    }

    return value;
};

/**
 * Parses authenticator extension data from the remaining authenticator data bytes.
 */
export const parseExtensionData = (
    authData: Buffer,
    offset: number
): { extensions?: Record<string, unknown>; offset: number } => {
    if (offset >= authData.length) {
        fail("ERR_INVALID_AUTHENTICATOR_DATA", "Authenticator data extension flag set but extension data missing");
    }

    const decoded = decodeCbor(authData, offset);
    if (!decoded.value || Array.isArray(decoded.value) || decoded.value instanceof Uint8Array || typeof decoded.value !== "object") {
        fail("ERR_INVALID_AUTHENTICATOR_DATA", "Authenticator extension data must be a CBOR map");
    }

    return {
        extensions: cborNodeToJson(decoded.value as Record<string, CborNode>) as Record<string, unknown>,
        offset: decoded.offset
    };
};

/**
 * Validates client extension outputs against the relying party policy supported by this library.
 */
export const ensureAllowedExtensions = (
    extensionResults: AuthenticationExtensionsClientOutputs | undefined,
    allowedExtensions: readonly string[] | undefined,
    context: "registration" | "authentication"
) => {
    if (!extensionResults) {
        return;
    }

    const allowed = new Set(allowedExtensions ?? []);
    for (const [key, value] of Object.entries(extensionResults)) {
        if (allowedExtensions && !allowed.has(key)) {
            fail("ERR_UNSUPPORTED_EXTENSION", `Client extension '${key}' is not allowed for ${context}`);
        }

        if (key === "credProps") {
            if (!value || typeof value !== "object" || Array.isArray(value)) {
                fail("ERR_INVALID_EXTENSION", "credProps must be an object");
            }
            const rk = (value as Record<string, unknown>).rk;
            if (rk !== undefined && typeof rk !== "boolean") {
                fail("ERR_INVALID_EXTENSION", "credProps.rk must be a boolean when present");
            }
        }

        if ((key === "appid" || key === "appidExclude") && typeof value !== "boolean") {
            fail("ERR_INVALID_EXTENSION", `${key} must be a boolean`);
        }

        if (key === "largeBlob") {
            if (typeof value !== "boolean" && (!value || typeof value !== "object" || Array.isArray(value))) {
                fail("ERR_INVALID_EXTENSION", "largeBlob must be a boolean or object");
            }
        }
    }
};
