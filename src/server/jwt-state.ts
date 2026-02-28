import {JWTPayload, sign, verify} from "@sourceregistry/node-jwt";
import {DEFAULT_TOKEN_TTL_SECONDS} from "./constants";
import {fail} from "./errors";
import {Realm, WebAuthConfig} from "./types";

/**
 * Normalizes the overloaded token signing arguments used by the compatibility API.
 */
export const normalisePayloadArgs = <TPayload extends JWTPayload>(
    realmOrPayload: Realm | TPayload,
    maybePayload?: TPayload
): TPayload => {
    if (maybePayload) {
        return maybePayload;
    }

    return realmOrPayload as TPayload;
};

/**
 * Signs a JWT-backed ceremony state payload.
 */
export const issueToken = <TPayload extends JWTPayload>(config: WebAuthConfig, payload: TPayload) => {
    const {private_key, kid} = config.keyPair;
    const now = Math.floor(Date.now() / 1000);
    const tokenTtlSeconds = config.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;

    return sign(
        {
            ...payload,
            iss: payload.iss ?? config.issuer,
            iat: now,
            exp: now + tokenTtlSeconds
        },
        private_key,
        {kid}
    );
};

/**
 * Verifies a JWT-backed ceremony state token.
 */
export const verifyToken = <TClaims extends JWTPayload>(config: WebAuthConfig, token: string): TClaims => {
    const result = verify(token, config.keyPair.public_key, {
        issuer: config.issuer
    });

    if (!result.valid) {
        fail("ERR_INVALID_TOKEN", result.error.reason);
    }

    return (result as {valid: true; payload: JWTPayload}).payload as TClaims;
};
