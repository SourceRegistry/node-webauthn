import {assertString} from "./assert";
import {DEFAULT_CHALLENGE_BYTES, DEFAULT_REGISTRATION_ALGORITHMS, DEFAULT_TIMEOUT_MS} from "./constants";
import {generateChallenge} from "./challenge";
import {fail} from "./errors";
import {
    AuthenticationOptionsJSON,
    CreateAuthenticationOptionsInput,
    CreateRegistrationOptionsInput,
    RegistrationOptionsJSON,
    WebAuthConfig
} from "./types";

/**
 * Creates JSON-safe registration options that can be passed directly into the client helpers.
 */
export const createRegistrationOptions = (
    input: CreateRegistrationOptionsInput,
    config?: Pick<WebAuthConfig, "challengeBytes" | "rpId" | "rpName" | "timeout">
): RegistrationOptionsJSON => {
    const rpId = input.rp?.id ?? config?.rpId;
    const rpName = input.rp?.name ?? config?.rpName;

    if (!rpId || !rpName) {
        fail("ERR_INVALID_INPUT", "Registration options require an RP id and RP name");
    }

    return {
        challenge: input.challenge ?? generateChallenge(config?.challengeBytes ?? DEFAULT_CHALLENGE_BYTES),
        rp: {
            ...(input.rp ?? {}),
            id: assertString(rpId, "rp.id"),
            name: assertString(rpName, "rp.name")
        },
        user: input.user,
        pubKeyCredParams: [...(input.pubKeyCredParams ?? DEFAULT_REGISTRATION_ALGORITHMS)],
        timeout: input.timeout ?? config?.timeout ?? DEFAULT_TIMEOUT_MS,
        excludeCredentials: input.excludeCredentials?.map(credential => ({
            ...credential,
            transports: credential.transports ? [...credential.transports] : undefined
        })),
        authenticatorSelection: input.authenticatorSelection,
        attestation: input.attestation ?? "none",
        extensions: input.extensions
    };
};

/**
 * Creates JSON-safe authentication options that can be passed directly into the client helpers.
 */
export const createAuthenticationOptions = (
    input: CreateAuthenticationOptionsInput = {},
    config?: Pick<WebAuthConfig, "challengeBytes" | "rpId" | "timeout">
): AuthenticationOptionsJSON => ({
    challenge: input.challenge ?? generateChallenge(config?.challengeBytes ?? DEFAULT_CHALLENGE_BYTES),
    timeout: input.timeout ?? config?.timeout ?? DEFAULT_TIMEOUT_MS,
    rpId: input.rpId ?? config?.rpId,
    allowCredentials: input.allowCredentials?.map(credential => ({
        ...credential,
        transports: credential.transports ? [...credential.transports] : undefined
    })),
    userVerification: input.userVerification ?? "preferred",
    extensions: input.extensions
});
