import {createHash, createVerify} from "node:crypto";
import {fromBase64Url, toBase64Url} from "./base64url";
import {DEFAULT_CHALLENGE_BYTES} from "./constants";
import {ensureAllowedExtensions} from "./extensions";
import {WebAuthError, fail} from "./errors";
import {normalisePayloadArgs, issueToken, verifyToken} from "./jwt-state";
import {coseToPublicKey} from "./keys";
import {createAuthenticationOptions, createRegistrationOptions} from "./options";
import {generateChallenge} from "./challenge";
import {validateCollectedClientData} from "./client-data";
import {
    parseAssertionAuthenticatorData,
    parseRegistrationAuthenticatorData
} from "./authenticator-data";
import {validateAttestationObject, verifyAttestationStatement} from "./attestation";
import type {
    AttestationMetadataEntry,
    AttestationMetadataProvider,
    AttestationPolicyInput,
    AuthenticationOptionsJSON,
    AuthenticationResponseInput,
    AuthenticationTokenClaims,
    AuthenticationTokenPayload,
    AuthenticationVerificationResult,
    CreateAuthenticationOptionsInput,
    CreateRegistrationOptionsInput,
    CredentialDescriptorJSON,
    ExtensionPolicyInput,
    ParsedAssertionAuthenticatorData,
    ParsedAuthenticatorFlags,
    ParsedRegistration,
    ParsedRegistrationAuthenticatorData,
    RegistrationOptionsJSON,
    RegistrationResponseInput,
    RegistrationTokenClaims,
    RegistrationTokenPayload,
    RegistrationUser,
    Realm,
    UsableKeyPair,
    VerifiedAttestation,
    WebAuthConfig
} from "./types";

export type {
    AttestationMetadataEntry,
    AttestationMetadataProvider,
    AttestationPolicyInput,
    AuthenticationOptionsJSON,
    AuthenticationResponseInput,
    AuthenticationTokenClaims,
    AuthenticationTokenPayload,
    AuthenticationVerificationResult,
    CreateAuthenticationOptionsInput,
    CreateRegistrationOptionsInput,
    CredentialDescriptorJSON,
    ExtensionPolicyInput,
    ParsedAssertionAuthenticatorData,
    ParsedAuthenticatorFlags,
    ParsedRegistration,
    ParsedRegistrationAuthenticatorData,
    RegistrationOptionsJSON,
    RegistrationResponseInput,
    RegistrationTokenClaims,
    RegistrationTokenPayload,
    RegistrationUser,
    Realm,
    UsableKeyPair,
    VerifiedAttestation,
    WebAuthConfig
} from "./types";

export {WebAuthError} from "./errors";
export {fromBase64Url, toBase64Url} from "./base64url";
export {generateChallenge} from "./challenge";
export {createRegistrationOptions, createAuthenticationOptions} from "./options";

const applyRegistrationPolicyDefaults = (
    config: WebAuthConfig,
    input: RegistrationResponseInput
): RegistrationResponseInput => ({
    ...input,
    allowed_origins: input.allowed_origins ?? config.allowedOrigins ?? [input.origin],
    allowed_attestation_formats: input.allowed_attestation_formats ?? config.attestation?.allowed_formats,
    require_trusted_attestation: input.require_trusted_attestation ?? config.attestation?.require_trusted_attestation,
    trust_mode: input.trust_mode ?? config.attestation?.trust_mode,
    trust_anchors: input.trust_anchors ?? config.attestation?.trust_anchors,
    max_safetynet_age_ms: input.max_safetynet_age_ms ?? config.attestation?.max_safetynet_age_ms,
    require_safetynet_cts_profile_match: input.require_safetynet_cts_profile_match ?? config.attestation?.require_safetynet_cts_profile_match,
    metadata_provider: input.metadata_provider ?? config.attestation?.metadata_provider,
    allowed_client_extensions: input.allowed_client_extensions ?? config.extensions?.allowed_registration_extensions
});

const applyAuthenticationPolicyDefaults = (
    config: WebAuthConfig,
    input: AuthenticationResponseInput
): AuthenticationResponseInput => ({
    ...input,
    allowed_origins: input.allowed_origins ?? config.allowedOrigins ?? [input.origin],
    allowed_client_extensions: input.allowed_client_extensions ?? config.extensions?.allowed_authentication_extensions
});

/**
 * Verifies a registration response and returns normalized credential data ready for persistence.
 *
 * Spec reference: WebAuthn Level 3, "7.1 Registering a New Credential".
 */
export const parseRegistration = (input: RegistrationResponseInput): ParsedRegistration => {
    const expectedChallenge = input.expected_challenge;
    if (typeof expectedChallenge !== "string" || expectedChallenge.length === 0) {
        fail("ERR_INVALID_INPUT", "expected_challenge must be a non-empty string");
    }

    const credentialId = input.credential_id;
    if (typeof credentialId !== "string" || credentialId.length === 0) {
        fail("ERR_INVALID_INPUT", "credential_id must be a non-empty string");
    }

    const clientDataBuffer = validateCollectedClientData({
        expectedType: "webauthn.create",
        expectedChallenge,
        allowedOrigins: input.allowed_origins ?? [input.origin],
        clientDataJson: input.client_data_json
    });

    const attestation = validateAttestationObject(input.attestation_object);
    const authDataBytes = Buffer.from(attestation.authData);
    const parsed = parseRegistrationAuthenticatorData(authDataBytes, input.rp_id);

    if (parsed.credentialId !== credentialId) {
        fail("ERR_CREDENTIAL_MISMATCH", "Credential ID mismatch");
    }

    if ((input.require_user_presence ?? true) && !parsed.flags.userPresent) {
        fail("ERR_USER_PRESENCE_REQUIRED", "User presence is required");
    }

    if (input.require_user_verification && !parsed.flags.userVerified) {
        fail("ERR_USER_VERIFICATION_REQUIRED", "User verification is required");
    }

    if (
        input.expected_algorithms &&
        parsed.publicKeyAlgorithm !== undefined &&
        !input.expected_algorithms.includes(parsed.publicKeyAlgorithm)
    ) {
        fail("ERR_UNEXPECTED_ALGORITHM", "Credential public key algorithm was not requested by the relying party");
    }

    ensureAllowedExtensions(input.client_extension_results, input.allowed_client_extensions, "registration");

    const attestationVerification = verifyAttestationStatement({
        attestationObject: attestation,
        authData: parsed,
        authDataBytes,
        clientDataHash: createHash("sha256").update(clientDataBuffer).digest(),
        rpId: input.rp_id,
        credentialId,
        policy: {
            allowed_formats: input.allowed_attestation_formats,
            require_trusted_attestation: input.require_trusted_attestation,
            trust_mode: input.trust_mode,
            trust_anchors: input.trust_anchors,
            max_safetynet_age_ms: input.max_safetynet_age_ms,
            require_safetynet_cts_profile_match: input.require_safetynet_cts_profile_match,
            metadata_provider: input.metadata_provider
        }
    });

    return {
        credential_id: parsed.credentialId,
        public_key: parsed.publicKey,
        aaguid: parsed.aaguid,
        counter: parsed.signCount,
        transports: input.transports ?? [],
        user_present: parsed.flags.userPresent,
        user_verified: parsed.flags.userVerified,
        backup_eligible: parsed.flags.backupEligible,
        backup_state: parsed.flags.backupState,
        attestation_format: attestationVerification.format,
        attestation_type: attestationVerification.type,
        attestation_trusted: attestationVerification.trusted,
        attestation_policy_accepted: attestationVerification.policyAccepted,
        metadata_status: attestationVerification.metadataStatus,
        algorithm: parsed.publicKeyAlgorithm,
        authenticator_extensions: parsed.extensions,
        client_extension_results: input.client_extension_results
    };
};

/**
 * Verifies an authentication assertion against the stored credential public key and counter.
 *
 * Spec reference: WebAuthn Level 3, "7.2 Verifying an Authentication Assertion".
 */
export const verifyAuthenticationResponse = (
    input: AuthenticationResponseInput
): AuthenticationVerificationResult => {
    const expectedChallenge = input.expected_challenge;
    if (typeof expectedChallenge !== "string" || expectedChallenge.length === 0) {
        fail("ERR_INVALID_INPUT", "expected_challenge must be a non-empty string");
    }

    const clientDataBuffer = validateCollectedClientData({
        expectedType: "webauthn.get",
        expectedChallenge,
        allowedOrigins: input.allowed_origins ?? [input.origin],
        clientDataJson: input.client_data_json
    });

    const authenticatorData = fromBase64Url(input.authenticator_data);
    const parsed = parseAssertionAuthenticatorData(
        authenticatorData,
        input.client_extension_results?.appid === true && input.app_id
            ? [input.rp_id, input.app_id]
            : [input.rp_id]
    );

    ensureAllowedExtensions(input.client_extension_results, input.allowed_client_extensions, "authentication");

    if ((input.require_user_presence ?? true) && !parsed.flags.userPresent) {
        fail("ERR_USER_PRESENCE_REQUIRED", "User presence is required");
    }

    if (input.require_user_verification && !parsed.flags.userVerified) {
        fail("ERR_USER_VERIFICATION_REQUIRED", "User verification is required");
    }

    const verifier = createVerify("SHA256");
    verifier.update(authenticatorData);
    verifier.update(createHash("sha256").update(clientDataBuffer).digest());
    verifier.end();

    if (!verifier.verify(coseToPublicKey(input.public_key), fromBase64Url(input.signature))) {
        fail("ERR_INVALID_SIGNATURE", "Invalid passkey signature");
    }

    const previousCounter = input.previous_counter ?? 0;
    if (parsed.signCount > 0 && previousCounter > 0 && parsed.signCount <= previousCounter) {
        fail("ERR_COUNTER_REPLAY", "Passkey signature counter did not advance");
    }

    return {
        counter: parsed.signCount,
        user_present: parsed.flags.userPresent,
        user_verified: parsed.flags.userVerified,
        backup_eligible: parsed.flags.backupEligible,
        backup_state: parsed.flags.backupState,
        authenticator_extensions: parsed.extensions,
        client_extension_results: input.client_extension_results
    };
};

/**
 * Creates the default server helper surface used by the `server` entrypoint.
 */
export const createWebAuth = (config: WebAuthConfig) => ({
    toBase64Url,
    fromBase64Url,
    challenge(bytes?: number) {
        return generateChallenge(bytes ?? config.challengeBytes ?? DEFAULT_CHALLENGE_BYTES);
    },
    generateChallenge(bytes?: number) {
        return generateChallenge(bytes ?? config.challengeBytes ?? DEFAULT_CHALLENGE_BYTES);
    },
    createRegistrationOptions(input: CreateRegistrationOptionsInput) {
        return createRegistrationOptions(input, config);
    },
    createAuthenticationOptions(input: CreateAuthenticationOptionsInput = {}) {
        return createAuthenticationOptions(input, config);
    },
    signRegistration(
        realmOrPayload: Realm | RegistrationTokenPayload,
        maybePayload?: RegistrationTokenPayload
    ) {
        return issueToken(config, normalisePayloadArgs(realmOrPayload, maybePayload));
    },
    verifyRegistration(realmOrToken: Realm | string, maybeToken?: string) {
        const token = maybeToken ?? (realmOrToken as string);
        return verifyToken<RegistrationTokenClaims>(config, token);
    },
    signAuthentication(
        realmOrPayload: Realm | AuthenticationTokenPayload,
        maybePayload?: AuthenticationTokenPayload
    ) {
        return issueToken(config, normalisePayloadArgs(realmOrPayload, maybePayload));
    },
    verifyAuthentication(realmOrToken: Realm | string, maybeToken?: string) {
        const token = maybeToken ?? (realmOrToken as string);
        return verifyToken<AuthenticationTokenClaims>(config, token);
    },
    parseRegistration(input: RegistrationResponseInput) {
        return parseRegistration(applyRegistrationPolicyDefaults(config, input));
    },
    verifyRegistrationResponse(input: RegistrationResponseInput) {
        return parseRegistration(applyRegistrationPolicyDefaults(config, input));
    },
    verifyAuthenticationResponse(input: AuthenticationResponseInput) {
        return verifyAuthenticationResponse(applyAuthenticationPolicyDefaults(config, input));
    }
});

/**
 * Backwards-compatible alias for the default server factory.
 */
export const WebAuthn = createWebAuth;

export default createWebAuth;
