import {KeyObject} from "node:crypto";
import {JWTPayload} from "@sourceregistry/node-jwt";

export type CborScalar = string | number | boolean | null | Uint8Array;
export interface CborArray extends Array<CborNode> {}
export interface CborMap {
    [key: string]: CborNode;
    [key: number]: CborNode;
}
export type CborNode = CborScalar | CborArray | CborMap;
export type CborResult = { value: CborNode; offset: number };

export type Realm = { alias: string };

export type CollectedClientData = {
    type?: string;
    challenge?: string;
    origin?: string;
    crossOrigin?: boolean;
    tokenBinding?: unknown;
};

export type UsableKeyPair = {
    readonly kid: string;
    readonly private_key: KeyObject;
    readonly public_key: KeyObject;
};

export type RegistrationTokenPayload = JWTPayload & {
    readonly sub: string;
    readonly challenge: string;
    readonly rp_id: string;
    readonly origin: string;
    readonly redirect_uri: string;
};

export type AuthenticationTokenPayload = RegistrationTokenPayload & {
    readonly credential_id?: string;
    readonly session_credential_id?: string;
    readonly federated_identity_id?: string;
    readonly external_session_id?: string;
    readonly metadata?: Record<string, unknown>;
};

export type RegistrationTokenClaims = RegistrationTokenPayload & {
    readonly iat: number;
    readonly exp: number;
};

export type AuthenticationTokenClaims = AuthenticationTokenPayload & {
    readonly iat: number;
    readonly exp: number;
};

export type AttestationPolicyInput = {
    readonly allowed_formats?: readonly ("none" | "packed" | "fido-u2f" | "apple" | "android-key" | "android-safetynet" | "tpm")[];
    readonly require_trusted_attestation?: boolean;
    readonly trust_mode?: "none" | "permissive" | "strict";
    readonly trust_anchors?: ReadonlyArray<string | Buffer | Uint8Array>;
    readonly max_safetynet_age_ms?: number;
    readonly require_safetynet_cts_profile_match?: boolean;
    readonly metadata_provider?: AttestationMetadataProvider;
};

export type AttestationMetadataEntry = {
    readonly status?: string;
    readonly trusted?: boolean;
    readonly revoked?: boolean;
    readonly allow?: boolean;
    readonly reason?: string;
};

export type AttestationMetadataProvider = {
    readonly getEntry?: (input: {
        readonly aaguid: string;
        readonly format: string;
        readonly certificates?: readonly string[];
    }) => AttestationMetadataEntry | null | undefined;
};

export type ExtensionPolicyInput = {
    readonly allowed_registration_extensions?: readonly ("appidExclude" | "credProps" | "largeBlob")[];
    readonly allowed_authentication_extensions?: readonly ("appid" | "largeBlob")[];
};

export type WebAuthConfig = {
    readonly keyPair: UsableKeyPair;
    readonly issuer?: string;
    readonly tokenTtlSeconds?: number;
    readonly challengeBytes?: number;
    readonly rpId?: string;
    readonly rpName?: string;
    readonly origin?: string;
    readonly allowedOrigins?: readonly string[];
    readonly timeout?: number;
    readonly attestation?: AttestationPolicyInput;
    readonly extensions?: ExtensionPolicyInput;
};

export type CredentialDescriptorJSON = {
    readonly id: string;
    readonly type: PublicKeyCredentialType;
    readonly transports?: readonly AuthenticatorTransport[];
};

export type RegistrationUser = {
    readonly id: string;
    readonly name: string;
    readonly displayName: string;
};

export type RegistrationOptionsJSON = {
    readonly challenge: string;
    readonly rp: PublicKeyCredentialRpEntity;
    readonly user: RegistrationUser;
    readonly pubKeyCredParams: ReadonlyArray<PublicKeyCredentialParameters>;
    readonly timeout?: number;
    readonly excludeCredentials?: ReadonlyArray<CredentialDescriptorJSON>;
    readonly authenticatorSelection?: AuthenticatorSelectionCriteria;
    readonly attestation?: AttestationConveyancePreference;
    readonly extensions?: AuthenticationExtensionsClientInputs;
};

export type AuthenticationOptionsJSON = {
    readonly challenge: string;
    readonly timeout?: number;
    readonly rpId?: string;
    readonly allowCredentials?: ReadonlyArray<CredentialDescriptorJSON>;
    readonly userVerification?: UserVerificationRequirement;
    readonly extensions?: AuthenticationExtensionsClientInputs;
};

export type CreateRegistrationOptionsInput = {
    readonly user: RegistrationUser;
    readonly challenge?: string;
    readonly rp?: PublicKeyCredentialRpEntity;
    readonly timeout?: number;
    readonly excludeCredentials?: ReadonlyArray<CredentialDescriptorJSON>;
    readonly authenticatorSelection?: AuthenticatorSelectionCriteria;
    readonly attestation?: AttestationConveyancePreference;
    readonly pubKeyCredParams?: ReadonlyArray<PublicKeyCredentialParameters>;
    readonly extensions?: AuthenticationExtensionsClientInputs;
};

export type CreateAuthenticationOptionsInput = {
    readonly challenge?: string;
    readonly timeout?: number;
    readonly rpId?: string;
    readonly allowCredentials?: ReadonlyArray<CredentialDescriptorJSON>;
    readonly userVerification?: UserVerificationRequirement;
    readonly extensions?: AuthenticationExtensionsClientInputs;
};

export type RegistrationResponseInput = {
    readonly expected_challenge: string;
    readonly credential_id: string;
    readonly client_data_json: string;
    readonly attestation_object: string;
    readonly transports?: readonly string[];
    readonly origin: string;
    readonly allowed_origins?: readonly string[];
    readonly rp_id: string;
    readonly require_user_presence?: boolean;
    readonly require_user_verification?: boolean;
    readonly expected_algorithms?: readonly number[];
    readonly allowed_attestation_formats?: readonly ("none" | "packed" | "fido-u2f" | "apple" | "android-key" | "android-safetynet" | "tpm")[];
    readonly require_trusted_attestation?: boolean;
    readonly trust_mode?: "none" | "permissive" | "strict";
    readonly trust_anchors?: ReadonlyArray<string | Buffer | Uint8Array>;
    readonly max_safetynet_age_ms?: number;
    readonly require_safetynet_cts_profile_match?: boolean;
    readonly metadata_provider?: AttestationMetadataProvider;
    readonly client_extension_results?: AuthenticationExtensionsClientOutputs;
    readonly allowed_client_extensions?: readonly ("appidExclude" | "credProps" | "largeBlob")[];
};

export type ParsedRegistration = {
    readonly credential_id: string;
    readonly public_key: string;
    readonly aaguid: string;
    readonly counter: number;
    readonly transports: readonly string[];
    readonly user_present: boolean;
    readonly user_verified: boolean;
    readonly backup_eligible: boolean;
    readonly backup_state: boolean;
    readonly attestation_format: string;
    readonly attestation_type: "none" | "self" | "basic" | "anonca";
    readonly attestation_trusted: boolean;
    readonly attestation_policy_accepted?: boolean;
    readonly metadata_status?: string;
    readonly algorithm?: number;
    readonly authenticator_extensions?: Record<string, unknown>;
    readonly client_extension_results?: AuthenticationExtensionsClientOutputs;
};

export type AuthenticationResponseInput = {
    readonly expected_challenge: string;
    readonly client_data_json: string;
    readonly authenticator_data: string;
    readonly signature: string;
    readonly origin: string;
    readonly allowed_origins?: readonly string[];
    readonly rp_id: string;
    readonly public_key: string;
    readonly previous_counter?: number;
    readonly require_user_presence?: boolean;
    readonly require_user_verification?: boolean;
    readonly credential_id?: string;
    readonly expected_credential_id?: string;
    readonly client_extension_results?: AuthenticationExtensionsClientOutputs;
    readonly allowed_client_extensions?: readonly ("appid" | "largeBlob")[];
    readonly app_id?: string;
};

export type AuthenticationVerificationResult = {
    readonly credential_id?: string;
    readonly counter: number;
    readonly user_present: boolean;
    readonly user_verified: boolean;
    readonly backup_eligible: boolean;
    readonly backup_state: boolean;
    readonly authenticator_extensions?: Record<string, unknown>;
    readonly client_extension_results?: AuthenticationExtensionsClientOutputs;
};

export type WebAuth = {
    readonly toBase64Url: (input: Buffer | Uint8Array | string) => string;
    readonly fromBase64Url: (input: string) => Buffer;
    readonly challenge: (bytes?: number) => string;
    readonly generateChallenge: (bytes?: number) => string;
    readonly createRegistrationOptions: (input: CreateRegistrationOptionsInput) => RegistrationOptionsJSON;
    readonly createAuthenticationOptions: (input?: CreateAuthenticationOptionsInput) => AuthenticationOptionsJSON;
    readonly signRegistration: (
        realmOrPayload: Realm | RegistrationTokenPayload,
        maybePayload?: RegistrationTokenPayload
    ) => string;
    readonly verifyRegistration: (realmOrToken: Realm | string, maybeToken?: string) => RegistrationTokenClaims;
    readonly signAuthentication: (
        realmOrPayload: Realm | AuthenticationTokenPayload,
        maybePayload?: AuthenticationTokenPayload
    ) => string;
    readonly verifyAuthentication: (realmOrToken: Realm | string, maybeToken?: string) => AuthenticationTokenClaims;
    readonly parseRegistration: (input: RegistrationResponseInput) => ParsedRegistration;
    readonly verifyRegistrationResponse: (input: RegistrationResponseInput) => ParsedRegistration;
    readonly verifyAuthenticationResponse: (input: AuthenticationResponseInput) => AuthenticationVerificationResult;
};

export type AttestationStatementNone = Record<string, never>;

export type ParsedAuthenticatorFlags = {
    readonly raw: number;
    readonly userPresent: boolean;
    readonly userVerified: boolean;
    readonly backupEligible: boolean;
    readonly backupState: boolean;
    readonly hasAttestedCredentialData: boolean;
    readonly hasExtensionData: boolean;
};

export type ParsedRegistrationAuthenticatorData = {
    readonly flags: ParsedAuthenticatorFlags;
    readonly signCount: number;
    readonly aaguid: string;
    readonly credentialId: string;
    readonly publicKey: string;
    readonly publicKeyAlgorithm?: number;
    readonly extensions?: Record<string, unknown>;
};

export type ParsedAssertionAuthenticatorData = {
    readonly flags: ParsedAuthenticatorFlags;
    readonly signCount: number;
    readonly extensions?: Record<string, unknown>;
};

export type VerifiedAttestation = {
    readonly format: "none" | "packed" | "fido-u2f" | "apple" | "android-key" | "android-safetynet" | "tpm";
    readonly type: "none" | "self" | "basic" | "anonca";
    readonly trusted: boolean;
    readonly policyAccepted?: boolean;
    readonly metadataStatus?: string;
};
