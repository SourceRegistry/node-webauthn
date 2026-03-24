const textEncoder = new TextEncoder();

/**
 * Stable error type emitted by browser-facing helper methods.
 */
export class WebAuthClientError extends Error {
    readonly code: string;

    constructor(code: string, message: string) {
        super(message);
        this.name = "WebAuthClientError";
        this.code = code;
    }
}

/**
 * Helper class to see if the error is a not allowed error.
 */
export class NotAllowedError extends DOMException {


    constructor(message: string) {
        super(message, "NotAllowedError");
    }

    isInstanceOf(e: unknown): e is NotAllowedError {
        return e instanceof DOMException && e.code === 0 && e.name === "NotAllowedError"
    }

}

export type Base64UrlJSON = string | number | boolean | null | Base64UrlJSON[] | {
    [key: string]: Base64UrlJSON;
};

/**
 * JSON-safe registration credential payload returned by the client helpers.
 */
export type RegistrationCredentialJSON = {
    readonly id: string;
    readonly raw_id: string;
    readonly type: string;
    readonly client_data_json: string;
    readonly attestation_object: string;
    readonly transports: readonly string[];
    readonly client_extension_results?: AuthenticationExtensionsClientOutputs;
};

/**
 * JSON-safe authentication credential payload returned by the client helpers.
 */
export type AuthenticationCredentialJSON = {
    readonly id: string;
    readonly raw_id: string;
    readonly type: string;
    readonly client_data_json: string;
    readonly authenticator_data: string;
    readonly signature: string;
    readonly user_handle?: string;
    readonly client_extension_results?: AuthenticationExtensionsClientOutputs;
};

/**
 * JSON-safe registration options expected by `startRegistration`.
 *
 * This is intentionally close to the JSON conversion form described by the
 * WebAuthn Level 3 specification so servers can return base64url strings.
 */
export type JsonCreationOptions = {
    readonly challenge: string;
    readonly rp: PublicKeyCredentialRpEntity;
    user: {
        readonly id: string;
        readonly name: string;
        readonly displayName: string;
    };
    readonly pubKeyCredParams: ReadonlyArray<PublicKeyCredentialParameters>;
    readonly excludeCredentials?: ReadonlyArray<{
        readonly id: string;
        readonly type: PublicKeyCredentialType;
        readonly transports?: readonly AuthenticatorTransport[];
    }>;
    [key: string]: unknown;
};

/**
 * JSON-safe authentication options expected by `startAuthentication`.
 */
export type JsonRequestOptions = {
    readonly challenge: string;
    readonly allowCredentials?: ReadonlyArray<{
        readonly id: string;
        readonly type: PublicKeyCredentialType;
        readonly transports?: readonly AuthenticatorTransport[];
    }>;
    [key: string]: unknown;
};

const fail = (code: string, message: string): never => {
    throw new WebAuthClientError(code, message);
};

const hasBuffer = () => typeof Buffer !== "undefined";

const toBufferSource = (input: Uint8Array): Uint8Array<ArrayBuffer> =>
    Uint8Array.from(input);

const base64ToBytes = (input: string): Uint8Array<ArrayBuffer> => {
    const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
    const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
    const value = normalized + padding;

    if (hasBuffer()) {
        return Uint8Array.from(Buffer.from(value, "base64"));
    }

    if (typeof atob !== "function") {
        fail("ERR_UNSUPPORTED_RUNTIME", "This runtime does not support base64 decoding");
    }

    const binary = atob(value);
    return Uint8Array.from(binary, character => character.charCodeAt(0));
};

const bytesToBase64Url = (input: ArrayBuffer | ArrayBufferView): string => {
    const bytes = input instanceof ArrayBuffer
        ? new Uint8Array(input)
        : new Uint8Array(input.buffer, input.byteOffset, input.byteLength);

    if (hasBuffer()) {
        return Buffer.from(bytes).toString("base64url");
    }

    if (typeof btoa !== "function") {
        fail("ERR_UNSUPPORTED_RUNTIME", "This runtime does not support base64 encoding");
    }

    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const utf8ToBase64Url = (input: string) => bytesToBase64Url(textEncoder.encode(input));

/**
 * Encodes bytes into base64url without padding.
 */
export const toBase64Url = bytesToBase64Url;

/**
 * Decodes base64url without padding into a byte array.
 */
export const fromBase64Url = base64ToBytes;

/**
 * Converts JSON-safe registration options into browser-native WebAuthn options.
 */
export const toCreationOptions = (
    input: JsonCreationOptions
): PublicKeyCredentialCreationOptions => ({
    ...input,
    pubKeyCredParams: [...input.pubKeyCredParams],
    challenge: toBufferSource(base64ToBytes(input.challenge)),
    user: {
        ...input.user,
        id: toBufferSource(base64ToBytes(input.user.id))
    },
    excludeCredentials: input.excludeCredentials?.map(credential => ({
        ...credential,
        transports: credential.transports ? [...credential.transports] : undefined,
        id: toBufferSource(base64ToBytes(credential.id))
    }))
});

/**
 * Converts JSON-safe authentication options into browser-native WebAuthn options.
 */
export const toRequestOptions = (
    input: JsonRequestOptions
): PublicKeyCredentialRequestOptions => ({
    ...input,
    challenge: toBufferSource(base64ToBytes(input.challenge)),
    allowCredentials: input.allowCredentials?.map(credential => ({
        ...credential,
        transports: credential.transports ? [...credential.transports] : undefined,
        id: toBufferSource(base64ToBytes(credential.id))
    }))
});

const assertPublicKeyCredential = (credential: Credential | null): PublicKeyCredential => {
    if (!(credential instanceof PublicKeyCredential)) {
        fail("ERR_INVALID_CREDENTIAL", "The browser did not return a public key credential");
    }

    return credential as PublicKeyCredential;
};

const assertAttestationResponse = (
    response: AuthenticatorResponse
): AuthenticatorAttestationResponse => {
    if (!(response instanceof AuthenticatorAttestationResponse)) {
        fail("ERR_INVALID_CREDENTIAL", "Expected an attestation response");
    }

    return response as AuthenticatorAttestationResponse;
};

const assertAssertionResponse = (
    response: AuthenticatorResponse
): AuthenticatorAssertionResponse => {
    if (!(response instanceof AuthenticatorAssertionResponse)) {
        fail("ERR_INVALID_CREDENTIAL", "Expected an assertion response");
    }

    return response as AuthenticatorAssertionResponse;
};

/**
 * Serializes a browser registration credential into JSON-safe values that can be
 * posted back to the relying party server.
 */
export const serializeRegistrationCredential = (
    credential: PublicKeyCredential
): RegistrationCredentialJSON => {
    const response = assertAttestationResponse(credential.response);

    return {
        id: credential.id,
        raw_id: bytesToBase64Url(credential.rawId),
        type: credential.type,
        client_data_json: bytesToBase64Url(response.clientDataJSON),
        attestation_object: bytesToBase64Url(response.attestationObject),
        transports: response.getTransports?.() ?? [],
        client_extension_results: credential.getClientExtensionResults?.()
    };
};

/**
 * Serializes a browser authentication credential into JSON-safe values that can be
 * posted back to the relying party server.
 */
export const serializeAuthenticationCredential = (
    credential: PublicKeyCredential
): AuthenticationCredentialJSON => {
    const response = assertAssertionResponse(credential.response);

    return {
        id: credential.id,
        raw_id: bytesToBase64Url(credential.rawId),
        type: credential.type,
        client_data_json: bytesToBase64Url(response.clientDataJSON),
        authenticator_data: bytesToBase64Url(response.authenticatorData),
        signature: bytesToBase64Url(response.signature),
        user_handle: response.userHandle ? bytesToBase64Url(response.userHandle) : undefined,
        client_extension_results: credential.getClientExtensionResults?.()
    };
};

const getCredentialsContainer = (): CredentialsContainer => {
    if (typeof navigator === "undefined" || !navigator.credentials) {
        fail("ERR_UNSUPPORTED_RUNTIME", "WebAuthn requires navigator.credentials");
    }

    return navigator.credentials;
};

/**
 * Starts a browser registration ceremony using JSON-safe options.
 */
export const startRegistration = async (
    options: JsonCreationOptions
): Promise<RegistrationCredentialJSON> => {
    const credential = await getCredentialsContainer().create({
        publicKey: toCreationOptions(options)
    });
    return serializeRegistrationCredential(assertPublicKeyCredential(credential));
};

/**
 * Starts a browser authentication ceremony using JSON-safe options.
 */
export const startAuthentication = async (
    options: JsonRequestOptions
): Promise<AuthenticationCredentialJSON> => {
    const credential = await getCredentialsContainer().get({
        publicKey: toRequestOptions(options)
    });
    return serializeAuthenticationCredential(assertPublicKeyCredential(credential));
};

/**
 * Creates the default browser helper surface used by the `client` entrypoint.
 */
export const createWebAuthClient = () => ({
    toBase64Url,
    fromBase64Url,
    utf8ToBase64Url,
    toCreationOptions,
    toRequestOptions,
    serializeRegistrationCredential,
    serializeAuthenticationCredential,
    startRegistration,
    startAuthentication
});

export default createWebAuthClient;

export const WebAuthnClient = createWebAuthClient
