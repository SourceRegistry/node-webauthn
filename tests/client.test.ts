import {beforeAll, describe, expect, it} from "vitest";
import {
    createWebAuthClient,
    serializeAuthenticationCredential,
    serializeRegistrationCredential,
    toCreationOptions,
    toRequestOptions
} from "../src/client";

class FakePublicKeyCredential {
    readonly id: string;
    readonly rawId: ArrayBuffer | SharedArrayBuffer;
    readonly type: PublicKeyCredentialType;
    readonly response: AuthenticatorResponse;
    readonly extensionResults?: AuthenticationExtensionsClientOutputs;

    constructor(input: {
        id: string;
        rawId: Uint8Array;
        type?: PublicKeyCredentialType;
        response: AuthenticatorResponse;
        extensionResults?: AuthenticationExtensionsClientOutputs;
    }) {
        this.id = input.id;
        this.rawId = input.rawId.buffer.slice(
            input.rawId.byteOffset,
            input.rawId.byteOffset + input.rawId.byteLength
        );
        this.type = input.type ?? "public-key";
        this.response = input.response;
        this.extensionResults = input.extensionResults;
    }

    getClientExtensionResults() {
        return this.extensionResults ?? {};
    }
}

class FakeAttestationResponse {
    readonly clientDataJSON: ArrayBuffer | SharedArrayBuffer;
    readonly attestationObject: ArrayBuffer | SharedArrayBuffer;
    readonly transports: readonly AuthenticatorTransport[];

    constructor(input: {
        clientDataJSON: Uint8Array;
        attestationObject: Uint8Array;
        transports?: readonly AuthenticatorTransport[];
    }) {
        this.clientDataJSON = input.clientDataJSON.buffer.slice(
            input.clientDataJSON.byteOffset,
            input.clientDataJSON.byteOffset + input.clientDataJSON.byteLength
        );
        this.attestationObject = input.attestationObject.buffer.slice(
            input.attestationObject.byteOffset,
            input.attestationObject.byteOffset + input.attestationObject.byteLength
        );
        this.transports = input.transports ?? [];
    }

    getTransports() {
        return [...this.transports];
    }
}

class FakeAssertionResponse {
    readonly clientDataJSON: ArrayBuffer | SharedArrayBuffer;
    readonly authenticatorData: ArrayBuffer | SharedArrayBuffer;
    readonly signature: ArrayBuffer | SharedArrayBuffer;
    readonly userHandle: ArrayBuffer | SharedArrayBuffer;

    constructor(input: {
        clientDataJSON: Uint8Array;
        authenticatorData: Uint8Array;
        signature: Uint8Array;
        userHandle?: Uint8Array;
    }) {
        this.clientDataJSON = input.clientDataJSON.buffer.slice(
            input.clientDataJSON.byteOffset,
            input.clientDataJSON.byteOffset + input.clientDataJSON.byteLength
        );
        this.authenticatorData = input.authenticatorData.buffer.slice(
            input.authenticatorData.byteOffset,
            input.authenticatorData.byteOffset + input.authenticatorData.byteLength
        );
        this.signature = input.signature.buffer.slice(
            input.signature.byteOffset,
            input.signature.byteOffset + input.signature.byteLength
        );
        // @ts-ignore
        this.userHandle = input.userHandle
            ? input.userHandle.buffer.slice(
                input.userHandle.byteOffset,
                input.userHandle.byteOffset + input.userHandle.byteLength
            )
            : null;
    }
}

beforeAll(() => {
    Object.assign(globalThis, {
        PublicKeyCredential: FakePublicKeyCredential,
        AuthenticatorAttestationResponse: FakeAttestationResponse,
        AuthenticatorAssertionResponse: FakeAssertionResponse
    });
});

describe("node-webauth/client", () => {
    it("converts JSON creation options into browser options", () => {
        const options = toCreationOptions({
            challenge: "Y2hhbGxlbmdl",
            rp: {name: "Example", id: "example.com"},
            user: {
                id: "dXNlci0x",
                name: "user@example.com",
                displayName: "Example User"
            },
            pubKeyCredParams: [{type: "public-key", alg: -7}],
            excludeCredentials: [
                {
                    id: "Y3JlZC0x",
                    type: "public-key",
                    transports: ["internal"]
                }
            ]
        });

        expect(new TextDecoder().decode(options.challenge)).toBe("challenge");
        expect(new TextDecoder().decode(options.user.id)).toBe("user-1");
        expect(options.excludeCredentials?.[0].id).toBeInstanceOf(Uint8Array);
    });

    it("converts JSON request options into browser options", () => {
        const options = toRequestOptions({
            challenge: "cmVxdWVzdC1jaGFsbGVuZ2U",
            rpId: "example.com",
            allowCredentials: [{id: "Y3JlZC0x", type: "public-key"}]
        });

        expect(new TextDecoder().decode(options.challenge)).toBe("request-challenge");
        expect(new TextDecoder().decode(options.allowCredentials?.[0].id ?? new Uint8Array())).toBe("cred-1");
    });

    it("serializes a registration credential", () => {
        const credential = new FakePublicKeyCredential({
            id: "credential-id",
            rawId: new TextEncoder().encode("raw-id"),
            extensionResults: {credProps: {rk: true}},
            response: new FakeAttestationResponse({
                clientDataJSON: new TextEncoder().encode("{\"type\":\"webauthn.create\"}"),
                attestationObject: new TextEncoder().encode("attestation"),
                transports: ["internal", "hybrid"]
            }) as unknown as AuthenticatorResponse
        }) as unknown as PublicKeyCredential;

        const serialized = serializeRegistrationCredential(credential);

        expect(serialized.id).toBe("credential-id");
        expect(serialized.transports).toEqual(["internal", "hybrid"]);
        expect(serialized.raw_id).toBe("cmF3LWlk");
        expect(serialized.client_extension_results).toEqual({credProps: {rk: true}});
    });

    it("serializes an authentication credential", () => {
        const credential = new FakePublicKeyCredential({
            id: "credential-id",
            rawId: new TextEncoder().encode("raw-id"),
            extensionResults: {appid: true},
            response: new FakeAssertionResponse({
                clientDataJSON: new TextEncoder().encode("{\"type\":\"webauthn.get\"}"),
                authenticatorData: new TextEncoder().encode("auth-data"),
                signature: new TextEncoder().encode("signature"),
                userHandle: new TextEncoder().encode("user-1")
            }) as unknown as AuthenticatorResponse
        }) as unknown as PublicKeyCredential;

        const serialized = serializeAuthenticationCredential(credential);

        expect(serialized.signature).toBe("c2lnbmF0dXJl");
        expect(serialized.user_handle).toBe("dXNlci0x");
        expect(serialized.client_extension_results).toEqual({appid: true});
    });

    it("creates a small client facade", () => {
        const client = createWebAuthClient();

        expect(typeof client.startRegistration).toBe("function");
        expect(typeof client.startAuthentication).toBe("function");
        expect(typeof client.toCreationOptions).toBe("function");
    });
});
