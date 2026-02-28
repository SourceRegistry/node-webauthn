import {describe, expect, it} from "vitest";
import {generateChallenge, toBase64Url, WebAuthError} from "../../src";
import {
    appId,
    appIdAuthenticationSignature,
    appIdAuthenticatorData,
    attestationObject,
    authenticationAuthenticatorData,
    authenticationClientData,
    authenticationSignature,
    challenge,
    createAlternativeAuthenticationFixture,
    credentialCoseKey,
    credentialId,
    origin,
    packedClientData,
    packedSelfAttestationObject,
    registrationClientData,
    rpId,
    unsupportedAttestationObject,
    webauth,
    webauthWithAllowedOrigins
} from "./shared";

describe("server core flow", () => {
    it("generates a base64url challenge", () => {
        const value = generateChallenge(32);

        expect(value).toMatch(/^[A-Za-z0-9_-]+$/);
        expect(Buffer.from(value, "base64url")).toHaveLength(32);
    });

    it("issues and verifies registration tokens", () => {
        const token = webauth.signRegistration({
            sub: "user-1",
            challenge,
            rp_id: rpId,
            origin,
            redirect_uri: "https://example.com/callback"
        });

        const claims = webauth.verifyRegistration(token);

        expect(claims.sub).toBe("user-1");
        expect(claims.challenge).toBe(challenge);
        expect(claims.iss).toBe("https://issuer.example.com");
        expect(claims.exp).toBeGreaterThan(claims.iat);
    });

    it("creates registration options with sane defaults", () => {
        const options = webauth.createRegistrationOptions({
            user: {
                id: "dXNlci0x",
                name: "user@example.com",
                displayName: "Example User"
            }
        });

        expect(options.rp.id).toBe(rpId);
        expect(options.rp.name).toBe("Example RP");
        expect(options.attestation).toBe("none");
        expect(options.pubKeyCredParams[0].alg).toBe(-7);
    });

    it("creates authentication options with configured RP defaults", () => {
        const options = webauth.createAuthenticationOptions({
            allowCredentials: [{id: toBase64Url(credentialId), type: "public-key"}]
        });

        expect(options.rpId).toBe(rpId);
        expect(options.userVerification).toBe("preferred");
        expect(options.allowCredentials?.[0].id).toBe(toBase64Url(credentialId));
    });

    it("parses a registration response", () => {
        const parsed = webauth.parseRegistration({
            expected_challenge: challenge,
            credential_id: toBase64Url(credentialId),
            client_data_json: registrationClientData,
            attestation_object: toBase64Url(attestationObject),
            transports: ["internal"],
            origin,
            rp_id: rpId
        });

        expect(parsed.credential_id).toBe(toBase64Url(credentialId));
        expect(parsed.counter).toBe(7);
        expect(parsed.transports).toEqual(["internal"]);
        expect(parsed.user_present).toBe(true);
        expect(parsed.user_verified).toBe(false);
        expect(parsed.attestation_format).toBe("none");
        expect(parsed.public_key.length).toBeGreaterThan(20);
    });

    it("parses packed self attestation and authenticator extensions", () => {
        const parsed = webauth.parseRegistration({
            expected_challenge: challenge,
            credential_id: toBase64Url(credentialId),
            client_data_json: packedClientData,
            attestation_object: toBase64Url(packedSelfAttestationObject),
            transports: ["internal"],
            origin,
            rp_id: rpId,
            expected_algorithms: [-7],
            client_extension_results: {credProps: {rk: true}}
        });

        expect(parsed.attestation_format).toBe("packed");
        expect(parsed.attestation_type).toBe("self");
        expect(parsed.attestation_trusted).toBe(false);
        expect(parsed.authenticator_extensions).toEqual({credProps: {rk: true}});
        expect(parsed.client_extension_results).toEqual({credProps: {rk: true}});
    });

    it("applies metadata provider attestation policy", () => {
        const parsed = webauth.parseRegistration({
            expected_challenge: challenge,
            credential_id: toBase64Url(credentialId),
            client_data_json: packedClientData,
            attestation_object: toBase64Url(packedSelfAttestationObject),
            origin,
            rp_id: rpId,
            allowed_attestation_formats: ["packed"],
            metadata_provider: {
                getEntry() {
                    return {
                        trusted: true,
                        status: "approved"
                    };
                }
            }
        });

        expect(parsed.attestation_trusted).toBe(true);
        expect(parsed.metadata_status).toBe("approved");
    });

    it("verifies an authentication response", () => {
        const result = webauth.verifyAuthenticationResponse({
            expected_challenge: challenge,
            client_data_json: authenticationClientData,
            authenticator_data: toBase64Url(authenticationAuthenticatorData),
            signature: authenticationSignature,
            origin,
            rp_id: rpId,
            public_key: toBase64Url(credentialCoseKey),
            previous_counter: 7,
            require_user_verification: true
        });

        expect(result).toEqual({
            counter: 8,
            user_present: true,
            user_verified: true,
            backup_eligible: false,
            backup_state: false,
            authenticator_extensions: undefined,
            client_extension_results: undefined
        });
    });

    it("accepts authentication from a configured allowed origin", () => {
        const alternative = createAlternativeAuthenticationFixture();
        const result = webauthWithAllowedOrigins.verifyAuthenticationResponse({
            expected_challenge: challenge,
            client_data_json: alternative.clientDataJson,
            authenticator_data: toBase64Url(authenticationAuthenticatorData),
            signature: alternative.signature,
            origin,
            rp_id: rpId,
            public_key: toBase64Url(credentialCoseKey)
        });

        expect(result.counter).toBe(8);
    });

    it("rejects replayed authentication counters", () => {
        expect(() => webauth.verifyAuthenticationResponse({
            expected_challenge: challenge,
            client_data_json: authenticationClientData,
            authenticator_data: toBase64Url(authenticationAuthenticatorData),
            signature: authenticationSignature,
            origin,
            rp_id: rpId,
            public_key: toBase64Url(credentialCoseKey),
            previous_counter: 8
        })).toThrowError(WebAuthError);
    });

    it("accepts appid extension when app id hash is used", () => {
        const result = webauth.verifyAuthenticationResponse({
            expected_challenge: challenge,
            client_data_json: authenticationClientData,
            authenticator_data: toBase64Url(appIdAuthenticatorData),
            signature: appIdAuthenticationSignature,
            origin,
            rp_id: rpId,
            public_key: toBase64Url(credentialCoseKey),
            app_id: appId,
            client_extension_results: {appid: true},
            allowed_client_extensions: ["appid"]
        });

        expect(result.counter).toBe(9);
        expect(result.client_extension_results).toEqual({appid: true});
    });

    it("rejects disallowed client extensions", () => {
        expect(() => webauth.verifyAuthenticationResponse({
            expected_challenge: challenge,
            client_data_json: authenticationClientData,
            authenticator_data: toBase64Url(authenticationAuthenticatorData),
            signature: authenticationSignature,
            origin,
            rp_id: rpId,
            public_key: toBase64Url(credentialCoseKey),
            client_extension_results: {appid: true},
            allowed_client_extensions: []
        })).toThrowError(WebAuthError);
    });

    it("rejects unsupported attestation formats", () => {
        expect(() => webauth.parseRegistration({
            expected_challenge: challenge,
            credential_id: toBase64Url(credentialId),
            client_data_json: registrationClientData,
            attestation_object: toBase64Url(unsupportedAttestationObject),
            origin,
            rp_id: rpId
        })).toThrowError(/attestation/i);
    });

    it("rejects authentication origin mismatches", () => {
        expect(() => webauth.verifyAuthenticationResponse({
            expected_challenge: challenge,
            client_data_json: authenticationClientData,
            authenticator_data: toBase64Url(authenticationAuthenticatorData),
            signature: authenticationSignature,
            origin: "https://invalid.example.com",
            rp_id: rpId,
            public_key: toBase64Url(credentialCoseKey)
        })).toThrowError(WebAuthError);
    });
});
