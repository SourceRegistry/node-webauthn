import {describe, expect, it} from "vitest";
import {toBase64Url} from "../../src";
import {appleAttestationObject, appleClientData, appleCredentialId, challenge, origin, rpId, webauth} from "./shared";

describe("apple attestation", () => {
    it("verifies apple attestation", () => {
        const parsed = webauth.parseRegistration({
            expected_challenge: challenge,
            credential_id: toBase64Url(appleCredentialId),
            client_data_json: appleClientData,
            attestation_object: toBase64Url(appleAttestationObject),
            origin,
            rp_id: rpId,
            allowed_attestation_formats: ["apple"]
        });

        expect(parsed.attestation_format).toBe("apple");
        expect(parsed.attestation_type).toBe("anonca");
        expect(parsed.attestation_trusted).toBe(false);
    });
});
