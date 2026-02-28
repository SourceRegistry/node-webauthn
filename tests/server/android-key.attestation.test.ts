import {describe, expect, it} from "vitest";
import {toBase64Url} from "../../src";
import {androidKeyAttestationObject, androidKeyCredentialCoseKey, androidKeyCredentialId, challenge, origin, packedClientData, rpId, webauth} from "./shared";

describe("android-key attestation", () => {
    it("verifies android-key attestation", () => {
        const parsed = webauth.parseRegistration({
            expected_challenge: challenge,
            credential_id: toBase64Url(androidKeyCredentialId),
            client_data_json: packedClientData,
            attestation_object: toBase64Url(androidKeyAttestationObject),
            origin,
            rp_id: rpId,
            allowed_attestation_formats: ["android-key"]
        });

        expect(parsed.attestation_format).toBe("android-key");
        expect(parsed.attestation_type).toBe("basic");
        expect(parsed.public_key).toBe(toBase64Url(androidKeyCredentialCoseKey));
    });
});
