import {describe, expect, it} from "vitest";
import {toBase64Url} from "../../src";
import {challenge, credentialId, origin, packedClientData, rpId, safetyNetAttestationObject, webauth} from "./shared";

describe("android-safetynet attestation", () => {
    it("verifies android-safetynet attestation", () => {
        const parsed = webauth.parseRegistration({
            expected_challenge: challenge,
            credential_id: toBase64Url(credentialId),
            client_data_json: packedClientData,
            attestation_object: toBase64Url(safetyNetAttestationObject),
            origin,
            rp_id: rpId,
            allowed_attestation_formats: ["android-safetynet"],
            max_safetynet_age_ms: 60_000
        });

        expect(parsed.attestation_format).toBe("android-safetynet");
        expect(parsed.attestation_type).toBe("basic");
    });
});
