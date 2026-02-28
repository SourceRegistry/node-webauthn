import {describe, expect, it} from "vitest";
import {toBase64Url} from "../../src";
import {challenge, credentialId, fidoAttestationCertificatePem, fidoU2fAttestationObject, origin, packedClientData, rpId, webauth} from "./shared";

describe("fido-u2f attestation", () => {
    it("verifies fido-u2f attestation with trust anchors", () => {
        const parsed = webauth.parseRegistration({
            expected_challenge: challenge,
            credential_id: toBase64Url(credentialId),
            client_data_json: packedClientData,
            attestation_object: toBase64Url(fidoU2fAttestationObject),
            origin,
            rp_id: rpId,
            allowed_attestation_formats: ["fido-u2f"],
            require_trusted_attestation: true,
            trust_anchors: [fidoAttestationCertificatePem]
        });

        expect(parsed.attestation_format).toBe("fido-u2f");
        expect(parsed.attestation_type).toBe("basic");
        expect(parsed.attestation_trusted).toBe(true);
    });
});
