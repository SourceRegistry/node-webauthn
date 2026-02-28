import {describe, expect, it, vi} from "vitest";
import {toBase64Url, WebAuthError} from "../../src";
import {challenge, credentialId, origin, packedClientData, rpId, tpmAttestationCertificatePem, tpmAttestationObject, webauth} from "./shared";

describe("tpm attestation", () => {
    it("verifies TPM attestation with trust anchors", () => {
        const parsed = webauth.parseRegistration({
            expected_challenge: challenge,
            credential_id: toBase64Url(credentialId),
            client_data_json: packedClientData,
            attestation_object: toBase64Url(tpmAttestationObject),
            origin,
            rp_id: rpId,
            allowed_attestation_formats: ["tpm"],
            trust_mode: "strict",
            trust_anchors: [tpmAttestationCertificatePem]
        });

        expect(parsed.attestation_format).toBe("tpm");
        expect(parsed.attestation_trusted).toBe(true);
        expect(parsed.attestation_policy_accepted).toBe(true);
    });

    it("rejects expired attestation chains in strict trust mode", () => {
        const nowSpy = vi.spyOn(Date, "now").mockReturnValue(new Date("2040-01-01T00:00:00Z").getTime());

        try {
            expect(() => webauth.parseRegistration({
                expected_challenge: challenge,
                credential_id: toBase64Url(credentialId),
                client_data_json: packedClientData,
                attestation_object: toBase64Url(tpmAttestationObject),
                origin,
                rp_id: rpId,
                allowed_attestation_formats: ["tpm"],
                trust_mode: "strict",
                trust_anchors: [tpmAttestationCertificatePem]
            })).toThrowError(WebAuthError);
        } finally {
            nowSpy.mockRestore();
        }
    });
});
