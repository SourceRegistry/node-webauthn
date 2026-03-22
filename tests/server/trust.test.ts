import {X509Certificate} from "node:crypto";
import {describe, expect, it} from "vitest";
import {allowsCertificateSigning, isCertificateAuthority, verifyCertificatePath} from "../../src/server/trust";
import {tpmAttestationCertificatePem} from "./shared";

const createFakeCertificate = (input: {
    readonly ca?: boolean;
    readonly keyUsage?: string[];
}) => ({
    keyUsage: input.keyUsage,
    toLegacyObject() {
        return {ca: input.ca};
    }
}) as unknown as X509Certificate;

describe("certificate trust helpers", () => {
    it("accepts exact trust-anchor pinning for the final certificate", () => {
        const certificate = new X509Certificate(tpmAttestationCertificatePem);

        expect(verifyCertificatePath([certificate], [tpmAttestationCertificatePem])).toBe(true);
    });

    it("recognizes certificate-authority constraints", () => {
        expect(isCertificateAuthority(createFakeCertificate({ca: true}))).toBe(true);
        expect(isCertificateAuthority(createFakeCertificate({ca: false}))).toBe(false);
    });

    it("requires keyCertSign when key usage is present", () => {
        expect(allowsCertificateSigning(createFakeCertificate({keyUsage: ["keyCertSign"]}))).toBe(true);
        expect(allowsCertificateSigning(createFakeCertificate({keyUsage: ["digitalSignature"]}))).toBe(false);
        expect(allowsCertificateSigning(createFakeCertificate({keyUsage: undefined}))).toBe(true);
    });
});
