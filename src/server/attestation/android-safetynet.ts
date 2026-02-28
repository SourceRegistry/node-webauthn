import {createHash, createVerify, X509Certificate} from "node:crypto";
import {fail} from "../errors";
import {AttestationVerificationInput, resolveAttestationTrust, resolveMetadata} from "./utils";

const decodeJsonBase64 = (input: string) => JSON.parse(Buffer.from(input, "base64url").toString("utf8")) as Record<string, unknown>;

const verifyJwsSignature = (headerPart: string, payloadPart: string, signaturePart: string, certificate: X509Certificate, algorithm: string) => {
    const verifier = createVerify(
        ({
            ES256: "SHA256",
            ES384: "SHA384",
            ES512: "SHA512",
            RS256: "SHA256",
            RS384: "SHA384",
            RS512: "SHA512"
        } as Record<string, string>)[algorithm] ?? fail("ERR_INVALID_ATTESTATION", `Unsupported SafetyNet JWS alg ${algorithm}`)
    );
    verifier.update(`${headerPart}.${payloadPart}`);
    verifier.end();
    return verifier.verify(certificate.publicKey, Buffer.from(signaturePart, "base64url"));
};

/**
 * Verifies Android SafetyNet attestation.
 */
export const verifyAndroidSafetyNetAttestation = (input: AttestationVerificationInput) => {
    const response = input.attestationObject.attStmt.response;
    if (!(response instanceof Uint8Array)) {
        fail("ERR_INVALID_ATTESTATION", "android-safetynet attestation requires a binary response field");
    }

    const token = Buffer.from(response as Uint8Array).toString("utf8");
    const [headerPart, payloadPart, signaturePart] = token.split(".");
    if (!headerPart || !payloadPart || !signaturePart) {
        fail("ERR_INVALID_ATTESTATION", "android-safetynet response was not a compact JWS");
    }

    const header = decodeJsonBase64(headerPart);
    const payload = decodeJsonBase64(payloadPart);
    const x5c = Array.isArray(header.x5c) ? header.x5c : undefined;
    const alg = typeof header.alg === "string" ? header.alg : undefined;

    if (!x5c || !alg) {
        fail("ERR_INVALID_ATTESTATION", "android-safetynet response header is missing alg or x5c");
    }
    const certificateChain = x5c as unknown[];
    const jwsAlgorithm = alg as string;

    const certificates = certificateChain.map(entry => new X509Certificate(Buffer.from(String(entry), "base64")));
    const leaf = certificates[0];
    if (!leaf || !verifyJwsSignature(headerPart, payloadPart, signaturePart, leaf, jwsAlgorithm)) {
        fail("ERR_INVALID_ATTESTATION", "android-safetynet JWS signature verification failed");
    }

    const expectedNonce = createHash("sha256").update(Buffer.concat([input.authDataBytes, input.clientDataHash])).digest("base64");
    if (typeof payload.nonce !== "string" || payload.nonce !== expectedNonce) {
        fail("ERR_INVALID_ATTESTATION", "android-safetynet nonce did not match authData and clientDataHash");
    }

    const timestampMs = typeof payload.timestampMs === "number" ? payload.timestampMs : Number(payload.timestampMs);
    const maxAge = input.policy.max_safetynet_age_ms ?? 5 * 60 * 1000;
    if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > maxAge) {
        fail("ERR_INVALID_ATTESTATION", "android-safetynet timestamp is outside the accepted window");
    }

    if ((input.policy.require_safetynet_cts_profile_match ?? true) && payload.ctsProfileMatch !== true) {
        fail("ERR_INVALID_ATTESTATION", "android-safetynet requires ctsProfileMatch=true");
    }

    const trust = resolveAttestationTrust(certificates, input.policy);
    return resolveMetadata({
        format: "android-safetynet",
        type: "basic",
        trusted: trust.trusted,
        policyAccepted: trust.policyAccepted
    }, input, certificates);
};
