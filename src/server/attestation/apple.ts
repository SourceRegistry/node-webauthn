import {verifyAppleCore, toCertificates, AttestationVerificationInput} from "./utils";

export const verifyAppleAttestation = (input: AttestationVerificationInput) =>
    verifyAppleCore(input, toCertificates(input.attestationObject.attStmt.x5c));
