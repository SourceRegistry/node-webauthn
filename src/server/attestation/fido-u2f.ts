import {fail} from "../errors";
import {verifyFidoU2fCore, toCertificates, AttestationVerificationInput} from "./utils";

export const verifyFidoU2fAttestation = (input: AttestationVerificationInput) => {
    const signatureNode = input.attestationObject.attStmt.sig;
    if (!(signatureNode instanceof Uint8Array)) {
        fail("ERR_INVALID_ATTESTATION", "FIDO U2F attestation requires a binary sig field");
    }

    return verifyFidoU2fCore(input, toCertificates(input.attestationObject.attStmt.x5c as Uint8Array[]), signatureNode as Uint8Array);
};
