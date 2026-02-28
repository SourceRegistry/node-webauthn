import {fail} from "../errors";
import {AttestationVerificationInput, validateAttestationObject} from "./utils";
import {verifyAndroidKeyAttestation} from "./android-key";
import {verifyAndroidSafetyNetAttestation} from "./android-safetynet";
import {verifyAppleAttestation} from "./apple";
import {verifyFidoU2fAttestation} from "./fido-u2f";
import {verifyNoneFormat} from "./none";
import {verifyPackedAttestation} from "./packed";
import {verifyTpmAttestation} from "./tpm";

export {validateAttestationObject} from "./utils";

/**
 * Dispatches registration attestation verification based on the attestation format identifier.
 */
export const verifyAttestationStatement = (input: AttestationVerificationInput) => {
    const allowedFormats = input.policy.allowed_formats ?? ["none", "packed", "fido-u2f", "apple", "android-key", "android-safetynet", "tpm"];
    if (!allowedFormats.includes(input.attestationObject.fmt as typeof allowedFormats[number])) {
        fail("ERR_UNSUPPORTED_ATTESTATION", `Attestation format ${input.attestationObject.fmt} is not allowed`);
    }

    switch (input.attestationObject.fmt) {
        case "none":
            return verifyNoneFormat();
        case "packed":
            return verifyPackedAttestation(input);
        case "fido-u2f":
            return verifyFidoU2fAttestation(input);
        case "apple":
            return verifyAppleAttestation(input);
        case "android-key":
            return verifyAndroidKeyAttestation(input);
        case "android-safetynet":
            return verifyAndroidSafetyNetAttestation(input);
        case "tpm":
            return verifyTpmAttestation(input);
        default:
            return fail("ERR_UNSUPPORTED_ATTESTATION", `Unsupported attestation format: ${input.attestationObject.fmt}`);
    }
};
