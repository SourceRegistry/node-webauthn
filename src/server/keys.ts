import {createPublicKey, KeyObject} from "node:crypto";
import {fromBase64Url, toBase64Url} from "./base64url";
import {decodeCbor} from "./cbor";
import {fail} from "./errors";

/**
 * Converts a COSE-encoded credential public key into a Node.js `KeyObject`.
 */
export const coseToPublicKey = (input: string): KeyObject => {
    const decoded = decodeCbor(fromBase64Url(input));
    const key = decoded.value as Record<number, Uint8Array | number>;

    if (key[1] === 2) {
        const curve = ({
            1: "P-256",
            2: "P-384",
            3: "P-521"
        } as Record<number, string>)[key[-1] as number];

        if (!curve || !(key[-2] instanceof Uint8Array) || !(key[-3] instanceof Uint8Array)) {
            fail("ERR_INVALID_PUBLIC_KEY", "Invalid EC public key");
        }

        return createPublicKey({
            key: {
                kty: "EC",
                crv: curve,
                x: toBase64Url(key[-2] as Uint8Array),
                y: toBase64Url(key[-3] as Uint8Array),
                ext: true
            },
            format: "jwk"
        });
    }

    if (key[1] === 3) {
        if (!(key[-1] instanceof Uint8Array) || !(key[-2] instanceof Uint8Array)) {
            fail("ERR_INVALID_PUBLIC_KEY", "Invalid RSA public key");
        }

        return createPublicKey({
            key: {
                kty: "RSA",
                n: toBase64Url(key[-1] as Uint8Array),
                e: toBase64Url(key[-2] as Uint8Array),
                ext: true
            },
            format: "jwk"
        });
    }

    return fail("ERR_UNSUPPORTED_KEY", "Unsupported COSE public key type");
};

/**
 * Converts a credential public key into the uncompressed EC point required by FIDO U2F attestation.
 */
export const coseEc2ToUncompressedPoint = (input: string): Buffer => {
    const decoded = decodeCbor(fromBase64Url(input));
    const key = decoded.value as Record<number, Uint8Array | number>;

    if (key[1] !== 2 || key[-1] !== 1 || !(key[-2] instanceof Uint8Array) || !(key[-3] instanceof Uint8Array)) {
        fail("ERR_UNSUPPORTED_KEY", "FIDO U2F attestation requires an EC2 P-256 credential public key");
    }

    return Buffer.concat([
        Buffer.from([0x04]),
        Buffer.from(key[-2] as Uint8Array),
        Buffer.from(key[-3] as Uint8Array)
    ]);
};
