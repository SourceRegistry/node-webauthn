import {Buffer} from "node:buffer";
import {fail} from "./errors";

type DerElement = {
    readonly tag: number;
    readonly headerLength: number;
    readonly length: number;
    readonly start: number;
    readonly end: number;
};

export const oidToDer = (oid: string): Buffer => {
    const arcs = oid.split(".").map(part => Number(part));
    if (arcs.length < 2 || arcs.some(value => !Number.isInteger(value) || value < 0)) {
        fail("ERR_INVALID_ATTESTATION", `Invalid OID: ${oid}`);
    }

    const bytes = [40 * arcs[0] + arcs[1]];
    for (const arc of arcs.slice(2)) {
        const encoded: number[] = [arc & 0x7f];
        let value = arc >>> 7;
        while (value > 0) {
            encoded.unshift((value & 0x7f) | 0x80);
            value >>>= 7;
        }
        bytes.push(...encoded);
    }

    return Buffer.from(bytes);
};

const readDerLength = (buffer: Buffer, offset: number): {length: number; offset: number} => {
    const initial = buffer[offset];
    if ((initial & 0x80) === 0) return {length: initial, offset: offset + 1};

    const bytes = initial & 0x7f;
    if (bytes === 0 || bytes > 4) {
        fail("ERR_INVALID_ATTESTATION", "Unsupported DER length encoding");
    }

    let length = 0;
    for (let index = 0; index < bytes; index += 1) {
        length = (length << 8) | buffer[offset + 1 + index];
    }

    return {length, offset: offset + 1 + bytes};
};

const readDerElement = (buffer: Buffer, offset: number): DerElement => {
    const tag = buffer[offset];
    const {length, offset: valueOffset} = readDerLength(buffer, offset + 1);
    return {tag, headerLength: valueOffset - offset, length, start: valueOffset, end: valueOffset + length};
};

export const collectDerChildren = (buffer: Buffer): DerElement[] => {
    const children: DerElement[] = [];
    let offset = 0;
    while (offset < buffer.length) {
        const element = readDerElement(buffer, offset);
        children.push(element);
        offset = element.end;
    }
    return children;
};

export const findDerOctetString = (buffer: Buffer, expectedLength: number): Buffer | undefined => {
    const children = collectDerChildren(buffer);
    for (const child of children) {
        const value = buffer.subarray(child.start, child.end);
        if (child.tag === 0x04 && value.length === expectedLength) {
            return value;
        }
        if ((child.tag & 0x20) !== 0 || child.tag === 0x30 || child.tag === 0x31 || (child.tag & 0xc0) === 0x80) {
            const nested = findDerOctetString(value, expectedLength);
            if (nested) return nested;
        }
    }
    return undefined;
};

/**
 * Finds an extension value by OID in an X.509 certificate's DER payload.
 */
export const findCertificateExtensionValue = (
    certificate: { readonly raw: Buffer | Uint8Array },
    oid: string
): Buffer | undefined => {
    const targetOid = oidToDer(oid);

    const search = (buffer: Buffer): Buffer | undefined => {
        const children = collectDerChildren(buffer);

        for (const child of children) {
            const value = buffer.subarray(child.start, child.end);
            if (child.tag === 0x30) {
                const sequenceChildren = collectDerChildren(value);
                if (
                    sequenceChildren.length >= 2 &&
                    sequenceChildren[0].tag === 0x06 &&
                    value.subarray(sequenceChildren[0].start, sequenceChildren[0].end).equals(targetOid)
                ) {
                    const octet = sequenceChildren.find(entry => entry.tag === 0x04);
                    if (octet) {
                        return value.subarray(octet.start, octet.end);
                    }
                }

                const nested = search(value);
                if (nested) {
                    return nested;
                }
            } else if ((child.tag & 0x20) !== 0 || (child.tag & 0xc0) === 0x80) {
                const nested = search(value);
                if (nested) {
                    return nested;
                }
            }
        }

        return undefined;
    };

    return search(Buffer.from(certificate.raw));
};
