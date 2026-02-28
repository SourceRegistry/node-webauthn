import {assertBufferLength} from "./assert";
import {fail} from "./errors";
import {CborNode, CborResult} from "./types";

const textDecoder = new TextDecoder();

const readLength = (
    data: Uint8Array,
    offset: number,
    additionalInfo: number
): {length: number; offset: number} => {
    if (additionalInfo < 24) return {length: additionalInfo, offset};
    if (additionalInfo === 24) {
        assertBufferLength(data.subarray(offset), 1, "CBOR payload");
        return {length: data[offset], offset: offset + 1};
    }
    if (additionalInfo === 25) {
        assertBufferLength(data.subarray(offset), 2, "CBOR payload");
        return {length: (data[offset] << 8) | data[offset + 1], offset: offset + 2};
    }
    if (additionalInfo === 26) {
        assertBufferLength(data.subarray(offset), 4, "CBOR payload");
        return {
            length: (
                (data[offset] * 0x1000000) +
                ((data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3])
            ),
            offset: offset + 4
        };
    }
    return fail("ERR_UNSUPPORTED_CBOR", "Unsupported CBOR length encoding");
};

/**
 * Minimal CBOR decoder for the subset WebAuthn uses in authenticator and attestation objects.
 */
export const decodeCbor = (data: Uint8Array, offset = 0): CborResult => {
    assertBufferLength(data.subarray(offset), 1, "CBOR payload");

    const initialByte = data[offset++];
    const majorType = initialByte >> 5;
    const additionalInfo = initialByte & 0x1f;
    const lengthInfo = readLength(data, offset, additionalInfo);
    offset = lengthInfo.offset;

    switch (majorType) {
        case 0:
            return {value: lengthInfo.length, offset};
        case 1:
            return {value: -1 - lengthInfo.length, offset};
        case 2: {
            assertBufferLength(data.subarray(offset), lengthInfo.length, "CBOR byte string");
            const value = data.slice(offset, offset + lengthInfo.length);
            return {value, offset: offset + lengthInfo.length};
        }
        case 3: {
            assertBufferLength(data.subarray(offset), lengthInfo.length, "CBOR text string");
            const value = textDecoder.decode(data.slice(offset, offset + lengthInfo.length));
            return {value, offset: offset + lengthInfo.length};
        }
        case 4: {
            const value: CborNode[] = [];
            for (let index = 0; index < lengthInfo.length; index += 1) {
                const item = decodeCbor(data, offset);
                value.push(item.value);
                offset = item.offset;
            }
            return {value, offset};
        }
        case 5: {
            const value: Record<string | number, CborNode> = {};
            for (let index = 0; index < lengthInfo.length; index += 1) {
                const key = decodeCbor(data, offset);
                offset = key.offset;
                const item = decodeCbor(data, offset);
                offset = item.offset;
                value[key.value as string | number] = item.value;
            }
            return {value, offset};
        }
        case 7:
            if (additionalInfo === 20) return {value: false, offset};
            if (additionalInfo === 21) return {value: true, offset};
            if (additionalInfo === 22) return {value: null, offset};
            return fail("ERR_UNSUPPORTED_CBOR", "Unsupported CBOR simple value");
        default:
            return fail("ERR_UNSUPPORTED_CBOR", "Unsupported CBOR major type");
    }
};
