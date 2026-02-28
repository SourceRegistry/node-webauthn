import {fail} from "./errors";

export const assertString = (value: unknown, field: string): string => {
    if (typeof value !== "string" || value.length === 0) {
        fail("ERR_INVALID_INPUT", `${field} must be a non-empty string`);
    }
    return value as string;
};

export const assertBufferLength = (buffer: Uint8Array, minLength: number, field: string) => {
    if (buffer.length < minLength) {
        fail("ERR_INVALID_INPUT", `${field} is shorter than expected`);
    }
};
