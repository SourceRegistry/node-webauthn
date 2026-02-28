/**
 * Encodes arbitrary byte-like input as RFC 4648 base64url without padding.
 */
export const toBase64Url = (input: Buffer | Uint8Array | string): string =>
    Buffer.from(input).toString("base64url");

/**
 * Decodes RFC 4648 base64url without padding into a Node.js `Buffer`.
 */
export const fromBase64Url = (input: string): Buffer =>
    Buffer.from(input, "base64url");
