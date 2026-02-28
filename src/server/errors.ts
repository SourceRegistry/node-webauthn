/**
 * Stable error type emitted by server-side validation and helper methods.
 */
export class WebAuthError extends Error {
    readonly code: string;

    constructor(code: string, message: string) {
        super(message);
        this.name = "WebAuthError";
        this.code = code;
    }
}

/**
 * Throws a `WebAuthError` with a stable machine-readable error code.
 */
export const fail = (code: string, message: string): never => {
    throw new WebAuthError(code, message);
};
