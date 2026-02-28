export const DEFAULT_CHALLENGE_BYTES = 32;
export const DEFAULT_TOKEN_TTL_SECONDS = 600;
export const DEFAULT_TIMEOUT_MS = 60_000;
export const USER_PRESENT_FLAG = 0x01;
export const USER_VERIFIED_FLAG = 0x04;
export const BACKUP_ELIGIBLE_FLAG = 0x08;
export const BACKUP_STATE_FLAG = 0x10;
export const ATTESTED_CREDENTIAL_DATA_FLAG = 0x40;
export const EXTENSION_DATA_FLAG = 0x80;

export const DEFAULT_REGISTRATION_ALGORITHMS: ReadonlyArray<PublicKeyCredentialParameters> = [
    {type: "public-key", alg: -7},
    {type: "public-key", alg: -257}
];
