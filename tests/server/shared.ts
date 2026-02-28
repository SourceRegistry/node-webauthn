import {createHash, createPrivateKey, createPublicKey, createSign, generateKeyPairSync, X509Certificate} from "node:crypto";
import {createWebAuth, toBase64Url} from "../../src";

export const rpId = "example.com";
export const origin = "https://example.com";
export const challenge = "challenge-value";
export const credentialId = Buffer.from("credential-123");
export const appId = "https://appid.example.com";
const appleCredentialPrivateKeyPem = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDVQSPu3DhRSyM4lTe6JLcQy8MO87RH06re6DTHn9C0poAoGCCqGSM49
AwEHoUQDQgAEE6iXbrL1n1q0J6VkCIcZD5zxEnmfO7zsmLaioUlz0Oy1W1CJiYwc
8lV4LDWr4scIvSnFgYPI/MZc/soZvw9ycw==
-----END EC PRIVATE KEY-----`;
const appleAttestationCertificatePem = `-----BEGIN CERTIFICATE-----
MIIB7zCCAZagAwIBAgIUC2M49otN1IsrqYZbjVt7Mn8XaP0wCgYIKoZIzj0EAwIw
NDELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0V4YW1wbGUxEzARBgNVBAMMCkFwcGxl
IFRlc3QwHhcNMjYwMjI4MTQwNjQ0WhcNMzYwMjI2MTQwNjQ0WjA0MQswCQYDVQQG
EwJVUzEQMA4GA1UECgwHRXhhbXBsZTETMBEGA1UEAwwKQXBwbGUgVGVzdDBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABBOol26y9Z9atCelZAiHGQ+c8RJ5nzu87Ji2
oqFJc9DstVtQiYmMHPJVeCw1q+LHCL0pxYGDyPzGXP7KGb8PcnOjgYUwgYIwHQYD
VR0OBBYEFHWRH9AB+CPoGst0dD7tMinGD48dMB8GA1UdIwQYMBaAFHWRH9AB+CPo
Gst0dD7tMinGD48dMA8GA1UdEwEB/wQFMAMBAf8wLwYJKoZIhvdjZAgCBCIEIFpj
JAEnWsSGlnA2/Y313h4Gbm0K201OA5rGTm++Vz+4MAoGCCqGSM49BAMCA0cAMEQC
IFtKndhYT417fASiQInMcIYVFLFUrFMV+a/L0pG2ZcznAiAhKmvXoBBDZGaDhNQK
Ba5mzJJ+roBa8V9GcbZUPE+Kvw==
-----END CERTIFICATE-----`;
const fidoAttestationPrivateKeyPem = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEWw7+5OFz/MnvEtfbBcivy5OiCqXJRcvDbAlmaoqj53oAoGCCqGSM49
AwEHoUQDQgAElqRUXV/iBxdMjX0EWyc1C+onZwTUeCzel9gC1MTzen2XDM5Y1L/W
DLp8Gix51fL6zHc1iD/HhWoCRWmhXccR/A==
-----END EC PRIVATE KEY-----`;
export const fidoAttestationCertificatePem = `-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIUeU1KLs+i7BA63RLgOIL9/b45BykwCgYIKoZIzj0EAwIw
MjELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0V4YW1wbGUxETAPBgNVBAMMCFUyRiBU
ZXN0MB4XDTI2MDIyODE0MDEzMloXDTM2MDIyNjE0MDEzMlowMjELMAkGA1UEBhMC
VVMxEDAOBgNVBAoMB0V4YW1wbGUxETAPBgNVBAMMCFUyRiBUZXN0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAElqRUXV/iBxdMjX0EWyc1C+onZwTUeCzel9gC1MTz
en2XDM5Y1L/WDLp8Gix51fL6zHc1iD/HhWoCRWmhXccR/KNTMFEwHQYDVR0OBBYE
FJRYbVXw4j65sZiOcaAKw3+z3QkmMB8GA1UdIwQYMBaAFJRYbVXw4j65sZiOcaAK
w3+z3QkmMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhALqoUr3x
uSCrF0dG6C5jfoessN/7cmBVZysMYmRmvI9JAiA9Z+Tgh/0bsJjNdm6MqlNrRz8n
j8i6bIfUQyFbmM5VEg==
-----END CERTIFICATE-----`;
const androidKeyCredentialPrivateKeyPem = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINPCgRgD9CSz91GFPYt/8Oo2CGm7W8IkXBCO+XLRr+fBoAoGCCqGSM49
AwEHoUQDQgAE3hC8orVMSCaFvwkiUeKGrlSFGPaiVHfCdBXqZwGPSOMkPr8UYFqU
Qj/PJbF6zrCr8vZg6YDxVDsS5A4BGEUxIQ==
-----END EC PRIVATE KEY-----`;
const androidKeyAttestationCertificatePem = `-----BEGIN CERTIFICATE-----
MIIB6DCCAY6gAwIBAgIUf/2O7XEZhsNvDpqajdziKWDYLNIwCgYIKoZIzj0EAwIw
OjEZMBcGA1UEAwwQQW5kcm9pZCBLZXkgVGVzdDEQMA4GA1UECgwHRXhhbXBsZTEL
MAkGA1UEBhMCVVMwHhcNMjYwMjI4MTQyNTU2WhcNMzYwMjI2MTQyNTU2WjA6MRkw
FwYDVQQDDBBBbmRyb2lkIEtleSBUZXN0MRAwDgYDVQQKDAdFeGFtcGxlMQswCQYD
VQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABN4QvKK1TEgmhb8JIlHi
hq5UhRj2olR3wnQV6mcBj0jjJD6/FGBalEI/zyWxes6wq/L2YOmA8VQ7EuQOARhF
MSGjcjBwMEQGCisGAQQB1nkCAREENjA0AgEBCgEAAgEBCgEABCBiIBe2GJoqCkmm
dsTTa9qN72AZ4mO/1AazVwWwG6gLxQQAoAChADAJBgNVHRMEAjAAMB0GA1UdDgQW
BBSgBWmyKsh30UwCynklf0GjYenxRzAKBggqhkjOPQQDAgNIADBFAiBtz7fv2Osy
sHvhlNoTSlfURLVrH7fMjaiE2+HWm+kPtQIhAPS9Yi0DiLmAOvBLU6Cg/bV5SBP+
ORFBibh8DOJ3/O5v
-----END CERTIFICATE-----`;
const tpmAttestationPrivateKeyPem = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK2EOmDhsqgUOAIvr0xmElfrgyEA2hpedUJgZRNk+GNfoAoGCCqGSM49
AwEHoUQDQgAESEeMhbKw5sLDaHkTZWpQ3PVTtWKYjWIVo/25CdvP0dQn7a4qmvxq
DlyeRWHluU0m3QhxxFwkLXw/czCJuY+Fnw==
-----END EC PRIVATE KEY-----`;
export const tpmAttestationCertificatePem = `-----BEGIN CERTIFICATE-----
MIIBqjCCAVCgAwIBAgIUOPxNa3wIfCINEsavBznJpks0Q1owCgYIKoZIzj0EAwIw
PjEdMBsGA1UEAwwUVFBNIEF0dGVzdGF0aW9uIFRlc3QxEDAOBgNVBAoMB0V4YW1w
bGUxCzAJBgNVBAYTAlVTMB4XDTI2MDIyODE0MjYwNVoXDTM2MDIyNjE0MjYwNVow
PjEdMBsGA1UEAwwUVFBNIEF0dGVzdGF0aW9uIFRlc3QxEDAOBgNVBAoMB0V4YW1w
bGUxCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESEeMhbKw
5sLDaHkTZWpQ3PVTtWKYjWIVo/25CdvP0dQn7a4qmvxqDlyeRWHluU0m3QhxxFwk
LXw/czCJuY+Fn6MsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQU8wPK1kuP2s1H+Mk9
aj76Mkb+dnkwCgYIKoZIzj0EAwIDSAAwRQIhAIwVERfCR2w5DK6bXowCbHDDz4++
pTeNGvZv7qenG8stAiANPmglXdy7RoSIViP9DMbb84yT5g6pL2lZnL3/Xb+zyw==
-----END CERTIFICATE-----`;
const safetyNetPrivateKeyPem = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBNTraXUIfoboM2RvKKXZ0CNrn9bNwzwwqkuuTwr5ZrLoAoGCCqGSM49
AwEHoUQDQgAEiGRMDEN3Nckh1cI8rq1vSShcWRXMS27wgRMOZBgBdwvABhbMR4XB
9uarLRD12aM2cV/k1VohiUTXhKmMtT2aag==
-----END EC PRIVATE KEY-----`;
const safetyNetCertificatePem = `-----BEGIN CERTIFICATE-----
MIIBnzCCAUSgAwIBAgIUYCBHMWIvy9Lh61VWbiRgkZiK88MwCgYIKoZIzj0EAwIw
ODEXMBUGA1UEAwwOU2FmZXR5TmV0IFRlc3QxEDAOBgNVBAoMB0V4YW1wbGUxCzAJ
BgNVBAYTAlVTMB4XDTI2MDIyODE0MjYwNVoXDTM2MDIyNjE0MjYwNVowODEXMBUG
A1UEAwwOU2FmZXR5TmV0IFRlc3QxEDAOBgNVBAoMB0V4YW1wbGUxCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiGRMDEN3Nckh1cI8rq1vSShc
WRXMS27wgRMOZBgBdwvABhbMR4XB9uarLRD12aM2cV/k1VohiUTXhKmMtT2aaqMs
MCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUYdv32ciNWxFdxHhLVlGzjK3+OCkwCgYI
KoZIzj0EAwIDSQAwRgIhAOPiYMHcsS8XmL7caPLXCQA8J1fd2cnCwUJjXd2wBjuE
AiEAlHlN7+WfhVQA+oxbAtxhdK7wnUbVyuBREFvrzXJKe40=
-----END CERTIFICATE-----`;
const extensionData = {__cborMap: [["credProps", {__cborMap: [["rk", true]]}]]} as const;

const encodeLength = (majorType: number, length: number): number[] => {
    if (length < 24) return [(majorType << 5) | length];
    if (length < 0x100) return [(majorType << 5) | 24, length];
    if (length < 0x10000) return [(majorType << 5) | 25, length >> 8, length & 0xff];

    return [
        (majorType << 5) | 26,
        (length >>> 24) & 0xff,
        (length >>> 16) & 0xff,
        (length >>> 8) & 0xff,
        length & 0xff
    ];
};

const encodeUnsigned = (value: number): number[] => encodeLength(0, value);
const encodeNegative = (value: number): number[] => encodeLength(1, -1 - value);
const encodeBytes = (value: Uint8Array): number[] => [...encodeLength(2, value.length), ...value];
const encodeArray = (value: unknown[]): number[] => [...encodeLength(4, value.length), ...value.flatMap(encodeItem)];
const encodeBoolean = (value: boolean): number[] => [value ? 0xf5 : 0xf4];
const encodeText = (value: string): number[] => {
    const encoded = Buffer.from(value, "utf8");
    return [...encodeLength(3, encoded.length), ...encoded];
};

const encodeItem = (value: unknown): number[] => {
    if (typeof value === "boolean") return encodeBoolean(value);
    if (typeof value === "number") return value >= 0 ? encodeUnsigned(value) : encodeNegative(value);
    if (typeof value === "string") return encodeText(value);
    if (value instanceof Uint8Array || Buffer.isBuffer(value)) return encodeBytes(value);
    if (Array.isArray(value)) return encodeArray(value);
    if (value && typeof value === "object" && "__cborMap" in value) {
        return [...encodeMap((value as {__cborMap: Array<[number | string, unknown]>}).__cborMap)];
    }

    throw new Error(`Unsupported CBOR test value: ${String(value)}`);
};

const encodeMap = (entries: Array<[number | string, unknown]>): Buffer => Buffer.from([
    ...encodeLength(5, entries.length),
    ...entries.flatMap(([key, value]) => [...encodeItem(key), ...encodeItem(value)])
]);

const createAuthenticatorDataPrefix = (flags: number, counter: number): Buffer => Buffer.concat([
    createHash("sha256").update(rpId).digest(),
    Buffer.from([flags]),
    Buffer.from([
        (counter >>> 24) & 0xff,
        (counter >>> 16) & 0xff,
        (counter >>> 8) & 0xff,
        counter & 0xff
    ])
]);

const {privateKey: jwtPrivateKey, publicKey: jwtPublicKey} = generateKeyPairSync("ec", {namedCurve: "P-256"});
export const {privateKey: credentialPrivateKey} = generateKeyPairSync("ec", {namedCurve: "P-256"});
const credentialPublicKey = createPublicKey(credentialPrivateKey);
const credentialJwk = credentialPublicKey.export({format: "jwk"}) as JsonWebKey;
const appleCredentialPrivateKey = createPrivateKey(appleCredentialPrivateKeyPem);
const appleCredentialPublicKey = createPublicKey(appleCredentialPrivateKey);
const appleCredentialJwk = appleCredentialPublicKey.export({format: "jwk"}) as JsonWebKey;
const androidKeyCredentialPrivateKey = createPrivateKey(androidKeyCredentialPrivateKeyPem);
const androidKeyCredentialPublicKey = createPublicKey(androidKeyCredentialPrivateKey);
const androidKeyCredentialJwk = androidKeyCredentialPublicKey.export({format: "jwk"}) as JsonWebKey;
const tpmAttestationPrivateKey = createPrivateKey(tpmAttestationPrivateKeyPem);
const tpmAttestationCertificate = new X509Certificate(tpmAttestationCertificatePem);
const safetyNetPrivateKey = createPrivateKey(safetyNetPrivateKeyPem);
const safetyNetCertificate = new X509Certificate(safetyNetCertificatePem);

export const credentialCoseKey = encodeMap([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, Buffer.from(credentialJwk.x!, "base64url")],
    [-3, Buffer.from(credentialJwk.y!, "base64url")]
]);
export const appleCredentialId = Buffer.from("apple-credential-123");
const appleCredentialCoseKey = encodeMap([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, Buffer.from(appleCredentialJwk.x!, "base64url")],
    [-3, Buffer.from(appleCredentialJwk.y!, "base64url")]
]);
export const androidKeyCredentialId = Buffer.from("android-key-credential-123");
export const androidKeyCredentialCoseKey = encodeMap([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, Buffer.from(androidKeyCredentialJwk.x!, "base64url")],
    [-3, Buffer.from(androidKeyCredentialJwk.y!, "base64url")]
]);

export const registrationAuthenticatorData = Buffer.concat([
    createAuthenticatorDataPrefix(0x41, 7),
    Buffer.alloc(16),
    Buffer.from([0x00, credentialId.length]),
    credentialId,
    credentialCoseKey
]);
const appleRegistrationAuthenticatorData = Buffer.concat([
    createAuthenticatorDataPrefix(0x41, 1),
    Buffer.alloc(16),
    Buffer.from([0x00, appleCredentialId.length]),
    appleCredentialId,
    appleCredentialCoseKey
]);
const androidKeyRegistrationAuthenticatorData = Buffer.concat([
    createAuthenticatorDataPrefix(0x41, 3),
    Buffer.alloc(16),
    Buffer.from([0x00, androidKeyCredentialId.length]),
    androidKeyCredentialId,
    androidKeyCredentialCoseKey
]);

const registrationAuthenticatorDataWithExtensions = Buffer.concat([
    createAuthenticatorDataPrefix(0xc1, 7),
    Buffer.alloc(16),
    Buffer.from([0x00, credentialId.length]),
    credentialId,
    credentialCoseKey,
    encodeMap(extensionData.__cborMap)
]);

export const attestationObject = encodeMap([
    ["fmt", "none"],
    ["authData", registrationAuthenticatorData],
    ["attStmt", encodeMap([])]
]);

export const unsupportedAttestationObject = encodeMap([
    ["fmt", "packed"],
    ["authData", registrationAuthenticatorData],
    ["attStmt", encodeMap([])]
]);

const packedClientDataRaw = Buffer.from(JSON.stringify({
    type: "webauthn.create",
    challenge,
    origin
}));
export const packedClientData = toBase64Url(packedClientDataRaw);
const packedAttestationSigner = createSign("SHA256");
packedAttestationSigner.update(Buffer.concat([
    registrationAuthenticatorDataWithExtensions,
    createHash("sha256").update(packedClientDataRaw).digest()
]));
packedAttestationSigner.end();
export const packedSelfAttestationObject = encodeMap([
    ["fmt", "packed"],
    ["authData", registrationAuthenticatorDataWithExtensions],
    ["attStmt", encodeMap([
        ["alg", -7],
        ["sig", packedAttestationSigner.sign(credentialPrivateKey)]
    ])]
]);
const appleClientDataRaw = Buffer.from(JSON.stringify({
    type: "webauthn.create",
    challenge,
    origin
}));
export const appleClientData = toBase64Url(appleClientDataRaw);
export const appleAttestationObject = encodeMap([
    ["fmt", "apple"],
    ["authData", appleRegistrationAuthenticatorData],
    ["attStmt", encodeMap([
        ["x5c", [new X509Certificate(appleAttestationCertificatePem).raw]]
    ])]
]);
const androidKeyAttestationSigner = createSign("SHA256");
androidKeyAttestationSigner.update(Buffer.concat([
    androidKeyRegistrationAuthenticatorData,
    createHash("sha256").update(packedClientDataRaw).digest()
]));
androidKeyAttestationSigner.end();
export const androidKeyAttestationObject = encodeMap([
    ["fmt", "android-key"],
    ["authData", androidKeyRegistrationAuthenticatorData],
    ["attStmt", encodeMap([
        ["alg", -7],
        ["sig", androidKeyAttestationSigner.sign(androidKeyCredentialPrivateKey)],
        ["x5c", [new X509Certificate(androidKeyAttestationCertificatePem).raw]]
    ])]
]);
const fidoAttestationPrivateKey = createPrivateKey(fidoAttestationPrivateKeyPem);
const fidoAttestationCertificate = new X509Certificate(fidoAttestationCertificatePem);
const fidoU2fVerificationData = Buffer.concat([
    Buffer.from([0x00]),
    createHash("sha256").update(rpId).digest(),
    createHash("sha256").update(packedClientDataRaw).digest(),
    credentialId,
    Buffer.from([0x04]),
    Buffer.from(credentialJwk.x!, "base64url"),
    Buffer.from(credentialJwk.y!, "base64url")
]);
const fidoU2fSigner = createSign("SHA256");
fidoU2fSigner.update(fidoU2fVerificationData);
fidoU2fSigner.end();
export const fidoU2fAttestationObject = encodeMap([
    ["fmt", "fido-u2f"],
    ["authData", registrationAuthenticatorData],
    ["attStmt", encodeMap([
        ["sig", fidoU2fSigner.sign(fidoAttestationPrivateKey)],
        ["x5c", [fidoAttestationCertificate.raw]]
    ])]
]);

const encodeU16 = (value: number) => Buffer.from([(value >>> 8) & 0xff, value & 0xff]);
const encodeU32 = (value: number) => Buffer.from([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
]);
const encodeSized = (value: Buffer) => Buffer.concat([encodeU16(value.length), value]);
const createTpmPubArea = (jwk: JsonWebKey) => Buffer.concat([
    encodeU16(0x0023),
    encodeU16(0x000b),
    encodeU32(0x00000000),
    encodeU16(0),
    encodeU16(0x0010),
    encodeU16(0x0010),
    encodeU16(0x0003),
    encodeU16(0x0000),
    encodeSized(Buffer.from(jwk.x!, "base64url")),
    encodeSized(Buffer.from(jwk.y!, "base64url"))
]);
const createTpmCertInfo = (pubArea: Buffer, attestedDataHash: Buffer) => Buffer.concat([
    encodeU32(0xff544347),
    encodeU16(0x8017),
    encodeU16(0),
    encodeSized(attestedDataHash),
    Buffer.alloc(17),
    Buffer.alloc(8),
    encodeSized(Buffer.concat([
        encodeU16(0x000b),
        createHash("sha256").update(pubArea).digest()
    ])),
    encodeU16(0)
]);
const tpmPubArea = createTpmPubArea(credentialJwk);
const tpmCertInfo = createTpmCertInfo(
    tpmPubArea,
    createHash("sha256").update(Buffer.concat([
        registrationAuthenticatorData,
        createHash("sha256").update(packedClientDataRaw).digest()
    ])).digest()
);
const tpmAttestationSigner = createSign("SHA256");
tpmAttestationSigner.update(tpmCertInfo);
tpmAttestationSigner.end();
export const tpmAttestationObject = encodeMap([
    ["fmt", "tpm"],
    ["authData", registrationAuthenticatorData],
    ["attStmt", encodeMap([
        ["alg", -7],
        ["sig", tpmAttestationSigner.sign(tpmAttestationPrivateKey)],
        ["x5c", [tpmAttestationCertificate.raw]],
        ["ver", "2.0"],
        ["certInfo", tpmCertInfo],
        ["pubArea", tpmPubArea]
    ])]
]);

const createCompactJws = (
    header: Record<string, unknown>,
    payload: Record<string, unknown>,
    signingKey: ReturnType<typeof createPrivateKey>
) => {
    const encodedHeader = toBase64Url(JSON.stringify(header));
    const encodedPayload = toBase64Url(JSON.stringify(payload));
    const signer = createSign("SHA256");
    signer.update(`${encodedHeader}.${encodedPayload}`);
    signer.end();
    return `${encodedHeader}.${encodedPayload}.${toBase64Url(signer.sign(signingKey))}`;
};
export const safetyNetAttestationObject = encodeMap([
    ["fmt", "android-safetynet"],
    ["authData", registrationAuthenticatorData],
    ["attStmt", encodeMap([
        ["ver", "2025.02"],
        ["response", Buffer.from(createCompactJws(
            {
                alg: "ES256",
                x5c: [safetyNetCertificate.raw.toString("base64")]
            },
            {
                nonce: createHash("sha256").update(Buffer.concat([
                    registrationAuthenticatorData,
                    createHash("sha256").update(packedClientDataRaw).digest()
                ])).digest("base64"),
                timestampMs: Date.now(),
                ctsProfileMatch: true
            },
            safetyNetPrivateKey
        ))]
    ])]
]);

export const registrationClientData = toBase64Url(JSON.stringify({
    type: "webauthn.create",
    challenge,
    origin
}));

const authenticationClientDataRaw = Buffer.from(JSON.stringify({
    type: "webauthn.get",
    challenge,
    origin
}));
export const authenticationClientData = toBase64Url(authenticationClientDataRaw);

export const authenticationAuthenticatorData = createAuthenticatorDataPrefix(0x05, 8);
export const appIdAuthenticatorData = Buffer.concat([
    createHash("sha256").update(appId).digest(),
    Buffer.from([0x05]),
    Buffer.from([0x00, 0x00, 0x00, 0x09])
]);
const authenticationMessage = Buffer.concat([
    authenticationAuthenticatorData,
    createHash("sha256").update(authenticationClientDataRaw).digest()
]);
const appIdAuthenticationMessage = Buffer.concat([
    appIdAuthenticatorData,
    createHash("sha256").update(authenticationClientDataRaw).digest()
]);

const signer = createSign("SHA256");
signer.update(authenticationMessage);
signer.end();
export const authenticationSignature = toBase64Url(signer.sign(credentialPrivateKey));
const appIdSigner = createSign("SHA256");
appIdSigner.update(appIdAuthenticationMessage);
appIdSigner.end();
export const appIdAuthenticationSignature = toBase64Url(appIdSigner.sign(credentialPrivateKey));

export const webauth = createWebAuth({
    keyPair: {
        kid: "kid-1",
        private_key: jwtPrivateKey,
        public_key: jwtPublicKey
    },
    issuer: "https://issuer.example.com",
    rpId,
    rpName: "Example RP",
    origin
});
export const webauthWithAllowedOrigins = createWebAuth({
    keyPair: {
        kid: "kid-1",
        private_key: jwtPrivateKey,
        public_key: jwtPublicKey
    },
    issuer: "https://issuer.example.com",
    rpId,
    rpName: "Example RP",
    origin,
    allowedOrigins: [origin, "https://login.example.com"]
});

export const createAlternativeAuthenticationFixture = () => {
    const alternativeOrigin = "https://login.example.com";
    const clientDataRaw = Buffer.from(JSON.stringify({
        type: "webauthn.get",
        challenge,
        origin: alternativeOrigin
    }));
    const message = Buffer.concat([
        authenticationAuthenticatorData,
        createHash("sha256").update(clientDataRaw).digest()
    ]);
    const signer = createSign("SHA256");
    signer.update(message);
    signer.end();

    return {
        origin: alternativeOrigin,
        clientDataJson: toBase64Url(clientDataRaw),
        signature: toBase64Url(signer.sign(credentialPrivateKey))
    };
};
