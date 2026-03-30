# @sourceregistry/node-webauthn

TypeScript helpers for WebAuthn registration and authentication with dedicated `server` and `client` entrypoints.

## Install

```bash
npm install @sourceregistry/node-webauthn
```

```bash
npx jsr add @sourceregistry/node-webauthn
```

## Entry points

```ts
import createWebAuth from "@sourceregistry/node-webauthn/server";
import createWebAuthClient from "@sourceregistry/node-webauthn/client";
```

`@sourceregistry/node-webauthn` re-exports the server entry:

```ts
import createWebAuth from "@sourceregistry/node-webauthn";
```

## Quick start

```ts
import createWebAuth from "@sourceregistry/node-webauthn/server";
import createWebAuthClient from "@sourceregistry/node-webauthn/client";
import {generateKeyPairSync} from "node:crypto";

const {privateKey, publicKey} = generateKeyPairSync("ec", {namedCurve: "P-256"});

const server = createWebAuth({
    keyPair: {
        kid: "main",
        private_key: privateKey,
        public_key: publicKey
    },
    issuer: "https://auth.example.com",
    rpId: "example.com",
    rpName: "Example"
});

const client = createWebAuthClient();

const registrationOptions = server.createRegistrationOptions({
    user: {
        id: server.toBase64Url("user-123"),
        name: "user@example.com",
        displayName: "Example User"
    }
});

const credential = await client.startRegistration(registrationOptions);

const parsed = server.verifyRegistrationResponse({
    expected_challenge: registrationOptions.challenge,
    credential_id: credential.id,
    client_data_json: credential.client_data_json,
    attestation_object: credential.attestation_object,
    transports: credential.transports,
    client_extension_results: credential.client_extension_results,
    origin: "https://example.com",
    rp_id: "example.com",
    expected_algorithms: registrationOptions.pubKeyCredParams.map(item => item.alg)
});
```

## Package layout

- `@sourceregistry/node-webauthn`
  Re-exports the server entry.
- `@sourceregistry/node-webauthn/server`
  Node.js option building, ceremony token, and verification helpers.
- `@sourceregistry/node-webauthn/client`
  Browser helpers for JSON conversion, WebAuthn calls, and credential serialization.

## Examples

- Registration server flow: [examples/registration-flow.ts](./examples/registration-flow.ts)
- Authentication server flow: [examples/authentication-flow.ts](./examples/authentication-flow.ts)
- Browser client flow: [examples/browser-client.ts](./examples/browser-client.ts)

## Compliance snapshot

| Area | Status | Notes |
| --- | --- | --- |
| Server-generated registration/authentication options | Strong | `createRegistrationOptions(...)` and `createAuthenticationOptions(...)` are the intended entrypoints. |
| `clientDataJSON` validation | Strong | Checks ceremony type, challenge, origin allowlist, rejects unsupported cross-origin ceremonies, and normalizes malformed JSON into stable library errors. |
| Authenticator data parsing | Strong | Parses RP ID hash, flags, counters, attested credential data, and extension data. |
| Authentication assertion verification | Strong | Verifies signature, RP/appid hash, optional credential binding, UP/UV policy, counter progression, and allowed client extensions. |
| Registration verification core | Strong | Verifies RP ID hash, credential binding, requested algorithm policy, and attestation dispatch. |
| Attestation format coverage | Broad | Supports `none`, `packed`, `fido-u2f`, `apple`, `android-key`, `android-safetynet`, and `tpm`. |
| Attestation trust policy | Good | Supports `none`, `permissive`, and `strict` trust modes plus trust anchors, metadata hooks, CA/key-usage checks for issuing certs, and exact leaf pinning. |
| Extension support | Partial | Practical subset today: `credProps`, `appid`, `appidExclude`, and `largeBlob`. |
| Metadata / revocation | Partial | Metadata hooks exist, but there is no built-in FIDO MDS integration or revocation pipeline yet. |
| Cross-origin / advanced browser edge cases | Limited | Cross-origin ceremonies are intentionally rejected for now. |
| Full spec-tight attestation semantics | Partial | Some format-specific policy checks are still lighter than full ecosystem-grade verification. |

Practical summary:

- This library is strong for common relying-party registration and authentication flows.
- It is not yet fully spec-tight in every attestation and trust-policy edge case.
- The largest remaining gaps are deeper attestation semantics, revocation, and metadata-backed trust.

## Server API

### `createWebAuth(config)`

Creates a reusable server helper with:

- `generateChallenge(bytes?)`
- `createRegistrationOptions(input)`
- `createAuthenticationOptions(input)`
- `signRegistration(payload)`
- `verifyRegistration(token)`
- `signAuthentication(payload)`
- `verifyAuthentication(token)`
- `parseRegistration(input)`
- `verifyRegistrationResponse(input)`
- `verifyAuthenticationResponse(input)`

### `createRegistrationOptions(input)`

Returns JSON-safe registration options for the client helper.

### `createAuthenticationOptions(input)`

Returns JSON-safe authentication options for the client helper.

### `verifyRegistrationResponse(input)`

Validates:

- ceremony type
- challenge
- origin
- RP ID hash
- credential ID match
- requested algorithm policy
- attestation format and trust policy
- registration extension allowlist

Supported attestation formats:

- `none`
- `packed`
- `fido-u2f`
- `apple`
- `android-key`
- `android-safetynet`
- `tpm`

Attestation support status:

| Format | Status | Notes |
| --- | --- | --- |
| `none` | Strong | Suitable default for easy deployment. |
| `packed` | Strong | Supports self attestation and certificate-backed validation with optional trust anchors. |
| `fido-u2f` | Strong | Verified with optional trust anchors. |
| `apple` | Good | Verifies Apple nonce extension and credential public-key binding. |
| `android-key` | Partial | Core verification is present, but Android authorization-list policy checks are not exhaustive yet. |
| `android-safetynet` | Partial | Verifies JWS, nonce, timestamp, and CTS profile, but ecosystem trust/revocation remains lightweight. |
| `tpm` | Partial | Core `certInfo` / `pubArea` validation is present, but TPM certificate/profile checks are not exhaustive yet. |

Registration results include:

- `credential_id`
- `public_key`
- `aaguid`
- `counter`
- `attestation_format`
- `attestation_type`
- `attestation_trusted`
- `attestation_policy_accepted`
- `metadata_status`

### `verifyAuthenticationResponse(input)`

Validates:

- ceremony type
- challenge
- origin
- RP ID hash
- optional credential ID binding when `credential_id` and `expected_credential_id` are supplied
- signature
- counter progression
- user presence / verification policy
- authentication extension allowlist

Typical usage:

```ts
const result = server.verifyAuthenticationResponse({
    expected_challenge: publicKey.challenge,
    credential_id: credential.id,
    expected_credential_id: storedCredential.credential_id,
    client_data_json: credential.client_data_json,
    authenticator_data: credential.authenticator_data,
    signature: credential.signature,
    origin: "https://example.com",
    rp_id: "example.com",
    public_key: storedCredential.public_key,
    previous_counter: storedCredential.counter
});
```

## Client API

### `createWebAuthClient()`

Creates browser helpers with:

- `toCreationOptions(json)`
- `toRequestOptions(json)`
- `startRegistration(json)`
- `startAuthentication(json)`
- `serializeRegistrationCredential(credential)`
- `serializeAuthenticationCredential(credential)`
- `toBase64Url(value)`
- `fromBase64Url(value)`

## End-to-end flow

Server begin step:

```ts
const publicKey = server.createRegistrationOptions({
    user: {
        id: server.toBase64Url("user-123"),
        name: "user@example.com",
        displayName: "Example User"
    }
});
```

Client step:

```ts
const credential = await client.startRegistration(publicKey);
```

Server finish step:

```ts
const parsed = server.verifyRegistrationResponse({
    expected_challenge: publicKey.challenge,
    credential_id: credential.id,
    client_data_json: credential.client_data_json,
    attestation_object: credential.attestation_object,
    transports: credential.transports,
    client_extension_results: credential.client_extension_results,
    origin: "https://example.com",
    rp_id: "example.com",
    expected_algorithms: publicKey.pubKeyCredParams.map(item => item.alg)
});
```

## Attestation policy

Simple format allowlist:

```ts
const server = createWebAuth({
    keyPair,
    rpId: "example.com",
    rpName: "Example",
    attestation: {
        allowed_formats: ["none", "packed"]
    }
});
```

Strict trust:

```ts
const server = createWebAuth({
    keyPair,
    rpId: "example.com",
    rpName: "Example",
    attestation: {
        allowed_formats: ["packed", "tpm"],
        trust_mode: "strict",
        trust_anchors: [rootCertificatePem]
    }
});
```

Metadata-backed policy:

```ts
const server = createWebAuth({
    keyPair,
    rpId: "example.com",
    rpName: "Example",
    attestation: {
        allowed_formats: ["android-key", "tpm"],
        metadata_provider: {
            getEntry({format}) {
                if (format === "android-key") {
                    return {status: "trusted", trusted: true};
                }

                return null;
            }
        }
    }
});
```

## Extension policy

```ts
const server = createWebAuth({
    keyPair,
    rpId: "example.com",
    rpName: "Example",
    extensions: {
        allowed_registration_extensions: ["credProps"],
        allowed_authentication_extensions: ["appid", "largeBlob"]
    }
});
```

## Documentation

- Compliance notes: [docs/spec-notes.md](./docs/spec-notes.md)
- Trust model: [docs/trust-model.md](./docs/trust-model.md)

## Toward fuller compliance

The remaining work is intentionally small and incremental so the API can stay easy to use.

- Tighten `android-key` verification with stronger authorization-list checks from the Android key attestation extension.
- Tighten `tpm` verification with more complete certificate/profile validation and TPM-specific policy checks.
- Strengthen `android-safetynet` trust handling with clearer certificate-policy validation and optional revocation hooks.
- Add optional FIDO Metadata Service integration behind the existing `metadata_provider` style trust model.
- Add optional revocation checking for attestation certificate chains.
- Expand extension semantics only where they matter for relying-party policy, instead of trying to support every extension by default.
- Add more conformance-style negative fixtures for attestation and trust-policy edge cases.

## Notes

- The default API is intentionally small.
- Trust evaluation is optional by default and can be tightened with `trust_mode`, `trust_anchors`, and `metadata_provider`.
