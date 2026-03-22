# Spec Notes

This document records the current compliance-oriented design of `@sourceregistry/node-webauthn`.

## Scope

The library is split into:

- `server`
  The relying-party authority. It generates options, validates client data, parses authenticator data, verifies signatures, and enforces policy.
- `client`
  A thin browser adapter. It converts JSON-safe values into browser-native WebAuthn options, calls `navigator.credentials`, and serializes the resulting credential payloads.

This keeps the security-sensitive behavior on the server while preserving a simple client API.

## Current spec-aligned areas

- Random challenge generation and verification
- `clientDataJSON` validation for:
  - ceremony `type`
  - `challenge`
  - `origin`
  - stable malformed-JSON rejection
- RP ID hash verification in authenticator data
- Authenticator flag parsing for:
  - UP
  - UV
  - BE
  - BS
  - AT
  - ED
- Signature verification for authentication assertions
- Optional authentication credential ID binding
- Signature counter replay detection
- JSON-safe option builders for registration and authentication
- Registration attestation verification for:
  - `none`
  - `packed` self attestation
  - `packed` certificate-based attestation with optional trust anchors
- `fido-u2f` attestation verification with optional trust anchors
- `apple` attestation verification using the Apple nonce extension and credential public-key binding
- `android-key` attestation verification using the Android key attestation extension and credential public-key binding
- `android-safetynet` attestation verification with JWS signature, nonce, timestamp, and CTS profile checks
- `tpm` attestation verification with `certInfo`, `pubArea`, and credential public-key binding checks
- Authenticator extension data parsing
- Client extension result transport through the client/server helpers
- Attestation trust modes:
  - `none`
  - `permissive`
  - `strict`
- Optional metadata provider hooks for relying-party trust policy
- CA and `keyCertSign` checks when a certificate issues another certificate in the attestation path
- Lightweight extension policy enforcement for:
  - `credProps`
  - `appid`
  - `appidExclude`
  - `largeBlob`

## Current constraints

- Full FIDO Metadata Service integration is not implemented yet
- Certificate revocation checking is not implemented yet
- Extension handling currently validates only a practical subset of extension result shapes
- Cross-origin ceremony support is intentionally rejected for now

## Useful spec references

- WebAuthn Level 3
  https://www.w3.org/TR/webauthn-3/
- Registration ceremony verification
  https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
- Authentication assertion verification
  https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
- Authenticator data
  https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
- Attestation object
  https://www.w3.org/TR/webauthn-3/#sctn-attestation
- Packed attestation statement format
  https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
- FIDO U2F attestation statement format
  https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation
- Apple anonymous attestation
  https://www.w3.org/TR/webauthn-3/#sctn-apple-anonymous-attestation
- Android key attestation statement format
  https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation
- Android SafetyNet attestation statement format
  https://www.w3.org/TR/webauthn-3/#sctn-android-safetynet-attestation
- TPM attestation statement format
  https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation
- Client extension processing
  https://www.w3.org/TR/webauthn-3/#client-extension-processing

## Design intent

The default API should remain easy:

- `createRegistrationOptions(...)`
- `verifyRegistrationResponse(...)`
- `createAuthenticationOptions(...)`
- `verifyAuthenticationResponse(...)`

Advanced verification, including richer attestation formats and trust policy, should be added incrementally without forcing that complexity onto every consumer.
