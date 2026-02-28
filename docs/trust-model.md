# Trust Model

This library keeps the common WebAuthn flow simple and makes attestation trust stricter only when you opt in.

## Configuration

The server attestation policy accepts:

- `allowed_formats`
- `trust_mode`
- `trust_anchors`
- `metadata_provider`

## Trust modes

- `none`
  Accept cryptographically valid attestation without chain trust enforcement.
- `permissive`
  Verify cryptographic validity, attempt trust-path validation if anchors are configured, and surface the trust result.
- `strict`
  Require certificate-backed attestation to validate against configured trust anchors.

## Metadata provider

`metadata_provider.getEntry(...)` receives:

- `aaguid`
- `format`
- `certificates`

It may return:

- `trusted`
- `status`
- `revoked`
- `allow`
- `reason`

This lets applications layer allow/deny logic or external metadata decisions on top of the built-in attestation format verification.

## Result fields

Registration verification now surfaces:

- `attestation_trusted`
- `attestation_policy_accepted`
- `metadata_status`
