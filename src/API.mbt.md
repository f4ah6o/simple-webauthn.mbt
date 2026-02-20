# API Documentation

This file contains executable doc tests using `mbt test` blocks.

WebAuthn (FIDO2) implementation for MoonBit, providing browser-side and server-side
passkey authentication functionality.

## Browser API

The browser package exposes ceremony helpers compatible with SimpleWebAuthn concepts:
- `browser_supports_webauthn()`
- `platform_authenticator_is_available()`
- `browser_supports_webauthn_autofill()`
- `start_registration(input)`
- `start_authentication(input)`
- `cancel_ceremony()`

## Types

The types package exports all WebAuthn-related types including:
- `Base64URLString` - Base64URL encoded string wrapper
- `PublicKeyCredentialCreationOptionsJSON` - Registration options
- `PublicKeyCredentialRequestOptionsJSON` - Authentication options
- `RegistrationResponseJSON` - Browser registration response
- `AuthenticationResponseJSON` - Browser authentication response
- Various enums for transports, attestation, user verification, etc.
