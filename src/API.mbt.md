# API Documentation

This file contains executable doc tests using `mbt test` blocks.

WebAuthn (FIDO2) implementation for MoonBit, providing browser-side and server-side
passkey authentication functionality.

## Types

The types package exports all WebAuthn-related types including:
- `Base64URLString` - Base64URL encoded string wrapper
- `PublicKeyCredentialCreationOptionsJSON` - Registration options
- `PublicKeyCredentialRequestOptionsJSON` - Authentication options
- `RegistrationResponseJSON` - Browser registration response
- `AuthenticationResponseJSON` - Browser authentication response
- Various enums for transports, attestation, user verification, etc.
