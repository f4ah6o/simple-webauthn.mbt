# simple-webauthn for MoonBit

A WebAuthn (FIDO2/Passkey) server library for MoonBit, ported from [@simplewebauthn/server](https://github.com/MasterKale/SimpleWebAuthn).

## Features

- **Registration**: Generate options and verify registration responses
- **Authentication**: Generate options and verify authentication responses  
- **ES256 Signature Verification**: Real cryptographic verification via WebCrypto FFI
- **Passkey Support**: Handles synced passkeys with flexible signCount policies
- **Type-safe**: Full MoonBit type safety with detailed error types

## Installation

Add to your `moon.mod.json`:

```json
{
  "deps": {
    "f4ah6o/simple-webauthn": "0.1.0"
  }
}
```

## Quick Start

### Registration Flow

```moonbit
// 1. Generate registration options (server)
let input = @server.GenerateRegistrationOptionsInput::new(
  "ACME Corp",      // RP name
  "example.com",    // RP ID
  "johndoe",        // username
  user_display_name=Some("John Doe"),
)
let options = @server.generate_registration_options(input)
// Send options.to_json() to client

// 2. Verify registration response (server)
let verify_options = @server.VerifyRegistrationOptions::new(
  challenge_bytes,        // The challenge you sent
  "https://example.com",  // Expected origin
  "example.com",          // Expected RP ID
)
let result = @server.verify_registration_response(
  client_data_json,       // From client response
  attestation_object,     // From client response
  verify_options,
) catch {
  e => // Handle error
}
// Store: result.credential_id, result.credential_public_key, result.sign_count
```

### Authentication Flow

```moonbit
// 1. Generate authentication options (server)
let input = @server.GenerateAuthenticationOptionsInput::new(
  rp_id=Some("example.com"),
)
let options = @server.generate_authentication_options(input)
// Send options.to_json() to client

// 2. Verify authentication response (server) - async version with real crypto
let credential = @server.AuthenticatorCredential::new(
  stored_credential_id,
  stored_public_key,
  stored_sign_count,
)
let verify_options = @server.VerifyAuthenticationOptions::new(
  challenge_bytes,
  "https://example.com",
  "example.com",
  credential,
)
let result = @server.verify_authentication_response_async(
  credential_id,
  client_data_json,
  authenticator_data,
  signature,
  verify_options,
)
match result {
  Ok(verified) => // Update stored_sign_count = verified.new_sign_count
  Err(e) => // Handle error
}
```

## SignCount Policy

Control how signature counters are validated to detect cloned authenticators:

```moonbit
let options = @server.VerifyAuthenticationOptions::new(...)
  .with_sign_count_policy_strict()      // Counter must always increase
  // OR
  .with_sign_count_policy_permissive()  // Never fail (log warnings externally)
  // Default: AllowZero - both 0 is OK, otherwise must increase
```

| Policy | Behavior | Use Case |
|--------|----------|----------|
| `Strict` | Counter must always increase | High-security with hardware keys |
| `AllowZero` (default) | Allow both counters = 0 | Most applications, supports synced passkeys |
| `Permissive` | Never fail on counter | Prefer availability over clone detection |

## Project Structure

```
src/
├── types/      # WebAuthn type definitions (COSE, credentials, etc.)
├── helpers/    # Parsing utilities (base64url, clientData, authenticatorData)
├── crypto/     # Cryptographic operations (SHA-256, ES256 via WebCrypto FFI)
└── server/     # Main API (generate/verify for registration & authentication)
```

## API Reference

### Registration

- `generate_registration_options(input)` - Create options for navigator.credentials.create()
- `verify_registration_response(clientData, attestation, options)` - Verify and extract credential

### Authentication

- `generate_authentication_options(input)` - Create options for navigator.credentials.get()
- `verify_authentication_response_async(...)` - Verify with real ES256 signature verification
- `verify_authentication_response(...)` - Sync version (signature verification stub)

### Error Types

- `RegistrationVerifyError` - Detailed registration failure reasons
- `AuthenticationVerifyError` - Detailed authentication failure reasons

## Development

```bash
just           # check + test
just fmt       # format code  
just check     # type check
just test      # run tests (61 tests)
```

## Current Limitations

- Only ES256 (P-256) signature verification implemented
- Packed attestation verification not yet implemented (fmt="none" works)
- Browser-side API (startRegistration/startAuthentication) not included

## License

Apache-2.0
