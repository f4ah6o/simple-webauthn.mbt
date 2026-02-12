///|
/// Authentication verification for WebAuthn.
///
/// This implements the server-side verification of authentication responses
/// as specified in the WebAuthn specification.
///
/// ## Verification Steps
/// 
/// 1. Parse and verify clientDataJSON
///    - type must be "webauthn.get"
///    - challenge must match expected
///    - origin must match expected
/// 
/// 2. Parse authenticatorData
/// 
/// 3. Verify authenticatorData
///    - rpIdHash must match expected rpId
///    - UP (user present) flag must be set
///    - UV (user verified) flag must be set if required
/// 
/// 4. Verify credential ID is in allowlist (if provided)
/// 
/// 5. Verify signature
///    - signedData = authenticatorDataBytes + SHA256(clientDataJSON)
///    - Verify using stored public key
/// 
/// 6. Verify sign count (replay protection)
///    - newCounter > storedCounter (or handle 0 specially)
///
/// ## Design Note
/// 
/// All inputs are raw Bytes (base64url decoded by caller).
/// This avoids re-encoding issues and matches the WebAuthn data model.

///|
/// Stored credential information from registration.
/// 
/// This represents the data that should be stored in your database
/// after a successful registration.
pub struct AuthenticatorCredential {
  /// The credential ID (unique per credential)
  credential_id : Bytes
  /// The public key in COSE format (for signature verification)
  public_key : Bytes
  /// The current signature counter (0 initially, incremented on each use)
  sign_count : UInt
} derive(Show, Eq)

///|
/// Create a new authenticator credential.
pub fn AuthenticatorCredential::new(
  credential_id : Bytes,
  public_key : Bytes,
  sign_count : UInt,
) -> AuthenticatorCredential {
  { credential_id, public_key, sign_count }
}

///|
/// Options for authentication verification.
pub struct VerifyAuthenticationOptions {
  /// Expected challenge (must match clientDataJSON.challenge)
  expected_challenge : Bytes
  /// Expected origin(s) - at least one must match
  expected_origins : Array[String]
  /// Expected rpId (hashed and compared with authenticatorData.rpIdHash)
  expected_rp_id : String
  /// Whether to require user verification (UV flag)
  require_user_verification : Bool
  /// The stored credential from registration
  credential : AuthenticatorCredential
  /// Policy for handling signature counter validation (default: AllowZero)
  sign_count_policy : SignCountPolicy
} derive(Show, Eq)

///|
/// Create default verification options.
pub fn VerifyAuthenticationOptions::new(
  challenge : Bytes,
  origin : String,
  rp_id : String,
  credential : AuthenticatorCredential,
) -> VerifyAuthenticationOptions {
  {
    expected_challenge: challenge,
    expected_origins: [origin],
    expected_rp_id: rp_id,
    require_user_verification: false,
    credential,
    sign_count_policy: SignCountPolicy::AllowZero,
  }
}

///|
/// Create verification options with multiple allowed origins.
pub fn VerifyAuthenticationOptions::with_origins(
  challenge : Bytes,
  origins : Array[String],
  rp_id : String,
  credential : AuthenticatorCredential,
) -> VerifyAuthenticationOptions {
  {
    expected_challenge: challenge,
    expected_origins: origins,
    expected_rp_id: rp_id,
    require_user_verification: false,
    credential,
    sign_count_policy: SignCountPolicy::AllowZero,
  }
}

///|
/// Set whether user verification is required.
pub fn VerifyAuthenticationOptions::require_user_verification(
  self : VerifyAuthenticationOptions,
  required : Bool,
) -> VerifyAuthenticationOptions {
  { ..self, require_user_verification: required }
}

///|
/// Set the signature counter validation policy.
/// 
/// ## Example
/// ```
/// let options = VerifyAuthenticationOptions::new(...)
///   .with_sign_count_policy(SignCountPolicy::Strict)
/// ```
pub fn VerifyAuthenticationOptions::with_sign_count_policy(
  self : VerifyAuthenticationOptions,
  policy : SignCountPolicy,
) -> VerifyAuthenticationOptions {
  { ..self, sign_count_policy: policy }
}

///|
/// Set strict sign count policy (counter must always increase).
pub fn VerifyAuthenticationOptions::with_sign_count_policy_strict(
  self : VerifyAuthenticationOptions,
) -> VerifyAuthenticationOptions {
  { ..self, sign_count_policy: SignCountPolicy::Strict }
}

///|
/// Set permissive sign count policy (never fail on counter issues).
pub fn VerifyAuthenticationOptions::with_sign_count_policy_permissive(
  self : VerifyAuthenticationOptions,
) -> VerifyAuthenticationOptions {
  { ..self, sign_count_policy: SignCountPolicy::Permissive }
}

///|
/// Result of successful authentication verification.
pub struct VerifiedAuthentication {
  /// The credential ID that was used
  credential_id : Bytes
  /// The new signature counter (should be stored in database)
  new_sign_count : UInt
  /// Whether user verification was performed
  user_verified : Bool
  /// Whether the credential is backup eligible (synced passkey)
  backup_eligible : Bool
  /// Whether the credential has been backed up
  backup_state : Bool
} derive(Show, Eq)

///|
/// Verify a WebAuthn authentication response.
///
/// ## Parameters
/// - `credential_id`: Raw bytes of the credential ID (rawId, base64url decoded)
/// - `client_data_json`: Raw bytes of clientDataJSON (base64url decoded)
/// - `authenticator_data`: Raw bytes of authenticatorData (base64url decoded)
/// - `signature`: Raw bytes of the signature (base64url decoded)
/// - `options`: Verification options (challenge, origin, rpId, credential)
///
/// ## Returns
/// - `VerifiedAuthentication` on success
/// - `AuthenticationVerifyError` on failure
///
/// ## Example
/// ```
/// let credential = AuthenticatorCredential::new(
///   stored_credential_id,
///   stored_public_key,
///   stored_sign_count
/// )
/// let options = VerifyAuthenticationOptions::new(
///   challenge_bytes,
///   "https://example.com",
///   "example.com",
///   credential
/// )
/// let result = verify_authentication_response(
///   credential_id_bytes,
///   client_data_json_bytes,
///   authenticator_data_bytes,
///   signature_bytes,
///   options
/// )
/// ```
pub fn verify_authentication_response(
  credential_id : Bytes,
  client_data_json : Bytes,
  authenticator_data_bytes : Bytes,
  signature : Bytes,
  options : VerifyAuthenticationOptions,
) -> VerifiedAuthentication raise AuthenticationVerifyError {
  // Step 1: Verify credential ID matches stored credential
  verify_credential_id(credential_id, options)

  // Step 2: Parse and verify clientDataJSON
  let _client_data = parse_and_verify_auth_client_data(
    client_data_json, options,
  )

  // Step 3: Parse authenticatorData
  let auth_data = @helpers.parse_authenticator_data(authenticator_data_bytes) catch {
    @helpers.AuthenticatorDataError::TooShort(expected, actual) =>
      raise AuthenticatorDataParseError(
        "Data too short: expected at least \{expected} bytes, got \{actual}",
      )
    @helpers.AuthenticatorDataError::InvalidFlags(byte) =>
      raise AuthenticatorDataParseError("Invalid flags byte: \{byte}")
    @helpers.AuthenticatorDataError::InvalidAAGUID =>
      raise AuthenticatorDataParseError("Invalid AAGUID")
    @helpers.AuthenticatorDataError::InvalidCredentialId =>
      raise AuthenticatorDataParseError("Invalid credential ID")
    @helpers.AuthenticatorDataError::InvalidPublicKey(msg) =>
      raise AuthenticatorDataParseError("Invalid public key: \{msg}")
    @helpers.AuthenticatorDataError::CborDecodeError(msg) =>
      raise AuthenticatorDataParseError("CBOR decode error: \{msg}")
  }

  // Step 4: Verify authenticatorData
  verify_auth_authenticator_data(auth_data, options)

  // Step 5: Verify signature
  // signedData = authenticatorDataBytes + SHA256(clientDataJSON)
  let client_data_hash = @crypto.sha256(client_data_json)
  let signed_data = concat_bytes(authenticator_data_bytes, client_data_hash)
  verify_signature(signed_data, signature, options.credential.public_key)

  // Step 6: Verify sign count
  verify_sign_count(
    auth_data.sign_count,
    options.credential.sign_count,
    options.sign_count_policy,
  )

  // Build result
  {
    credential_id,
    new_sign_count: auth_data.sign_count,
    user_verified: auth_data.flags.user_verified,
    backup_eligible: auth_data.flags.backup_eligible,
    backup_state: auth_data.flags.backup_state,
  }
}

///|
/// Verify credential ID matches the stored credential.
fn verify_credential_id(
  credential_id : Bytes,
  options : VerifyAuthenticationOptions,
) -> Unit raise AuthenticationVerifyError {
  if not(
      @helpers.constant_time_equal(
        credential_id,
        options.credential.credential_id,
      ),
    ) {
    raise CredentialNotAllowed("Credential ID does not match stored credential")
  }
}

///|
/// Parse and verify clientDataJSON for authentication.
fn parse_and_verify_auth_client_data(
  client_data_json : Bytes,
  options : VerifyAuthenticationOptions,
) -> @helpers.ClientData raise AuthenticationVerifyError {
  // Decode UTF-8 with validation
  let utf8_decoder = @encoding.decoder(@encoding.Encoding::UTF8)
  let json_str = utf8_decoder.decode(client_data_json[:]) catch {
    @encoding.MalformedError(_) =>
      raise ClientDataParseError("Invalid UTF-8 in clientDataJSON")
    @encoding.TruncatedError(_) =>
      raise ClientDataParseError("Truncated UTF-8 in clientDataJSON")
    _ => raise ClientDataParseError("UTF-8 decode error")
  }
  let client_data = @helpers.parse_client_data_json_string(json_str) catch {
    @helpers.ClientDataError::InvalidJson(msg) =>
      raise ClientDataParseError("Invalid JSON: \{msg}")
    @helpers.ClientDataError::MissingField(field) =>
      raise ClientDataParseError("Missing field: \{field}")
    @helpers.ClientDataError::InvalidType(t) =>
      raise InvalidClientDataType("Got type: \{t}")
    @helpers.ClientDataError::InvalidChallenge =>
      raise ClientDataParseError("Invalid challenge encoding")
    @helpers.ClientDataError::InvalidOrigin =>
      raise ClientDataParseError("Invalid origin format")
  }

  // Verify type is "webauthn.get"
  match client_data.type_ {
    @helpers.ClientDataType::Get => ()
    @helpers.ClientDataType::Create =>
      raise InvalidClientDataType(
        "Expected 'webauthn.get', got 'webauthn.create'",
      )
  }

  // Verify challenge
  if not(
      @helpers.constant_time_equal(
        client_data.challenge,
        options.expected_challenge,
      ),
    ) {
    raise ChallengeMismatch("Challenge does not match expected value")
  }

  // Verify origin
  let origin_matches = options.expected_origins
    .iter()
    .any(fn(expected) { client_data.origin == expected })
  if not(origin_matches) {
    raise OriginMismatch(
      "Origin '\{client_data.origin}' not in allowed origins",
    )
  }
  client_data
}

///|
/// Verify authenticatorData fields for authentication.
fn verify_auth_authenticator_data(
  auth_data : @helpers.AuthenticatorData,
  options : VerifyAuthenticationOptions,
) -> Unit raise AuthenticationVerifyError {
  // Verify rpIdHash
  let expected_hash = @crypto.hash_rp_id(options.expected_rp_id)
  if not(@helpers.constant_time_equal(auth_data.rp_id_hash, expected_hash)) {
    raise RpIdHashMismatch("rpIdHash does not match expected rpId")
  }

  // Verify UP (user present) flag
  if not(auth_data.flags.user_present) {
    raise UserNotPresent
  }

  // Verify UV (user verified) flag if required
  if options.require_user_verification && not(auth_data.flags.user_verified) {
    raise UserVerificationRequired
  }
}

///|
/// Verify the signature over the signed data.
/// 
/// Note: This is a stub implementation. Real signature verification
/// requires WebCrypto FFI which is not yet implemented.
fn verify_signature(
  _signed_data : Bytes,
  _signature : Bytes,
  _public_key : Bytes,
) -> Unit raise AuthenticationVerifyError {
  // TODO: Implement actual signature verification with WebCrypto FFI
  // For now, we raise an error to indicate this is not yet implemented
  // In production, this would:
  // 1. Parse the COSE public key
  // 2. Parse the DER-encoded signature  
  // 3. Verify using the appropriate algorithm (ES256, RS256, etc.)
  raise SignatureVerificationFailed(
    "Signature verification not yet implemented (requires WebCrypto FFI)",
  )
}

///|
/// Verify the signature counter to detect cloned authenticators.
/// 
/// Behavior depends on the SignCountPolicy:
/// - Strict: counter must always increase
/// - AllowZero: both being 0 is allowed, otherwise must increase
/// - Permissive: never fails (consider logging warnings externally)
fn verify_sign_count(
  new_count : UInt,
  stored_count : UInt,
  policy : SignCountPolicy,
) -> Unit raise AuthenticationVerifyError {
  match policy {
    SignCountPolicy::Permissive => ()
    SignCountPolicy::AllowZero => {
      // Special case: if both are 0, the authenticator doesn't use counters
      if new_count == 0 && stored_count == 0 {
        return
      }
      // Counter must strictly increase
      if new_count <= stored_count {
        raise SignCountInvalid(
          "Sign count \{new_count} is not greater than stored count \{stored_count}. Possible cloned authenticator.",
        )
      }
    }
    SignCountPolicy::Strict =>
      // Counter must always increase, no exceptions
      if new_count <= stored_count {
        raise SignCountInvalid(
          "Sign count \{new_count} is not greater than stored count \{stored_count}. Possible cloned authenticator.",
        )
      }
  }
}

///|
/// Concatenate two byte arrays.
fn concat_bytes(a : Bytes, b : Bytes) -> Bytes {
  let buf = @buffer.new()
  buf.write_bytes(a)
  buf.write_bytes(b)
  buf.to_bytes()
}

///|
/// Convenience function to verify authentication from base64url strings.
/// 
/// This is a higher-level API that handles base64url decoding.
pub fn verify_authentication_response_b64(
  credential_id_b64 : String,
  client_data_json_b64 : String,
  authenticator_data_b64 : String,
  signature_b64 : String,
  options : VerifyAuthenticationOptions,
) -> VerifiedAuthentication raise AuthenticationVerifyError {
  // Decode base64url
  let credential_id = @helpers.base64url_decode(credential_id_b64) catch {
    _ => raise Base64DecodeError("Failed to decode credential ID")
  }
  let client_data_json = @helpers.base64url_decode(client_data_json_b64) catch {
    _ => raise Base64DecodeError("Failed to decode clientDataJSON")
  }
  let authenticator_data = @helpers.base64url_decode(authenticator_data_b64) catch {
    _ => raise Base64DecodeError("Failed to decode authenticatorData")
  }
  let signature = @helpers.base64url_decode(signature_b64) catch {
    _ => raise Base64DecodeError("Failed to decode signature")
  }
  verify_authentication_response(
    credential_id, client_data_json, authenticator_data, signature, options,
  )
}

// ============================================================================
// ASYNC VERSION WITH WEBCRYPTO SIGNATURE VERIFICATION
// ============================================================================

///|
/// Verify a WebAuthn authentication response (async version with real signature verification).
///
/// This is the **recommended** function for production use. It uses WebCrypto API
/// for actual ES256 signature verification.
///
/// ## Parameters
/// - `credential_id`: Raw bytes of the credential ID (rawId, base64url decoded)
/// - `client_data_json`: Raw bytes of clientDataJSON (base64url decoded)
/// - `authenticator_data`: Raw bytes of authenticatorData (base64url decoded)
/// - `signature`: Raw bytes of the signature (base64url decoded)
/// - `options`: Verification options (challenge, origin, rpId, credential)
///
/// ## Returns
/// - `Ok(VerifiedAuthentication)` on success
/// - `Err(AuthenticationVerifyError)` on failure
///
/// ## Example
/// ```
/// let result = verify_authentication_response_async(
///   credential_id_bytes,
///   client_data_json_bytes,
///   authenticator_data_bytes,
///   signature_bytes,
///   options
/// ).wait()
/// ```
pub async fn verify_authentication_response_async(
  credential_id : Bytes,
  client_data_json : Bytes,
  authenticator_data_bytes : Bytes,
  signature : Bytes,
  options : VerifyAuthenticationOptions,
) -> Result[VerifiedAuthentication, AuthenticationVerifyError] {
  // Step 1: Verify credential ID matches stored credential
  let cred_check = try {
    verify_credential_id(credential_id, options)
    Ok(())
  } catch {
    e => Err(e)
  }
  guard cred_check is Ok(_) else { return Err(cred_check.unwrap_err()) }

  // Step 2: Parse and verify clientDataJSON
  let client_data_result = try {
    let _ = parse_and_verify_auth_client_data(client_data_json, options)
    Ok(())
  } catch {
    e => Err(e)
  }
  guard client_data_result is Ok(_) else {
    return Err(client_data_result.unwrap_err())
  }

  // Step 3: Parse authenticatorData
  let auth_data_result = Ok(
    @helpers.parse_authenticator_data(authenticator_data_bytes) catch {
      @helpers.AuthenticatorDataError::TooShort(expected, actual) =>
        raise AuthenticatorDataParseError(
          "Data too short: expected at least \{expected} bytes, got \{actual}",
        )
      @helpers.AuthenticatorDataError::InvalidFlags(byte) =>
        raise AuthenticatorDataParseError("Invalid flags byte: \{byte}")
      @helpers.AuthenticatorDataError::InvalidAAGUID =>
        raise AuthenticatorDataParseError("Invalid AAGUID")
      @helpers.AuthenticatorDataError::InvalidCredentialId =>
        raise AuthenticatorDataParseError("Invalid credential ID")
      @helpers.AuthenticatorDataError::InvalidPublicKey(msg) =>
        raise AuthenticatorDataParseError("Invalid public key: \{msg}")
      @helpers.AuthenticatorDataError::CborDecodeError(msg) =>
        raise AuthenticatorDataParseError("CBOR decode error: \{msg}")
    },
  ) catch {
    e => Err(e)
  }
  let auth_data = match auth_data_result {
    Ok(data) => data
    Err(e) => return Err(e)
  }

  // Step 4: Verify authenticatorData
  let auth_verify = try {
    verify_auth_authenticator_data(auth_data, options)
    Ok(())
  } catch {
    e => Err(e)
  }
  guard auth_verify is Ok(_) else { return Err(auth_verify.unwrap_err()) }

  // Step 5: Parse public key from COSE format
  let public_key_result = Ok(
    @crypto.parse_cose_ec2_key(options.credential.public_key) catch {
      @crypto.ECDSAError::InvalidPublicKey(msg) =>
        raise AuthenticationVerifyError::InvalidPublicKey(
          "Invalid COSE key: \{msg}",
        )
      @crypto.ECDSAError::UnsupportedAlgorithm(alg) =>
        raise AuthenticationVerifyError::InvalidPublicKey(
          "Unsupported algorithm: \{alg}",
        )
      @crypto.ECDSAError::InvalidSignature(msg) =>
        raise AuthenticationVerifyError::InvalidPublicKey(
          "Unexpected error: \{msg}",
        )
      @crypto.ECDSAError::VerificationFailed(msg) =>
        raise AuthenticationVerifyError::InvalidPublicKey(
          "Unexpected error: \{msg}",
        )
    },
  ) catch {
    AuthenticationVerifyError::InvalidPublicKey(msg) =>
      Err(AuthenticationVerifyError::InvalidPublicKey(msg))
    _ => Err(AuthenticationVerifyError::InvalidPublicKey("Unknown error"))
  }
  let public_key = match public_key_result {
    Ok(pk) => pk
    Err(e) => return Err(e)
  }

  // Step 6: Verify signature using WebCrypto
  // signedData = authenticatorDataBytes + SHA256(clientDataJSON)
  let client_data_hash = @crypto.sha256(client_data_json)
  let signed_data = concat_bytes(authenticator_data_bytes, client_data_hash)
  let sig_valid = @crypto.verify_es256_async(public_key, signature, signed_data)
  if not(sig_valid) {
    return Err(SignatureVerificationFailed("Signature verification failed"))
  }

  // Step 7: Verify sign count
  let count_result = try {
    verify_sign_count(
      auth_data.sign_count,
      options.credential.sign_count,
      options.sign_count_policy,
    )
    Ok(())
  } catch {
    e => Err(e)
  }
  guard count_result is Ok(_) else { return Err(count_result.unwrap_err()) }

  // Build result
  Ok({
    credential_id,
    new_sign_count: auth_data.sign_count,
    user_verified: auth_data.flags.user_verified,
    backup_eligible: auth_data.flags.backup_eligible,
    backup_state: auth_data.flags.backup_state,
  })
}

///|
/// Async convenience function to verify authentication from base64url strings.
/// 
/// This is the **recommended** API for production use.
pub async fn verify_authentication_response_b64_async(
  credential_id_b64 : String,
  client_data_json_b64 : String,
  authenticator_data_b64 : String,
  signature_b64 : String,
  options : VerifyAuthenticationOptions,
) -> Result[VerifiedAuthentication, AuthenticationVerifyError] {
  // Decode base64url
  let credential_id = @helpers.base64url_decode(credential_id_b64) catch {
    _ => return Err(Base64DecodeError("Failed to decode credential ID"))
  }
  let client_data_json = @helpers.base64url_decode(client_data_json_b64) catch {
    _ => return Err(Base64DecodeError("Failed to decode clientDataJSON"))
  }
  let authenticator_data = @helpers.base64url_decode(authenticator_data_b64) catch {
    _ => return Err(Base64DecodeError("Failed to decode authenticatorData"))
  }
  let signature = @helpers.base64url_decode(signature_b64) catch {
    _ => return Err(Base64DecodeError("Failed to decode signature"))
  }
  verify_authentication_response_async(
    credential_id, client_data_json, authenticator_data, signature, options,
  )
}
