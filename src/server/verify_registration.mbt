///|
/// Registration verification for WebAuthn.
///
/// This implements the server-side verification of registration responses
/// as specified in the WebAuthn specification.
///
/// ## Verification Steps
/// 
/// 1. Parse and verify clientDataJSON
///    - type must be "webauthn.create"
///    - challenge must match expected
///    - origin must match expected
/// 
/// 2. Parse attestationObject and extract authenticatorData
/// 
/// 3. Verify authenticatorData
///    - rpIdHash must match expected rpId
///    - UP (user present) flag must be set
///    - UV (user verified) flag must be set if required
///    - AT (attested credential data) flag must be set
/// 
/// 4. Extract credential data
///    - credentialId
///    - credentialPublicKey (COSE format)
/// 
/// 5. Verify attestation (optional, depends on fmt)
///    - "none": no verification needed
///    - "packed": verify signature (NOT YET IMPLEMENTED)
///
/// ## Design Note
/// 
/// All inputs are raw Bytes (base64url decoded by caller).
/// This avoids re-encoding issues and matches the WebAuthn data model.

///|
/// Verify a WebAuthn registration response.
///
/// ## Parameters
/// - `client_data_json`: Raw bytes of clientDataJSON (base64url decoded)
/// - `attestation_object`: Raw bytes of attestationObject (base64url decoded)
/// - `options`: Verification options (challenge, origin, rpId, etc.)
///
/// ## Returns
/// - `VerifiedRegistration` on success
/// - `RegistrationVerifyError` on failure
///
/// ## Example
/// ```
/// let options = VerifyRegistrationOptions::new(
///   challenge_bytes,
///   "https://example.com",
///   "example.com"
/// )
/// let result = verify_registration_response(
///   client_data_json_bytes,
///   attestation_object_bytes,
///   options
/// )
/// ```
pub fn verify_registration_response(
  client_data_json : Bytes,
  attestation_object : Bytes,
  options : VerifyRegistrationOptions,
) -> VerifiedRegistration raise RegistrationVerifyError {
  // Step 1: Parse and verify clientDataJSON
  let client_data = parse_and_verify_client_data(client_data_json, options)

  // Step 2: Parse attestationObject
  let att_obj = @helpers.parse_attestation_object(attestation_object) catch {
    @helpers.AttestationObjectError::CborDecodeError(msg) =>
      raise AttestationObjectParseError("CBOR decode failed: \{msg}")
    @helpers.AttestationObjectError::InvalidFormat(msg) =>
      raise AttestationObjectParseError("Invalid format: \{msg}")
    @helpers.AttestationObjectError::MissingField(field) =>
      raise AttestationObjectParseError("Missing field: \{field}")
    @helpers.AttestationObjectError::InvalidAuthData(msg) =>
      raise AttestationObjectParseError("Invalid authData: \{msg}")
  }

  // Step 3: Verify authenticatorData
  let auth_data = att_obj.auth_data
  verify_authenticator_data(auth_data, options)

  // Step 4: Extract credential data
  let (credential_id, credential_public_key, credential_algorithm) = extract_credential_data(
    auth_data,
  )

  // Step 5: Verify attestation
  let attestation_verified = verify_attestation(
    att_obj, auth_data, client_data_json, credential_public_key,
  )

  // Build result
  let acd = auth_data.attested_credential_data.unwrap() // Safe: already checked AT flag
  {
    credential_id,
    credential_public_key,
    credential_algorithm,
    sign_count: auth_data.sign_count,
    backup_eligible: auth_data.flags.backup_eligible,
    backup_state: auth_data.flags.backup_state,
    aaguid: acd.aaguid,
    attestation_format: att_obj.fmt,
    attestation_verified,
  }
}

///|
/// Parse and verify clientDataJSON.
fn parse_and_verify_client_data(
  client_data_json : Bytes,
  options : VerifyRegistrationOptions,
) -> @helpers.ClientData raise RegistrationVerifyError {
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

  // Verify type
  match client_data.type_ {
    @helpers.ClientDataType::Create => ()
    @helpers.ClientDataType::Get =>
      raise InvalidClientDataType(
        "Expected 'webauthn.create', got 'webauthn.get'",
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
/// Verify authenticatorData fields.
fn verify_authenticator_data(
  auth_data : @helpers.AuthenticatorData,
  options : VerifyRegistrationOptions,
) -> Unit raise RegistrationVerifyError {
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

  // Verify AT (attested credential data) flag
  if not(auth_data.flags.attested_credential_data) {
    raise AttestedCredentialDataMissing
  }
}

///|
/// Extract credential data from authenticatorData.
fn extract_credential_data(
  auth_data : @helpers.AuthenticatorData,
) -> (Bytes, Bytes, Int) raise RegistrationVerifyError {
  // Get attested credential data (already verified AT flag is set)
  let acd = match auth_data.attested_credential_data {
    Some(data) => data
    None => raise AttestedCredentialDataMissing
  }

  // Validate credential ID
  if acd.credential_id.length() == 0 {
    raise InvalidCredentialId("Credential ID is empty")
  }
  if acd.credential_id.length() > 1023 {
    raise InvalidCredentialId(
      "Credential ID too long: \{acd.credential_id.length()} bytes",
    )
  }

  // Parse and validate public key
  let public_key = @crypto.parse_cose_ec2_key(acd.credential_public_key) catch {
    @crypto.ECDSAError::InvalidPublicKey(msg) =>
      raise InvalidPublicKey("Invalid COSE key: \{msg}")
    @crypto.ECDSAError::UnsupportedAlgorithm(alg) =>
      raise InvalidPublicKey("Unsupported algorithm: \{alg}")
    @crypto.ECDSAError::InvalidSignature(msg) =>
      raise InvalidPublicKey("Unexpected error: \{msg}")
    @crypto.ECDSAError::VerificationFailed(msg) =>
      raise InvalidPublicKey("Unexpected error: \{msg}")
  }
  (acd.credential_id, acd.credential_public_key, public_key.alg)
}

///|
/// Verify attestation based on format.
/// 
/// Returns true if attestation was verified, false if not applicable (e.g., fmt=none).
fn verify_attestation(
  att_obj : @helpers.AttestationObject,
  _auth_data : @helpers.AuthenticatorData,
  _client_data_json : Bytes,
  _credential_public_key : Bytes,
) -> Bool raise RegistrationVerifyError {
  match att_obj.fmt {
    @helpers.AttestationFormat::None =>
      // No attestation to verify
      false
    @helpers.AttestationFormat::Packed =>
      // Packed attestation requires signature verification
      // TODO: Implement packed attestation verification
      // For now, we reject to avoid false sense of security
      raise SignatureVerificationNotImplemented
    @helpers.AttestationFormat::FidoU2F =>
      raise UnsupportedAttestationFormat("fido-u2f")
    @helpers.AttestationFormat::TPM => raise UnsupportedAttestationFormat("tpm")
    @helpers.AttestationFormat::AndroidKey =>
      raise UnsupportedAttestationFormat("android-key")
    @helpers.AttestationFormat::AndroidSafetyNet =>
      raise UnsupportedAttestationFormat("android-safetynet")
    @helpers.AttestationFormat::Apple =>
      raise UnsupportedAttestationFormat("apple")
    @helpers.AttestationFormat::Unknown(fmt) =>
      raise UnsupportedAttestationFormat(fmt)
  }
}

///|
/// Convenience function to verify registration from base64url strings.
/// 
/// This is a higher-level API that handles base64url decoding.
pub fn verify_registration_response_b64(
  client_data_json_b64 : String,
  attestation_object_b64 : String,
  options : VerifyRegistrationOptions,
) -> VerifiedRegistration raise RegistrationVerifyError {
  // Decode base64url
  let client_data_json = @helpers.base64url_decode(client_data_json_b64) catch {
    _ => raise Base64DecodeError("Failed to decode clientDataJSON")
  }
  let attestation_object = @helpers.base64url_decode(attestation_object_b64) catch {
    _ => raise Base64DecodeError("Failed to decode attestationObject")
  }
  verify_registration_response(client_data_json, attestation_object, options)
}
