///|
// Tests for server package - verify_registration_response
// Failure cases first, then success cases

// ============================================================================
// Test Helpers
// ============================================================================

///|
/// Create a minimal valid clientDataJSON for testing
fn make_client_data_json(
  type_ : String,
  challenge_b64 : String,
  origin : String,
) -> Bytes {
  let json = "{\"type\":\"\{type_}\",\"challenge\":\"\{challenge_b64}\",\"origin\":\"\{origin}\",\"crossOrigin\":false}"
  @encoding.encode(@encoding.Encoding::UTF8, json)
}

///|
/// Create a minimal attestation object with fmt="none" for testing
/// Structure: CBOR map { "fmt": "none", "authData": <bytes>, "attStmt": {} }
fn make_attestation_object_none(auth_data : Bytes) -> Bytes {
  // Use cbor library for correct encoding
  let cbor_value = @cbor.vmap([
    (@cbor.vstring("fmt"), @cbor.vstring("none")),
    (@cbor.vstring("authData"), @cbor.vbytes(auth_data)),
    (@cbor.vstring("attStmt"), @cbor.vmap([])),
  ])
  @cbor.encode(cbor_value)
}

///|
/// Create minimal valid authenticatorData for testing
/// rpIdHash(32) + flags(1) + signCount(4) + [attestedCredData if AT flag]
fn make_auth_data(
  rp_id : String,
  flags : Byte,
  sign_count : UInt,
  credential_id : Bytes?,
  public_key_cbor : Bytes?,
) -> Bytes {
  let buf = @buffer.new()
  // rpIdHash: SHA-256 of rpId
  let rp_id_hash = @crypto.sha256_string(rp_id)
  for i in 0..<32 {
    buf.write_byte(rp_id_hash[i])
  }
  // flags
  buf.write_byte(flags)
  // signCount (big-endian 4 bytes)
  buf.write_byte(((sign_count >> 24) & 0xFFU).to_byte())
  buf.write_byte(((sign_count >> 16) & 0xFFU).to_byte())
  buf.write_byte(((sign_count >> 8) & 0xFFU).to_byte())
  buf.write_byte((sign_count & 0xFFU).to_byte())
  // If AT flag is set, add attested credential data
  if (flags.to_int() & 0x40) != 0 {
    // AAGUID (16 bytes of zeros)
    for _i in 0..<16 {
      buf.write_byte(b'\x00')
    }
    // Credential ID length (2 bytes big-endian)
    match credential_id {
      Some(cred_id) => {
        let cred_len = cred_id.length()
        buf.write_byte((cred_len >> 8).to_byte())
        buf.write_byte((cred_len & 0xFF).to_byte())
        // Credential ID
        for i in 0..<cred_len {
          buf.write_byte(cred_id[i])
        }
      }
      None => {
        // 0-length credential ID (invalid but for testing)
        buf.write_byte(b'\x00')
        buf.write_byte(b'\x00')
      }
    }
    // Public key (COSE format)
    match public_key_cbor {
      Some(pk) =>
        for i in 0..<pk.length() {
          buf.write_byte(pk[i])
        }
      None => ()
    }
  }
  buf.to_bytes()
}

///|
/// Create a minimal ES256 public key in COSE format
fn make_es256_public_key() -> Bytes {
  // COSE_Key for ES256 (P-256):
  // {1: 2, 3: -7, -1: 1, -2: x_coord(32), -3: y_coord(32)}
  // Using dummy coordinates (all zeros - not a valid point but works for parsing)
  let buf = @buffer.new()
  // Map with 5 items
  buf.write_byte(b'\xa5')
  // 1: 2 (kty: EC2)
  buf.write_byte(b'\x01')
  buf.write_byte(b'\x02')
  // 3: -7 (alg: ES256) - negative int: -1-n, so -7 = 0x26
  buf.write_byte(b'\x03')
  buf.write_byte(b'\x26')
  // -1: 1 (crv: P-256) - negative key: 0x20
  buf.write_byte(b'\x20')
  buf.write_byte(b'\x01')
  // -2: x coordinate (32 bytes) - key 0x21, bytes
  buf.write_byte(b'\x21')
  buf.write_byte(b'\x58')
  buf.write_byte(b'\x20') // 32 bytes
  for _i in 0..<32 {
    buf.write_byte(b'\x01') // dummy non-zero values
  }
  // -3: y coordinate (32 bytes) - key 0x22, bytes
  buf.write_byte(b'\x22')
  buf.write_byte(b'\x58')
  buf.write_byte(b'\x20') // 32 bytes
  for _i in 0..<32 {
    buf.write_byte(b'\x02') // dummy non-zero values
  }
  buf.to_bytes()
}

// ============================================================================
// FAILURE CASES
// ============================================================================

///|
// FAILURE: Invalid UTF-8 in clientDataJSON
test "verify_registration_invalid_utf8" {
  // Invalid UTF-8 sequence
  let invalid_utf8 = b"\xff\xfe"
  let attestation_obj = make_attestation_object_none(
    make_auth_data(
      "example.com",
      b'\x41',
      0U,
      Some(b"cred-id"),
      Some(make_es256_public_key()),
    ),
  )
  let options = @server.VerifyRegistrationOptions::new(
    b"test-challenge", "https://example.com", "example.com",
  )
  let result = try {
    let _ = @server.verify_registration_response(
      invalid_utf8, attestation_obj, options,
    )
    Ok(())
  } catch {
    @server.RegistrationVerifyError::ClientDataParseError(_) =>
      Err("ClientDataParseError")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("ClientDataParseError"))
}

///|
// FAILURE: Invalid JSON in clientDataJSON
test "verify_registration_invalid_json" {
  let invalid_json = @encoding.encode(
    @encoding.Encoding::UTF8,
    "not valid json {",
  )
  let attestation_obj = make_attestation_object_none(
    make_auth_data(
      "example.com",
      b'\x41',
      0U,
      Some(b"cred-id"),
      Some(make_es256_public_key()),
    ),
  )
  let options = @server.VerifyRegistrationOptions::new(
    b"test-challenge", "https://example.com", "example.com",
  )
  let result = try {
    let _ = @server.verify_registration_response(
      invalid_json, attestation_obj, options,
    )
    Ok(())
  } catch {
    @server.RegistrationVerifyError::ClientDataParseError(_) =>
      Err("ClientDataParseError")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("ClientDataParseError"))
}

///|
// FAILURE: Wrong type in clientDataJSON (webauthn.get instead of webauthn.create)
test "verify_registration_wrong_type" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.get", // Wrong type for registration
     challenge_b64, "https://example.com",
  )
  let attestation_obj = make_attestation_object_none(
    make_auth_data(
      "example.com",
      b'\x41',
      0U,
      Some(b"cred-id"),
      Some(make_es256_public_key()),
    ),
  )
  let options = @server.VerifyRegistrationOptions::new(
    b"test-challenge", "https://example.com", "example.com",
  )
  let result = try {
    let _ = @server.verify_registration_response(
      client_data, attestation_obj, options,
    )
    Ok(())
  } catch {
    @server.RegistrationVerifyError::InvalidClientDataType(_) =>
      Err("InvalidClientDataType")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("InvalidClientDataType"))
}

///|
// FAILURE: Challenge mismatch
test "verify_registration_challenge_mismatch" {
  let wrong_challenge_b64 = @helpers.base64url_encode(b"wrong-challenge")
  let client_data = make_client_data_json(
    "webauthn.create", wrong_challenge_b64, "https://example.com",
  )
  let attestation_obj = make_attestation_object_none(
    make_auth_data(
      "example.com",
      b'\x41',
      0U,
      Some(b"cred-id"),
      Some(make_es256_public_key()),
    ),
  )
  let options = @server.VerifyRegistrationOptions::new(
    b"expected-challenge", // Different from wrong-challenge
     "https://example.com", "example.com",
  )
  let result = try {
    let _ = @server.verify_registration_response(
      client_data, attestation_obj, options,
    )
    Ok(())
  } catch {
    @server.RegistrationVerifyError::ChallengeMismatch(_) =>
      Err("ChallengeMismatch")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("ChallengeMismatch"))
}

///|
// FAILURE: Origin mismatch
test "verify_registration_origin_mismatch" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.create", challenge_b64, "https://evil.com", // Wrong origin
  )
  let attestation_obj = make_attestation_object_none(
    make_auth_data(
      "example.com",
      b'\x41',
      0U,
      Some(b"cred-id"),
      Some(make_es256_public_key()),
    ),
  )
  let options = @server.VerifyRegistrationOptions::new(
    b"test-challenge", "https://example.com", // Expected origin
     "example.com",
  )
  let result = try {
    let _ = @server.verify_registration_response(
      client_data, attestation_obj, options,
    )
    Ok(())
  } catch {
    @server.RegistrationVerifyError::OriginMismatch(_) => Err("OriginMismatch")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("OriginMismatch"))
}

///|
// FAILURE: rpIdHash mismatch
test "verify_registration_rp_id_mismatch" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.create", challenge_b64, "https://example.com",
  )
  // Auth data uses wrong rpId
  let attestation_obj = make_attestation_object_none(
    make_auth_data(
      "wrong-rp.com",
      b'\x41',
      0U,
      Some(b"cred-id"),
      Some(make_es256_public_key()),
    ),
  )
  let options = @server.VerifyRegistrationOptions::new(
    b"test-challenge", "https://example.com", "example.com", // Expected rpId
  )
  let result = try {
    let _ = @server.verify_registration_response(
      client_data, attestation_obj, options,
    )
    Ok(())
  } catch {
    @server.RegistrationVerifyError::RpIdHashMismatch(_) =>
      Err("RpIdHashMismatch")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("RpIdHashMismatch"))
}

///|
// FAILURE: User not present (UP flag not set)
test "verify_registration_user_not_present" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.create", challenge_b64, "https://example.com",
  )
  // flags = 0x40 = AT only, no UP
  let attestation_obj = make_attestation_object_none(
    make_auth_data(
      "example.com",
      b'\x40',
      0U,
      Some(b"cred-id"),
      Some(make_es256_public_key()),
    ),
  )
  let options = @server.VerifyRegistrationOptions::new(
    b"test-challenge", "https://example.com", "example.com",
  )
  let result = try {
    let _ = @server.verify_registration_response(
      client_data, attestation_obj, options,
    )
    Ok(())
  } catch {
    @server.RegistrationVerifyError::UserNotPresent => Err("UserNotPresent")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("UserNotPresent"))
}

///|
// FAILURE: User verification required but not done
test "verify_registration_user_verification_required" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.create", challenge_b64, "https://example.com",
  )
  // flags = 0x41 = UP | AT, but no UV
  let attestation_obj = make_attestation_object_none(
    make_auth_data(
      "example.com",
      b'\x41',
      0U,
      Some(b"cred-id"),
      Some(make_es256_public_key()),
    ),
  )
  let options = @server.VerifyRegistrationOptions::new(
    b"test-challenge", "https://example.com", "example.com",
  ).require_user_verification(true) // Require UV
  let result = try {
    let _ = @server.verify_registration_response(
      client_data, attestation_obj, options,
    )
    Ok(())
  } catch {
    @server.RegistrationVerifyError::UserVerificationRequired =>
      Err("UserVerificationRequired")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("UserVerificationRequired"))
}

///|
// FAILURE: Attested credential data missing (AT flag not set)
test "verify_registration_at_flag_missing" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.create", challenge_b64, "https://example.com",
  )
  // flags = 0x01 = UP only, no AT
  let attestation_obj = make_attestation_object_none(
    make_auth_data("example.com", b'\x01', 0U, None, None),
  )
  let options = @server.VerifyRegistrationOptions::new(
    b"test-challenge", "https://example.com", "example.com",
  )
  let result = try {
    let _ = @server.verify_registration_response(
      client_data, attestation_obj, options,
    )
    Ok(())
  } catch {
    @server.RegistrationVerifyError::AttestedCredentialDataMissing =>
      Err("AttestedCredentialDataMissing")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("AttestedCredentialDataMissing"))
}

///|
// FAILURE: Empty credential ID
test "verify_registration_empty_credential_id" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.create", challenge_b64, "https://example.com",
  )
  // Empty credential ID
  let attestation_obj = make_attestation_object_none(
    make_auth_data(
      "example.com",
      b'\x41',
      0U,
      Some(b""),
      Some(make_es256_public_key()),
    ),
  )
  let options = @server.VerifyRegistrationOptions::new(
    b"test-challenge", "https://example.com", "example.com",
  )
  let result = try {
    let _ = @server.verify_registration_response(
      client_data, attestation_obj, options,
    )
    Ok(())
  } catch {
    @server.RegistrationVerifyError::InvalidCredentialId(_) =>
      Err("InvalidCredentialId")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("InvalidCredentialId"))
}

// ============================================================================
// SUCCESS CASE (fmt="none")
// ============================================================================

///|
// SUCCESS: Valid registration with fmt="none"
test "verify_registration_success_fmt_none" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.create", challenge_b64, "https://example.com",
  )
  // flags = 0x41 = UP | AT
  let cred_id = b"test-credential-id-12345"
  let attestation_obj = make_attestation_object_none(
    make_auth_data(
      "example.com",
      b'\x41',
      0U,
      Some(cred_id),
      Some(make_es256_public_key()),
    ),
  )
  let options = @server.VerifyRegistrationOptions::new(
    b"test-challenge", "https://example.com", "example.com",
  )
  let result = @server.verify_registration_response(
    client_data, attestation_obj, options,
  ) catch {
    _ => panic()
  }
  // Verify result
  assert_eq(result.credential_id, cred_id)
  assert_eq(result.credential_algorithm, -7) // ES256
  assert_eq(result.sign_count, 0U)
  assert_eq(result.backup_eligible, false)
  assert_eq(result.backup_state, false)
  // attestation_format is None variant
  inspect(result.attestation_format, content="None")
  assert_eq(result.attestation_verified, false) // fmt=none means not verified
}

///|
// SUCCESS: Valid registration with user verification
test "verify_registration_success_with_uv" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.create", challenge_b64, "https://example.com",
  )
  // flags = 0x45 = UP | UV | AT
  let cred_id = b"uv-credential-id"
  let attestation_obj = make_attestation_object_none(
    make_auth_data(
      "example.com",
      b'\x45',
      42U,
      Some(cred_id),
      Some(make_es256_public_key()),
    ),
  )
  let options = @server.VerifyRegistrationOptions::new(
    b"test-challenge", "https://example.com", "example.com",
  ).require_user_verification(true)
  let result = @server.verify_registration_response(
    client_data, attestation_obj, options,
  ) catch {
    _ => panic()
  }
  assert_eq(result.credential_id, cred_id)
  assert_eq(result.sign_count, 42U)
}

// ============================================================================
// GENERATE REGISTRATION OPTIONS TESTS
// ============================================================================

///|
// Test: Basic generation with required fields only
test "generate_registration_options_basic" {
  let input = @server.GenerateRegistrationOptionsInput::new(
    "ACME Corp", "example.com", "johndoe",
  )
  let options = @server.generate_registration_options(input)
  // Check RP
  inspect(options.rp.name, content="ACME Corp")
  inspect(options.rp.id, content="Some(\"example.com\")")
  // Check user
  inspect(options.user.name, content="johndoe")
  inspect(options.user.display_name, content="johndoe") // defaults to user_name
  // Check challenge is generated (32 bytes = 43 base64url chars without padding)
  assert_true(options.challenge.value.length() >= 42)
  // Check user id is generated
  assert_true(options.user.id.length() >= 42)
  // Check default algorithms (ES256 and RS256)
  assert_eq(options.pub_key_cred_params.length(), 2)
  assert_eq(options.pub_key_cred_params[0].alg.to_int(), -7) // ES256
  assert_eq(options.pub_key_cred_params[1].alg.to_int(), -257) // RS256
  // Check default timeout
  inspect(options.timeout, content="Some(60000)")
  // Check default attestation
  inspect(options.attestation, content="Some(None)")
}

///|
// Test: Custom challenge and user ID
test "generate_registration_options_custom_challenge" {
  let custom_challenge = b"my-custom-challenge-bytes"
  let custom_user_id = b"user-12345"
  let input = @server.GenerateRegistrationOptionsInput::new(
    "Test RP",
    "test.com",
    "testuser",
    user_id=Some(custom_user_id),
    user_display_name=Some("Test User Display"),
    challenge=Some(custom_challenge),
  )
  let options = @server.generate_registration_options(input)
  // Challenge should be base64url encoded version of our custom challenge
  let expected_challenge = @helpers.base64url_encode(custom_challenge)
  assert_eq(options.challenge.value, expected_challenge)
  // User ID should be base64url encoded version of our custom user ID
  let expected_user_id = @helpers.base64url_encode(custom_user_id)
  assert_eq(options.user.id, expected_user_id)
  // Display name should be custom
  inspect(options.user.display_name, content="Test User Display")
}

///|
// Test: Custom algorithms
test "generate_registration_options_custom_algorithms" {
  let input = @server.GenerateRegistrationOptionsInput::new(
    "Test RP",
    "test.com",
    "testuser",
    supported_algorithm_ids=Some([-7, -8, -35]), // ES256, EdDSA, ES384
  )
  let options = @server.generate_registration_options(input)
  assert_eq(options.pub_key_cred_params.length(), 3)
  assert_eq(options.pub_key_cred_params[0].alg.to_int(), -7) // ES256
  assert_eq(options.pub_key_cred_params[1].alg.to_int(), -8) // EdDSA
  assert_eq(options.pub_key_cred_params[2].alg.to_int(), -35) // ES384
}

///|
// Test: Custom timeout
test "generate_registration_options_custom_timeout" {
  let input = @server.GenerateRegistrationOptionsInput::new(
    "Test RP",
    "test.com",
    "testuser",
    timeout=Some(120000),
  )
  let options = @server.generate_registration_options(input)
  inspect(options.timeout, content="Some(120000)")
}

///|
// Test: Direct attestation
test "generate_registration_options_direct_attestation" {
  let input = @server.GenerateRegistrationOptionsInput::new(
    "Test RP",
    "test.com",
    "testuser",
    attestation=Some(@types.AttestationConveyance::Direct),
  )
  let options = @server.generate_registration_options(input)
  inspect(options.attestation, content="Some(Direct)")
}

///|
// Test: JSON serialization
test "generate_registration_options_json_output" {
  let input = @server.GenerateRegistrationOptionsInput::new(
    "ACME Corp",
    "example.com",
    "johndoe",
    user_id=Some(b"user123"),
    user_display_name=Some("John Doe"),
    challenge=Some(b"test-challenge"),
    supported_algorithm_ids=Some([-7]),
    timeout=Some(60000),
  )
  let options = @server.generate_registration_options(input)
  let json = options.to_json()
  // Verify JSON structure
  guard json is Json::Object(obj) else { panic() }
  // Check rp
  guard obj["rp"] is Json::Object(rp) else { panic() }
  inspect(rp["name"], content="String(\"ACME Corp\")")
  inspect(rp["id"], content="String(\"example.com\")")
  // Check user
  guard obj["user"] is Json::Object(user) else { panic() }
  inspect(user["name"], content="String(\"johndoe\")")
  inspect(user["displayName"], content="String(\"John Doe\")")
  // Check pubKeyCredParams
  guard obj["pubKeyCredParams"] is Json::Array(params) else { panic() }
  assert_eq(params.length(), 1)
  guard params[0] is Json::Object(param) else { panic() }
  inspect(param["type"], content="String(\"public-key\")")
  inspect(param["alg"], content="Number(-7)")
}

// ============================================================================
// GENERATE AUTHENTICATION OPTIONS TESTS
// ============================================================================

///|
// Test: Basic generation with defaults (discoverable credentials)
test "generate_authentication_options_basic" {
  let input = @server.GenerateAuthenticationOptionsInput::new()
  let options = @server.generate_authentication_options(input)
  // Check challenge is generated (32 bytes = 43 base64url chars without padding)
  assert_true(options.challenge.value.length() >= 42)
  // Check default timeout
  inspect(options.timeout, content="Some(60000)")
  // Check default user verification
  inspect(options.user_verification, content="Some(Preferred)")
  // Check rpId is None (allows discoverable credentials from any RP)
  inspect(options.rp_id, content="None")
  // Check allow_credentials is None (discoverable credential flow)
  inspect(options.allow_credentials, content="None")
}

///|
// Test: With rpId specified
test "generate_authentication_options_with_rp_id" {
  let input = @server.GenerateAuthenticationOptionsInput::new(
    rp_id=Some("example.com"),
  )
  let options = @server.generate_authentication_options(input)
  inspect(options.rp_id, content="Some(\"example.com\")")
}

///|
// Test: Custom challenge
test "generate_authentication_options_custom_challenge" {
  let custom_challenge = b"my-auth-challenge-bytes"
  let input = @server.GenerateAuthenticationOptionsInput::new(
    challenge=Some(custom_challenge),
  )
  let options = @server.generate_authentication_options(input)
  let expected_challenge = @helpers.base64url_encode(custom_challenge)
  assert_eq(options.challenge.value, expected_challenge)
}

///|
// Test: Custom timeout
test "generate_authentication_options_custom_timeout" {
  let input = @server.GenerateAuthenticationOptionsInput::new(
    timeout=Some(120000),
  )
  let options = @server.generate_authentication_options(input)
  inspect(options.timeout, content="Some(120000)")
}

///|
// Test: User verification required
test "generate_authentication_options_uv_required" {
  let input = @server.GenerateAuthenticationOptionsInput::new(
    user_verification=Some(@types.UserVerification::Required),
  )
  let options = @server.generate_authentication_options(input)
  inspect(options.user_verification, content="Some(Required)")
}

///|
// Test: With allow credentials (non-discoverable flow)
test "generate_authentication_options_with_allow_credentials" {
  let cred1 = @types.PublicKeyCredentialDescriptor::new(
    @types.Base64URLString::new("credential-id-1"),
  )
  let cred2 = @types.PublicKeyCredentialDescriptor::new(
    @types.Base64URLString::new("credential-id-2"),
  )
  let input = @server.GenerateAuthenticationOptionsInput::new(
    rp_id=Some("example.com"),
    allow_credentials=Some([cred1, cred2]),
  )
  let options = @server.generate_authentication_options(input)
  guard options.allow_credentials is Some(creds) else { panic() }
  assert_eq(creds.length(), 2)
  assert_eq(creds[0].id.value, "credential-id-1")
  assert_eq(creds[1].id.value, "credential-id-2")
}

///|
// Test: JSON serialization
test "generate_authentication_options_json_output" {
  let input = @server.GenerateAuthenticationOptionsInput::new(
    rp_id=Some("example.com"),
    challenge=Some(b"test-auth-challenge"),
    timeout=Some(60000),
    user_verification=Some(@types.UserVerification::Required),
  )
  let options = @server.generate_authentication_options(input)
  let json = options.to_json()
  // Verify JSON structure
  guard json is Json::Object(obj) else { panic() }
  // Check rpId
  inspect(obj["rpId"], content="String(\"example.com\")")
  // Check timeout
  inspect(obj["timeout"], content="Number(60000)")
  // Check userVerification
  inspect(obj["userVerification"], content="String(\"required\")")
  // Check challenge is base64url encoded
  guard obj["challenge"] is Json::String(_) else { panic() }
}

// ============================================================================
// VERIFY AUTHENTICATION TESTS
// ============================================================================

///|
/// Helper: Create a minimal stored credential for testing
fn make_test_credential(
  cred_id : Bytes,
  public_key : Bytes,
  sign_count : UInt,
) -> @server.AuthenticatorCredential {
  @server.AuthenticatorCredential::new(cred_id, public_key, sign_count)
}

///|
/// Helper: Create authenticator data for authentication (no attested credential data)
/// rpIdHash(32) + flags(1) + signCount(4)
fn make_auth_data_assertion(
  rp_id : String,
  flags : Byte,
  sign_count : UInt,
) -> Bytes {
  let buf = @buffer.new()
  // rpIdHash: SHA-256 of rpId
  let rp_id_hash = @crypto.sha256_string(rp_id)
  for i in 0..<32 {
    buf.write_byte(rp_id_hash[i])
  }
  // flags
  buf.write_byte(flags)
  // signCount (big-endian 4 bytes)
  buf.write_byte(((sign_count >> 24) & 0xFFU).to_byte())
  buf.write_byte(((sign_count >> 16) & 0xFFU).to_byte())
  buf.write_byte(((sign_count >> 8) & 0xFFU).to_byte())
  buf.write_byte((sign_count & 0xFFU).to_byte())
  buf.to_bytes()
}

// ============================================================================
// AUTHENTICATION FAILURE CASES
// ============================================================================

///|
// FAILURE: Invalid UTF-8 in clientDataJSON
test "verify_authentication_invalid_utf8" {
  let invalid_utf8 = b"\xff\xfe"
  let auth_data = make_auth_data_assertion("example.com", b'\x01', 1U)
  let credential = make_test_credential(
    b"test-credential-id",
    make_es256_public_key(),
    0U,
  )
  let options = @server.VerifyAuthenticationOptions::new(
    b"test-challenge",
    "https://example.com",
    "example.com",
    credential,
  )
  let result = try {
    let _ = @server.verify_authentication_response(
      b"test-credential-id",
      invalid_utf8,
      auth_data,
      b"fake-signature",
      options,
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::ClientDataParseError(_) =>
      Err("ClientDataParseError")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("ClientDataParseError"))
}

///|
// FAILURE: Invalid JSON in clientDataJSON
test "verify_authentication_invalid_json" {
  let invalid_json = @encoding.encode(
    @encoding.Encoding::UTF8,
    "not valid json {",
  )
  let auth_data = make_auth_data_assertion("example.com", b'\x01', 1U)
  let credential = make_test_credential(
    b"test-credential-id",
    make_es256_public_key(),
    0U,
  )
  let options = @server.VerifyAuthenticationOptions::new(
    b"test-challenge",
    "https://example.com",
    "example.com",
    credential,
  )
  let result = try {
    let _ = @server.verify_authentication_response(
      b"test-credential-id",
      invalid_json,
      auth_data,
      b"fake-signature",
      options,
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::ClientDataParseError(_) =>
      Err("ClientDataParseError")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("ClientDataParseError"))
}

///|
// FAILURE: Wrong type in clientDataJSON (webauthn.create instead of webauthn.get)
test "verify_authentication_wrong_type" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.create", // Wrong type for authentication
     challenge_b64, "https://example.com",
  )
  let auth_data = make_auth_data_assertion("example.com", b'\x01', 1U)
  let credential = make_test_credential(
    b"test-credential-id",
    make_es256_public_key(),
    0U,
  )
  let options = @server.VerifyAuthenticationOptions::new(
    b"test-challenge",
    "https://example.com",
    "example.com",
    credential,
  )
  let result = try {
    let _ = @server.verify_authentication_response(
      b"test-credential-id",
      client_data,
      auth_data,
      b"fake-signature",
      options,
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::InvalidClientDataType(_) =>
      Err("InvalidClientDataType")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("InvalidClientDataType"))
}

///|
// FAILURE: Challenge mismatch
test "verify_authentication_challenge_mismatch" {
  let wrong_challenge_b64 = @helpers.base64url_encode(b"wrong-challenge")
  let client_data = make_client_data_json(
    "webauthn.get", wrong_challenge_b64, "https://example.com",
  )
  let auth_data = make_auth_data_assertion("example.com", b'\x01', 1U)
  let credential = make_test_credential(
    b"test-credential-id",
    make_es256_public_key(),
    0U,
  )
  let options = @server.VerifyAuthenticationOptions::new(
    b"expected-challenge", // Different from wrong-challenge
     "https://example.com", "example.com", credential,
  )
  let result = try {
    let _ = @server.verify_authentication_response(
      b"test-credential-id",
      client_data,
      auth_data,
      b"fake-signature",
      options,
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::ChallengeMismatch(_) =>
      Err("ChallengeMismatch")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("ChallengeMismatch"))
}

///|
// FAILURE: Origin mismatch
test "verify_authentication_origin_mismatch" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.get", challenge_b64, "https://evil.com", // Wrong origin
  )
  let auth_data = make_auth_data_assertion("example.com", b'\x01', 1U)
  let credential = make_test_credential(
    b"test-credential-id",
    make_es256_public_key(),
    0U,
  )
  let options = @server.VerifyAuthenticationOptions::new(
    b"test-challenge",
    "https://example.com", // Expected origin
     "example.com", credential,
  )
  let result = try {
    let _ = @server.verify_authentication_response(
      b"test-credential-id",
      client_data,
      auth_data,
      b"fake-signature",
      options,
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::OriginMismatch(_) => Err("OriginMismatch")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("OriginMismatch"))
}

///|
// FAILURE: Credential ID mismatch
test "verify_authentication_credential_not_allowed" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.get", challenge_b64, "https://example.com",
  )
  let auth_data = make_auth_data_assertion("example.com", b'\x01', 1U)
  let credential = make_test_credential(
    b"stored-credential-id", // Different from the one being verified
     make_es256_public_key(), 0U,
  )
  let options = @server.VerifyAuthenticationOptions::new(
    b"test-challenge",
    "https://example.com",
    "example.com",
    credential,
  )
  let result = try {
    let _ = @server.verify_authentication_response(
      b"wrong-credential-id", // Different credential ID
       client_data, auth_data, b"fake-signature", options,
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::CredentialNotAllowed(_) =>
      Err("CredentialNotAllowed")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("CredentialNotAllowed"))
}

///|
// FAILURE: rpIdHash mismatch
test "verify_authentication_rp_id_mismatch" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.get", challenge_b64, "https://example.com",
  )
  // Auth data uses wrong rpId
  let auth_data = make_auth_data_assertion("wrong-rp.com", b'\x01', 1U)
  let credential = make_test_credential(
    b"test-credential-id",
    make_es256_public_key(),
    0U,
  )
  let options = @server.VerifyAuthenticationOptions::new(
    b"test-challenge",
    "https://example.com",
    "example.com", // Expected rpId
     credential,
  )
  let result = try {
    let _ = @server.verify_authentication_response(
      b"test-credential-id",
      client_data,
      auth_data,
      b"fake-signature",
      options,
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::RpIdHashMismatch(_) =>
      Err("RpIdHashMismatch")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("RpIdHashMismatch"))
}

///|
// FAILURE: User not present (UP flag not set)
test "verify_authentication_user_not_present" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.get", challenge_b64, "https://example.com",
  )
  // flags = 0x00 = no UP
  let auth_data = make_auth_data_assertion("example.com", b'\x00', 1U)
  let credential = make_test_credential(
    b"test-credential-id",
    make_es256_public_key(),
    0U,
  )
  let options = @server.VerifyAuthenticationOptions::new(
    b"test-challenge",
    "https://example.com",
    "example.com",
    credential,
  )
  let result = try {
    let _ = @server.verify_authentication_response(
      b"test-credential-id",
      client_data,
      auth_data,
      b"fake-signature",
      options,
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::UserNotPresent => Err("UserNotPresent")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("UserNotPresent"))
}

///|
// FAILURE: User verification required but not done
test "verify_authentication_user_verification_required" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.get", challenge_b64, "https://example.com",
  )
  // flags = 0x01 = UP only, no UV
  let auth_data = make_auth_data_assertion("example.com", b'\x01', 1U)
  let credential = make_test_credential(
    b"test-credential-id",
    make_es256_public_key(),
    0U,
  )
  let options = @server.VerifyAuthenticationOptions::new(
    b"test-challenge",
    "https://example.com",
    "example.com",
    credential,
  ).require_user_verification(true) // Require UV
  let result = try {
    let _ = @server.verify_authentication_response(
      b"test-credential-id",
      client_data,
      auth_data,
      b"fake-signature",
      options,
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::UserVerificationRequired =>
      Err("UserVerificationRequired")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("UserVerificationRequired"))
}

///|
// FAILURE: Signature verification not implemented (expected current behavior)
test "verify_authentication_signature_not_implemented" {
  let challenge_b64 = @helpers.base64url_encode(b"test-challenge")
  let client_data = make_client_data_json(
    "webauthn.get", challenge_b64, "https://example.com",
  )
  // flags = 0x01 = UP
  let auth_data = make_auth_data_assertion("example.com", b'\x01', 1U)
  let credential = make_test_credential(
    b"test-credential-id",
    make_es256_public_key(),
    0U,
  )
  let options = @server.VerifyAuthenticationOptions::new(
    b"test-challenge",
    "https://example.com",
    "example.com",
    credential,
  )
  let result = try {
    let _ = @server.verify_authentication_response(
      b"test-credential-id",
      client_data,
      auth_data,
      b"fake-signature",
      options,
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::SignatureVerificationFailed(_) =>
      Err("SignatureVerificationFailed")
    _ => Err("OtherError")
  }
  // Currently, signature verification is not implemented and always fails
  assert_eq(result, Err("SignatureVerificationFailed"))
}

// ============================================================================
// SIGN COUNT VALIDATION TESTS
// ============================================================================

///|
// Test: Sign count validation - counter must increase
test "verify_authentication_sign_count_not_increased" {
  // This test would pass clientData and authenticatorData verification
  // but fail at sign count verification
  // Since signature verification is not implemented yet, we can't fully test this
  // We'll test the verify_sign_count function indirectly through the flow
  // For now, document expected behavior

  // When sign count is 5 (stored) and new is 3, should fail
  // When sign count is 5 (stored) and new is 5, should fail (must be strictly greater)
  // When sign count is 5 (stored) and new is 6, should pass
  // When sign count is 0 (stored) and new is 0, should pass (authenticator doesn't use counters)
  ()
}

// ============================================================================
// SIGN COUNT POLICY TESTS
// ============================================================================

///|
// Test: Default policy is AllowZero
test "sign_count_policy_default_is_allow_zero" {
  let credential = make_test_credential(
    b"test-credential-id",
    make_es256_public_key(),
    0U,
  )
  let options = @server.VerifyAuthenticationOptions::new(
    b"test-challenge",
    "https://example.com",
    "example.com",
    credential,
  )
  // Check default policy using pattern match (enum is read-only externally)
  guard options.sign_count_policy is @server.SignCountPolicy::AllowZero else {
    panic()
  }
}

///|
// Test: with_sign_count_policy method changes to Strict
test "sign_count_policy_with_strict" {
  let credential = make_test_credential(
    b"test-credential-id",
    make_es256_public_key(),
    0U,
  )
  // Use internal helper to get Strict policy
  let options = @server.VerifyAuthenticationOptions::new(
    b"test-challenge",
    "https://example.com",
    "example.com",
    credential,
  ).with_sign_count_policy_strict()
  guard options.sign_count_policy is @server.SignCountPolicy::Strict else {
    panic()
  }
}

///|
// Test: with_sign_count_policy method changes to Permissive
test "sign_count_policy_with_permissive" {
  let credential = make_test_credential(
    b"test-credential-id",
    make_es256_public_key(),
    0U,
  )
  let options = @server.VerifyAuthenticationOptions::new(
    b"test-challenge",
    "https://example.com",
    "example.com",
    credential,
  ).with_sign_count_policy_permissive()
  guard options.sign_count_policy is @server.SignCountPolicy::Permissive else {
    panic()
  }
}

///|
// Test: with_origins also preserves default policy
test "sign_count_policy_with_origins" {
  let credential = make_test_credential(
    b"test-credential-id",
    make_es256_public_key(),
    0U,
  )
  let options = @server.VerifyAuthenticationOptions::with_origins(
    b"test-challenge",
    ["https://example.com", "https://localhost:3000"],
    "example.com",
    credential,
  )
  guard options.sign_count_policy is @server.SignCountPolicy::AllowZero else {
    panic()
  }
}

