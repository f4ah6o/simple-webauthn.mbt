///|
// Tests for helpers package

///|
// SUCCESS: Base64URL encode/decode roundtrip
test "base64url_roundtrip" {
  // Test with various byte patterns
  let test_cases : Array[Bytes] = [
    b"hello world", b"\x00\x01\x02\x03\x04\x05", b"",
    // Bytes that would use + and / in standard base64
     b"\xfb\xef\xbe",
  ]
  for bytes in test_cases {
    let encoded = @helpers.base64url_encode(bytes)
    let decoded = @helpers.base64url_decode(encoded) catch { _ => panic() }
    assert_eq(decoded, bytes)
  }
}

///|
// SUCCESS: ClientData JSON parsing
test "client_data_parse_webauthn_create" {
  // Typical clientDataJSON from registration
  let client_data_json =
    #|{"type":"webauthn.create","challenge":"dGVzdC1jaGFsbGVuZ2U","origin":"https://example.com","crossOrigin":false}
  let client_data = @helpers.parse_client_data_json_string(client_data_json) catch {
    _ => panic()
  }
  assert_eq(client_data.type_, @helpers.ClientDataType::Create)
  assert_eq(client_data.origin, "https://example.com")
  assert_eq(client_data.cross_origin, false)
  // Challenge bytes should decode to "test-challenge"
  assert_eq(client_data.challenge, b"test-challenge")
  // challenge_raw is the original base64url string
  assert_eq(client_data.challenge_raw, "dGVzdC1jaGFsbGVuZ2U")
}

///|
// SUCCESS: AuthFlags parsing
test "auth_flags_parse" {
  // flags = 0x45 = 0b01000101 = UP | UV | AT
  let flags = @helpers.parse_auth_flags(b'\x45')
  assert_eq(flags.user_present, true)
  assert_eq(flags.user_verified, true)
  assert_eq(flags.backup_eligible, false)
  assert_eq(flags.backup_state, false)
  assert_eq(flags.attested_credential_data, true)
  assert_eq(flags.extension_data, false)
}

///|
// FAILURE: Base64URL decode with invalid characters
test "base64url_decode_invalid_char" {
  // Contains invalid character '#'
  let invalid = "abc#def"
  let result = try {
    let _ = @helpers.base64url_decode(invalid)
    Ok(())
  } catch {
    _ => Err("Base64URLError")
  }
  assert_eq(result, Err("Base64URLError"))
}

///|
// FAILURE: ClientData JSON missing required field
test "client_data_missing_type" {
  // Missing "type" field
  let invalid_json =
    #|{"challenge":"dGVzdA","origin":"https://example.com"}
  let result = try {
    let _ = @helpers.parse_client_data_json_string(invalid_json)
    Ok(())
  } catch {
    @helpers.ClientDataError::MissingField(_) => Err("MissingField")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("MissingField"))
}

///|
// FAILURE: AuthenticatorData too short
test "authenticator_data_too_short" {
  // Only 10 bytes, need at least 37
  let short_data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"
  let result = try {
    let _ = @helpers.parse_authenticator_data(short_data)
    Ok(())
  } catch {
    @helpers.AuthenticatorDataError::TooShort(_, _) => Err("TooShort")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("TooShort"))
}

///|
// SUCCESS: Bytes utilities
test "bytes_concat_and_slice" {
  let a = b"hello"
  let b = b" "
  let c = b"world"
  let concat = @helpers.bytes_concat([a, b, c])
  assert_eq(concat, b"hello world")
  let slice = @helpers.bytes_slice(concat, 6, 5) catch { _ => panic() }
  assert_eq(slice, b"world")
}

///|
// FAILURE: Bytes slice out of bounds
test "bytes_slice_out_of_bounds" {
  let data = b"short"
  let result = try {
    let _ = @helpers.bytes_slice(data, 3, 10)
    Ok(())
  } catch {
    @helpers.BytesError::OutOfBounds(_, _) => Err("OutOfBounds")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("OutOfBounds"))
}

///|
// SUCCESS: Constant time equal - same values
test "constant_time_equal" {
  let a = b"secret123"
  let b = b"secret123"
  assert_eq(@helpers.constant_time_equal(a, b), true)
}

///|
// FAILURE: Constant time equal - different lengths
test "constant_time_equal_different_length" {
  let a = b"secret123"
  let shorter = b"secret12"
  let longer = b"secret1234"
  // Different lengths should return false (not leak timing)
  assert_eq(@helpers.constant_time_equal(a, shorter), false)
  assert_eq(@helpers.constant_time_equal(a, longer), false)
}

///|
// FAILURE: Constant time equal - single byte difference
test "constant_time_equal_single_byte_diff" {
  // Same length, differs only in last byte
  let a = b"secret123"
  let b = b"secret124"
  assert_eq(@helpers.constant_time_equal(a, b), false)
  // Differs only in first byte
  let c = b"aecret123"
  assert_eq(@helpers.constant_time_equal(a, c), false)
  // Differs in middle byte
  let d = b"secrat123"
  assert_eq(@helpers.constant_time_equal(a, d), false)
}

///|
// SUCCESS: Hex encoding/decoding
test "hex_roundtrip" {
  let bytes = b"\xde\xad\xbe\xef"
  let hex = @helpers.bytes_to_hex(bytes)
  assert_eq(hex, "deadbeef")
  let decoded = @helpers.hex_to_bytes(hex) catch { _ => panic() }
  assert_eq(decoded, bytes)
}
