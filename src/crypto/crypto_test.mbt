///|
// Tests for crypto package

///|
// SUCCESS: SHA-256 hash produces correct length
test "sha256_length" {
  let data = b"hello world"
  let hash = @crypto.sha256(data)
  // SHA-256 always produces 32 bytes
  assert_eq(hash.length(), 32)
}

///|
// SUCCESS: SHA-256 hash is deterministic
test "sha256_deterministic" {
  let data = b"test data for hashing"
  let hash1 = @crypto.sha256(data)
  let hash2 = @crypto.sha256(data)
  assert_eq(hash1, hash2)
}

///|
// SUCCESS: Different inputs produce different hashes
test "sha256_different_inputs" {
  let hash1 = @crypto.sha256(b"input1")
  let hash2 = @crypto.sha256(b"input2")
  assert_eq(hash1 == hash2, false)
}

///|
// SUCCESS: Create signed data for WebAuthn
test "create_signed_data" {
  let auth_data = b"authenticator-data-bytes"
  let client_data = b"client-data-json"
  let signed_data = @crypto.create_signed_data(auth_data, client_data)
  // Should be auth_data + SHA-256(client_data)
  // auth_data (24) + hash (32) = 56 bytes
  assert_eq(signed_data.length(), 24 + 32)
}

///|
// SUCCESS: Normalize 64-byte signature (already raw)
test "normalize_signature_raw" {
  // Create a 64-byte "signature"
  let raw_sig = Bytes::make(64, b'\xAB')
  let normalized = @crypto.normalize_signature(raw_sig) catch { _ => panic() }
  assert_eq(normalized.length(), 64)
  assert_eq(normalized, raw_sig)
}

///|
// FAILURE: Invalid signature length
test "normalize_signature_invalid_length" {
  let bad_sig = Bytes::make(50, b'\x00')
  let result = try {
    let _ = @crypto.normalize_signature(bad_sig)
    Ok(())
  } catch {
    @crypto.ECDSAError::InvalidSignature(_) => Err("InvalidSignature")
    _ => Err("OtherError")
  }
  assert_eq(result, Err("InvalidSignature"))
}

///|
// SUCCESS: ES256 algorithm check
test "is_es256" {
  assert_eq(@crypto.is_es256(-7), true)
  assert_eq(@crypto.is_es256(-257), false)
  assert_eq(@crypto.is_es256(0), false)
}

// ============================================================================
// WEBCRYPTO FFI TESTS (ES256 signature verification)
// ============================================================================

///|
// Test: ES256 verify with invalid signature returns false (not error)
// This tests that the WebCrypto FFI can be called and handles errors gracefully
async test "verify_es256_async_invalid_signature" {
  // Create a valid-looking public key structure
  let x = Bytes::make(32, b'\x01')
  let y = Bytes::make(32, b'\x02')
  let public_key = @crypto.EC2PublicKey::new(x, y, -7)
  // Invalid signature
  let signature = Bytes::make(64, b'\x00')
  // Some data
  let data = b"test data to verify"
  // Should return false (invalid), not throw
  let result = @crypto.verify_es256_async(public_key, signature, data)
  // Invalid key coordinates will fail key import, returning false
  assert_eq(result, false)
}

///|
// Test: ES256 verify with real P-256 test vectors
// These vectors are from a known valid ES256 key pair
async test "verify_es256_async_with_test_vectors" {
  // Test vector: A valid P-256 public key from WebAuthn tests
  // Generated using: crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, true, ["sign", "verify"])
  // This is a well-known test key - DO NOT use in production
  // 
  // Public Key (JWK format):
  // x: 71BVaB3W8ijN95umlD8bUjP4EiGo_46UXE2VITFmUwE
  // y: jB7-2P3LZKV-KlvMwU7zLvBB6TZeVVvkZzlvHqXDtLc
  let x = @helpers.base64url_decode("71BVaB3W8ijN95umlD8bUjP4EiGo_46UXE2VITFmUwE") catch {
    _ => panic()
  }
  let y = @helpers.base64url_decode("jB7-2P3LZKV-KlvMwU7zLvBB6TZeVVvkZzlvHqXDtLc") catch {
    _ => panic()
  }
  let public_key = @crypto.EC2PublicKey::new(x, y, -7)
  // Test with invalid signature (correct length but wrong data)
  // Even with valid public key, invalid signature should return false
  let invalid_signature = Bytes::make(64, b'\xAB')
  let data = b"test message"
  let result = @crypto.verify_es256_async(public_key, invalid_signature, data)
  // Should return false since signature doesn't match
  assert_eq(result, false)
}
