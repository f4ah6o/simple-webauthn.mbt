///|
/// ECDSA signature verification for WebAuthn (ES256 algorithm).
///
/// This module provides ECDSA P-256 (secp256r1) signature verification.
///
/// ## Supported Algorithm
/// 
/// - ES256 (ECDSA with SHA-256 and P-256 curve)
///   - COSE Algorithm ID: -7
///   - This is the most common algorithm for WebAuthn
///
/// ## Design Note
/// 
/// Pure MoonBit ECDSA implementation is complex. For the JS target,
/// we'll use WebCrypto API via FFI. For now, we provide the parsing
/// logic and a stub for verification.

///|
/// Error types for ECDSA operations.
pub suberror ECDSAError {
  InvalidPublicKey(String)
  InvalidSignature(String)
  VerificationFailed(String)
  UnsupportedAlgorithm(Int)
}

///|
/// Parsed EC2 public key coordinates.
pub struct EC2PublicKey {
  /// X coordinate (32 bytes for P-256)
  x : Bytes
  /// Y coordinate (32 bytes for P-256)
  y : Bytes
  /// COSE algorithm (-7 for ES256)
  alg : Int
} derive(Show, Eq)

///|
/// Create a new EC2 public key from coordinates.
/// 
/// For P-256 (ES256), both x and y must be 32 bytes.
pub fn EC2PublicKey::new(x : Bytes, y : Bytes, alg : Int) -> EC2PublicKey {
  { x, y, alg }
}

///|
/// Parse a COSE-encoded EC2 public key.
/// Returns the x and y coordinates for signature verification.
pub fn parse_cose_ec2_key(cose_key : Bytes) -> EC2PublicKey raise ECDSAError {
  // COSE EC2 key structure (CBOR map):
  // 1 (kty): 2 (EC2)
  // 3 (alg): -7 (ES256)
  // -1 (crv): 1 (P-256)
  // -2 (x): 32 bytes
  // -3 (y): 32 bytes
  let cbor_value = @cbor.decode(cose_key) catch {
    CborError(msg) => raise InvalidPublicKey("CBOR decode failed: \{msg}")
  }
  let map = match cbor_value {
    VMap(entries) => entries
    _ => raise InvalidPublicKey("Expected CBOR map")
  }
  // Extract fields from CBOR map
  let mut kty : Int64? = None
  let mut alg : Int64? = None
  let mut crv : Int64? = None
  let mut x_bytes : Bytes? = None
  let mut y_bytes : Bytes? = None
  for entry in map {
    let (key, value) = entry
    match key {
      VInt(k) =>
        match k {
          1L =>
            // kty
            match value {
              VUInt(v) => kty = Some(v.reinterpret_as_int64())
              VInt(v) => kty = Some(v)
              _ => ()
            }
          3L =>
            // alg
            match value {
              VInt(v) => alg = Some(v)
              VUInt(v) => alg = Some(v.reinterpret_as_int64())
              _ => ()
            }
          -1L =>
            // crv (negative key)
            match value {
              VUInt(v) => crv = Some(v.reinterpret_as_int64())
              VInt(v) => crv = Some(v)
              _ => ()
            }
          -2L =>
            // x coordinate
            match value {
              VBytes(b) => x_bytes = Some(b)
              _ => ()
            }
          -3L =>
            // y coordinate
            match value {
              VBytes(b) => y_bytes = Some(b)
              _ => ()
            }
          _ => ()
        }
      VUInt(k) =>
        match k {
          1UL =>
            // kty
            match value {
              VUInt(v) => kty = Some(v.reinterpret_as_int64())
              VInt(v) => kty = Some(v)
              _ => ()
            }
          3UL =>
            // alg
            match value {
              VInt(v) => alg = Some(v)
              VUInt(v) => alg = Some(v.reinterpret_as_int64())
              _ => ()
            }
          _ => ()
        }
      _ => ()
    }
  }
  // Validate key type
  match kty {
    Some(2L) => () // EC2
    Some(other) => raise InvalidPublicKey("Expected kty=2 (EC2), got \{other}")
    None => raise InvalidPublicKey("Missing kty field")
  }
  // Get algorithm (default to ES256 if not specified)
  let algorithm = match alg {
    Some(-7L) => -7 // ES256
    Some(other) => raise UnsupportedAlgorithm(other.to_int())
    None => -7 // Default to ES256
  }
  // Validate curve
  match crv {
    Some(1L) => () // P-256
    Some(other) =>
      raise InvalidPublicKey("Expected crv=1 (P-256), got \{other}")
    None => () // Curve can be implied for ES256
  }
  // Extract coordinates
  let x = match x_bytes {
    Some(b) => b
    None => raise InvalidPublicKey("Missing x coordinate")
  }
  let y = match y_bytes {
    Some(b) => b
    None => raise InvalidPublicKey("Missing y coordinate")
  }
  // P-256 coordinates must be 32 bytes
  if x.length() != 32 {
    raise InvalidPublicKey("x coordinate must be 32 bytes, got \{x.length()}")
  }
  if y.length() != 32 {
    raise InvalidPublicKey("y coordinate must be 32 bytes, got \{y.length()}")
  }
  { x, y, alg: algorithm }
}

///|
/// Normalize signature to raw 64-byte format.
/// WebAuthn signatures may be DER-encoded; WebCrypto expects raw format.
pub fn normalize_signature(sig : Bytes) -> Bytes raise ECDSAError {
  // If already 64 bytes, assume raw format
  if sig.length() == 64 {
    return sig
  }
  // Try to parse as DER
  if sig.length() > 64 && sig[0] == b'\x30' {
    return parse_der_signature(sig)
  }
  raise InvalidSignature(
    "Invalid signature length: \{sig.length()} (expected 64 or DER-encoded)",
  )
}

///|
/// Parse a DER-encoded ECDSA signature to raw format.
/// DER format: 0x30 <len> 0x02 <r-len> <r> 0x02 <s-len> <s>
fn parse_der_signature(der : Bytes) -> Bytes raise ECDSAError {
  if der.length() < 8 {
    raise InvalidSignature("DER signature too short")
  }
  if der[0] != b'\x30' {
    raise InvalidSignature("Invalid DER sequence tag")
  }
  let mut offset = 2 // Skip 0x30 and length byte
  // Parse r
  if der[offset] != b'\x02' {
    raise InvalidSignature("Invalid DER integer tag for r")
  }
  offset = offset + 1
  let r_len = der[offset].to_int()
  offset = offset + 1
  let r_bytes = @helpers.bytes_slice(der, offset, r_len) catch {
    _ => raise InvalidSignature("Failed to extract r")
  }
  offset = offset + r_len
  // Parse s
  if der[offset] != b'\x02' {
    raise InvalidSignature("Invalid DER integer tag for s")
  }
  offset = offset + 1
  let s_len = der[offset].to_int()
  offset = offset + 1
  let s_bytes = @helpers.bytes_slice(der, offset, s_len) catch {
    _ => raise InvalidSignature("Failed to extract s")
  }
  // Normalize r and s to 32 bytes each (remove leading zeros, pad if needed)
  let r_normalized = normalize_integer(r_bytes, 32)
  let s_normalized = normalize_integer(s_bytes, 32)
  @helpers.bytes_concat([r_normalized, s_normalized])
}

///|
/// Normalize an integer to a fixed length (remove leading zeros or pad).
fn normalize_integer(bytes : Bytes, target_len : Int) -> Bytes {
  let len = bytes.length()
  if len == target_len {
    return bytes
  }
  if len > target_len {
    // Remove leading zeros
    let skip = len - target_len
    @helpers.bytes_slice(bytes, skip, target_len) catch {
      _ => bytes
    }
  } else {
    // Pad with leading zeros
    let padding = Bytes::make(target_len - len, b'\x00')
    @helpers.bytes_concat([padding, bytes])
  }
}

///|
/// Verify an ES256 signature (stub implementation).
/// 
/// ## Note
/// 
/// This is a placeholder. Full verification requires WebCrypto FFI
/// which will be implemented in a follow-up. For now, this always
/// returns false to indicate "not verified".
/// 
/// In production, use the async `verify_es256_async` function which
/// calls the WebCrypto API.
pub fn verify_es256_sync(
  _public_key : EC2PublicKey,
  _signature : Bytes,
  _data : Bytes,
) -> Bool {
  // TODO: Implement pure MoonBit ECDSA or FFI
  // For now, return false (not verified)
  false
}

///|
/// Create an uncompressed public key in SEC1 format.
/// Format: 0x04 || x (32 bytes) || y (32 bytes)
/// This is the format expected by WebCrypto for P-256 keys.
pub fn to_uncompressed_public_key(key : EC2PublicKey) -> Bytes {
  let prefix = Bytes::make(1, b'\x04')
  @helpers.bytes_concat([prefix, key.x, key.y])
}

///|
/// Get the COSE algorithm identifier for ES256.
pub fn es256_algorithm() -> Int {
  -7
}

///|
/// Check if a COSE algorithm is ES256.
pub fn is_es256(alg : Int) -> Bool {
  alg == -7
}
