///|
/// SHA-256 hashing utilities for WebAuthn.
///
/// This module wraps `moonbitlang/x/crypto` SHA-256 and provides
/// WebAuthn-specific convenience functions.

///|
/// Compute SHA-256 hash of bytes.
/// Returns a 32-byte hash.
pub fn sha256(data : Bytes) -> Bytes {
  let hash_arr = @xcrypto.sha256(data)
  Bytes::from_array(hash_arr[:])
}

///|
/// Compute SHA-256 hash of a string (UTF-8 encoded).
pub fn sha256_string(s : String) -> Bytes {
  sha256(@encoding.encode(@encoding.Encoding::UTF8, s))
}

///|
/// Compute SHA-256 hash of the rpId for comparison with authenticator data.
/// This is used to verify that the authenticator used the correct rpId.
pub fn hash_rp_id(rp_id : String) -> Bytes {
  sha256_string(rp_id)
}

///|
/// Verify that a hash matches the expected rpIdHash in authenticator data.
pub fn verify_rp_id_hash(rp_id_hash : Bytes, expected_rp_id : String) -> Bool {
  let expected_hash = hash_rp_id(expected_rp_id)
  @helpers.constant_time_equal(rp_id_hash, expected_hash)
}

///|
/// Compute the hash of clientDataJSON for signature verification.
/// In WebAuthn, signatures are computed over: authenticatorData || SHA-256(clientDataJSON)
pub fn hash_client_data_json(client_data_json : Bytes) -> Bytes {
  sha256(client_data_json)
}

///|
/// Create the signed data for signature verification.
/// WebAuthn signatures are over: authenticatorData || SHA-256(clientDataJSON)
pub fn create_signed_data(
  auth_data_raw : Bytes,
  client_data_json : Bytes,
) -> Bytes {
  let client_data_hash = hash_client_data_json(client_data_json)
  @helpers.bytes_concat([auth_data_raw, client_data_hash])
}
