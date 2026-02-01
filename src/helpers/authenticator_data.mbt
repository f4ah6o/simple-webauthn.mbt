///|
/// AuthenticatorData parsing for WebAuthn.
/// 
/// Authenticator data is a binary structure with the following layout:
/// - rpIdHash (32 bytes) - SHA-256 hash of the relying party ID
/// - flags (1 byte) - Bit flags for UP, UV, AT, ED, etc.
/// - signCount (4 bytes) - Big-endian signature counter
/// - attestedCredentialData (variable) - Present if AT flag is set
/// - extensions (variable) - Present if ED flag is set

///|
/// Error types for AuthenticatorData parsing.
pub suberror AuthenticatorDataError {
  TooShort(Int, Int) // (expected_min, actual)
  InvalidFlags(Byte)
  InvalidAAGUID
  InvalidCredentialId
  InvalidPublicKey(String)
  CborDecodeError(String)
}

///|
/// Authenticator data flags.
/// Bit 0: User Present (UP)
/// Bit 2: User Verified (UV)
/// Bit 3: Backup Eligibility (BE)
/// Bit 4: Backup State (BS)
/// Bit 6: Attested Credential Data present (AT)
/// Bit 7: Extension Data present (ED)
pub struct AuthFlags {
  /// User was present during authentication
  user_present : Bool
  /// User was verified (e.g., biometric, PIN)
  user_verified : Bool
  /// Credential is backup eligible (synced passkey)
  backup_eligible : Bool
  /// Credential has been backed up
  backup_state : Bool
  /// Attested credential data is included
  attested_credential_data : Bool
  /// Extension data is included
  extension_data : Bool
  /// Raw flags byte
  raw : Byte
} derive(Show, Eq)

///|
/// Parse flags byte into AuthFlags struct.
pub fn parse_auth_flags(flags : Byte) -> AuthFlags {
  let f = flags.to_int()
  {
    user_present: (f & 0x01) != 0,
    user_verified: (f & 0x04) != 0,
    backup_eligible: (f & 0x08) != 0,
    backup_state: (f & 0x10) != 0,
    attested_credential_data: (f & 0x40) != 0,
    extension_data: (f & 0x80) != 0,
    raw: flags,
  }
}

///|
/// Attested credential data (present during registration).
pub struct AttestedCredentialData {
  /// Authenticator Attestation GUID
  aaguid : Bytes
  /// Credential ID
  credential_id : Bytes
  /// COSE-encoded public key (raw bytes)
  credential_public_key : Bytes
  /// Length of the attested credential data section
  length : Int
} derive(Show, Eq)

///|
/// Parsed authenticator data.
pub struct AuthenticatorData {
  /// SHA-256 hash of the relying party ID
  rp_id_hash : Bytes
  /// Authentication flags
  flags : AuthFlags
  /// Signature counter (for replay attack detection)
  sign_count : UInt
  /// Attested credential data (only present if AT flag is set)
  attested_credential_data : AttestedCredentialData?
  /// Extension data (raw CBOR bytes, only present if ED flag is set)
  extensions : Bytes?
  /// Total length of parsed data
  length : Int
} derive(Show, Eq)

///|
/// Minimum length of authenticator data (rpIdHash + flags + signCount).
let min_auth_data_length : Int = 32 + 1 + 4 // 37 bytes

///|
/// Parse authenticator data from bytes.
pub fn parse_authenticator_data(
  data : Bytes,
) -> AuthenticatorData raise AuthenticatorDataError {
  if data.length() < min_auth_data_length {
    raise TooShort(min_auth_data_length, data.length())
  }
  // Parse rpIdHash (32 bytes)
  let rp_id_hash = bytes_slice(data, 0, 32) catch {
    _ => raise TooShort(32, data.length())
  }
  // Parse flags (1 byte)
  let flags = parse_auth_flags(data[32])
  // Parse signCount (4 bytes, big-endian)
  let sign_count = read_u32_be(data, 33) catch {
    _ => raise TooShort(37, data.length())
  }
  let mut offset = 37
  // Parse attested credential data if AT flag is set
  let attested_credential_data = if flags.attested_credential_data {
    let acd = parse_attested_credential_data(data, offset)
    offset = offset + acd.length
    Some(acd)
  } else {
    None
  }
  // Parse extensions if ED flag is set
  let extensions = if flags.extension_data {
    // Extensions are CBOR-encoded, take the rest
    let ext = bytes_slice_from(data, offset) catch {
      _ => raise TooShort(offset, data.length())
    }
    offset = data.length()
    Some(ext)
  } else {
    None
  }
  {
    rp_id_hash,
    flags,
    sign_count,
    attested_credential_data,
    extensions,
    length: offset,
  }
}

///|
/// Parse attested credential data from bytes at the given offset.
fn parse_attested_credential_data(
  data : Bytes,
  offset : Int,
) -> AttestedCredentialData raise AuthenticatorDataError {
  // AAGUID (16 bytes)
  if offset + 16 > data.length() {
    raise TooShort(offset + 16, data.length())
  }
  let aaguid = bytes_slice(data, offset, 16) catch { _ => raise InvalidAAGUID }
  // Credential ID length (2 bytes, big-endian)
  if offset + 18 > data.length() {
    raise TooShort(offset + 18, data.length())
  }
  let cred_id_len = read_u16_be(data, offset + 16) catch {
    _ => raise InvalidCredentialId
  }
  let cred_id_len_int = cred_id_len.reinterpret_as_int()
  // Credential ID
  if offset + 18 + cred_id_len_int > data.length() {
    raise TooShort(offset + 18 + cred_id_len_int, data.length())
  }
  let credential_id = bytes_slice(data, offset + 18, cred_id_len_int) catch {
    _ => raise InvalidCredentialId
  }
  // Public key (CBOR-encoded)
  // The public key is variable-length CBOR, so we need to parse it
  // to determine its length. For now, we'll extract a reasonable amount
  // and let the CBOR parser handle validation.
  let pk_start = offset + 18 + cred_id_len_int
  // We need to determine the length of the CBOR-encoded public key.
  // This is tricky without actually parsing the CBOR.
  // For now, we'll try to parse it and get the length.
  let pk_bytes = bytes_slice_from(data, pk_start) catch {
    _ => raise InvalidPublicKey("Cannot slice public key bytes")
  }
  // Try to decode CBOR to get actual length
  let pk_len = get_cbor_length(pk_bytes)
  let credential_public_key = bytes_slice(data, pk_start, pk_len) catch {
    _ => raise InvalidPublicKey("Public key too short")
  }
  let total_length = 16 + 2 + cred_id_len_int + pk_len
  { aaguid, credential_id, credential_public_key, length: total_length }
}

///|
/// Estimate the length of a CBOR-encoded value.
/// This is needed because CBOR is self-delimiting.
fn get_cbor_length(data : Bytes) -> Int raise AuthenticatorDataError {
  // Try to decode and see how much we consumed
  // For COSE keys, we expect a map at the root
  let result = @cbor.decode(data) catch {
    CborError(msg) => raise CborDecodeError(msg)
  }
  // Re-encode to get the exact length
  let reencoded = @cbor.encode(result)
  reencoded.length()
}

///|
/// Verify that the rpIdHash matches the expected rpId.
pub fn verify_rp_id_hash(
  auth_data : AuthenticatorData,
  expected_rp_id : String,
) -> Bool {
  let utf8_bytes = @encoding.encode(@encoding.Encoding::UTF8, expected_rp_id)
  let hash_arr = @xcrypto.sha256(utf8_bytes)
  let expected_hash = Bytes::from_array(hash_arr[:])
  constant_time_equal(auth_data.rp_id_hash, expected_hash)
}

///|
/// Check if user presence was verified.
pub fn is_user_present(auth_data : AuthenticatorData) -> Bool {
  auth_data.flags.user_present
}

///|
/// Check if user verification was performed.
pub fn is_user_verified(auth_data : AuthenticatorData) -> Bool {
  auth_data.flags.user_verified
}

///|
/// Check if this is a backup-eligible (synced) passkey.
pub fn is_backup_eligible(auth_data : AuthenticatorData) -> Bool {
  auth_data.flags.backup_eligible
}

///|
/// Get the credential ID from attested credential data.
pub fn get_credential_id(auth_data : AuthenticatorData) -> Bytes? {
  match auth_data.attested_credential_data {
    Some(acd) => Some(acd.credential_id)
    None => None
  }
}

///|
/// Get the public key bytes from attested credential data.
pub fn get_credential_public_key(auth_data : AuthenticatorData) -> Bytes? {
  match auth_data.attested_credential_data {
    Some(acd) => Some(acd.credential_public_key)
    None => None
  }
}
