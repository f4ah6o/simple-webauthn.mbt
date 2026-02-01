///|
/// AttestationObject parsing for WebAuthn registration.
///
/// The attestation object is a CBOR-encoded structure containing:
/// - fmt: Attestation statement format identifier (e.g., "none", "packed", "fido-u2f")
/// - attStmt: Attestation statement (format-specific)
/// - authData: Authenticator data bytes

///|
/// Error types for AttestationObject parsing.
pub suberror AttestationObjectError {
  CborDecodeError(String)
  InvalidFormat(String)
  MissingField(String)
  InvalidAuthData(String)
}

///|
/// Attestation statement format types.
/// See: https://www.w3.org/TR/webauthn/#sctn-defined-attestation-formats
///
/// ## Implementation Policy
/// 
/// This enum defines all standard attestation formats for completeness,
/// but **verification support is limited**:
/// 
/// - `None`: Fully supported (no attestation to verify)
/// - `Packed`: Supported (self-attestation and basic attestation)
/// - Others: Parsed but verification returns `UnsupportedAttestation` in server
/// 
/// This is intentional: most real-world deployments use `None` or `Packed`.
/// Full attestation verification (TPM, Android, etc.) requires platform-specific
/// certificate chains that are rarely needed in practice.
pub enum AttestationFormat {
  /// No attestation
  None
  /// Packed attestation (self-attestation or full attestation)
  Packed
  /// TPM attestation
  TPM
  /// Android Key attestation
  AndroidKey
  /// Android SafetyNet attestation
  AndroidSafetyNet
  /// FIDO U2F attestation
  FidoU2F
  /// Apple Anonymous attestation
  Apple
  /// Unknown/unsupported format
  Unknown(String)
} derive(Show, Eq)

///|
/// Convert string to AttestationFormat.
pub fn AttestationFormat::from_string(s : String) -> AttestationFormat {
  match s {
    "none" => None
    "packed" => Packed
    "tpm" => TPM
    "android-key" => AndroidKey
    "android-safetynet" => AndroidSafetyNet
    "fido-u2f" => FidoU2F
    "apple" => Apple
    _ => Unknown(s)
  }
}

///|
/// Convert AttestationFormat to string.
pub fn AttestationFormat::to_string(self : AttestationFormat) -> String {
  match self {
    None => "none"
    Packed => "packed"
    TPM => "tpm"
    AndroidKey => "android-key"
    AndroidSafetyNet => "android-safetynet"
    FidoU2F => "fido-u2f"
    Apple => "apple"
    Unknown(s) => s
  }
}

///|
/// Parsed attestation object.
pub struct AttestationObject {
  /// Attestation statement format
  fmt : AttestationFormat
  /// Raw attestation statement as CBOR value.
  /// 
  /// ## Design Note
  /// 
  /// This field is intentionally left as raw `CborValue` (not parsed into
  /// format-specific structs) because:
  /// 
  /// 1. Attestation statement interpretation is format-dependent
  /// 2. Server-side verification handles the format-specific logic
  /// 3. Most deployments use `fmt: "none"` where attStmt is empty `{}`
  /// 
  /// The server package will interpret this based on `fmt` when needed.
  att_stmt : @cbor.CborValue
  /// Raw authenticator data bytes
  auth_data_raw : Bytes
  /// Parsed authenticator data
  auth_data : AuthenticatorData
} derive(Show, Eq)

///|
/// Parse attestation object from base64url-encoded string.
pub fn parse_attestation_object_base64url(
  base64url_data : @types.Base64URLString,
) -> AttestationObject raise {
  let bytes = decode_base64url_string(base64url_data)
  parse_attestation_object(bytes)
}

///|
/// Parse attestation object from raw CBOR bytes.
pub fn parse_attestation_object(
  data : Bytes,
) -> AttestationObject raise AttestationObjectError {
  // Decode CBOR
  let cbor_value = @cbor.decode(data) catch {
    CborError(msg) => raise CborDecodeError(msg)
  }
  // Expect a map
  let map = match cbor_value {
    VMap(entries) => entries
    _ => raise InvalidFormat("Expected CBOR map at root")
  }
  // Extract fields using a loop
  let mut fmt_opt : String? = None
  let mut att_stmt_opt : @cbor.CborValue? = None
  let mut auth_data_opt : Bytes? = None
  for entry in map {
    let (key, value) = entry
    match key {
      VString(k) =>
        match k {
          "fmt" =>
            match value {
              VString(s) => fmt_opt = Some(s)
              _ => raise InvalidFormat("'fmt' must be a string")
            }
          "attStmt" => att_stmt_opt = Some(value)
          "authData" =>
            match value {
              VBytes(b) => auth_data_opt = Some(b)
              _ => raise InvalidFormat("'authData' must be a byte string")
            }
          _ => () // Ignore unknown fields
        }
      _ => () // Ignore non-string keys
    }
  }
  // Validate required fields
  let fmt_str = match fmt_opt {
    Some(s) => s
    None => raise MissingField("fmt")
  }
  let att_stmt = match att_stmt_opt {
    Some(v) => v
    None => raise MissingField("attStmt")
  }
  let auth_data_raw = match auth_data_opt {
    Some(b) => b
    None => raise MissingField("authData")
  }
  // Parse authenticator data
  let auth_data = parse_authenticator_data(auth_data_raw) catch {
    TooShort(expected, actual) =>
      raise InvalidAuthData(
        "AuthenticatorData too short: expected \{expected}, got \{actual}",
      )
    InvalidAAGUID => raise InvalidAuthData("Invalid AAGUID")
    InvalidCredentialId => raise InvalidAuthData("Invalid credential ID")
    InvalidPublicKey(msg) => raise InvalidAuthData("Invalid public key: \{msg}")
    CborDecodeError(msg) => raise InvalidAuthData("CBOR decode error: \{msg}")
    InvalidFlags(f) => raise InvalidAuthData("Invalid flags: \{f}")
  }
  {
    fmt: AttestationFormat::from_string(fmt_str),
    att_stmt,
    auth_data_raw,
    auth_data,
  }
}

///|
/// Get the attestation format.
pub fn get_format(att_obj : AttestationObject) -> AttestationFormat {
  att_obj.fmt
}

///|
/// Check if this is a "none" attestation (no attestation statement).
pub fn is_none_attestation(att_obj : AttestationObject) -> Bool {
  match att_obj.fmt {
    None => true
    _ => false
  }
}

///|
/// Get the authenticator data.
pub fn get_auth_data(att_obj : AttestationObject) -> AuthenticatorData {
  att_obj.auth_data
}

///|
/// Get the raw authenticator data bytes.
pub fn get_auth_data_raw(att_obj : AttestationObject) -> Bytes {
  att_obj.auth_data_raw
}

///|
/// Get the credential ID from the attestation object.
pub fn get_credential_id_from_attestation(
  att_obj : AttestationObject,
) -> Bytes? {
  get_credential_id(att_obj.auth_data)
}

///|
/// Get the public key bytes from the attestation object.
pub fn get_public_key_from_attestation(att_obj : AttestationObject) -> Bytes? {
  get_credential_public_key(att_obj.auth_data)
}
