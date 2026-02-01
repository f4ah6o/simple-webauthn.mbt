///|
/// WebAuthn-specific errors.
pub(all) suberror WebAuthnError {
  /// Invalid Base64URL encoding
  InvalidBase64URL(String)
  /// Invalid authenticator data
  InvalidAuthenticatorData(String)
  /// Invalid client data JSON
  InvalidClientDataJSON(String)
  /// Invalid attestation object
  InvalidAttestationObject(String)
  /// Invalid COSE key
  InvalidCOSEKey(String)
  /// Signature verification failed
  SignatureVerificationFailed(String)
  /// Challenge mismatch
  ChallengeMismatch
  /// Origin mismatch
  OriginMismatch(expected~ : String, actual~ : String)
  /// RP ID mismatch
  RpIdMismatch(expected~ : String, actual~ : String)
  /// User verification required but not performed
  UserVerificationRequired
  /// Counter too low (potential cloned authenticator)
  CounterTooLow(expected~ : UInt, actual~ : UInt)
  /// Unsupported attestation format
  UnsupportedAttestationFormat(String)
  /// Browser does not support WebAuthn
  WebAuthnNotSupported
  /// User cancelled the operation
  UserCancelled
  /// Timeout
  Timeout
  /// Unknown error
  Unknown(String)
} derive(Show)

///|
/// Authenticator flags parsed from authenticator data.
pub struct AuthenticatorFlags {
  /// User Present (UP) - user interacted with authenticator
  up : Bool
  /// User Verified (UV) - user verification performed (biometric, PIN, etc.)
  uv : Bool
  /// Backup Eligibility (BE) - credential can be backed up
  be : Bool
  /// Backup State (BS) - credential is currently backed up
  bs : Bool
  /// Attested Credential Data (AT) - includes credential data
  at : Bool
  /// Extension Data (ED) - includes extension data
  ed : Bool
  /// Raw flag byte value
  raw : Byte
} derive(Show, Eq)

///|
/// Parsed authenticator data from attestation/assertion.
pub struct ParsedAuthenticatorData {
  /// SHA-256 hash of the RP ID
  rp_id_hash : Bytes
  /// Authenticator flags
  flags : AuthenticatorFlags
  /// Signature counter (32-bit big-endian)
  counter : UInt
  /// AAGUID of the authenticator (16 bytes, only in attestation)
  aaguid : Bytes?
  /// Credential ID (only in attestation)
  credential_id : Bytes?
  /// COSE-encoded credential public key (only in attestation)
  credential_public_key : Bytes?
  /// Extension data (if ED flag is set)
  extensions_data : Json?
} derive(Show, Eq)

///|
/// Determine credential device type from backup eligibility flag.
pub fn AuthenticatorFlags::credential_device_type(
  self : AuthenticatorFlags,
) -> CredentialDeviceType {
  if self.be {
    MultiDevice
  } else {
    SingleDevice
  }
}

///|
/// Whether the credential is currently backed up.
pub fn AuthenticatorFlags::credential_backed_up(
  self : AuthenticatorFlags,
) -> Bool {
  self.bs
}

///|
/// Parsed client data JSON from the browser.
pub struct ParsedClientDataJSON {
  /// Type of operation ("webauthn.create" or "webauthn.get")
  type_ : String
  /// Base64URL-encoded challenge
  challenge : Base64URLString
  /// Origin that initiated the operation
  origin : String
  /// Whether the request was cross-origin
  cross_origin : Bool?
  /// Token binding (rarely used)
  token_binding : Json?
} derive(Show, Eq)

///|
/// Parsed attestation object from registration.
pub struct ParsedAttestationObject {
  /// Attestation format
  fmt : AttestationFormat
  /// Attestation statement (format-specific)
  att_stmt : Json
  /// Raw authenticator data bytes
  auth_data : Bytes
} derive(Show, Eq)

///|
/// Verified registration result.
pub struct VerifiedRegistrationResponse {
  /// Whether verification succeeded
  verified : Bool
  /// Registration info (if verified)
  registration_info : RegistrationInfo?
} derive(Show, Eq)

///|
/// Information extracted from a verified registration.
pub struct RegistrationInfo {
  /// Raw credential ID bytes
  credential_id : Bytes
  /// Raw credential public key (COSE format)
  credential_public_key : Bytes
  /// Initial counter value
  counter : UInt
  /// Device type (single/multi)
  credential_device_type : CredentialDeviceType
  /// Whether credential is backed up
  credential_backed_up : Bool
  /// Authenticator AAGUID as UUID string
  aaguid : String
  /// Attestation format
  attestation_format : AttestationFormat
} derive(Show, Eq)

///|
/// Verified authentication result.
pub struct VerifiedAuthenticationResponse {
  /// Whether verification succeeded
  verified : Bool
  /// Authentication info (if verified)
  authentication_info : AuthenticationInfo?
} derive(Show, Eq)

///|
/// Information extracted from a verified authentication.
pub struct AuthenticationInfo {
  /// Credential ID used
  credential_id : Bytes
  /// New counter value (should be stored)
  new_counter : UInt
  /// Device type
  credential_device_type : CredentialDeviceType
  /// Whether credential is backed up
  credential_backed_up : Bool
  /// Origin from client data
  origin : String
  /// RP ID hash from authenticator data
  rp_id_hash : Bytes
} derive(Show, Eq)
