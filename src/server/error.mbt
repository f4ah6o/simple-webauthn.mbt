///|
/// Policy for handling signature counter (signCount) validation.
/// 
/// The signature counter is used to detect cloned authenticators.
/// Different authenticators have different counter behaviors:
/// - Hardware keys: Usually increment counter on each use
/// - Platform authenticators: May or may not use counters
/// - Synced passkeys: Often keep counter at 0
/// 
/// ## Usage
/// ```
/// let options = VerifyAuthenticationOptions::new(...)
///   .with_sign_count_policy(SignCountPolicy::AllowZero)
/// ```
pub enum SignCountPolicy {
  /// Strict validation: counter must always increase.
  /// Use this for high-security scenarios with hardware authenticators.
  Strict
  /// Allow both counters to be 0 (default).
  /// This is the recommended setting for most applications as it
  /// accommodates synced passkeys while still detecting obvious clones.
  AllowZero
  /// Permissive: never fail on counter issues.
  /// Use this if you have many synced passkeys and prefer availability
  /// over clone detection. Consider logging warnings instead.
  Permissive
} derive(Show, Eq)

///|
/// Error types for registration verification.
///
/// These provide detailed failure reasons for debugging and logging.
/// Each variant represents a specific validation failure in the
/// WebAuthn registration flow.

///|
/// Registration verification error.
/// 
/// All variants include a descriptive message for debugging.
/// Production code should log these for troubleshooting while
/// returning a generic error to the client.
pub suberror RegistrationVerifyError {
  /// clientDataJSON.type is not "webauthn.create"
  InvalidClientDataType(String)
  /// Challenge in response doesn't match expected challenge
  ChallengeMismatch(String)
  /// Origin in response doesn't match expected origin(s)
  OriginMismatch(String)
  /// rpIdHash in authenticatorData doesn't match expected rpId
  RpIdHashMismatch(String)
  /// User presence flag (UP) is not set
  UserNotPresent
  /// User verification required but UV flag not set
  UserVerificationRequired
  /// Attested credential data (AT flag) not present in registration
  AttestedCredentialDataMissing
  /// Credential ID is missing or invalid
  InvalidCredentialId(String)
  /// Public key is missing or invalid
  InvalidPublicKey(String)
  /// Unsupported attestation format (only None/Packed supported)
  UnsupportedAttestationFormat(String)
  /// Attestation signature verification failed
  AttestationSignatureInvalid(String)
  /// Signature verification not yet implemented (temporary)
  SignatureVerificationNotImplemented
  /// Failed to parse clientDataJSON
  ClientDataParseError(String)
  /// Failed to parse attestationObject
  AttestationObjectParseError(String)
  /// Failed to decode base64url data
  Base64DecodeError(String)
  /// Generic validation error
  ValidationError(String)
}

///|
/// Authentication verification error.
/// 
/// Similar to RegistrationVerifyError but for the authentication (login) flow.
pub suberror AuthenticationVerifyError {
  /// clientDataJSON.type is not "webauthn.get"
  InvalidClientDataType(String)
  /// Challenge in response doesn't match expected challenge
  ChallengeMismatch(String)
  /// Origin in response doesn't match expected origin(s)
  OriginMismatch(String)
  /// rpIdHash in authenticatorData doesn't match expected rpId
  RpIdHashMismatch(String)
  /// User presence flag (UP) is not set
  UserNotPresent
  /// User verification required but UV flag not set
  UserVerificationRequired
  /// Credential ID not found in allowed credentials list
  CredentialNotAllowed(String)
  /// Signature verification failed
  SignatureVerificationFailed(String)
  /// Sign count is not greater than previous (replay attack detected)
  SignCountInvalid(String)
  /// Failed to parse clientDataJSON
  ClientDataParseError(String)
  /// Failed to parse authenticatorData
  AuthenticatorDataParseError(String)
  /// Failed to decode base64url data
  Base64DecodeError(String)
  /// Public key is invalid or unsupported
  InvalidPublicKey(String)
  /// Generic validation error
  ValidationError(String)
}

///|
/// Result of successful registration verification.
pub struct VerifiedRegistration {
  /// The credential ID to store (base64url encoded for storage)
  credential_id : Bytes
  /// The public key in COSE format (for signature verification)
  credential_public_key : Bytes
  /// The COSE algorithm identifier (e.g., -7 for ES256)
  credential_algorithm : Int
  /// Signature counter (should be stored and checked on authentication)
  sign_count : UInt
  /// Whether the credential is backup eligible (synced passkey)
  backup_eligible : Bool
  /// Whether the credential has been backed up
  backup_state : Bool
  /// Authenticator AAGUID (can identify authenticator type)
  aaguid : Bytes
  /// Attestation format used
  attestation_format : @helpers.AttestationFormat
  /// Whether attestation was verified (false if fmt=none or not implemented)
  attestation_verified : Bool
} derive(Show, Eq)

///|
/// Options for registration verification.
pub struct VerifyRegistrationOptions {
  /// Expected challenge (must match clientDataJSON.challenge)
  expected_challenge : Bytes
  /// Expected origin(s) - at least one must match
  expected_origins : Array[String]
  /// Expected rpId (hashed and compared with authenticatorData.rpIdHash)
  expected_rp_id : String
  /// Optional additional expected rpIds (at least one hash must match)
  expected_rp_ids : Array[String]?
  /// Optional expected clientDataJSON.type values
  expected_types : Array[String]?
  /// Whether to require user verification (UV flag)
  require_user_verification : Bool
  /// Whether to require user presence (UP flag)
  require_user_presence : Bool
  /// Whether SafetyNet CTS profile check should be enforced.
  /// This flag is currently reserved for compatibility with upstream options.
  attestation_safetynet_enforce_cts_check : Bool
} derive(Show, Eq)

///|
/// Create default verification options.
pub fn VerifyRegistrationOptions::new(
  challenge : Bytes,
  origin : String,
  rp_id : String,
) -> VerifyRegistrationOptions {
  {
    expected_challenge: challenge,
    expected_origins: [origin],
    expected_rp_id: rp_id,
    expected_rp_ids: None,
    expected_types: None,
    require_user_verification: false,
    require_user_presence: true,
    attestation_safetynet_enforce_cts_check: true,
  }
}

///|
/// Create verification options with multiple allowed origins.
pub fn VerifyRegistrationOptions::with_origins(
  challenge : Bytes,
  origins : Array[String],
  rp_id : String,
) -> VerifyRegistrationOptions {
  {
    expected_challenge: challenge,
    expected_origins: origins,
    expected_rp_id: rp_id,
    expected_rp_ids: None,
    expected_types: None,
    require_user_verification: false,
    require_user_presence: true,
    attestation_safetynet_enforce_cts_check: true,
  }
}

///|
/// Create verification options with multiple allowed RP IDs.
pub fn VerifyRegistrationOptions::with_rp_ids(
  challenge : Bytes,
  origins : Array[String],
  rp_ids : Array[String],
) -> VerifyRegistrationOptions {
  let first_rp_id = match rp_ids.get(0) {
    Some(v) => v
    None => ""
  }
  {
    expected_challenge: challenge,
    expected_origins: origins,
    expected_rp_id: first_rp_id,
    expected_rp_ids: Some(rp_ids),
    expected_types: None,
    require_user_verification: false,
    require_user_presence: true,
    attestation_safetynet_enforce_cts_check: true,
  }
}

///|
/// Set whether user verification is required.
pub fn VerifyRegistrationOptions::require_user_verification(
  self : VerifyRegistrationOptions,
  required : Bool,
) -> VerifyRegistrationOptions {
  { ..self, require_user_verification: required }
}

///|
/// Set whether user presence is required.
pub fn VerifyRegistrationOptions::require_user_presence(
  self : VerifyRegistrationOptions,
  required : Bool,
) -> VerifyRegistrationOptions {
  { ..self, require_user_presence: required }
}

///|
/// Set accepted clientDataJSON.type values.
pub fn VerifyRegistrationOptions::with_expected_types(
  self : VerifyRegistrationOptions,
  expected_types : Array[String],
) -> VerifyRegistrationOptions {
  { ..self, expected_types: Some(expected_types) }
}

///|
/// Set expected RP IDs for hash matching.
pub fn VerifyRegistrationOptions::with_expected_rp_ids(
  self : VerifyRegistrationOptions,
  expected_rp_ids : Array[String],
) -> VerifyRegistrationOptions {
  let first_rp_id = match expected_rp_ids.get(0) {
    Some(v) => v
    None => self.expected_rp_id
  }
  {
    ..self,
    expected_rp_id: first_rp_id,
    expected_rp_ids: Some(expected_rp_ids),
  }
}

///|
/// Set SafetyNet CTS check behavior.
pub fn VerifyRegistrationOptions::with_attestation_safetynet_enforce_cts_check(
  self : VerifyRegistrationOptions,
  enforce : Bool,
) -> VerifyRegistrationOptions {
  { ..self, attestation_safetynet_enforce_cts_check: enforce }
}
