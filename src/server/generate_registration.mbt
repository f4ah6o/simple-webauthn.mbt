///|
/// Generate registration options for WebAuthn credential creation.
/// 
/// This generates the options that are passed to the browser's
/// `navigator.credentials.create()` API.

///|
/// Browser authenticator preference hint.
pub enum PreferredAuthenticatorType {
  SecurityKey
  LocalDevice
  RemoteDevice
} derive(Show, Eq)

///|
/// Input parameters for generating registration options.
pub struct GenerateRegistrationOptionsInput {
  /// Human-readable name of the Relying Party (e.g., "ACME Corporation")
  rp_name : String
  /// Unique identifier for the Relying Party, typically the domain (e.g., "example.com")
  rp_id : String
  /// Username for the user account (e.g., "johndoe" or "john@example.com")
  user_name : String
  /// Optional unique identifier for the user (auto-generated if not provided)
  /// Recommended: 32 random bytes
  user_id : Bytes?
  /// Optional human-readable display name (defaults to user_name if not provided)
  user_display_name : String?
  /// Optional custom challenge (auto-generated if not provided)
  /// Recommended: 32 random bytes
  challenge : Bytes?
  /// Attestation preference (defaults to None)
  attestation : @types.AttestationConveyance?
  /// Credentials to exclude (prevent re-registration of existing credentials)
  exclude_credentials : Array[@types.PublicKeyCredentialDescriptor]?
  /// Authenticator selection criteria
  authenticator_selection : @types.AuthenticatorSelectionCriteria?
  /// Supported COSE algorithm identifiers (defaults to [-7, -257] for ES256, RS256)
  supported_algorithm_ids : Array[Int]?
  /// Timeout in milliseconds (defaults to 60000)
  timeout : Int?
  /// UI hints for the browser
  hints : Array[@types.PublicKeyCredentialHint]?
  /// Encourage a specific authenticator class on supported browsers.
  preferred_authenticator_type : PreferredAuthenticatorType?
  /// Client extensions
  extensions : Json?
} derive(Show)

///|
/// Create a new GenerateRegistrationOptionsInput with required fields.
/// All optional fields default to None.
pub fn GenerateRegistrationOptionsInput::new(
  rp_name : String,
  rp_id : String,
  user_name : String,
  user_id? : Bytes? = None,
  user_display_name? : String? = None,
  challenge? : Bytes? = None,
  attestation? : @types.AttestationConveyance? = None,
  exclude_credentials? : Array[@types.PublicKeyCredentialDescriptor]? = None,
  authenticator_selection? : @types.AuthenticatorSelectionCriteria? = None,
  supported_algorithm_ids? : Array[Int]? = None,
  timeout? : Int? = None,
  hints? : Array[@types.PublicKeyCredentialHint]? = None,
  preferred_authenticator_type? : PreferredAuthenticatorType? = None,
  extensions? : Json? = None,
) -> GenerateRegistrationOptionsInput {
  {
    rp_name,
    rp_id,
    user_name,
    user_id,
    user_display_name,
    challenge,
    attestation,
    exclude_credentials,
    authenticator_selection,
    supported_algorithm_ids,
    timeout,
    hints,
    preferred_authenticator_type,
    extensions,
  }
}

///|
/// Default values for registration options.
let default_timeout : Int = 60000

///|
let default_challenge_length : Int = 32

///|
let default_user_id_length : Int = 32

///|
/// Default supported algorithms: EdDSA (-8), ES256 (-7), RS256 (-257)
let default_algorithms : Array[Int] = [-8, -7, -257]

///|
/// Generate random bytes using ChaCha8 PRNG.
/// 
/// ⚠️ SECURITY WARNING: This is NOT cryptographically secure!
/// The current implementation uses MoonBit's ChaCha8 PRNG without a secure seed,
/// which means the output is predictable and NOT suitable for production use.
/// 
/// For production deployments, this function MUST be replaced with a CSPRNG:
/// - JS target: Use Web Crypto API (`crypto.getRandomValues`)
/// - Node.js: Use `crypto.randomBytes`
/// 
/// TODO: Implement platform-specific CSPRNG via FFI
fn generate_random_bytes(length : Int) -> Bytes {
  // WARNING: This PRNG is not cryptographically secure without proper seeding!
  // In production, replace with platform's CSPRNG.
  let rng = @random.Rand::chacha8()
  let arr : Array[Byte] = Array::make(length, b'\x00')
  for i in 0..<length {
    arr[i] = rng.uint(limit=256).to_byte()
  }
  Bytes::from_array(arr)
}

///|
/// Generate registration options for WebAuthn credential creation.
/// 
/// Returns a `PublicKeyCredentialCreationOptionsJSON` that can be serialized
/// to JSON and sent to the browser.
pub fn generate_registration_options(
  input : GenerateRegistrationOptionsInput,
) -> @types.PublicKeyCredentialCreationOptionsJSON {
  // Generate or use provided challenge
  let challenge_bytes = match input.challenge {
    Some(c) => c
    None => generate_random_bytes(default_challenge_length)
  }
  let challenge = @helpers.encode_to_base64url_string(challenge_bytes)

  // Generate or use provided user ID
  let user_id_bytes = match input.user_id {
    Some(id) => id
    None => generate_random_bytes(default_user_id_length)
  }
  let user_id = @helpers.base64url_encode(user_id_bytes)

  // Build user entity
  let display_name = match input.user_display_name {
    Some(dn) => dn
    None => input.user_name
  }
  let user = @types.PublicKeyCredentialUserEntity::new(
    user_id,
    input.user_name,
    display_name,
  )

  // Build relying party entity
  let rp = @types.RelyingParty::new(input.rp_name, id=Some(input.rp_id))

  // Build public key credential parameters
  let algorithm_ids = match input.supported_algorithm_ids {
    Some(ids) => ids
    None => default_algorithms
  }
  let pub_key_cred_params : Array[@types.PublicKeyCredentialParameters] = algorithm_ids.map(fn(
      alg_id,
    ) {
      let alg = match @types.COSEAlgorithm::from_int(alg_id) {
        Some(a) => a
        None => @types.COSEAlgorithm::ES256 // Default to ES256 if unknown
      }
      @types.PublicKeyCredentialParameters::new(alg)
    },
  )

  // Build timeout
  let timeout = match input.timeout {
    Some(t) => Some(t)
    None => Some(default_timeout)
  }

  // Build attestation
  let attestation = match input.attestation {
    Some(a) => Some(a)
    None => Some(@types.AttestationConveyance::None)
  }

  let hints = match input.hints {
    Some(h) => h
    None => []
  }

  match input.preferred_authenticator_type {
    Some(PreferredAuthenticatorType::SecurityKey) => {
      if not(hints.iter().any(fn(h) { h == @types.PublicKeyCredentialHint::SecurityKey })) {
        hints.push(@types.PublicKeyCredentialHint::SecurityKey)
      }
    }
    Some(PreferredAuthenticatorType::LocalDevice) => {
      if not(hints.iter().any(fn(h) { h == @types.PublicKeyCredentialHint::ClientDevice })) {
        hints.push(@types.PublicKeyCredentialHint::ClientDevice)
      }
    }
    Some(PreferredAuthenticatorType::RemoteDevice) => {
      if not(hints.iter().any(fn(h) { h == @types.PublicKeyCredentialHint::Hybrid })) {
        hints.push(@types.PublicKeyCredentialHint::Hybrid)
      }
    }
    None => ()
  }

  let hints_option = if hints.length() == 0 {
    Option::None
  } else {
    Option::Some(hints)
  }
  let extensions = ensure_cred_props_extension(input.extensions)

  // Build the final options
  @types.PublicKeyCredentialCreationOptionsJSON::new(
    rp,
    user,
    challenge,
    pub_key_cred_params,
    timeout~,
    exclude_credentials=input.exclude_credentials,
    authenticator_selection=input.authenticator_selection,
    hints=hints_option,
    attestation~,
    extensions~,
  )
}

///|
fn ensure_cred_props_extension(extensions : Json?) -> Json? {
  match extensions {
    Some(Json::Object(existing)) => {
      existing["credProps"] = true.to_json()
      Some(Json::object(existing))
    }
    Some(other) => Some(other)
    None => Some(Json::object({ "credProps": true.to_json() }))
  }
}
