///|
/// Generate authentication options for WebAuthn credential assertion.
/// 
/// This generates the options that are passed to the browser's
/// `navigator.credentials.get()` API.

///|
/// Input parameters for generating authentication options.
pub struct GenerateAuthenticationOptionsInput {
  /// Relying Party ID (domain). Required for non-discoverable credentials.
  rp_id : String?
  /// Challenge bytes. If not provided, 32 random bytes will be generated.
  /// ⚠️ See security warning in generate_random_bytes about CSPRNG.
  challenge : Bytes?
  /// Timeout in milliseconds (defaults to 60000)
  timeout : Int?
  /// Allowed credentials. If empty/None, allows any discoverable credential.
  allow_credentials : Array[@types.PublicKeyCredentialDescriptor]?
  /// User verification requirement (defaults to "preferred")
  user_verification : @types.UserVerification?
  /// UI hints for the browser
  hints : Array[@types.PublicKeyCredentialHint]?
  /// Client extensions
  extensions : Json?
} derive(Show)

///|
/// Create a new GenerateAuthenticationOptionsInput.
/// All fields are optional with sensible defaults.
pub fn GenerateAuthenticationOptionsInput::new(
  rp_id? : String? = None,
  challenge? : Bytes? = None,
  timeout? : Int? = None,
  allow_credentials? : Array[@types.PublicKeyCredentialDescriptor]? = None,
  user_verification? : @types.UserVerification? = None,
  hints? : Array[@types.PublicKeyCredentialHint]? = None,
  extensions? : Json? = None,
) -> GenerateAuthenticationOptionsInput {
  {
    rp_id,
    challenge,
    timeout,
    allow_credentials,
    user_verification,
    hints,
    extensions,
  }
}

///|
/// Generate authentication options for WebAuthn credential assertion.
/// 
/// Returns a `PublicKeyCredentialRequestOptionsJSON` that can be serialized
/// to JSON and sent to the browser.
/// 
/// ## Discoverable vs Non-Discoverable Credentials
/// 
/// - If `allow_credentials` is empty or None, the browser will prompt the user
///   to select from discoverable (resident) credentials stored on the authenticator.
/// - If `allow_credentials` contains credential IDs, the browser will only allow
///   those specific credentials to be used.
pub fn generate_authentication_options(
  input : GenerateAuthenticationOptionsInput,
) -> @types.PublicKeyCredentialRequestOptionsJSON {
  // Generate or use provided challenge
  let challenge_bytes = match input.challenge {
    Some(c) => c
    None => generate_random_bytes(default_challenge_length)
  }
  let challenge = @helpers.encode_to_base64url_string(challenge_bytes)

  // Build timeout (default 60s)
  let timeout = match input.timeout {
    Some(t) => Some(t)
    None => Some(default_timeout)
  }

  // Build user verification (default "preferred")
  let user_verification = match input.user_verification {
    Some(uv) => Some(uv)
    None => Some(@types.UserVerification::Preferred)
  }

  // Build the final options
  @types.PublicKeyCredentialRequestOptionsJSON::new(
    challenge,
    timeout~,
    rp_id=input.rp_id,
    allow_credentials=input.allow_credentials,
    user_verification~,
    hints=input.hints,
    extensions=input.extensions,
  )
}
