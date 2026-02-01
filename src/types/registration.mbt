///|
/// Options for creating a new credential (registration).
/// Sent from server to browser.
pub struct PublicKeyCredentialCreationOptionsJSON {
  /// Relying party information
  rp : RelyingParty
  /// User information
  user : PublicKeyCredentialUserEntity
  /// Challenge (Base64URL-encoded)
  challenge : Base64URLString
  /// Supported public key algorithms
  pub_key_cred_params : Array[PublicKeyCredentialParameters]
  /// Timeout in milliseconds
  timeout : Int?
  /// Credentials to exclude (prevent re-registration)
  exclude_credentials : Array[PublicKeyCredentialDescriptor]?
  /// Authenticator requirements
  authenticator_selection : AuthenticatorSelectionCriteria?
  /// UI hints for the browser
  hints : Array[PublicKeyCredentialHint]?
  /// Attestation preference
  attestation : AttestationConveyance?
  /// Preferred attestation formats
  attestation_formats : Array[AttestationFormat]?
  /// Client extensions
  extensions : Json?
} derive(Show, Eq)

///|
/// Create a new PublicKeyCredentialCreationOptionsJSON.
pub fn PublicKeyCredentialCreationOptionsJSON::new(
  rp : RelyingParty,
  user : PublicKeyCredentialUserEntity,
  challenge : Base64URLString,
  pub_key_cred_params : Array[PublicKeyCredentialParameters],
  timeout? : Int? = None,
  exclude_credentials? : Array[PublicKeyCredentialDescriptor]? = None,
  authenticator_selection? : AuthenticatorSelectionCriteria? = None,
  hints? : Array[PublicKeyCredentialHint]? = None,
  attestation? : AttestationConveyance? = None,
  attestation_formats? : Array[AttestationFormat]? = None,
  extensions? : Json? = None,
) -> PublicKeyCredentialCreationOptionsJSON {
  {
    rp,
    user,
    challenge,
    pub_key_cred_params,
    timeout,
    exclude_credentials,
    authenticator_selection,
    hints,
    attestation,
    attestation_formats,
    extensions,
  }
}

///|
pub impl ToJson for PublicKeyCredentialCreationOptionsJSON with to_json(self) {
  let obj : Map[String, Json] = {}
  obj["rp"] = self.rp.to_json()
  obj["user"] = self.user.to_json()
  obj["challenge"] = self.challenge.to_json()
  obj["pubKeyCredParams"] = self.pub_key_cred_params.to_json()
  match self.timeout {
    Some(t) => obj["timeout"] = t.to_json()
    None => ()
  }
  match self.exclude_credentials {
    Some(ec) => obj["excludeCredentials"] = ec.to_json()
    None => ()
  }
  match self.authenticator_selection {
    Some(s) => obj["authenticatorSelection"] = s.to_json()
    None => ()
  }
  match self.hints {
    Some(h) => obj["hints"] = h.to_json()
    None => ()
  }
  match self.attestation {
    Some(a) => obj["attestation"] = a.to_json()
    None => ()
  }
  match self.attestation_formats {
    Some(af) =>
      obj["attestationFormats"] = af
        .map(fn(f) { f.to_string().to_json() })
        .to_json()
    None => ()
  }
  match self.extensions {
    Some(e) => obj["extensions"] = e
    None => ()
  }
  Json::object(obj)
}

///|
pub impl FromJson for PublicKeyCredentialCreationOptionsJSON with from_json(
  json,
  path,
) {
  guard json is Object(obj) else {
    raise JsonDecodeError(
      (path, "Expected object for PublicKeyCredentialCreationOptionsJSON"),
    )
  }
  let rp : RelyingParty = FromJson::from_json(obj["rp"], path)
  let user : PublicKeyCredentialUserEntity = FromJson::from_json(
    obj["user"],
    path,
  )
  let challenge : Base64URLString = FromJson::from_json(obj["challenge"], path)
  let pub_key_cred_params : Array[PublicKeyCredentialParameters] = FromJson::from_json(
    obj["pubKeyCredParams"],
    path,
  )
  let timeout : Int? = match obj.get("timeout") {
    Some(t) => Some(FromJson::from_json(t, path))
    None => None
  }
  let exclude_credentials : Array[PublicKeyCredentialDescriptor]? = match
    obj.get("excludeCredentials") {
    Some(ec) => Some(FromJson::from_json(ec, path))
    None => None
  }
  let authenticator_selection : AuthenticatorSelectionCriteria? = match
    obj.get("authenticatorSelection") {
    Some(s) => Some(FromJson::from_json(s, path))
    None => None
  }
  let hints : Array[PublicKeyCredentialHint]? = match obj.get("hints") {
    Some(h) => Some(FromJson::from_json(h, path))
    None => None
  }
  let attestation : AttestationConveyance? = match obj.get("attestation") {
    Some(a) => Some(FromJson::from_json(a, path))
    None => None
  }
  let attestation_formats : Array[AttestationFormat]? = None // Complex, skip for now
  let extensions : Json? = obj.get("extensions")
  {
    rp,
    user,
    challenge,
    pub_key_cred_params,
    timeout,
    exclude_credentials,
    authenticator_selection,
    hints,
    attestation,
    attestation_formats,
    extensions,
  }
}

///|
/// Authenticator attestation response from the browser (registration).
pub struct AuthenticatorAttestationResponseJSON {
  /// Base64URL-encoded client data JSON
  client_data_json : Base64URLString
  /// Base64URL-encoded attestation object (CBOR)
  attestation_object : Base64URLString
  /// Base64URL-encoded authenticator data (L3)
  authenticator_data : Base64URLString?
  /// Transport hints from the authenticator
  transports : Array[AuthenticatorTransport]?
  /// Public key algorithm used
  public_key_algorithm : COSEAlgorithm?
  /// Base64URL-encoded public key (SPKI format, L3)
  public_key : Base64URLString?
} derive(Show, Eq)

///|
pub impl ToJson for AuthenticatorAttestationResponseJSON with to_json(self) {
  let obj : Map[String, Json] = {}
  obj["clientDataJSON"] = self.client_data_json.to_json()
  obj["attestationObject"] = self.attestation_object.to_json()
  match self.authenticator_data {
    Some(ad) => obj["authenticatorData"] = ad.to_json()
    None => ()
  }
  match self.transports {
    Some(t) => obj["transports"] = t.to_json()
    None => ()
  }
  match self.public_key_algorithm {
    Some(a) => obj["publicKeyAlgorithm"] = a.to_json()
    None => ()
  }
  match self.public_key {
    Some(pk) => obj["publicKey"] = pk.to_json()
    None => ()
  }
  Json::object(obj)
}

///|
pub impl FromJson for AuthenticatorAttestationResponseJSON with from_json(
  json,
  path,
) {
  guard json is Object(obj) else {
    raise JsonDecodeError(
      (path, "Expected object for AuthenticatorAttestationResponseJSON"),
    )
  }
  let client_data_json : Base64URLString = FromJson::from_json(
    obj["clientDataJSON"],
    path,
  )
  let attestation_object : Base64URLString = FromJson::from_json(
    obj["attestationObject"],
    path,
  )
  let authenticator_data : Base64URLString? = match
    obj.get("authenticatorData") {
    Some(ad) => Some(FromJson::from_json(ad, path))
    None => None
  }
  let transports : Array[AuthenticatorTransport]? = match
    obj.get("transports") {
    Some(t) => Some(FromJson::from_json(t, path))
    None => None
  }
  let public_key_algorithm : COSEAlgorithm? = match
    obj.get("publicKeyAlgorithm") {
    Some(a) => Some(FromJson::from_json(a, path))
    None => None
  }
  let public_key : Base64URLString? = match obj.get("publicKey") {
    Some(pk) => Some(FromJson::from_json(pk, path))
    None => None
  }
  {
    client_data_json,
    attestation_object,
    authenticator_data,
    transports,
    public_key_algorithm,
    public_key,
  }
}

///|
/// Registration response from the browser.
pub struct RegistrationResponseJSON {
  /// Base64URL-encoded credential ID
  id : Base64URLString
  /// Base64URL-encoded raw credential ID
  raw_id : Base64URLString
  /// Attestation response
  response : AuthenticatorAttestationResponseJSON
  /// Authenticator attachment used
  authenticator_attachment : AuthenticatorAttachment?
  /// Client extension results
  client_extension_results : Json
  /// Credential type (always "public-key")
  type_ : PublicKeyCredentialType
} derive(Show, Eq)

///|
pub impl ToJson for RegistrationResponseJSON with to_json(self) {
  let obj : Map[String, Json] = {}
  obj["id"] = self.id.to_json()
  obj["rawId"] = self.raw_id.to_json()
  obj["response"] = self.response.to_json()
  match self.authenticator_attachment {
    Some(a) => obj["authenticatorAttachment"] = a.to_json()
    None => ()
  }
  obj["clientExtensionResults"] = self.client_extension_results
  obj["type"] = self.type_.to_json()
  Json::object(obj)
}

///|
pub impl FromJson for RegistrationResponseJSON with from_json(json, path) {
  guard json is Object(obj) else {
    raise JsonDecodeError(
      (path, "Expected object for RegistrationResponseJSON"),
    )
  }
  let id : Base64URLString = FromJson::from_json(obj["id"], path)
  let raw_id : Base64URLString = FromJson::from_json(obj["rawId"], path)
  let response : AuthenticatorAttestationResponseJSON = FromJson::from_json(
    obj["response"],
    path,
  )
  let authenticator_attachment : AuthenticatorAttachment? = match
    obj.get("authenticatorAttachment") {
    Some(a) => Some(FromJson::from_json(a, path))
    None => None
  }
  let client_extension_results : Json = match
    obj.get("clientExtensionResults") {
    Some(r) => r
    None => Json::object({})
  }
  let type_ : PublicKeyCredentialType = FromJson::from_json(obj["type"], path)
  {
    id,
    raw_id,
    response,
    authenticator_attachment,
    client_extension_results,
    type_,
  }
}
