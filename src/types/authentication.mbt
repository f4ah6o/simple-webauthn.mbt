///|
/// Options for authenticating with an existing credential.
/// Sent from server to browser.
pub struct PublicKeyCredentialRequestOptionsJSON {
  /// Challenge (Base64URL-encoded)
  challenge : Base64URLString
  /// Timeout in milliseconds
  timeout : Int?
  /// Relying party ID (domain)
  rp_id : String?
  /// Allowed credentials (if empty, allows any discoverable credential)
  allow_credentials : Array[PublicKeyCredentialDescriptor]?
  /// User verification requirement
  user_verification : UserVerification?
  /// UI hints for the browser
  hints : Array[PublicKeyCredentialHint]?
  /// Client extensions
  extensions : Json?
} derive(Show, Eq)

///|
/// Create a new PublicKeyCredentialRequestOptionsJSON.
pub fn PublicKeyCredentialRequestOptionsJSON::new(
  challenge : Base64URLString,
  timeout? : Int? = None,
  rp_id? : String? = None,
  allow_credentials? : Array[PublicKeyCredentialDescriptor]? = None,
  user_verification? : UserVerification? = None,
  hints? : Array[PublicKeyCredentialHint]? = None,
  extensions? : Json? = None,
) -> PublicKeyCredentialRequestOptionsJSON {
  {
    challenge,
    timeout,
    rp_id,
    allow_credentials,
    user_verification,
    hints,
    extensions,
  }
}

///|
pub impl ToJson for PublicKeyCredentialRequestOptionsJSON with to_json(self) {
  let obj : Map[String, Json] = {}
  obj["challenge"] = self.challenge.to_json()
  match self.timeout {
    Some(t) => obj["timeout"] = t.to_json()
    None => ()
  }
  match self.rp_id {
    Some(id) => obj["rpId"] = id.to_json()
    None => ()
  }
  match self.allow_credentials {
    Some(ac) => obj["allowCredentials"] = ac.to_json()
    None => ()
  }
  match self.user_verification {
    Some(uv) => obj["userVerification"] = uv.to_json()
    None => ()
  }
  match self.hints {
    Some(h) => obj["hints"] = h.to_json()
    None => ()
  }
  match self.extensions {
    Some(e) => obj["extensions"] = e
    None => ()
  }
  Json::object(obj)
}

///|
pub impl FromJson for PublicKeyCredentialRequestOptionsJSON with from_json(
  json,
  path,
) {
  guard json is Object(obj) else {
    raise JsonDecodeError(
      (path, "Expected object for PublicKeyCredentialRequestOptionsJSON"),
    )
  }
  let challenge : Base64URLString = FromJson::from_json(obj["challenge"], path)
  let timeout : Int? = match obj.get("timeout") {
    Some(t) => Some(FromJson::from_json(t, path))
    None => None
  }
  let rp_id : String? = match obj.get("rpId") {
    Some(id) => Some(FromJson::from_json(id, path))
    None => None
  }
  let allow_credentials : Array[PublicKeyCredentialDescriptor]? = match
    obj.get("allowCredentials") {
    Some(ac) => Some(FromJson::from_json(ac, path))
    None => None
  }
  let user_verification : UserVerification? = match
    obj.get("userVerification") {
    Some(uv) => Some(FromJson::from_json(uv, path))
    None => None
  }
  let hints : Array[PublicKeyCredentialHint]? = match obj.get("hints") {
    Some(h) => Some(FromJson::from_json(h, path))
    None => None
  }
  let extensions : Json? = obj.get("extensions")
  {
    challenge,
    timeout,
    rp_id,
    allow_credentials,
    user_verification,
    hints,
    extensions,
  }
}

///|
/// Authenticator assertion response from the browser (authentication).
pub struct AuthenticatorAssertionResponseJSON {
  /// Base64URL-encoded client data JSON
  client_data_json : Base64URLString
  /// Base64URL-encoded authenticator data
  authenticator_data : Base64URLString
  /// Base64URL-encoded signature
  signature : Base64URLString
  /// Base64URL-encoded user handle (if present)
  user_handle : Base64URLString?
} derive(Show, Eq)

///|
pub impl ToJson for AuthenticatorAssertionResponseJSON with to_json(self) {
  let obj : Map[String, Json] = {}
  obj["clientDataJSON"] = self.client_data_json.to_json()
  obj["authenticatorData"] = self.authenticator_data.to_json()
  obj["signature"] = self.signature.to_json()
  match self.user_handle {
    Some(uh) => obj["userHandle"] = uh.to_json()
    None => ()
  }
  Json::object(obj)
}

///|
pub impl FromJson for AuthenticatorAssertionResponseJSON with from_json(
  json,
  path,
) {
  guard json is Object(obj) else {
    raise JsonDecodeError(
      (path, "Expected object for AuthenticatorAssertionResponseJSON"),
    )
  }
  let client_data_json : Base64URLString = FromJson::from_json(
    obj["clientDataJSON"],
    path,
  )
  let authenticator_data : Base64URLString = FromJson::from_json(
    obj["authenticatorData"],
    path,
  )
  let signature : Base64URLString = FromJson::from_json(obj["signature"], path)
  let user_handle : Base64URLString? = match obj.get("userHandle") {
    Some(uh) if uh is Null => None
    Some(uh) => Some(FromJson::from_json(uh, path))
    None => None
  }
  { client_data_json, authenticator_data, signature, user_handle }
}

///|
/// Authentication response from the browser.
pub struct AuthenticationResponseJSON {
  /// Base64URL-encoded credential ID
  id : Base64URLString
  /// Base64URL-encoded raw credential ID
  raw_id : Base64URLString
  /// Assertion response
  response : AuthenticatorAssertionResponseJSON
  /// Authenticator attachment used
  authenticator_attachment : AuthenticatorAttachment?
  /// Client extension results
  client_extension_results : Json
  /// Credential type (always "public-key")
  type_ : PublicKeyCredentialType
} derive(Show, Eq)

///|
pub impl ToJson for AuthenticationResponseJSON with to_json(self) {
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
pub impl FromJson for AuthenticationResponseJSON with from_json(json, path) {
  guard json is Object(obj) else {
    raise JsonDecodeError(
      (path, "Expected object for AuthenticationResponseJSON"),
    )
  }
  let id : Base64URLString = FromJson::from_json(obj["id"], path)
  let raw_id : Base64URLString = FromJson::from_json(obj["rawId"], path)
  let response : AuthenticatorAssertionResponseJSON = FromJson::from_json(
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
