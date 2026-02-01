///|
/// Public key credential information for verification.
pub struct WebAuthnCredential {
  id : Base64URLString
  public_key : Bytes
  counter : UInt
  transports : Array[AuthenticatorTransport]?
} derive(Show, Eq)

///|
/// Relying Party entity information.
pub struct RelyingParty {
  id : String?
  name : String
} derive(Show, Eq, ToJson, FromJson)

///|
/// Create a new RelyingParty.
pub fn RelyingParty::new(name : String, id? : String? = None) -> RelyingParty {
  { id, name }
}

///|
/// User entity information for credential creation.
pub struct PublicKeyCredentialUserEntity {
  id : String
  name : String
  display_name : String
} derive(Show, Eq)

///|
/// Create a new PublicKeyCredentialUserEntity.
pub fn PublicKeyCredentialUserEntity::new(
  id : String,
  name : String,
  display_name : String,
) -> PublicKeyCredentialUserEntity {
  { id, name, display_name }
}

///|
pub impl ToJson for PublicKeyCredentialUserEntity with to_json(self) {
  let obj : Map[String, Json] = {}
  obj["id"] = self.id.to_json()
  obj["name"] = self.name.to_json()
  obj["displayName"] = self.display_name.to_json()
  Json::object(obj)
}

///|
pub impl FromJson for PublicKeyCredentialUserEntity with from_json(json, path) {
  guard json is Object(obj) else {
    raise JsonDecodeError((path, "Expected object"))
  }
  let id : String = FromJson::from_json(obj["id"], path)
  let name : String = FromJson::from_json(obj["name"], path)
  let display_name : String = FromJson::from_json(obj["displayName"], path)
  { id, name, display_name }
}

///|
/// Public key credential parameters.
pub struct PublicKeyCredentialParameters {
  type_ : PublicKeyCredentialType
  alg : COSEAlgorithm
} derive(Show, Eq)

///|
/// Create a new PublicKeyCredentialParameters.
pub fn PublicKeyCredentialParameters::new(
  alg : COSEAlgorithm,
) -> PublicKeyCredentialParameters {
  { type_: PublicKeyCredentialType::PublicKey, alg }
}

///|
pub impl ToJson for PublicKeyCredentialParameters with to_json(self) {
  let obj : Map[String, Json] = {}
  obj["type"] = self.type_.to_json()
  obj["alg"] = self.alg.to_json()
  Json::object(obj)
}

///|
pub impl FromJson for PublicKeyCredentialParameters with from_json(json, path) {
  guard json is Object(obj) else {
    raise JsonDecodeError((path, "Expected object"))
  }
  let type_ : PublicKeyCredentialType = FromJson::from_json(obj["type"], path)
  let alg : COSEAlgorithm = FromJson::from_json(obj["alg"], path)
  { type_, alg }
}

///|
/// Descriptor for an existing credential.
pub struct PublicKeyCredentialDescriptor {
  id : Base64URLString
  type_ : PublicKeyCredentialType
  transports : Array[AuthenticatorTransport]?
} derive(Show, Eq)

///|
/// Create a new PublicKeyCredentialDescriptor.
pub fn PublicKeyCredentialDescriptor::new(
  id : Base64URLString,
  transports? : Array[AuthenticatorTransport]? = None,
) -> PublicKeyCredentialDescriptor {
  { id, type_: PublicKeyCredentialType::PublicKey, transports }
}

///|
pub impl ToJson for PublicKeyCredentialDescriptor with to_json(self) {
  let obj : Map[String, Json] = {}
  obj["id"] = self.id.to_json()
  obj["type"] = self.type_.to_json()
  match self.transports {
    Some(t) => obj["transports"] = t.to_json()
    None => ()
  }
  Json::object(obj)
}

///|
pub impl FromJson for PublicKeyCredentialDescriptor with from_json(json, path) {
  guard json is Object(obj) else {
    raise JsonDecodeError((path, "Expected object"))
  }
  let id : Base64URLString = FromJson::from_json(obj["id"], path)
  let type_ : PublicKeyCredentialType = FromJson::from_json(obj["type"], path)
  let transports : Array[AuthenticatorTransport]? = match
    obj.get("transports") {
    Some(t) => Some(FromJson::from_json(t, path))
    None => None
  }
  { id, type_, transports }
}

///|
/// Authenticator selection criteria.
pub struct AuthenticatorSelectionCriteria {
  authenticator_attachment : AuthenticatorAttachment?
  resident_key : ResidentKey?
  require_resident_key : Bool?
  user_verification : UserVerification?
} derive(Show, Eq)

///|
pub impl ToJson for AuthenticatorSelectionCriteria with to_json(self) {
  let obj : Map[String, Json] = {}
  match self.authenticator_attachment {
    Some(a) => obj["authenticatorAttachment"] = a.to_json()
    None => ()
  }
  match self.resident_key {
    Some(r) => obj["residentKey"] = r.to_json()
    None => ()
  }
  match self.require_resident_key {
    Some(r) => obj["requireResidentKey"] = r.to_json()
    None => ()
  }
  match self.user_verification {
    Some(u) => obj["userVerification"] = u.to_json()
    None => ()
  }
  Json::object(obj)
}

///|
pub impl FromJson for AuthenticatorSelectionCriteria with from_json(json, path) {
  guard json is Object(obj) else {
    raise JsonDecodeError((path, "Expected object"))
  }
  let authenticator_attachment : AuthenticatorAttachment? = match
    obj.get("authenticatorAttachment") {
    Some(a) => Some(FromJson::from_json(a, path))
    None => None
  }
  let resident_key : ResidentKey? = match obj.get("residentKey") {
    Some(r) => Some(FromJson::from_json(r, path))
    None => None
  }
  let require_resident_key : Bool? = match obj.get("requireResidentKey") {
    Some(r) => Some(FromJson::from_json(r, path))
    None => None
  }
  let user_verification : UserVerification? = match
    obj.get("userVerification") {
    Some(u) => Some(FromJson::from_json(u, path))
    None => None
  }
  {
    authenticator_attachment,
    resident_key,
    require_resident_key,
    user_verification,
  }
}
