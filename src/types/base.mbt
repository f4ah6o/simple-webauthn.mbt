///|
/// Base64URL-encoded string type for documentation clarity.
pub struct Base64URLString {
  value : String
} derive(Show, Eq)

///|
/// Serialize as a plain JSON string (not as an object with "value" field).
pub impl ToJson for Base64URLString with to_json(self) {
  self.value.to_json()
}

///|
/// Deserialize from a plain JSON string.
pub impl FromJson for Base64URLString with from_json(json, path) {
  let s : String = FromJson::from_json(json, path)
  { value: s }
}

///|
pub fn Base64URLString::new(s : String) -> Base64URLString {
  { value: s }
}

///|
pub fn Base64URLString::to_string(self : Base64URLString) -> String {
  self.value
}

///|
/// Authenticator transport methods.
pub(all) enum AuthenticatorTransport {
  Ble // Bluetooth Low Energy
  Cable // Cloud-Assisted BLE (deprecated)
  Hybrid // Hybrid transport
  Internal // Platform authenticator
  Nfc // Near Field Communication
  SmartCard // Smart card
  Usb // USB connection
} derive(Show, Eq)

///|
pub fn AuthenticatorTransport::to_string(
  self : AuthenticatorTransport,
) -> String {
  match self {
    Ble => "ble"
    Cable => "cable"
    Hybrid => "hybrid"
    Internal => "internal"
    Nfc => "nfc"
    SmartCard => "smart-card"
    Usb => "usb"
  }
}

///|
pub fn AuthenticatorTransport::from_string(
  s : String,
) -> AuthenticatorTransport? {
  match s {
    "ble" => Some(Ble)
    "cable" => Some(Cable)
    "hybrid" => Some(Hybrid)
    "internal" => Some(Internal)
    "nfc" => Some(Nfc)
    "smart-card" => Some(SmartCard)
    "usb" => Some(Usb)
    _ => None
  }
}

///|
pub impl ToJson for AuthenticatorTransport with to_json(self) {
  self.to_string().to_json()
}

///|
pub impl FromJson for AuthenticatorTransport with from_json(json, path) {
  let s : String = FromJson::from_json(json, path)
  match AuthenticatorTransport::from_string(s) {
    Some(t) => t
    None => raise JsonDecodeError((path, "Invalid AuthenticatorTransport"))
  }
}

///|
/// Credential device type based on backup eligibility.
pub(all) enum CredentialDeviceType {
  SingleDevice
  MultiDevice
} derive(Show, Eq)

///|
pub fn CredentialDeviceType::to_string(self : CredentialDeviceType) -> String {
  match self {
    SingleDevice => "singleDevice"
    MultiDevice => "multiDevice"
  }
}

///|
pub impl ToJson for CredentialDeviceType with to_json(self) {
  self.to_string().to_json()
}

///|
/// User verification requirement.
pub(all) enum UserVerification {
  Required
  Preferred
  Discouraged
} derive(Show, Eq)

///|
pub fn UserVerification::to_string(self : UserVerification) -> String {
  match self {
    Required => "required"
    Preferred => "preferred"
    Discouraged => "discouraged"
  }
}

///|
pub fn UserVerification::from_string(s : String) -> UserVerification? {
  match s {
    "required" => Some(Required)
    "preferred" => Some(Preferred)
    "discouraged" => Some(Discouraged)
    _ => None
  }
}

///|
pub impl ToJson for UserVerification with to_json(self) {
  self.to_string().to_json()
}

///|
pub impl FromJson for UserVerification with from_json(json, path) {
  let s : String = FromJson::from_json(json, path)
  match UserVerification::from_string(s) {
    Some(v) => v
    None => raise JsonDecodeError((path, "Invalid UserVerification"))
  }
}

///|
/// Attestation conveyance preference.
pub(all) enum AttestationConveyance {
  None
  Indirect
  Direct
  Enterprise
} derive(Show, Eq)

///|
pub fn AttestationConveyance::to_string(self : AttestationConveyance) -> String {
  match self {
    None => "none"
    Indirect => "indirect"
    Direct => "direct"
    Enterprise => "enterprise"
  }
}

///|
pub fn AttestationConveyance::from_string(s : String) -> AttestationConveyance? {
  match s {
    "none" => Some(None)
    "indirect" => Some(Indirect)
    "direct" => Some(Direct)
    "enterprise" => Some(Enterprise)
    _ => Option::None
  }
}

///|
pub impl ToJson for AttestationConveyance with to_json(self) {
  self.to_string().to_json()
}

///|
pub impl FromJson for AttestationConveyance with from_json(json, path) {
  let s : String = FromJson::from_json(json, path)
  match AttestationConveyance::from_string(s) {
    Some(v) => v
    Option::None =>
      raise JsonDecodeError((path, "Invalid AttestationConveyance"))
  }
}

///|
/// Attestation format identifiers.
pub(all) enum AttestationFormat {
  None
  Packed
  FidoU2f
  AndroidKey
  AndroidSafetynet
  Tpm
  Apple
} derive(Show, Eq)

///|
pub fn AttestationFormat::to_string(self : AttestationFormat) -> String {
  match self {
    None => "none"
    Packed => "packed"
    FidoU2f => "fido-u2f"
    AndroidKey => "android-key"
    AndroidSafetynet => "android-safetynet"
    Tpm => "tpm"
    Apple => "apple"
  }
}

///|
pub fn AttestationFormat::from_string(s : String) -> AttestationFormat? {
  match s {
    "none" => Some(None)
    "packed" => Some(Packed)
    "fido-u2f" => Some(FidoU2f)
    "android-key" => Some(AndroidKey)
    "android-safetynet" => Some(AndroidSafetynet)
    "tpm" => Some(Tpm)
    "apple" => Some(Apple)
    _ => Option::None
  }
}

///|
pub impl ToJson for AttestationFormat with to_json(self) {
  self.to_string().to_json()
}

///|
/// Authenticator attachment modality.
pub(all) enum AuthenticatorAttachment {
  Platform
  CrossPlatform
} derive(Show, Eq)

///|
pub fn AuthenticatorAttachment::to_string(
  self : AuthenticatorAttachment,
) -> String {
  match self {
    Platform => "platform"
    CrossPlatform => "cross-platform"
  }
}

///|
pub fn AuthenticatorAttachment::from_string(
  s : String,
) -> AuthenticatorAttachment? {
  match s {
    "platform" => Some(Platform)
    "cross-platform" => Some(CrossPlatform)
    _ => None
  }
}

///|
pub impl ToJson for AuthenticatorAttachment with to_json(self) {
  self.to_string().to_json()
}

///|
pub impl FromJson for AuthenticatorAttachment with from_json(json, path) {
  let s : String = FromJson::from_json(json, path)
  match AuthenticatorAttachment::from_string(s) {
    Some(v) => v
    None => raise JsonDecodeError((path, "Invalid AuthenticatorAttachment"))
  }
}

///|
/// Resident key requirement.
pub(all) enum ResidentKey {
  Discouraged
  Preferred
  Required
} derive(Show, Eq)

///|
pub fn ResidentKey::to_string(self : ResidentKey) -> String {
  match self {
    Discouraged => "discouraged"
    Preferred => "preferred"
    Required => "required"
  }
}

///|
pub fn ResidentKey::from_string(s : String) -> ResidentKey? {
  match s {
    "discouraged" => Some(Discouraged)
    "preferred" => Some(Preferred)
    "required" => Some(Required)
    _ => None
  }
}

///|
pub impl ToJson for ResidentKey with to_json(self) {
  self.to_string().to_json()
}

///|
pub impl FromJson for ResidentKey with from_json(json, path) {
  let s : String = FromJson::from_json(json, path)
  match ResidentKey::from_string(s) {
    Some(v) => v
    None => raise JsonDecodeError((path, "Invalid ResidentKey"))
  }
}

///|
/// Public key credential type.
pub(all) enum PublicKeyCredentialType {
  PublicKey
} derive(Show, Eq)

///|
pub fn PublicKeyCredentialType::to_string(
  self : PublicKeyCredentialType,
) -> String {
  match self {
    PublicKey => "public-key"
  }
}

///|
pub fn PublicKeyCredentialType::from_string(
  s : String,
) -> PublicKeyCredentialType? {
  match s {
    "public-key" => Some(PublicKey)
    _ => None
  }
}

///|
pub impl ToJson for PublicKeyCredentialType with to_json(self) {
  self.to_string().to_json()
}

///|
pub impl FromJson for PublicKeyCredentialType with from_json(json, path) {
  let s : String = FromJson::from_json(json, path)
  match PublicKeyCredentialType::from_string(s) {
    Some(v) => v
    None => raise JsonDecodeError((path, "Invalid PublicKeyCredentialType"))
  }
}

///|
/// Hint for browsers to optimize credential selection UI.
pub(all) enum PublicKeyCredentialHint {
  Hybrid
  SecurityKey
  ClientDevice
} derive(Show, Eq)

///|
pub fn PublicKeyCredentialHint::to_string(
  self : PublicKeyCredentialHint,
) -> String {
  match self {
    Hybrid => "hybrid"
    SecurityKey => "security-key"
    ClientDevice => "client-device"
  }
}

///|
pub fn PublicKeyCredentialHint::from_string(
  s : String,
) -> PublicKeyCredentialHint? {
  match s {
    "hybrid" => Some(Hybrid)
    "security-key" => Some(SecurityKey)
    "client-device" => Some(ClientDevice)
    _ => None
  }
}

///|
pub impl ToJson for PublicKeyCredentialHint with to_json(self) {
  self.to_string().to_json()
}

///|
pub impl FromJson for PublicKeyCredentialHint with from_json(json, path) {
  let s : String = FromJson::from_json(json, path)
  match PublicKeyCredentialHint::from_string(s) {
    Some(v) => v
    None => raise JsonDecodeError((path, "Invalid PublicKeyCredentialHint"))
  }
}
