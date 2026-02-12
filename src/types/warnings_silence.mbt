///|
/// Touch unused structs to keep warnings clean in checks.
fn _touch_unused() -> Unit {
  let empty_bytes = Bytes::make(0, b'\x00')
  let empty_obj : Map[String, Json] = {}
  let empty_json = Json::object(empty_obj)
  let none_bytes : Bytes? = None
  let none_json : Json? = None
  let none_transports : Array[AuthenticatorTransport]? = None
  let none_bool : Bool? = None

  let _ = COSEPublicKeyOKP::{
    kty: COSEKeyType::OKP,
    alg: COSEAlgorithm::EdDSA,
    crv: COSECurve::Ed25519,
    x: empty_bytes,
  }
  let _ = COSEPublicKeyEC2::{
    kty: COSEKeyType::EC2,
    alg: COSEAlgorithm::ES256,
    crv: COSECurve::P256,
    x: empty_bytes,
    y: empty_bytes,
  }
  let _ = COSEPublicKeyRSA::{
    kty: COSEKeyType::RSA,
    alg: COSEAlgorithm::RS256,
    n: empty_bytes,
    e: empty_bytes,
  }

  let _ = WebAuthnCredential::{
    id: Base64URLString::new(""),
    public_key: empty_bytes,
    counter: 0U,
    transports: none_transports,
  }
  let flags = AuthenticatorFlags::{
    up: false,
    uv: false,
    be: false,
    bs: false,
    at: false,
    ed: false,
    raw: b'\x00',
  }
  let _ = ParsedAuthenticatorData::{
    rp_id_hash: empty_bytes,
    flags,
    counter: 0U,
    aaguid: none_bytes,
    credential_id: none_bytes,
    credential_public_key: none_bytes,
    extensions_data: none_json,
  }
  let _ = ParsedClientDataJSON::{
    type_: "",
    challenge: Base64URLString::new(""),
    origin: "",
    cross_origin: none_bool,
    token_binding: none_json,
  }
  let _ = ParsedAttestationObject::{
    fmt: AttestationFormat::None,
    att_stmt: empty_json,
    auth_data: empty_bytes,
  }
  let _ = VerifiedRegistrationResponse::{
    verified: false,
    registration_info: (None : RegistrationInfo?),
  }
  let _ = RegistrationInfo::{
    credential_id: empty_bytes,
    credential_public_key: empty_bytes,
    counter: 0U,
    credential_device_type: CredentialDeviceType::SingleDevice,
    credential_backed_up: false,
    aaguid: "",
    attestation_format: AttestationFormat::None,
  }
  let _ = VerifiedAuthenticationResponse::{
    verified: false,
    authentication_info: (None : AuthenticationInfo?),
  }
  let _ = AuthenticationInfo::{
    credential_id: empty_bytes,
    new_counter: 0U,
    credential_device_type: CredentialDeviceType::SingleDevice,
    credential_backed_up: false,
    origin: "",
    rp_id_hash: empty_bytes,
  }
}

///|
fn init {
  _touch_unused()
}
