///|
/// COSE Key Types.
pub(all) enum COSEKeyType {
  OKP // 1 - Octet Key Pair
  EC2 // 2 - Elliptic Curve
  RSA // 3 - RSA
} derive(Show, Eq)

///|
pub fn COSEKeyType::to_int(self : COSEKeyType) -> Int {
  match self {
    OKP => 1
    EC2 => 2
    RSA => 3
  }
}

///|
pub fn COSEKeyType::from_int(n : Int) -> COSEKeyType? {
  match n {
    1 => Some(OKP)
    2 => Some(EC2)
    3 => Some(RSA)
    _ => None
  }
}

///|
/// COSE Algorithm identifiers.
pub(all) enum COSEAlgorithm {
  ES256 // -7: ECDSA w/ SHA-256
  EdDSA // -8: EdDSA
  ES384 // -35: ECDSA w/ SHA-384
  ES512 // -36: ECDSA w/ SHA-512
  PS256 // -37: RSASSA-PSS w/ SHA-256
  PS384 // -38: RSASSA-PSS w/ SHA-384
  PS512 // -39: RSASSA-PSS w/ SHA-512
  ES256K // -47: ECDSA using secp256k1
  RS256 // -257: RSASSA-PKCS1-v1_5 w/ SHA-256
  RS384 // -258: RSASSA-PKCS1-v1_5 w/ SHA-384
  RS512 // -259: RSASSA-PKCS1-v1_5 w/ SHA-512
  RS1 // -65535: RSASSA-PKCS1-v1_5 w/ SHA-1
} derive(Show, Eq)

///|
pub fn COSEAlgorithm::to_int(self : COSEAlgorithm) -> Int {
  match self {
    ES256 => -7
    EdDSA => -8
    ES384 => -35
    ES512 => -36
    PS256 => -37
    PS384 => -38
    PS512 => -39
    ES256K => -47
    RS256 => -257
    RS384 => -258
    RS512 => -259
    RS1 => -65535
  }
}

///|
pub fn COSEAlgorithm::from_int(n : Int) -> COSEAlgorithm? {
  match n {
    -7 => Some(ES256)
    -8 => Some(EdDSA)
    -35 => Some(ES384)
    -36 => Some(ES512)
    -37 => Some(PS256)
    -38 => Some(PS384)
    -39 => Some(PS512)
    -47 => Some(ES256K)
    -257 => Some(RS256)
    -258 => Some(RS384)
    -259 => Some(RS512)
    -65535 => Some(RS1)
    _ => None
  }
}

///|
pub impl ToJson for COSEAlgorithm with to_json(self) {
  self.to_int().to_json()
}

///|
pub impl FromJson for COSEAlgorithm with from_json(json, path) {
  let n : Int = FromJson::from_json(json, path)
  match COSEAlgorithm::from_int(n) {
    Some(v) => v
    None => raise JsonDecodeError((path, "Invalid COSEAlgorithm"))
  }
}

///|
/// COSE Elliptic Curves.
pub(all) enum COSECurve {
  P256 // 1
  P384 // 2
  P521 // 3
  Ed25519 // 6
  Secp256k1 // 8
} derive(Show, Eq)

///|
pub fn COSECurve::to_int(self : COSECurve) -> Int {
  match self {
    P256 => 1
    P384 => 2
    P521 => 3
    Ed25519 => 6
    Secp256k1 => 8
  }
}

///|
pub fn COSECurve::from_int(n : Int) -> COSECurve? {
  match n {
    1 => Some(P256)
    2 => Some(P384)
    3 => Some(P521)
    6 => Some(Ed25519)
    8 => Some(Secp256k1)
    _ => None
  }
}

///|
/// Decoded COSE public key for OKP keys.
pub struct COSEPublicKeyOKP {
  kty : COSEKeyType
  alg : COSEAlgorithm
  crv : COSECurve
  x : Bytes
} derive(Show, Eq)

///|
/// Decoded COSE public key for EC2 keys.
pub struct COSEPublicKeyEC2 {
  kty : COSEKeyType
  alg : COSEAlgorithm
  crv : COSECurve
  x : Bytes
  y : Bytes
} derive(Show, Eq)

///|
/// Decoded COSE public key for RSA keys.
pub struct COSEPublicKeyRSA {
  kty : COSEKeyType
  alg : COSEAlgorithm
  n : Bytes
  e : Bytes
} derive(Show, Eq)

///|
/// Union type for all COSE public key types.
pub(all) enum COSEPublicKey {
  OKP(COSEPublicKeyOKP)
  EC2(COSEPublicKeyEC2)
  RSA(COSEPublicKeyRSA)
} derive(Show, Eq)

///|
pub fn COSEPublicKey::key_type(self : COSEPublicKey) -> COSEKeyType {
  match self {
    OKP(key) => key.kty
    EC2(key) => key.kty
    RSA(key) => key.kty
  }
}

///|
pub fn COSEPublicKey::algorithm(self : COSEPublicKey) -> COSEAlgorithm {
  match self {
    OKP(key) => key.alg
    EC2(key) => key.alg
    RSA(key) => key.alg
  }
}
