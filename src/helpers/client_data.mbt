///|
/// ClientDataJSON parsing for WebAuthn.
/// 
/// The clientDataJSON is a JSON object that contains critical verification data
/// including the type of operation, challenge, origin, and cross-origin status.

///|
/// Error types for ClientDataJSON parsing.
pub suberror ClientDataError {
  InvalidJson(String)
  MissingField(String)
  InvalidType(String) // Expected "webauthn.create" or "webauthn.get"
  InvalidChallenge
  InvalidOrigin
}

///|
/// Expected operation types.
pub(all) enum ClientDataType {
  Create // "webauthn.create" for registration
  Get // "webauthn.get" for authentication
} derive(Show, Eq)

///|
fn ClientDataType::to_string(self : ClientDataType) -> String {
  match self {
    Create => "webauthn.create"
    Get => "webauthn.get"
  }
}

///|
fn ClientDataType::from_string(s : String) -> ClientDataType? {
  match s {
    "webauthn.create" => Some(Create)
    "webauthn.get" => Some(Get)
    _ => None
  }
}

///|
/// Parsed clientDataJSON structure.
pub struct ClientData {
  /// The type of WebAuthn operation
  type_ : ClientDataType
  /// The challenge, decoded from base64url
  challenge : Bytes
  /// The challenge as the original string (before decoding)
  challenge_raw : String
  /// The origin (e.g., "https://example.com")
  origin : String
  /// Whether this is a cross-origin request
  cross_origin : Bool
  /// Token binding (optional, rarely used)
  token_binding : Json?
} derive(Show, Eq)

///|
/// Parse clientDataJSON from base64url-encoded string.
/// This is the typical format received from the browser.
pub fn parse_client_data_json(
  client_data_json_b64 : String,
) -> ClientData raise ClientDataError {
  // Decode base64url to get JSON bytes
  let json_bytes = base64url_decode(client_data_json_b64) catch {
    _ => raise InvalidJson("Failed to decode base64url")
  }
  // Convert bytes to string
  let json_str = json_bytes.to_unchecked_string()
  // Parse JSON
  parse_client_data_json_string(json_str)
}

///|
/// Parse clientDataJSON from raw JSON string.
pub fn parse_client_data_json_string(
  json_str : String,
) -> ClientData raise ClientDataError {
  let json = @json.parse(json_str) catch {
    err => raise InvalidJson(err.to_string())
  }
  parse_client_data_json_value(json)
}

///|
/// Parse clientDataJSON from a Json value.
pub fn parse_client_data_json_value(
  json : Json,
) -> ClientData raise ClientDataError {
  guard json is Object(obj) else { raise InvalidJson("Expected JSON object") }
  // Parse type
  let type_str = match obj.get("type") {
    Some(String(s)) => s
    Some(_) => raise MissingField("type must be a string")
    None => raise MissingField("type")
  }
  let type_ = match ClientDataType::from_string(type_str) {
    Some(t) => t
    None => raise InvalidType(type_str)
  }
  // Parse challenge
  let challenge_raw = match obj.get("challenge") {
    Some(String(s)) => s
    Some(_) => raise MissingField("challenge must be a string")
    None => raise MissingField("challenge")
  }
  let challenge = base64url_decode(challenge_raw) catch {
    _ => raise InvalidChallenge
  }
  // Parse origin
  let origin = match obj.get("origin") {
    Some(String(s)) => s
    Some(_) => raise MissingField("origin must be a string")
    None => raise MissingField("origin")
  }
  // Parse crossOrigin (optional, defaults to false)
  let cross_origin = match obj.get("crossOrigin") {
    Some(True) => true
    Some(False) => false
    Some(_) => false // Invalid value, treat as false
    None => false
  }
  // Parse tokenBinding (optional)
  let token_binding = obj.get("tokenBinding")
  { type_, challenge, challenge_raw, origin, cross_origin, token_binding }
}

///|
/// Verify that the clientDataJSON matches expected values.
pub fn verify_client_data(
  client_data : ClientData,
  expected_type : ClientDataType,
  expected_challenge : Bytes,
  expected_origin : String,
) -> Bool {
  // Check type
  if client_data.type_ != expected_type {
    return false
  }
  // Check challenge using constant-time comparison
  if not(constant_time_equal(client_data.challenge, expected_challenge)) {
    return false
  }
  // Check origin
  if client_data.origin != expected_origin {
    return false
  }
  true
}
