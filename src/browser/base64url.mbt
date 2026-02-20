///|
/// Convert a base64url string to raw bytes.
pub fn base64url_string_to_buffer(input : String) -> Bytes raise BrowserError {
  @helpers.base64url_decode(input) catch {
    @helpers.Base64URLError::InvalidChar(_) =>
      raise InvalidInput("Invalid base64url characters")
    @helpers.Base64URLError::InvalidPadding =>
      raise InvalidInput("Invalid base64url padding")
    @helpers.Base64URLError::InvalidLength =>
      raise InvalidInput("Invalid base64url length")
    @helpers.Base64URLError::DecodeFailed(msg) =>
      raise InvalidInput("Failed to decode base64url: \{msg}")
  }
}

///|
/// Convert raw bytes to a base64url string (without padding).
pub fn buffer_to_base64url_string(buffer : Bytes) -> String {
  @helpers.base64url_encode(buffer)
}
