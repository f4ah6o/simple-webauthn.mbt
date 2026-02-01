///|
/// Base64URL encoding/decoding utilities for WebAuthn.
/// 
/// WebAuthn uses Base64URL encoding (RFC 4648) without padding.
/// This module wraps moonbitlang/x/codec/base64 with WebAuthn-specific handling.

///|
/// Error types for Base64URL operations.
pub suberror Base64URLError {
  InvalidChar(Int) // Position of invalid character
  InvalidPadding // Incorrect padding
  InvalidLength // Length not valid for base64
  DecodeFailed(String) // Generic decode failure with message
}

///|
/// Decode a Base64URL string to bytes.
/// Handles both padded and unpadded input.
pub fn base64url_decode(input : String) -> Bytes raise Base64URLError {
  if input.length() == 0 {
    return Bytes::new(0)
  }
  // Add padding if necessary (WebAuthn often omits padding)
  let padded = add_padding(input)
  @base64.decode(padded, url_safe=true) catch {
    _ => raise DecodeFailed("Base64 decode failed")
  }
}

///|
/// Encode bytes to a Base64URL string without padding.
pub fn base64url_encode(input : Bytes) -> String {
  if input.length() == 0 {
    return ""
  }
  let encoded = @base64.encode(input[:], url_safe=true)
  // Remove padding
  remove_padding(encoded)
}

///|
/// Add padding to a Base64URL string if needed.
fn add_padding(input : String) -> String {
  let remainder = input.length() % 4
  if remainder == 0 {
    return input
  }
  let padding_needed = 4 - remainder
  let mut result = input
  for i = 0; i < padding_needed; i = i + 1 {
    result = result + "="
  }
  result
}

///|
/// Remove padding from a Base64URL string.
fn remove_padding(input : String) -> String {
  let mut end = input.length()
  while end > 0 && input[end - 1] == '='.to_int().to_uint16() {
    end = end - 1
  }
  if end == input.length() {
    return input
  }
  // Build result manually to avoid slice issues
  let buf = StringBuilder::new()
  for i = 0; i < end; i = i + 1 {
    buf.write_char(input[i].to_int().unsafe_to_char())
  }
  buf.to_string()
}

///|
/// Convert a Base64URLString type to bytes.
pub fn decode_base64url_string(
  s : @types.Base64URLString,
) -> Bytes raise Base64URLError {
  base64url_decode(s.to_string())
}

///|
/// Create a Base64URLString from bytes.
pub fn encode_to_base64url_string(input : Bytes) -> @types.Base64URLString {
  @types.Base64URLString::new(base64url_encode(input))
}
