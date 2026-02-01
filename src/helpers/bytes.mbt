///|
/// Byte array utilities for parsing WebAuthn binary data.

///|
/// Error types for byte operations.
pub suberror BytesError {
  OutOfBounds(Int, Int) // (requested_offset, actual_length)
  InvalidLength(Int, Int) // (expected, actual)
}

///|
/// Read a big-endian UInt16 from bytes at the given offset.
pub fn read_u16_be(bytes : Bytes, offset : Int) -> UInt raise BytesError {
  if offset + 2 > bytes.length() {
    raise OutOfBounds(offset + 2, bytes.length())
  }
  let b0 = bytes[offset].to_uint()
  let b1 = bytes[offset + 1].to_uint()
  (b0 << 8) | b1
}

///|
/// Read a big-endian UInt32 from bytes at the given offset.
pub fn read_u32_be(bytes : Bytes, offset : Int) -> UInt raise BytesError {
  if offset + 4 > bytes.length() {
    raise OutOfBounds(offset + 4, bytes.length())
  }
  let b0 = bytes[offset].to_uint()
  let b1 = bytes[offset + 1].to_uint()
  let b2 = bytes[offset + 2].to_uint()
  let b3 = bytes[offset + 3].to_uint()
  (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

///|
/// Read a big-endian UInt64 from bytes at the given offset.
pub fn read_u64_be(bytes : Bytes, offset : Int) -> UInt64 raise BytesError {
  if offset + 8 > bytes.length() {
    raise OutOfBounds(offset + 8, bytes.length())
  }
  let mut result : UInt64 = 0
  for i = 0; i < 8; i = i + 1 {
    result = (result << 8) | bytes[offset + i].to_uint64()
  }
  result
}

///|
/// Slice bytes from offset with given length.
pub fn bytes_slice(
  bytes : Bytes,
  offset : Int,
  len : Int,
) -> Bytes raise BytesError {
  if offset + len > bytes.length() {
    raise OutOfBounds(offset + len, bytes.length())
  }
  if offset < 0 || len < 0 {
    raise OutOfBounds(offset, bytes.length())
  }
  Bytes::makei(len, fn(i) { bytes[offset + i] })
}

///|
/// Slice bytes from offset to end.
pub fn bytes_slice_from(bytes : Bytes, offset : Int) -> Bytes raise BytesError {
  if offset > bytes.length() {
    raise OutOfBounds(offset, bytes.length())
  }
  if offset < 0 {
    raise OutOfBounds(offset, bytes.length())
  }
  let len = bytes.length() - offset
  Bytes::makei(len, fn(i) { bytes[offset + i] })
}

///|
/// Concatenate multiple byte arrays.
pub fn bytes_concat(arrays : Array[Bytes]) -> Bytes {
  let result : Array[Byte] = []
  for bytes in arrays {
    for i = 0; i < bytes.length(); i = i + 1 {
      result.push(bytes[i])
    }
  }
  Bytes::from_array(result[:])
}

///|
/// Constant-time comparison of two byte arrays.
/// Returns true if arrays are equal, false otherwise.
/// This prevents timing attacks when comparing secrets.
pub fn constant_time_equal(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut result : Int = 0
  for i = 0; i < a.length(); i = i + 1 {
    result = result | (a[i].to_int() ^ b[i].to_int())
  }
  result == 0
}

///|
/// Check if bytes start with the given prefix.
pub fn bytes_starts_with(bytes : Bytes, prefix : Bytes) -> Bool {
  if prefix.length() > bytes.length() {
    return false
  }
  for i = 0; i < prefix.length(); i = i + 1 {
    if bytes[i] != prefix[i] {
      return false
    }
  }
  true
}

///|
/// Convert bytes to hex string (useful for debugging).
pub fn bytes_to_hex(bytes : Bytes) -> String {
  let hex_chars = "0123456789abcdef"
  let buf = StringBuilder::new()
  for i = 0; i < bytes.length(); i = i + 1 {
    let b = bytes[i].to_int()
    buf.write_char(hex_chars[(b >> 4) & 0x0f].to_int().unsafe_to_char())
    buf.write_char(hex_chars[b & 0x0f].to_int().unsafe_to_char())
  }
  buf.to_string()
}

///|
/// Convert hex string to bytes.
pub fn hex_to_bytes(hex : String) -> Bytes raise BytesError {
  if hex.length() % 2 != 0 {
    raise BytesError::InvalidLength(hex.length() + 1, hex.length())
  }
  let len = hex.length() / 2
  let arr : Array[Byte] = []
  for i = 0; i < len; i = i + 1 {
    let hi = hex_char_to_int(hex[i * 2].to_int())
    let lo = hex_char_to_int(hex[i * 2 + 1].to_int())
    if hi < 0 || lo < 0 {
      raise BytesError::InvalidLength(0, -1) // Invalid hex char
    }
    arr.push(((hi << 4) | lo).to_byte())
  }
  Bytes::from_array(arr[:])
}

///|
fn hex_char_to_int(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    // '0' - '9'
    c - 0x30
  } else if c >= 0x41 && c <= 0x46 {
    // 'A' - 'F'
    c - 0x41 + 10
  } else if c >= 0x61 && c <= 0x66 {
    // 'a' - 'f'
    c - 0x61 + 10
  } else {
    -1
  }
}
