///|
/// Adapted from mizchi/cbor (https://github.com/mizchi/cbor.mbt),
/// commit ff8cbbcf2e8b945510fbe76bd6183657065f74bc.
/// The source and tests are distributed under MIT; see LICENSE-MIT.
/// Compatibility edits for the current MoonBit compiler are recorded here.
///
/// Pure MoonBit CBOR implementation (Optimized)
/// Based on RFC 8949
pub suberror CborError {
  CborError(String)
}

// CBOR Major types (3-bit)
// 0: unsigned integer
// 1: negative integer
// 2: byte string
// 3: text string
// 4: array
// 5: map
// 6: tag
// 7: simple/float

///|
/// CBOR value representation supporting nested structures
pub enum CborValue {
  VUInt(UInt64)
  VInt(Int64)
  VBytes(Bytes)
  VString(String)
  VArray(Array[CborValue])
  VMap(Array[(CborValue, CborValue)])
  VTag(UInt64, CborValue)
  VBool(Bool)
  VNull
  VUndefined
  VDouble(Double)
} derive(Debug, Eq)

///|
pub extend CborValue with Eq::{equal, not_equal}

///|
pub extend CborValue with @debug.Debug::{to_repr}

// Helper functions to construct CborValue (for blackbox tests)

///|
pub fn vuint(v : UInt64) -> CborValue {
  VUInt(v)
}

///|
pub fn vint(v : Int64) -> CborValue {
  VInt(v)
}

///|
pub fn vbytes(v : Bytes) -> CborValue {
  VBytes(v)
}

///|
pub fn vstring(v : String) -> CborValue {
  VString(v)
}

///|
pub fn varray(v : Array[CborValue]) -> CborValue {
  VArray(v)
}

///|
pub fn vmap(v : Array[(CborValue, CborValue)]) -> CborValue {
  VMap(v)
}

///|
pub fn vtag(tag : UInt64, v : CborValue) -> CborValue {
  VTag(tag, v)
}

///|
pub fn vbool(v : Bool) -> CborValue {
  VBool(v)
}

///|
pub fn vnull() -> CborValue {
  VNull
}

///|
pub fn vundefined() -> CborValue {
  VUndefined
}

///|
pub fn vdouble(v : Double) -> CborValue {
  VDouble(v)
}

// Pre-allocated constants for common values

///|
let cbor_true : Bytes = Bytes::from_array([b'\xf5'])

///|
let cbor_false : Bytes = Bytes::from_array([b'\xf4'])

///|
let cbor_null : Bytes = Bytes::from_array([b'\xf6'])

///|
/// Encode unsigned integer
pub fn encode_uint(value : UInt64) -> Bytes {
  encode_uint_internal(0, value)
}

///|
/// Encode signed integer (Int64)
pub fn encode_int(value : Int64) -> Bytes {
  if value >= 0L {
    encode_uint_internal(0, value.reinterpret_as_uint64())
  } else {
    encode_uint_internal(1, (-1L - value).reinterpret_as_uint64())
  }
}

///|
/// Internal: encode uint with known size using Bytes::makei
fn encode_uint_internal(major : Int, value : UInt64) -> Bytes {
  let major_shifted = (major << 5).to_byte()
  if value < 24UL {
    let b0 = major_shifted | value.to_byte()
    Bytes::makei(1, fn(_i) { b0 })
  } else if value < 256UL {
    let b0 = major_shifted | b'\x18'
    let b1 = value.to_byte()
    Bytes::makei(2, fn(i) { if i == 0 { b0 } else { b1 } })
  } else if value < 65536UL {
    let b0 = major_shifted | b'\x19'
    let b1 = (value >> 8).to_byte()
    let b2 = value.to_byte()
    Bytes::makei(3, fn(i) {
      match i {
        0 => b0
        1 => b1
        _ => b2
      }
    })
  } else if value < 4294967296UL {
    let b0 = major_shifted | b'\x1a'
    let b1 = (value >> 24).to_byte()
    let b2 = (value >> 16).to_byte()
    let b3 = (value >> 8).to_byte()
    let b4 = value.to_byte()
    Bytes::makei(5, fn(i) {
      match i {
        0 => b0
        1 => b1
        2 => b2
        3 => b3
        _ => b4
      }
    })
  } else {
    let b0 = major_shifted | b'\x1b'
    let b1 = (value >> 56).to_byte()
    let b2 = (value >> 48).to_byte()
    let b3 = (value >> 40).to_byte()
    let b4 = (value >> 32).to_byte()
    let b5 = (value >> 24).to_byte()
    let b6 = (value >> 16).to_byte()
    let b7 = (value >> 8).to_byte()
    let b8 = value.to_byte()
    Bytes::makei(9, fn(i) {
      match i {
        0 => b0
        1 => b1
        2 => b2
        3 => b3
        4 => b4
        5 => b5
        6 => b6
        7 => b7
        _ => b8
      }
    })
  }
}

///|
/// Decode signed integer
pub fn decode_int(input : Bytes) -> Int64 raise CborError {
  let (major, value, _) = decode_head(input, 0)
  if major == 0 {
    value.reinterpret_as_int64()
  } else if major == 1 {
    -1L - value.reinterpret_as_int64()
  } else {
    raise CborError("Expected integer type")
  }
}

///|
/// Encode double (64-bit float) using Bytes::makei
pub fn encode_double(value : Double) -> Bytes {
  let bits = value.reinterpret_as_uint64()
  Bytes::makei(9, fn(i) {
    match i {
      0 => b'\xfb'
      1 => ((bits >> 56) & 0xFFUL).to_byte()
      2 => ((bits >> 48) & 0xFFUL).to_byte()
      3 => ((bits >> 40) & 0xFFUL).to_byte()
      4 => ((bits >> 32) & 0xFFUL).to_byte()
      5 => ((bits >> 24) & 0xFFUL).to_byte()
      6 => ((bits >> 16) & 0xFFUL).to_byte()
      7 => ((bits >> 8) & 0xFFUL).to_byte()
      _ => (bits & 0xFFUL).to_byte()
    }
  })
}

///|
/// Decode double
pub fn decode_double(input : Bytes) -> Double raise CborError {
  if input.length() < 9 {
    raise CborError("Not enough bytes for double")
  }
  let header = input[0].to_int()
  if header != 0xfb {
    raise CborError("Expected 64-bit float")
  }
  let bits = (input[1].to_uint64() << 56) |
    (input[2].to_uint64() << 48) |
    (input[3].to_uint64() << 40) |
    (input[4].to_uint64() << 32) |
    (input[5].to_uint64() << 24) |
    (input[6].to_uint64() << 16) |
    (input[7].to_uint64() << 8) |
    input[8].to_uint64()
  bits.reinterpret_as_double()
}

///|
/// Encode string (UTF-8 text string) - optimized with FixedArray
pub fn encode_string(value : String) -> Bytes {
  // First pass: calculate UTF-8 length
  let mut utf8_len = 0
  for c in value {
    let code = c.to_int()
    if code < 0x80 {
      utf8_len = utf8_len + 1
    } else if code < 0x800 {
      utf8_len = utf8_len + 2
    } else if code < 0x10000 {
      utf8_len = utf8_len + 3
    } else {
      utf8_len = utf8_len + 4
    }
  }
  // Calculate header size
  let header_size = if utf8_len < 24 {
    1
  } else if utf8_len < 256 {
    2
  } else if utf8_len < 65536 {
    3
  } else {
    5
  }
  // Allocate exact size and build in place
  let result = FixedArray::make(header_size + utf8_len, b'\x00')
  // Write header
  let mut pos = write_header(result, 0, 3, utf8_len.to_uint64())
  // Write UTF-8 data directly
  for c in value {
    let code = c.to_int()
    if code < 0x80 {
      result[pos] = code.to_byte()
      pos = pos + 1
    } else if code < 0x800 {
      result[pos] = ((code >> 6) | 0xC0).to_byte()
      result[pos + 1] = ((code & 0x3F) | 0x80).to_byte()
      pos = pos + 2
    } else if code < 0x10000 {
      result[pos] = ((code >> 12) | 0xE0).to_byte()
      result[pos + 1] = (((code >> 6) & 0x3F) | 0x80).to_byte()
      result[pos + 2] = ((code & 0x3F) | 0x80).to_byte()
      pos = pos + 3
    } else {
      result[pos] = ((code >> 18) | 0xF0).to_byte()
      result[pos + 1] = (((code >> 12) & 0x3F) | 0x80).to_byte()
      result[pos + 2] = (((code >> 6) & 0x3F) | 0x80).to_byte()
      result[pos + 3] = ((code & 0x3F) | 0x80).to_byte()
      pos = pos + 4
    }
  }
  // Convert FixedArray to Bytes using makei
  Bytes::makei(result.length(), fn(i) { result[i] })
}

///|
/// Write CBOR header to FixedArray, returns new position
fn write_header(
  buf : FixedArray[Byte],
  pos : Int,
  major : Int,
  value : UInt64,
) -> Int {
  let major_shifted = (major << 5).to_byte()
  if value < 24UL {
    buf[pos] = major_shifted | value.to_byte()
    pos + 1
  } else if value < 256UL {
    buf[pos] = major_shifted | b'\x18'
    buf[pos + 1] = value.to_byte()
    pos + 2
  } else if value < 65536UL {
    buf[pos] = major_shifted | b'\x19'
    buf[pos + 1] = (value >> 8).to_byte()
    buf[pos + 2] = value.to_byte()
    pos + 3
  } else {
    buf[pos] = major_shifted | b'\x1a'
    buf[pos + 1] = (value >> 24).to_byte()
    buf[pos + 2] = (value >> 16).to_byte()
    buf[pos + 3] = (value >> 8).to_byte()
    buf[pos + 4] = value.to_byte()
    pos + 5
  }
}

///|
/// Decode string - optimized UTF-8 decoding
pub fn decode_string(input : Bytes) -> String raise CborError {
  let (major, len, offset) = decode_head(input, 0)
  if major != 3 {
    raise CborError("Expected text string")
  }
  let str_len = len.to_int()
  if input.length() < offset + str_len {
    raise CborError("Not enough bytes for string")
  }
  // Optimized UTF-8 decoding
  utf8_to_string_optimized(input, offset, str_len)
}

///|
/// Optimized UTF-8 decoding - processes 4 ASCII bytes at once when possible
fn utf8_to_string_optimized(bytes : Bytes, start : Int, len : Int) -> String {
  let buf = StringBuilder(size_hint=len)
  let end = start + len
  let mut i = start
  // Main loop
  while i < end {
    let b0 = bytes[i].to_int()
    if b0 < 0x80 {
      // Fast path: ASCII
      buf.write_char(b0.unsafe_to_char())
      i = i + 1
    } else if b0 < 0xE0 {
      // 2-byte sequence
      let b1 = bytes[i + 1].to_int()
      let code = ((b0 & 0x1F) << 6) | (b1 & 0x3F)
      buf.write_char(code.unsafe_to_char())
      i = i + 2
    } else if b0 < 0xF0 {
      // 3-byte sequence
      let b1 = bytes[i + 1].to_int()
      let b2 = bytes[i + 2].to_int()
      let code = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F)
      buf.write_char(code.unsafe_to_char())
      i = i + 3
    } else {
      // 4-byte sequence
      let b1 = bytes[i + 1].to_int()
      let b2 = bytes[i + 2].to_int()
      let b3 = bytes[i + 3].to_int()
      let code = ((b0 & 0x07) << 18) |
        ((b1 & 0x3F) << 12) |
        ((b2 & 0x3F) << 6) |
        (b3 & 0x3F)
      buf.write_char(code.unsafe_to_char())
      i = i + 4
    }
  }
  buf.to_string()
}

///|
/// Encode bytes (byte string) - optimized
pub fn encode_bytes(value : Bytes) -> Bytes {
  let len = value.length()
  let header_size = if len < 24 {
    1
  } else if len < 256 {
    2
  } else if len < 65536 {
    3
  } else {
    5
  }
  let result = FixedArray::make(header_size + len, b'\x00')
  let pos = write_header(result, 0, 2, len.to_uint64())
  // Copy bytes directly
  for i = 0; i < len; i = i + 1 {
    result[pos + i] = value[i]
  }
  Bytes::makei(result.length(), fn(i) { result[i] })
}

///|
/// Decode bytes - optimized with direct copy
pub fn decode_bytes(input : Bytes) -> Bytes raise CborError {
  let (major, len, offset) = decode_head(input, 0)
  if major != 2 {
    raise CborError("Expected byte string")
  }
  let byte_len = len.to_int()
  if input.length() < offset + byte_len {
    raise CborError("Not enough bytes")
  }
  // Direct copy without intermediate Array
  let result = FixedArray::make(byte_len, b'\x00')
  for i = 0; i < byte_len; i = i + 1 {
    result[i] = input[offset + i]
  }
  Bytes::makei(result.length(), fn(i) { result[i] })
}

///|
/// Encode boolean - uses pre-allocated constants
pub fn encode_bool(value : Bool) -> Bytes {
  if value {
    cbor_true
  } else {
    cbor_false
  }
}

///|
/// Decode boolean
pub fn decode_bool(input : Bytes) -> Bool raise CborError {
  if input.length() < 1 {
    raise CborError("Empty input")
  }
  let b = input[0].to_int()
  if b == 0xf5 {
    true
  } else if b == 0xf4 {
    false
  } else {
    raise CborError("Expected boolean")
  }
}

///|
/// Encode null - uses pre-allocated constant
pub fn encode_null() -> Bytes {
  cbor_null
}

// Internal helper functions

///|
/// Decode CBOR head, returns (major_type, value, bytes_consumed)
fn decode_head(
  input : Bytes,
  offset : Int,
) -> (Int, UInt64, Int) raise CborError {
  if offset >= input.length() {
    raise CborError("Unexpected end of input")
  }
  let first = input[offset].to_int()
  let major = first >> 5
  let additional = first & 0x1f
  if additional < 24 {
    (major, additional.to_uint64(), offset + 1)
  } else if additional == 24 {
    if offset + 1 >= input.length() {
      raise CborError("Not enough bytes")
    }
    (major, input[offset + 1].to_uint64(), offset + 2)
  } else if additional == 25 {
    if offset + 2 >= input.length() {
      raise CborError("Not enough bytes")
    }
    let v = (input[offset + 1].to_uint64() << 8) | input[offset + 2].to_uint64()
    (major, v, offset + 3)
  } else if additional == 26 {
    if offset + 4 >= input.length() {
      raise CborError("Not enough bytes")
    }
    let v = (input[offset + 1].to_uint64() << 24) |
      (input[offset + 2].to_uint64() << 16) |
      (input[offset + 3].to_uint64() << 8) |
      input[offset + 4].to_uint64()
    (major, v, offset + 5)
  } else if additional == 27 {
    if offset + 8 >= input.length() {
      raise CborError("Not enough bytes")
    }
    let v = (input[offset + 1].to_uint64() << 56) |
      (input[offset + 2].to_uint64() << 48) |
      (input[offset + 3].to_uint64() << 40) |
      (input[offset + 4].to_uint64() << 32) |
      (input[offset + 5].to_uint64() << 24) |
      (input[offset + 6].to_uint64() << 16) |
      (input[offset + 7].to_uint64() << 8) |
      input[offset + 8].to_uint64()
    (major, v, offset + 9)
  } else {
    raise CborError("Invalid additional info: \{additional}")
  }
}

///|
/// Encode CborValue to CBOR bytes (supports nested structures)
pub fn encode(value : CborValue) -> Bytes {
  match value {
    VUInt(v) => encode_uint(v)
    VInt(v) => encode_int(v)
    VBytes(v) => encode_bytes(v)
    VString(v) => encode_string(v)
    VArray(arr) => {
      // Encode array header
      let header = encode_uint_internal(4, arr.length().to_uint64())
      // Encode each element
      let parts : Array[Bytes] = [header]
      for item in arr {
        parts.push(encode(item))
      }
      concat_bytes(parts)
    }
    VMap(pairs) => {
      // Encode map header
      let header = encode_uint_internal(5, pairs.length().to_uint64())
      // Encode each key-value pair
      let parts : Array[Bytes] = [header]
      for pair in pairs {
        let (k, v) = pair
        parts.push(encode(k))
        parts.push(encode(v))
      }
      concat_bytes(parts)
    }
    VTag(tag, val) => {
      // Encode tag header
      let header = encode_uint_internal(6, tag)
      // Encode tagged value
      let value_bytes = encode(val)
      concat_bytes([header, value_bytes])
    }
    VBool(v) => encode_bool(v)
    VNull => encode_null()
    VUndefined => Bytes::from_array([b'\xf7'])
    VDouble(v) => encode_double(v)
  }
}

///|
/// Helper: concatenate multiple Bytes
fn concat_bytes(parts : Array[Bytes]) -> Bytes {
  let mut total_len = 0
  for part in parts {
    total_len = total_len + part.length()
  }
  let result = FixedArray::make(total_len, b'\x00')
  let mut pos = 0
  for part in parts {
    for i = 0; i < part.length(); i = i + 1 {
      result[pos] = part[i]
      pos = pos + 1
    }
  }
  Bytes::makei(total_len, fn(i) { result[i] })
}

///|
/// Decode CBOR bytes to CborValue (supports nested structures)
pub fn decode(input : Bytes) -> CborValue raise CborError {
  let (value, _consumed) = decode_value(input, 0)
  value
}

///|
/// Internal: decode CBOR value at given offset, returns (value, bytes_consumed)
fn decode_value(
  input : Bytes,
  offset : Int,
) -> (CborValue, Int) raise CborError {
  let (major, value, new_offset) = decode_head(input, offset)
  match major {
    // Major type 0: unsigned integer
    0 =>
      // If the value fits in Int64 range, return as VInt for convenience
      if value <= 0x7FFFFFFFFFFFFFFFUL {
        (VInt(value.reinterpret_as_int64()), new_offset)
      } else {
        (VUInt(value), new_offset)
      }
    // Major type 1: negative integer
    1 => (VInt(-1L - value.reinterpret_as_int64()), new_offset)
    // Major type 2: byte string
    2 => {
      let len = value.to_int()
      if input.length() < new_offset + len {
        raise CborError("Not enough bytes for byte string")
      }
      let bytes_data = FixedArray::make(len, b'\x00')
      for i = 0; i < len; i = i + 1 {
        bytes_data[i] = input[new_offset + i]
      }
      (VBytes(Bytes::makei(len, fn(i) { bytes_data[i] })), new_offset + len)
    }
    // Major type 3: text string
    3 => {
      let len = value.to_int()
      if input.length() < new_offset + len {
        raise CborError("Not enough bytes for text string")
      }
      let str = utf8_to_string_optimized(input, new_offset, len)
      (VString(str), new_offset + len)
    }
    // Major type 4: array
    4 => {
      let len = value.to_int()
      let arr : Array[CborValue] = []
      let mut pos = new_offset
      for _i = 0; _i < len; _i = _i + 1 {
        let (item, consumed) = decode_value(input, pos)
        arr.push(item)
        pos = consumed
      }
      (VArray(arr), pos)
    }
    // Major type 5: map
    5 => {
      let len = value.to_int()
      let map : Array[(CborValue, CborValue)] = []
      let mut pos = new_offset
      for _i = 0; _i < len; _i = _i + 1 {
        let (key, consumed1) = decode_value(input, pos)
        let (val, consumed2) = decode_value(input, consumed1)
        map.push((key, val))
        pos = consumed2
      }
      (VMap(map), pos)
    }
    // Major type 6: tag
    6 => {
      let (tagged_value, consumed) = decode_value(input, new_offset)
      (VTag(value, tagged_value), consumed)
    }
    // Major type 7: simple values and floats
    7 => {
      let additional = input[offset].to_int() & 0x1f
      if additional == 20 {
        (VBool(false), new_offset)
      } else if additional == 21 {
        (VBool(true), new_offset)
      } else if additional == 22 {
        (VNull, new_offset)
      } else if additional == 23 {
        (VUndefined, new_offset)
      } else if additional == 27 {
        // 64-bit float
        if input.length() < new_offset + 8 {
          raise CborError("Not enough bytes for double")
        }
        let bits = (input[new_offset].to_uint64() << 56) |
          (input[new_offset + 1].to_uint64() << 48) |
          (input[new_offset + 2].to_uint64() << 40) |
          (input[new_offset + 3].to_uint64() << 32) |
          (input[new_offset + 4].to_uint64() << 24) |
          (input[new_offset + 5].to_uint64() << 16) |
          (input[new_offset + 6].to_uint64() << 8) |
          input[new_offset + 7].to_uint64()
        (VDouble(bits.reinterpret_as_double()), new_offset + 8)
      } else {
        raise CborError("Unsupported simple value: \{additional}")
      }
    }
    _ => raise CborError("Invalid major type: \{major}")
  }
}
