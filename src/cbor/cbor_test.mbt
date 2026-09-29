///|
/// CBOR Test Suite
/// Tests encoding/decoding and validates against RFC 8949 examples
/// Adapted from mizchi/cbor (https://github.com/mizchi/cbor.mbt),
/// commit ff8cbbcf2e8b945510fbe76bd6183657065f74bc; MIT license.

// Helper functions

///|
fn bytes_equal(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

// RFC 8949 Appendix A Examples

///|
test "encode_int: small positive integers (RFC 8949)" {
  // 0 → 0x00
  assert_eq(@cbor.encode_int(0L), Bytes::from_array([b'\x00']))
  // 1 → 0x01
  assert_eq(@cbor.encode_int(1L), Bytes::from_array([b'\x01']))
  // 10 → 0x0a
  assert_eq(@cbor.encode_int(10L), Bytes::from_array([b'\x0a']))
  // 23 → 0x17
  assert_eq(@cbor.encode_int(23L), Bytes::from_array([b'\x17']))
}

///|
test "encode_int: uint8 range (RFC 8949)" {
  // 24 → 0x18 0x18
  assert_eq(@cbor.encode_int(24L), Bytes::from_array([b'\x18', b'\x18']))
  // 25 → 0x18 0x19
  assert_eq(@cbor.encode_int(25L), Bytes::from_array([b'\x18', b'\x19']))
  // 100 → 0x18 0x64
  assert_eq(@cbor.encode_int(100L), Bytes::from_array([b'\x18', b'\x64']))
}

///|
test "encode_int: uint16 range (RFC 8949)" {
  // 1000 → 0x19 0x03e8
  assert_eq(
    @cbor.encode_int(1000L),
    Bytes::from_array([b'\x19', b'\x03', b'\xe8']),
  )
}

///|
test "encode_int: uint32 range (RFC 8949)" {
  // 1000000 → 0x1a 0x000f4240
  assert_eq(
    @cbor.encode_int(1000000L),
    Bytes::from_array([b'\x1a', b'\x00', b'\x0f', b'\x42', b'\x40']),
  )
}

///|
test "encode_int: uint64 range (RFC 8949)" {
  // 1000000000000 → 0x1b 0x000000e8d4a51000
  assert_eq(
    @cbor.encode_int(1000000000000L),
    Bytes::from_array([
      b'\x1b', b'\x00', b'\x00', b'\x00', b'\xe8', b'\xd4', b'\xa5', b'\x10', b'\x00',
    ]),
  )
}

///|
test "encode_int: negative integers (RFC 8949)" {
  // -1 → 0x20
  assert_eq(@cbor.encode_int(-1L), Bytes::from_array([b'\x20']))
  // -10 → 0x29
  assert_eq(@cbor.encode_int(-10L), Bytes::from_array([b'\x29']))
  // -100 → 0x38 0x63
  assert_eq(@cbor.encode_int(-100L), Bytes::from_array([b'\x38', b'\x63']))
  // -1000 → 0x39 0x03e7
  assert_eq(
    @cbor.encode_int(-1000L),
    Bytes::from_array([b'\x39', b'\x03', b'\xe7']),
  )
}

///|
test "encode_string: empty and simple strings (RFC 8949)" {
  // "" → 0x60
  assert_eq(@cbor.encode_string(""), Bytes::from_array([b'\x60']))
  // "a" → 0x61 0x61
  assert_eq(@cbor.encode_string("a"), Bytes::from_array([b'\x61', b'\x61']))
  // "IETF" → 0x64 "IETF"
  assert_eq(
    @cbor.encode_string("IETF"),
    Bytes::from_array([b'\x64', b'\x49', b'\x45', b'\x54', b'\x46']),
  )
}

///|
test "encode_string: unicode strings" {
  // Test Japanese characters
  let encoded = @cbor.encode_string("こんにちは")
  let decoded = @cbor.decode_string(encoded)
  assert_eq(decoded, "こんにちは")

  // Test emoji
  let encoded_emoji = @cbor.encode_string("🎉")
  let decoded_emoji = @cbor.decode_string(encoded_emoji)
  assert_eq(decoded_emoji, "🎉")
}

///|
test "encode_bytes: various byte strings (RFC 8949)" {
  // h'' → 0x40
  assert_eq(
    @cbor.encode_bytes(Bytes::from_array([])),
    Bytes::from_array([b'\x40']),
  )

  // h'01020304' → 0x44 0x01020304
  assert_eq(
    @cbor.encode_bytes(Bytes::from_array([b'\x01', b'\x02', b'\x03', b'\x04'])),
    Bytes::from_array([b'\x44', b'\x01', b'\x02', b'\x03', b'\x04']),
  )
}

///|
test "encode_bool: true and false (RFC 8949)" {
  // false → 0xf4
  assert_eq(@cbor.encode_bool(false), Bytes::from_array([b'\xf4']))
  // true → 0xf5
  assert_eq(@cbor.encode_bool(true), Bytes::from_array([b'\xf5']))
}

///|
test "encode_null: null value (RFC 8949)" {
  // null → 0xf6
  assert_eq(@cbor.encode_null(), Bytes::from_array([b'\xf6']))
}

///|
test "encode_double: special float values (RFC 8949)" {
  // 0.0 → 0xfb 0x0000000000000000
  let zero = @cbor.encode_double(0.0)
  assert_eq(zero.length(), 9)
  assert_eq(zero[0], b'\xfb')

  // Test decode roundtrip
  assert_eq(@cbor.decode_double(zero), 0.0)

  // 1.0
  let one = @cbor.encode_double(1.0)
  assert_eq(@cbor.decode_double(one), 1.0)

  // -1.0
  let neg_one = @cbor.encode_double(-1.0)
  assert_eq(@cbor.decode_double(neg_one), -1.0)
}

// Roundtrip tests

///|
test "roundtrip: integers" {
  let test_values : Array[Int64] = [
    0L, 1L, 23L, 24L, 255L, 256L, 65535L, 65536L, 4294967295L, 4294967296L, -1L,
    -10L, -24L, -25L, -100L, -1000L, -1000000L,
  ]

  for v in test_values {
    let encoded = @cbor.encode_int(v)
    let decoded = @cbor.decode_int(encoded)
    if decoded != v {
      abort("Roundtrip failed for \{v}: got \{decoded}")
    }
  }
}

///|
test "roundtrip: doubles" {
  let test_values : Array[Double] = [
    0.0, 1.0, -1.0, 3.141592653589793, 1.0e10, 1.0e-10,
  ]

  for v in test_values {
    let encoded = @cbor.encode_double(v)
    let decoded = @cbor.decode_double(encoded)
    if decoded != v {
      abort("Roundtrip failed for \{v}: got \{decoded}")
    }
  }
}

///|
test "roundtrip: infinity values" {
  let inf = @double.infinity
  let encoded_inf = @cbor.encode_double(inf)
  let decoded_inf = @cbor.decode_double(encoded_inf)
  assert_true(decoded_inf == inf)

  let neg_inf = @double.neg_infinity
  let encoded_neg_inf = @cbor.encode_double(neg_inf)
  let decoded_neg_inf = @cbor.decode_double(encoded_neg_inf)
  assert_true(decoded_neg_inf == neg_inf)
}

///|
test "roundtrip: strings" {
  let test_values : Array[String] = [
    "", "a", "hello", "Hello, CBOR!", "こんにちは", "Hello, CBOR! こんにちは",
    "🎉", "emoji: 🚀🌟",
  ]

  for v in test_values {
    let encoded = @cbor.encode_string(v)
    let decoded = @cbor.decode_string(encoded)
    assert_eq(decoded, v)
  }
}

///|
test "roundtrip: bytes" {
  let test_values : Array[Bytes] = [
    Bytes::from_array([]),
    Bytes::from_array([b'\x00']),
    Bytes::from_array([b'\x01', b'\x02', b'\x03', b'\x04', b'\x05']),
    Bytes::from_array([b'\xff', b'\xfe', b'\xfd']),
  ]

  for v in test_values {
    let encoded = @cbor.encode_bytes(v)
    let decoded = @cbor.decode_bytes(encoded)
    assert_true(bytes_equal(decoded, v))
  }
}

///|
test "roundtrip: booleans" {
  let encoded_true = @cbor.encode_bool(true)
  let decoded_true = @cbor.decode_bool(encoded_true)
  assert_eq(decoded_true, true)

  let encoded_false = @cbor.encode_bool(false)
  let decoded_false = @cbor.decode_bool(encoded_false)
  assert_eq(decoded_false, false)
}

// Edge cases

///|
test "edge_case: large integers" {
  let max_u32 = 4294967295L
  let encoded = @cbor.encode_int(max_u32)
  let decoded = @cbor.decode_int(encoded)
  assert_eq(decoded, max_u32)

  let large = 12345678901234L
  let encoded_large = @cbor.encode_int(large)
  let decoded_large = @cbor.decode_int(encoded_large)
  assert_eq(decoded_large, large)
}

///|
test "edge_case: boundary values for encoding formats" {
  // Test boundary between different encoding formats

  // 23 (last inline value)
  let v23 = @cbor.encode_int(23L)
  assert_eq(v23.length(), 1)

  // 24 (first uint8 value)
  let v24 = @cbor.encode_int(24L)
  assert_eq(v24.length(), 2)

  // 255 (last uint8 value)
  let v255 = @cbor.encode_int(255L)
  assert_eq(v255.length(), 2)

  // 256 (first uint16 value)
  let v256 = @cbor.encode_int(256L)
  assert_eq(v256.length(), 3)
}

///|
test "edge_case: empty strings and bytes" {
  // Empty string
  let empty_str = @cbor.encode_string("")
  assert_eq(empty_str.length(), 1)
  assert_eq(@cbor.decode_string(empty_str), "")

  // Empty bytes
  let empty_bytes = @cbor.encode_bytes(Bytes::from_array([]))
  assert_eq(empty_bytes.length(), 1)
  assert_true(
    bytes_equal(@cbor.decode_bytes(empty_bytes), Bytes::from_array([])),
  )
}

///|
test "edge_case: string length boundaries" {
  // 23 character string (inline length)
  let s23 = "a".repeat(23)
  let e23 = @cbor.encode_string(s23)
  assert_eq(@cbor.decode_string(e23), s23)

  // 24 character string (uint8 length)
  let s24 = "a".repeat(24)
  let e24 = @cbor.encode_string(s24)
  assert_eq(@cbor.decode_string(e24), s24)
}

// Nested structure tests using CborValue

///|
test "CborValue: simple values" {
  // Int
  let v1 : @cbor.CborValue = @cbor.vint(42L)
  let encoded1 = @cbor.encode(v1)
  let decoded1 = @cbor.decode(encoded1)
  assert_eq(decoded1, v1)

  // String
  let v2 : @cbor.CborValue = @cbor.vstring("hello")
  let encoded2 = @cbor.encode(v2)
  let decoded2 = @cbor.decode(encoded2)
  assert_eq(decoded2, v2)

  // Bool
  let v3 : @cbor.CborValue = @cbor.vbool(true)
  let encoded3 = @cbor.encode(v3)
  let decoded3 = @cbor.decode(encoded3)
  assert_eq(decoded3, v3)

  // Null
  let v4 : @cbor.CborValue = @cbor.vnull()
  let encoded4 = @cbor.encode(v4)
  let decoded4 = @cbor.decode(encoded4)
  assert_eq(decoded4, v4)
}

///|
test "CborValue: array" {
  // Simple array [1, 2, 3]
  let arr1 : @cbor.CborValue = @cbor.varray([
    @cbor.vint(1L),
    @cbor.vint(2L),
    @cbor.vint(3L),
  ])
  let encoded1 = @cbor.encode(arr1)
  let decoded1 = @cbor.decode(encoded1)
  assert_eq(decoded1, arr1)

  // Empty array
  let arr2 : @cbor.CborValue = @cbor.varray([])
  let encoded2 = @cbor.encode(arr2)
  let decoded2 = @cbor.decode(encoded2)
  assert_eq(decoded2, arr2)

  // Mixed types array [1, "hello", true]
  let arr3 : @cbor.CborValue = @cbor.varray([
    @cbor.vint(1L),
    @cbor.vstring("hello"),
    @cbor.vbool(true),
  ])
  let encoded3 = @cbor.encode(arr3)
  let decoded3 = @cbor.decode(encoded3)
  assert_eq(decoded3, arr3)
}

///|
test "CborValue: nested array" {
  // [[1, 2], [3, 4]]
  let nested : @cbor.CborValue = @cbor.varray([
    @cbor.varray([@cbor.vint(1L), @cbor.vint(2L)]),
    @cbor.varray([@cbor.vint(3L), @cbor.vint(4L)]),
  ])
  let encoded = @cbor.encode(nested)
  let decoded = @cbor.decode(encoded)
  assert_eq(decoded, nested)

  // Deeply nested [[[1]]]
  let deep : @cbor.CborValue = @cbor.varray([
    @cbor.varray([@cbor.varray([@cbor.vint(1L)])]),
  ])
  let encoded_deep = @cbor.encode(deep)
  let decoded_deep = @cbor.decode(encoded_deep)
  assert_eq(decoded_deep, deep)
}

///|
test "CborValue: map" {
  // Simple map {1: "one", 2: "two"}
  let map1 : @cbor.CborValue = @cbor.vmap([
    (@cbor.vint(1L), @cbor.vstring("one")),
    (@cbor.vint(2L), @cbor.vstring("two")),
  ])
  let encoded1 = @cbor.encode(map1)
  let decoded1 = @cbor.decode(encoded1)
  assert_eq(decoded1, map1)

  // Empty map
  let map2 : @cbor.CborValue = @cbor.vmap([])
  let encoded2 = @cbor.encode(map2)
  let decoded2 = @cbor.decode(encoded2)
  assert_eq(decoded2, map2)

  // String keys {"name": "Alice", "age": 30}
  let map3 : @cbor.CborValue = @cbor.vmap([
    (@cbor.vstring("name"), @cbor.vstring("Alice")),
    (@cbor.vstring("age"), @cbor.vint(30L)),
  ])
  let encoded3 = @cbor.encode(map3)
  let decoded3 = @cbor.decode(encoded3)
  assert_eq(decoded3, map3)
}

///|
test "CborValue: nested map" {
  // {"user": {"name": "Bob", "id": 123}}
  let nested_map : @cbor.CborValue = @cbor.vmap([
    (
      @cbor.vstring("user"),
      @cbor.vmap([
        (@cbor.vstring("name"), @cbor.vstring("Bob")),
        (@cbor.vstring("id"), @cbor.vint(123L)),
      ]),
    ),
  ])
  let encoded = @cbor.encode(nested_map)
  let decoded = @cbor.decode(encoded)
  assert_eq(decoded, nested_map)
}

///|
test "CborValue: tag" {
  // Tag 0 (date/time string) with a string value
  let tagged1 : @cbor.CborValue = @cbor.vtag(
    0UL,
    @cbor.vstring("2024-01-01T00:00:00Z"),
  )
  let encoded1 = @cbor.encode(tagged1)
  let decoded1 = @cbor.decode(encoded1)
  assert_eq(decoded1, tagged1)

  // Tag 24 (CBOR data item) with an array
  let tagged2 : @cbor.CborValue = @cbor.vtag(
    24UL,
    @cbor.varray([@cbor.vint(1L), @cbor.vint(2L)]),
  )
  let encoded2 = @cbor.encode(tagged2)
  let decoded2 = @cbor.decode(encoded2)
  assert_eq(decoded2, tagged2)
}

///|
test "CborValue: complex nested structure" {
  // Complex structure: array of maps
  // [{"name": "Alice", "scores": [95, 87, 92]}, {"name": "Bob", "scores": [88, 91]}]
  let complex : @cbor.CborValue = @cbor.varray([
    @cbor.vmap([
      (@cbor.vstring("name"), @cbor.vstring("Alice")),
      (
        @cbor.vstring("scores"),
        @cbor.varray([@cbor.vint(95L), @cbor.vint(87L), @cbor.vint(92L)]),
      ),
    ]),
    @cbor.vmap([
      (@cbor.vstring("name"), @cbor.vstring("Bob")),
      (
        @cbor.vstring("scores"),
        @cbor.varray([@cbor.vint(88L), @cbor.vint(91L)]),
      ),
    ]),
  ])
  let encoded = @cbor.encode(complex)
  let decoded = @cbor.decode(encoded)
  assert_eq(decoded, complex)
}

///|
test "CborValue: all types" {
  // Test each type individually first
  let v1 : @cbor.CborValue = @cbor.vuint(123UL)
  let e1 = @cbor.encode(v1)
  let d1 = @cbor.decode(e1)
  assert_eq(d1, @cbor.vint(123L)) // vuint(123) decodes as vint(123) due to range check

  let v2 : @cbor.CborValue = @cbor.vint(-456L)
  let e2 = @cbor.encode(v2)
  let d2 = @cbor.decode(e2)
  assert_eq(d2, v2)

  let v3 : @cbor.CborValue = @cbor.vbytes(Bytes::from_array([b'\x01', b'\x02']))
  let e3 = @cbor.encode(v3)
  let d3 = @cbor.decode(e3)
  assert_eq(d3, v3)

  let v4 : @cbor.CborValue = @cbor.vstring("test")
  let e4 = @cbor.encode(v4)
  let d4 = @cbor.decode(e4)
  assert_eq(d4, v4)
}
