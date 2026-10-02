///|
test "topOrigin absent and null preserve optional browser field" {
  for suffix in ["", ",\"topOrigin\":null"] {
    let client_data = @helpers.parse_client_data_json_string(
      "{\"type\":\"webauthn.get\",\"challenge\":\"AQID\",\"origin\":\"https://example.com\",\"crossOrigin\":true\{suffix}}",
    )
    assert_eq(client_data.top_origin, None)
    assert_eq(client_data.cross_origin, true)
  }
}

///|
test "topOrigin rejects non-string JSON values" {
  for value in ["true", "42", "[]", "{}"] {
    let rejected = try {
      let _ = @helpers.parse_client_data_json_string(
        "{\"type\":\"webauthn.get\",\"challenge\":\"AQID\",\"origin\":\"https://example.com\",\"crossOrigin\":true,\"topOrigin\":\{value}}",
      )
      false
    } catch {
      @helpers.ClientDataError::InvalidOrigin => true
      _ => false
    }
    assert_true(rejected)
  }
}
