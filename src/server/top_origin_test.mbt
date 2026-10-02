///|
fn make_top_origin_client_data(
  cross_origin : Bool,
  top_origin : String?,
) -> Bytes {
  let challenge = @helpers.base64url_encode(b"top-origin-challenge")
  let cross_origin_json = if cross_origin { "true" } else { "false" }
  let top_origin_json = match top_origin {
    Some(value) => ",\"topOrigin\":\"\{value}\""
    None => ""
  }
  let json = "{\"type\":\"webauthn.get\",\"challenge\":\"\{challenge}\",\"origin\":\"https://example.com\",\"crossOrigin\":\{cross_origin_json}\{top_origin_json}}"
  @encoding.encode(@encoding.Encoding::UTF8, json)
}

///|
fn make_top_origin_options(
  expected_top_origins : Array[String]?,
) -> @server.VerifyAuthenticationOptions {
  let options = @server.VerifyAuthenticationOptions::new(
    b"top-origin-challenge",
    "https://example.com",
    "example.com",
    @server.AuthenticatorCredential::new(
      b"top-origin-credential", b"unused-public-key", 0U,
    ),
  )
  match expected_top_origins {
    Some(origins) => options.with_expected_top_origins(origins)
    None => options
  }
}

///|
test "client_data_parser_reads_top_origin" {
  let parsed = @helpers.parse_client_data_json_string(
    "{\"type\":\"webauthn.get\",\"challenge\":\"AQID\",\"origin\":\"https://example.com\",\"crossOrigin\":true,\"topOrigin\":\"https://frame.example\"}",
  ) catch {
    _ => panic()
  }
  assert_eq(parsed.top_origin, Some("https://frame.example"))
}

///|
test "verify_authentication_rejects_cross_origin_without_expected_top_origin" {
  let client_data = make_top_origin_client_data(
    true,
    Some("https://frame.example"),
  )
  let credential_id = b"top-origin-credential"
  let result = try {
    let _ = @server.verify_authentication_response(
      credential_id,
      client_data,
      b"",
      b"",
      make_top_origin_options(None),
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::ValidationError(_) => Err("TopOrigin")
    _ => Err("Other")
  }
  assert_eq(result, Err("TopOrigin"))
}

///|
async test "verify_authentication_rejects_unlisted_cross_origin_async" {
  let client_data = make_top_origin_client_data(
    true,
    Some("https://frame.example"),
  )
  let credential_id = b"top-origin-credential"
  let result = @server.verify_authentication_response_async(
    credential_id,
    client_data,
    b"",
    b"",
    make_top_origin_options(Some(["https://trusted-frame.example"])),
  )
  assert_true(
    result is Err(@server.AuthenticationVerifyError::ValidationError(_)),
  )
}

///|
test "verify_authentication_accepts_configured_top_origin" {
  let client_data = make_top_origin_client_data(
    true,
    Some("https://frame.example"),
  )
  let credential_id = b"top-origin-credential"
  let result = try {
    let _ = @server.verify_authentication_response(
      credential_id,
      client_data,
      b"",
      b"",
      make_top_origin_options(
        Some(["https://alternate.example", "https://frame.example"]),
      ),
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::AuthenticatorDataParseError(_) =>
      Err("TopOriginAccepted")
    @server.AuthenticationVerifyError::ValidationError(_) => Err("TopOrigin")
    _ => Err("Other")
  }
  assert_eq(result, Err("TopOriginAccepted"))
}

///|
test "verify_authentication_allows_cross_origin_when_top_origin_is_unreported" {
  let client_data = make_top_origin_client_data(true, None)
  let credential_id = b"top-origin-credential"
  let result = try {
    let _ = @server.verify_authentication_response(
      credential_id,
      client_data,
      b"",
      b"",
      make_top_origin_options(None),
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::AuthenticatorDataParseError(_) =>
      Err("TopOriginAccepted")
    @server.AuthenticationVerifyError::ValidationError(_) => Err("TopOrigin")
    _ => Err("Other")
  }
  assert_eq(result, Err("TopOriginAccepted"))
}

///|
test "verify_authentication_rejects_top_origin_without_cross_origin_flag" {
  let client_data = make_top_origin_client_data(
    false,
    Some("https://frame.example"),
  )
  let credential_id = b"top-origin-credential"
  let result = try {
    let _ = @server.verify_authentication_response(
      credential_id,
      client_data,
      b"",
      b"",
      make_top_origin_options(Some(["https://frame.example"])),
    )
    Ok(())
  } catch {
    @server.AuthenticationVerifyError::ValidationError(_) => Err("TopOrigin")
    _ => Err("Other")
  }
  assert_eq(result, Err("TopOrigin"))
}
