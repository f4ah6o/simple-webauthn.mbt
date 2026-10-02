///|
test "top_origin_policy_allows_same_origin_and_missing_safari_value" {
  assert_eq(top_origin_error_message(false, None, None), None)
  assert_eq(top_origin_error_message(true, None, None), None)
  assert_eq(top_origin_error_message(true, Some(""), None), None)
}

///|
test "top_origin_policy_requires_configuration_for_reported_iframe_origin" {
  assert_eq(
    top_origin_error_message(true, Some("https://top.example"), None),
    Some(
      "Detected cross-origin authentication response from top origin of " +
      "\"https://top.example\", but expected_top_origin was not specified",
    ),
  )
}

///|
test "top_origin_policy_matches_exactly_one_configured_origin" {
  assert_eq(
    top_origin_error_message(
      true,
      Some("https://top.example"),
      Some(["https://other.example", "https://top.example"]),
    ),
    None,
  )
}

///|
test "top_origin_policy_rejects_unlisted_iframe_origins" {
  assert_eq(
    top_origin_error_message(
      true,
      Some("https://evil.example"),
      Some(["https://top.example", "https://other.example"]),
    ),
    Some(
      "Unexpected cross-origin authentication response top origin of " +
      "\"https://evil.example\", expected one of: https://top.example, https://other.example",
    ),
  )
}

///|
test "top_origin_policy_rejects_top_origin_without_cross_origin_flag" {
  assert_eq(
    top_origin_error_message(false, Some("https://top.example"), None),
    Some(
      "Unexpected top origin of \"https://top.example\" within a non-cross-origin " +
      "authentication response",
    ),
  )
}
