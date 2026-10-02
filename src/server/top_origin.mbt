///|
/// Return an error message when top-origin information violates the RP policy.
/// Browsers that do not yet report `topOrigin` may still authenticate in an iframe.
fn top_origin_error_message(
  cross_origin : Bool,
  top_origin : String?,
  expected_top_origins : Array[String]?,
) -> String? {
  match top_origin {
    Some(origin) if origin != "" && cross_origin =>
      match expected_top_origins {
        Some(expected) =>
          if expected
            .iter()
            .any(fn(expected_origin) { expected_origin == origin }) {
            None
          } else {
            Some(
              "Unexpected cross-origin authentication response top origin of " +
              "\"\{origin}\", expected one of: " +
              expected.join(", "),
            )
          }
        None =>
          Some(
            "Detected cross-origin authentication response from top origin of " +
            "\"\{origin}\", but expected_top_origin was not specified",
          )
      }
    Some(origin) if origin != "" =>
      Some(
        "Unexpected top origin of \"\{origin}\" within a non-cross-origin " +
        "authentication response",
      )
    _ => None
  }
}
