///|
/// Preserve the upstream CBOR value's `Show` support while using the current
/// `Debug` representation for the implementation.
pub impl Show for CborValue with fn output(self, logger) {
  logger.write_string(@debug.to_string(self))
}

///|
pub extend CborValue with Show::{to_string, output}
