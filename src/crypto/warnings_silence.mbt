///|
/// Touch unused constructors to keep warnings clean in checks.
fn _touch_unused() -> Unit {
  let _ = ECDSAError::VerificationFailed("")
}

///|
fn init {
  _touch_unused()
}
