///|
/// Touch unused constructors to keep warnings clean in checks.
fn _touch_unused() -> Unit {
  let _ = RegistrationVerifyError::AttestationSignatureInvalid("")
  let _ = RegistrationVerifyError::ValidationError("")
  let _ = AuthenticationVerifyError::ValidationError("")
}

fn init {
  _touch_unused()
}
