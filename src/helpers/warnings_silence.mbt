///|
/// Touch unused constructors/functions to keep warnings clean in checks.
fn _touch_unused() -> Unit {
  let _ = AuthenticatorDataError::InvalidFlags(b'\x00')
  let _ = Base64URLError::InvalidChar(0)
  let _ = Base64URLError::InvalidPadding
  let _ = Base64URLError::InvalidLength
  let _ = ClientDataError::InvalidOrigin
  let _ = ClientDataType::to_string(Create)
}

fn init {
  _touch_unused()
}
