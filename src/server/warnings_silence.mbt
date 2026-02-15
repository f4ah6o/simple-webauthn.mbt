///|
/// Touch unused constructors to keep warnings clean in checks.
fn _touch_unused() -> Unit {
  let _ = RegistrationVerifyError::AttestationSignatureInvalid("")
  let _ = RegistrationVerifyError::SignatureVerificationNotImplemented
  let _ = RegistrationVerifyError::ValidationError("")
  let _ = AuthenticationVerifyError::ValidationError("")

  let _ = PreferredAuthenticatorType::SecurityKey
  let _ = PreferredAuthenticatorType::LocalDevice
  let _ = PreferredAuthenticatorType::RemoteDevice

  let _ = VerificationMode::Permissive
  let _ = VerificationMode::Strict

  let _ = RootCertIdentifier::NoneAttestation
  let _ = RootCertIdentifier::Packed
  let _ = RootCertIdentifier::FidoU2F
  let _ = RootCertIdentifier::TPM
  let _ = RootCertIdentifier::AndroidKey
  let _ = RootCertIdentifier::AndroidSafetyNet
  let _ = RootCertIdentifier::Apple
  let _ = RootCertIdentifier::Mds
}

///|
fn init {
  _touch_unused()
}
