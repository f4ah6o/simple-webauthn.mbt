///|
extern "js" fn ffi_browser_supports_webauthn() -> Bool =
  #| () => {
  #|   return (
  #|     typeof globalThis !== "undefined" &&
  #|     globalThis.PublicKeyCredential !== undefined &&
  #|     typeof globalThis.PublicKeyCredential === "function"
  #|   );
  #| }

///|
extern "js" fn ffi_platform_authenticator_is_available() -> @js.Promise[Bool] =
  #| async () => {
  #|   try {
  #|     if (
  #|       typeof globalThis === "undefined" ||
  #|       globalThis.PublicKeyCredential === undefined ||
  #|       typeof globalThis.PublicKeyCredential !== "function"
  #|     ) {
  #|       return false;
  #|     }
  #|
  #|     const fn = globalThis.PublicKeyCredential
  #|       .isUserVerifyingPlatformAuthenticatorAvailable;
  #|     if (typeof fn !== "function") {
  #|       return false;
  #|     }
  #|
  #|     return await fn.call(globalThis.PublicKeyCredential);
  #|   } catch (_error) {
  #|     return false;
  #|   }
  #| }

///|
extern "js" fn ffi_browser_supports_webauthn_autofill() -> @js.Promise[Bool] =
  #| async () => {
  #|   try {
  #|     if (
  #|       typeof globalThis === "undefined" ||
  #|       globalThis.PublicKeyCredential === undefined ||
  #|       typeof globalThis.PublicKeyCredential !== "function"
  #|     ) {
  #|       return false;
  #|     }
  #|
  #|     const fn = globalThis.PublicKeyCredential.isConditionalMediationAvailable;
  #|     if (typeof fn !== "function") {
  #|       return false;
  #|     }
  #|
  #|     return await fn.call(globalThis.PublicKeyCredential);
  #|   } catch (_error) {
  #|     return false;
  #|   }
  #| }

///|
/// Determine whether the current runtime supports WebAuthn APIs.
pub fn browser_supports_webauthn() -> Bool {
  ffi_browser_supports_webauthn()
}

///|
/// Determine whether a platform authenticator is available.
pub async fn platform_authenticator_is_available() -> Bool {
  ffi_platform_authenticator_is_available().wait() catch {
    _ => false
  }
}

///|
/// Determine whether conditional UI (autofill) is available.
pub async fn browser_supports_webauthn_autofill() -> Bool {
  ffi_browser_supports_webauthn_autofill().wait() catch {
    _ => false
  }
}
