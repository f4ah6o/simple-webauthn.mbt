///|
extern "js" fn ffi_cancel_ceremony() -> Unit =
  #| () => {
  #|   const key = "__simple_webauthn_mbt_abort_controller";
  #|   const controller = globalThis[key];
  #|   if (controller && typeof controller.abort === "function") {
  #|     const abortError = new Error("Manually cancelling existing WebAuthn API call");
  #|     abortError.name = "AbortError";
  #|     controller.abort(abortError);
  #|   }
  #|   globalThis[key] = undefined;
  #| }

///|
/// Cancel an active browser WebAuthn ceremony, if one exists.
pub fn cancel_ceremony() -> Unit {
  ffi_cancel_ceremony()
}
