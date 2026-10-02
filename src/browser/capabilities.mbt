///|
/// A tri-state result describing whether a WebAuthn capability is available.
pub(all) enum BrowserCapabilitySupport {
  Supported
  Unsupported
  Unknown
} derive(Debug, Eq)

///|
/// WebAuthn features reported by the browser capability API.
pub(all) struct BrowserCapabilities {
  conditional_create : BrowserCapabilitySupport
  conditional_get : BrowserCapabilitySupport
  hybrid_transport : BrowserCapabilitySupport
  passkey_platform_authenticator : BrowserCapabilitySupport
  user_verifying_platform_authenticator : BrowserCapabilitySupport
  related_origins : BrowserCapabilitySupport
  signal_all_accepted_credentials : BrowserCapabilitySupport
  signal_current_user_details : BrowserCapabilitySupport
  signal_unknown_credential : BrowserCapabilitySupport
} derive(Debug, Eq)

///|
/// Create a capability set where every value is unknown.
pub fn BrowserCapabilities::unknown() -> BrowserCapabilities {
  {
    conditional_create: Unknown,
    conditional_get: Unknown,
    hybrid_transport: Unknown,
    passkey_platform_authenticator: Unknown,
    user_verifying_platform_authenticator: Unknown,
    related_origins: Unknown,
    signal_all_accepted_credentials: Unknown,
    signal_current_user_details: Unknown,
    signal_unknown_credential: Unknown,
  }
}

///|
extern "js" fn ffi_get_browser_capability_payload() -> @js.Promise[String] =
  #| async () => {
  #|   const unknown = JSON.stringify({ available: false });
  #|   const credential = globalThis.PublicKeyCredential;
  #|   if (
  #|     typeof credential !== "function" ||
  #|     typeof credential.getClientCapabilities !== "function"
  #|   ) {
  #|     return unknown;
  #|   }
  #|
  #|   try {
  #|     const capabilities = await credential.getClientCapabilities();
  #|     const fallback = {};
  #|
  #|     if (
  #|       typeof capabilities?.userVerifyingPlatformAuthenticator !== "boolean" &&
  #|       typeof credential.isUserVerifyingPlatformAuthenticatorAvailable === "function"
  #|     ) {
  #|       try {
  #|         fallback.userVerifyingPlatformAuthenticator =
  #|           await credential.isUserVerifyingPlatformAuthenticatorAvailable();
  #|       } catch (_error) {
  #|       }
  #|     }
  #|
  #|     if (
  #|       typeof capabilities?.conditionalGet !== "boolean" &&
  #|       typeof credential.isConditionalMediationAvailable === "function"
  #|     ) {
  #|       try {
  #|         fallback.conditionalGet =
  #|           await credential.isConditionalMediationAvailable();
  #|       } catch (_error) {
  #|       }
  #|     }
  #|
  #|     return JSON.stringify({
  #|       available: true,
  #|       capabilities: capabilities || {},
  #|       fallback,
  #|     });
  #|   } catch (_error) {
  #|     return unknown;
  #|   }
  #| };

///|
fn json_member(json : Json, key : String) -> Json? {
  match json {
    Object(obj) => obj.get(key)
    _ => None
  }
}

///|
fn map_capability(value : Json?) -> BrowserCapabilitySupport {
  match value {
    Some(True) => Supported
    Some(False) => Unsupported
    _ => Unknown
  }
}

///|
fn map_capability_with_fallback(
  capabilities : Json,
  fallback : Json,
  key : String,
) -> BrowserCapabilitySupport {
  match json_member(capabilities, key) {
    Some(True) => Supported
    Some(False) => Unsupported
    _ => map_capability(json_member(fallback, key))
  }
}

///|
fn map_browser_capabilities(payload : Json) -> BrowserCapabilities {
  guard json_member(payload, "available") is Some(True) else {
    return BrowserCapabilities::unknown()
  }
  let capabilities = match json_member(payload, "capabilities") {
    Some(value) => value
    None => Json::empty_object()
  }
  let fallback = match json_member(payload, "fallback") {
    Some(value) => value
    None => Json::empty_object()
  }
  {
    conditional_create: map_capability(
      json_member(capabilities, "conditionalCreate"),
    ),
    conditional_get: map_capability_with_fallback(
      capabilities, fallback, "conditionalGet",
    ),
    hybrid_transport: map_capability(
      json_member(capabilities, "hybridTransport"),
    ),
    passkey_platform_authenticator: map_capability(
      json_member(capabilities, "passkeyPlatformAuthenticator"),
    ),
    user_verifying_platform_authenticator: map_capability_with_fallback(
      capabilities, fallback, "userVerifyingPlatformAuthenticator",
    ),
    related_origins: map_capability(json_member(capabilities, "relatedOrigins")),
    signal_all_accepted_credentials: map_capability(
      json_member(capabilities, "signalAllAcceptedCredentials"),
    ),
    signal_current_user_details: map_capability(
      json_member(capabilities, "signalCurrentUserDetails"),
    ),
    signal_unknown_credential: map_capability(
      json_member(capabilities, "signalUnknownCredential"),
    ),
  }
}

///|
/// Read browser WebAuthn capabilities, using older equivalent APIs when available.
pub async fn get_browser_capabilities() -> BrowserCapabilities {
  let payload = ffi_get_browser_capability_payload().wait() catch {
    _ => "{\"available\":false}"
  }
  let parsed = @json.parse(payload) catch { _ => Json::empty_object() }
  map_browser_capabilities(parsed)
}

///|
fn capabilities_support_passkeys(capabilities : BrowserCapabilities) -> Bool {
  capabilities.passkey_platform_authenticator == Supported ||
  capabilities.hybrid_transport == Supported ||
  capabilities.user_verifying_platform_authenticator == Supported
}

///|
/// Determine whether the browser can use a passkey for authentication.
pub async fn browser_supports_passkeys() -> Bool {
  let capabilities = get_browser_capabilities()
  capabilities_support_passkeys(capabilities)
}
