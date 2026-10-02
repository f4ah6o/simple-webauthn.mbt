///|
extern "js" fn ffi_test_install_capability_mock(
  capabilities_json : String,
  api_available : Bool,
  platform_available : Int,
  conditional_available : Int,
) -> Unit =
  #| (capabilities_json, api_available, platform_available, conditional_available) => {
  #|   function PublicKeyCredentialMock() {}
  #|   globalThis.__simple_webauthn_mbt_capability_fallback_calls = {
  #|     platform: 0,
  #|     conditional: 0,
  #|   };
  #|   if (api_available) {
  #|     PublicKeyCredentialMock.getClientCapabilities = async () =>
  #|       JSON.parse(capabilities_json);
  #|   }
  #|   if (platform_available >= 0) {
  #|     PublicKeyCredentialMock
  #|       .isUserVerifyingPlatformAuthenticatorAvailable =
  #|         async () => {
  #|           globalThis.__simple_webauthn_mbt_capability_fallback_calls.platform++;
  #|           if (platform_available === 2) {
  #|             throw new Error("platform capability lookup failed");
  #|           }
  #|           return platform_available === 1;
  #|         };
  #|   }
  #|   if (conditional_available >= 0) {
  #|     PublicKeyCredentialMock.isConditionalMediationAvailable =
  #|       async () => {
  #|         globalThis.__simple_webauthn_mbt_capability_fallback_calls.conditional++;
  #|         if (conditional_available === 2) {
  #|           throw new Error("conditional capability lookup failed");
  #|         }
  #|         return conditional_available === 1;
  #|       };
  #|   }
  #|   globalThis.PublicKeyCredential = PublicKeyCredentialMock;
  #| };

///|
extern "js" fn ffi_test_install_rejecting_capability_mock() -> Unit =
  #| () => {
  #|   function PublicKeyCredentialMock() {}
  #|   PublicKeyCredentialMock.getClientCapabilities = async () => {
  #|     throw new Error("client capability lookup failed");
  #|   };
  #|   globalThis.PublicKeyCredential = PublicKeyCredentialMock;
  #| };

///|
extern "js" fn ffi_test_platform_fallback_calls() -> Int =
  #| () => globalThis.__simple_webauthn_mbt_capability_fallback_calls?.platform ?? 0;

///|
extern "js" fn ffi_test_conditional_fallback_calls() -> Int =
  #| () => globalThis.__simple_webauthn_mbt_capability_fallback_calls?.conditional ?? 0;

///|
async test "browser_capabilities_and_passkey_support" {
  ffi_test_reset_environment()

  // A browser without getClientCapabilities reports every value as unknown,
  // even if legacy fallback methods exist.
  ffi_test_install_capability_mock("{}", false, 1, 1)
  assert_eq(
    @browser.get_browser_capabilities(),
    @browser.BrowserCapabilities::unknown(),
  )
  assert_eq(ffi_test_platform_fallback_calls(), 0)
  assert_eq(ffi_test_conditional_fallback_calls(), 0)

  // Unknown values use the two legacy APIs, while explicit true/false values
  // for the other capabilities pass through unchanged.
  ffi_test_install_capability_mock(
    "{\"conditionalCreate\":true,\"hybridTransport\":false,\"passkeyPlatformAuthenticator\":true,\"relatedOrigins\":false,\"signalAllAcceptedCredentials\":true,\"signalCurrentUserDetails\":false}",
    true, 1, 0,
  )
  let mut capabilities = @browser.get_browser_capabilities()
  assert_eq(
    capabilities.conditional_create,
    @browser.BrowserCapabilitySupport::Supported,
  )
  assert_eq(
    capabilities.conditional_get,
    @browser.BrowserCapabilitySupport::Unsupported,
  )
  assert_eq(
    capabilities.hybrid_transport,
    @browser.BrowserCapabilitySupport::Unsupported,
  )
  assert_eq(
    capabilities.passkey_platform_authenticator,
    @browser.BrowserCapabilitySupport::Supported,
  )
  assert_eq(
    capabilities.user_verifying_platform_authenticator,
    @browser.BrowserCapabilitySupport::Supported,
  )
  assert_eq(
    capabilities.related_origins,
    @browser.BrowserCapabilitySupport::Unsupported,
  )
  assert_eq(
    capabilities.signal_all_accepted_credentials,
    @browser.BrowserCapabilitySupport::Supported,
  )
  assert_eq(
    capabilities.signal_current_user_details,
    @browser.BrowserCapabilitySupport::Unsupported,
  )
  assert_eq(
    capabilities.signal_unknown_credential,
    @browser.BrowserCapabilitySupport::Unknown,
  )
  assert_eq(ffi_test_platform_fallback_calls(), 1)
  assert_eq(ffi_test_conditional_fallback_calls(), 1)

  // A known false value must not be overwritten by a positive legacy fallback.
  ffi_test_install_capability_mock(
    "{\"conditionalGet\":false,\"userVerifyingPlatformAuthenticator\":false}", true,
    1, 1,
  )
  capabilities = @browser.get_browser_capabilities()
  assert_eq(
    capabilities.conditional_get,
    @browser.BrowserCapabilitySupport::Unsupported,
  )
  assert_eq(
    capabilities.user_verifying_platform_authenticator,
    @browser.BrowserCapabilitySupport::Unsupported,
  )
  assert_eq(ffi_test_platform_fallback_calls(), 0)
  assert_eq(ffi_test_conditional_fallback_calls(), 0)

  // This MoonBit port conservatively maps rejected capability APIs to unknown.
  ffi_test_install_rejecting_capability_mock()
  assert_eq(
    @browser.get_browser_capabilities(),
    @browser.BrowserCapabilities::unknown(),
  )
  ffi_test_install_capability_mock(
    "{\"conditionalGet\":null,\"userVerifyingPlatformAuthenticator\":null}", true,
    2, 2,
  )
  capabilities = @browser.get_browser_capabilities()
  assert_eq(
    capabilities.conditional_get,
    @browser.BrowserCapabilitySupport::Unknown,
  )
  assert_eq(
    capabilities.user_verifying_platform_authenticator,
    @browser.BrowserCapabilitySupport::Unknown,
  )
  assert_eq(ffi_test_platform_fallback_calls(), 1)
  assert_eq(ffi_test_conditional_fallback_calls(), 1)

  // Each of the three passkey-related capabilities independently enables it.
  ffi_test_install_capability_mock(
    "{\"passkeyPlatformAuthenticator\":true,\"hybridTransport\":false,\"userVerifyingPlatformAuthenticator\":false}",
    true, -1, -1,
  )
  assert_true(@browser.browser_supports_passkeys())
  ffi_test_install_capability_mock(
    "{\"passkeyPlatformAuthenticator\":false,\"hybridTransport\":true,\"userVerifyingPlatformAuthenticator\":false}",
    true, -1, -1,
  )
  assert_true(@browser.browser_supports_passkeys())
  ffi_test_install_capability_mock(
    "{\"passkeyPlatformAuthenticator\":false,\"hybridTransport\":false}", true, 1,
    -1,
  )
  assert_true(@browser.browser_supports_passkeys())
  ffi_test_install_capability_mock(
    "{\"passkeyPlatformAuthenticator\":false,\"hybridTransport\":false,\"userVerifyingPlatformAuthenticator\":false}",
    true, -1, -1,
  )
  assert_false(@browser.browser_supports_passkeys())

  ffi_test_reset_environment()
  assert_false(@browser.browser_supports_passkeys())
  ffi_test_reset_environment()
}
