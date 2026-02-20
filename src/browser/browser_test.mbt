///|
extern "js" fn ffi_test_reset_environment() -> Unit =
  #| () => {
  #|   const clear = (key) => {
  #|     try {
  #|       delete globalThis[key];
  #|     } catch (_error) {
  #|       globalThis[key] = undefined;
  #|     }
  #|   };
  #|
  #|   clear("PublicKeyCredential");
  #|   clear("__simple_webauthn_mbt_abort_controller");
  #|   clear("__simple_webauthn_mbt_abort_called");
  #|   clear("document");
  #|
  #|   if (globalThis.navigator && globalThis.navigator.credentials) {
  #|     delete globalThis.navigator.credentials.create;
  #|     delete globalThis.navigator.credentials.get;
  #|   }
  #| }

///|
extern "js" fn ffi_test_install_support(
  autofill_supported : Bool,
  platform_available : Bool,
) -> Unit =
  #| (autofill_supported, platform_available) => {
  #|   function PublicKeyCredentialMock() {}
  #|
  #|   PublicKeyCredentialMock
  #|     .isUserVerifyingPlatformAuthenticatorAvailable = async () => platform_available;
  #|
  #|   if (autofill_supported) {
  #|     PublicKeyCredentialMock.isConditionalMediationAvailable = async () => true;
  #|   }
  #|
  #|   globalThis.PublicKeyCredential = PublicKeyCredentialMock;
  #|   if (!globalThis.navigator) {
  #|     globalThis.navigator = {};
  #|   }
  #|   if (!globalThis.navigator.credentials) {
  #|     globalThis.navigator.credentials = {};
  #|   }
  #| }

///|
extern "js" fn ffi_test_install_registration_mock() -> Unit =
  #| () => {
  #|   const toArrayBuffer = (s) => new TextEncoder().encode(s).buffer;
  #|   if (!globalThis.navigator) {
  #|     globalThis.navigator = {};
  #|   }
  #|   if (!globalThis.navigator.credentials) {
  #|     globalThis.navigator.credentials = {};
  #|   }
  #|   globalThis.navigator.credentials.create = async (_opts) => {
  #|     return {
  #|       id: "test-registration-id",
  #|       rawId: toArrayBuffer("raw-registration-id"),
  #|       type: "public-key",
  #|       response: {
  #|         attestationObject: toArrayBuffer("attestation-object"),
  #|         clientDataJSON: toArrayBuffer("client-data-json"),
  #|         getTransports: () => ["internal"],
  #|         getPublicKeyAlgorithm: () => -7,
  #|         getPublicKey: () => toArrayBuffer("public-key"),
  #|         getAuthenticatorData: () => toArrayBuffer("authenticator-data"),
  #|       },
  #|       getClientExtensionResults: () => ({ appid: false }),
  #|       authenticatorAttachment: "platform",
  #|     };
  #|   };
  #| }

///|
extern "js" fn ffi_test_install_authentication_mock() -> Unit =
  #| () => {
  #|   const toArrayBuffer = (s) => new TextEncoder().encode(s).buffer;
  #|   if (!globalThis.navigator) {
  #|     globalThis.navigator = {};
  #|   }
  #|   if (!globalThis.navigator.credentials) {
  #|     globalThis.navigator.credentials = {};
  #|   }
  #|   globalThis.navigator.credentials.get = async (_opts) => {
  #|     return {
  #|       id: "test-authentication-id",
  #|       rawId: toArrayBuffer("raw-authentication-id"),
  #|       type: "public-key",
  #|       response: {
  #|         authenticatorData: toArrayBuffer("authenticator-data"),
  #|         clientDataJSON: toArrayBuffer("client-data-json"),
  #|         signature: toArrayBuffer("signature-bytes"),
  #|         userHandle: toArrayBuffer("user-handle"),
  #|       },
  #|       getClientExtensionResults: () => ({ appid: false }),
  #|       authenticatorAttachment: "platform",
  #|     };
  #|   };
  #| }

///|
extern "js" fn ffi_test_set_document_inputs(count : Int) -> Unit =
  #| (count) => {
  #|   globalThis.document = {
  #|     querySelectorAll: () => Array.from({ length: count }, () => ({})),
  #|   };
  #| }

///|
extern "js" fn ffi_test_install_abort_stub() -> Unit =
  #| () => {
  #|   globalThis.__simple_webauthn_mbt_abort_called = false;
  #|   globalThis.__simple_webauthn_mbt_abort_controller = {
  #|     abort: () => {
  #|       globalThis.__simple_webauthn_mbt_abort_called = true;
  #|     },
  #|   };
  #| }

///|
extern "js" fn ffi_test_abort_called() -> Bool =
  #| () => {
  #|   return globalThis.__simple_webauthn_mbt_abort_called === true;
  #| }

///|
fn make_registration_options() -> @types.PublicKeyCredentialCreationOptionsJSON {
  let rp = @types.RelyingParty::new("Example RP", id=Some("example.com"))
  let user = @types.PublicKeyCredentialUserEntity::new(
    @helpers.base64url_encode(b"user-id"),
    "alice",
    "Alice",
  )
  let challenge = @types.Base64URLString::new(
    @helpers.base64url_encode(b"registration-challenge"),
  )
  let params = [
    @types.PublicKeyCredentialParameters::new(@types.COSEAlgorithm::ES256),
  ]
  @types.PublicKeyCredentialCreationOptionsJSON::new(
    rp, user, challenge, params,
  )
}

///|
fn make_authentication_options() -> @types.PublicKeyCredentialRequestOptionsJSON {
  let challenge = @types.Base64URLString::new(
    @helpers.base64url_encode(b"authentication-challenge"),
  )
  @types.PublicKeyCredentialRequestOptionsJSON::new(challenge)
}

///|
fn json_object_get_string(obj : Map[String, Json], key : String) -> String {
  match obj.get(key) {
    Some(Json::String(value)) => value
    _ => panic()
  }
}

///|
test "base64url_helpers_roundtrip" {
  let original = b"hello-browser-api"
  let encoded = buffer_to_base64url_string(original)
  let decoded = base64url_string_to_buffer(encoded) catch { _ => panic() }
  assert_eq(decoded, original)
}

///|
test "browser_supports_webauthn_detects_runtime" {
  ffi_test_reset_environment()
  assert_eq(browser_supports_webauthn(), false)

  ffi_test_install_support(false, false)
  assert_eq(browser_supports_webauthn(), true)
}

///|
async test "platform_authenticator_is_available_reads_api" {
  ffi_test_reset_environment()
  ffi_test_install_support(false, true)
  let available = platform_authenticator_is_available()
  assert_eq(available, true)
}

///|
async test "start_registration_returns_not_supported" {
  ffi_test_reset_environment()

  let input = StartRegistrationInput::new(make_registration_options())
  let result = start_registration(input)

  match result {
    Err(NotSupported(_)) => ()
    _ => panic()
  }
}

///|
async test "start_authentication_autofill_not_supported" {
  ffi_test_reset_environment()
  ffi_test_install_support(false, true)

  let input = StartAuthenticationInput::new(
    make_authentication_options(),
    use_browser_autofill=true,
  )
  let result = start_authentication(input)

  match result {
    Err(AutofillNotSupported(_)) => ()
    _ => panic()
  }
}

///|
async test "start_authentication_missing_autofill_input" {
  ffi_test_reset_environment()
  ffi_test_install_support(true, true)
  ffi_test_set_document_inputs(0)

  let input = StartAuthenticationInput::new(
    make_authentication_options(),
    use_browser_autofill=true,
    verify_browser_autofill_input=true,
  )
  let result = start_authentication(input)

  match result {
    Err(MissingAutofillInput(_)) => ()
    _ => panic()
  }
}

///|
async test "start_registration_maps_response" {
  ffi_test_reset_environment()
  ffi_test_install_support(false, true)
  ffi_test_install_registration_mock()

  let input = StartRegistrationInput::new(make_registration_options())
  let result = start_registration(input)

  guard result is Ok(response) else { panic() }
  let response_json = response.to_json()
  guard response_json is Json::Object(obj) else { panic() }

  assert_eq(json_object_get_string(obj, "id"), "test-registration-id")
  assert_eq(
    json_object_get_string(obj, "rawId"),
    buffer_to_base64url_string(b"raw-registration-id"),
  )
  assert_eq(json_object_get_string(obj, "type"), "public-key")

  guard obj.get("response") is Some(Json::Object(response_obj)) else { panic() }
  assert_eq(
    json_object_get_string(response_obj, "attestationObject"),
    buffer_to_base64url_string(b"attestation-object"),
  )
}

///|
async test "start_authentication_maps_response" {
  ffi_test_reset_environment()
  ffi_test_install_support(false, true)
  ffi_test_install_authentication_mock()

  let input = StartAuthenticationInput::new(make_authentication_options())
  let result = start_authentication(input)

  guard result is Ok(response) else { panic() }
  let response_json = response.to_json()
  guard response_json is Json::Object(obj) else { panic() }

  assert_eq(json_object_get_string(obj, "id"), "test-authentication-id")
  assert_eq(
    json_object_get_string(obj, "rawId"),
    buffer_to_base64url_string(b"raw-authentication-id"),
  )

  guard obj.get("response") is Some(Json::Object(response_obj)) else { panic() }
  assert_eq(
    json_object_get_string(response_obj, "signature"),
    buffer_to_base64url_string(b"signature-bytes"),
  )
  assert_eq(
    json_object_get_string(response_obj, "userHandle"),
    buffer_to_base64url_string(b"user-handle"),
  )
}

///|
test "cancel_ceremony_aborts_active_controller" {
  ffi_test_reset_environment()
  ffi_test_install_abort_stub()

  cancel_ceremony()

  assert_eq(ffi_test_abort_called(), true)
}
