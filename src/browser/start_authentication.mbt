///|
pub struct StartAuthenticationInput {
  options_json : @types.PublicKeyCredentialRequestOptionsJSON
  use_browser_autofill : Bool
  verify_browser_autofill_input : Bool
} derive(Show, Eq)

///|
pub fn StartAuthenticationInput::new(
  options_json : @types.PublicKeyCredentialRequestOptionsJSON,
  use_browser_autofill? : Bool = false,
  verify_browser_autofill_input? : Bool = true,
) -> StartAuthenticationInput {
  { options_json, use_browser_autofill, verify_browser_autofill_input }
}

///|
extern "js" fn ffi_start_authentication(
  options_json : String,
  use_browser_autofill : Bool,
  verify_browser_autofill_input : Bool,
) -> @js.Promise[String] =
  #| async (options_json, use_browser_autofill, verify_browser_autofill_input) => {
  #|   const ok = (value) => JSON.stringify({ ok: true, value });
  #|   const err = (code, message) => JSON.stringify({ ok: false, code, message });
  #|
  #|   const mapRuntimeError = (error) => {
  #|     const name = error && error.name ? String(error.name) : "Error";
  #|     const message = error && error.message ? String(error.message) : "Unknown error";
  #|     if (name === "AbortError") {
  #|       return { code: "ceremony_aborted", message };
  #|     }
  #|     if (name === "NotSupportedError" || name === "SecurityError") {
  #|       return { code: "not_supported", message };
  #|     }
  #|     return { code: "dom_error", message: `${name}: ${message}` };
  #|   };
  #|
  #|   const base64URLStringToBuffer = (base64URLString) => {
  #|     const base64 = base64URLString.replace(/-/g, "+").replace(/_/g, "/");
  #|     const padLength = (4 - (base64.length % 4)) % 4;
  #|     const padded = base64 + "=".repeat(padLength);
  #|
  #|     if (typeof atob === "function") {
  #|       const binary = atob(padded);
  #|       const buffer = new ArrayBuffer(binary.length);
  #|       const bytes = new Uint8Array(buffer);
  #|       for (let i = 0; i < binary.length; i++) {
  #|         bytes[i] = binary.charCodeAt(i);
  #|       }
  #|       return buffer;
  #|     }
  #|
  #|     if (typeof Buffer !== "undefined") {
  #|       const buf = Buffer.from(padded, "base64");
  #|       return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  #|     }
  #|
  #|     throw new Error("No base64 decoder is available");
  #|   };
  #|
  #|   const bufferToBase64URLString = (bufferLike) => {
  #|     const bytes = bufferLike instanceof Uint8Array
  #|       ? bufferLike
  #|       : new Uint8Array(bufferLike);
  #|
  #|     let base64;
  #|     if (typeof btoa === "function") {
  #|       let str = "";
  #|       for (const charCode of bytes) {
  #|         str += String.fromCharCode(charCode);
  #|       }
  #|       base64 = btoa(str);
  #|     } else if (typeof Buffer !== "undefined") {
  #|       base64 = Buffer.from(bytes).toString("base64");
  #|     } else {
  #|       throw new Error("No base64 encoder is available");
  #|     }
  #|
  #|     return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  #|   };
  #|
  #|   const toPublicKeyCredentialDescriptor = (desc) => {
  #|     const converted = { ...desc, id: base64URLStringToBuffer(desc.id) };
  #|     return converted;
  #|   };
  #|
  #|   const createNewAbortSignal = () => {
  #|     const key = "__simple_webauthn_mbt_abort_controller";
  #|     const previous = globalThis[key];
  #|     if (previous && typeof previous.abort === "function") {
  #|       const abortError = new Error("Cancelling existing WebAuthn API call for new one");
  #|       abortError.name = "AbortError";
  #|       previous.abort(abortError);
  #|     }
  #|     const next = new AbortController();
  #|     globalThis[key] = next;
  #|     return next.signal;
  #|   };
  #|
  #|   const supportsAutofill = async () => {
  #|     if (
  #|       typeof globalThis === "undefined" ||
  #|       globalThis.PublicKeyCredential === undefined ||
  #|       typeof globalThis.PublicKeyCredential !== "function"
  #|     ) {
  #|       return false;
  #|     }
  #|     const fn = globalThis.PublicKeyCredential.isConditionalMediationAvailable;
  #|     if (typeof fn !== "function") {
  #|       return false;
  #|     }
  #|     try {
  #|       return await fn.call(globalThis.PublicKeyCredential);
  #|     } catch (_error) {
  #|       return false;
  #|     }
  #|   };
  #|
  #|   try {
  #|     if (
  #|       typeof globalThis === "undefined" ||
  #|       globalThis.PublicKeyCredential === undefined ||
  #|       typeof globalThis.PublicKeyCredential !== "function"
  #|     ) {
  #|       return err("not_supported", "WebAuthn is not supported in this browser");
  #|     }
  #|
  #|     const optionsJSON = JSON.parse(options_json);
  #|
  #|     let allowCredentials;
  #|     if (optionsJSON.allowCredentials?.length !== 0) {
  #|       allowCredentials = optionsJSON.allowCredentials?.map(
  #|         toPublicKeyCredentialDescriptor,
  #|       );
  #|     }
  #|
  #|     const publicKey = {
  #|       ...optionsJSON,
  #|       challenge: base64URLStringToBuffer(optionsJSON.challenge),
  #|       allowCredentials,
  #|     };
  #|
  #|     const getOptions = {
  #|       publicKey,
  #|     };
  #|
  #|     if (use_browser_autofill) {
  #|       if (!(await supportsAutofill())) {
  #|         return err("autofill_not_supported", "Browser does not support WebAuthn autofill");
  #|       }
  #|
  #|       let eligibleInputs = [];
  #|       if (typeof document !== "undefined" && typeof document.querySelectorAll === "function") {
  #|         eligibleInputs = document.querySelectorAll("input[autocomplete$='webauthn']");
  #|       }
  #|       if (verify_browser_autofill_input && eligibleInputs.length < 1) {
  #|         return err(
  #|           "missing_autofill_input",
  #|           "No input with autocomplete ending in webauthn was detected",
  #|         );
  #|       }
  #|
  #|       getOptions.mediation = "conditional";
  #|       publicKey.allowCredentials = [];
  #|     }
  #|
  #|     if (typeof AbortController === "function") {
  #|       getOptions.signal = createNewAbortSignal();
  #|     }
  #|
  #|     let credential;
  #|     try {
  #|       credential = await navigator.credentials.get(getOptions);
  #|     } catch (error) {
  #|       const mapped = mapRuntimeError(error);
  #|       return err(mapped.code, mapped.message);
  #|     }
  #|
  #|     if (!credential) {
  #|       return err("invalid_response", "Authentication was not completed");
  #|     }
  #|     if (!credential.response) {
  #|       return err("invalid_response", "Credential response is missing");
  #|     }
  #|
  #|     const response = credential.response;
  #|     if (!response.authenticatorData || !response.clientDataJSON || !response.signature) {
  #|       return err("invalid_response", "Assertion response is missing required fields");
  #|     }
  #|
  #|     const result = {
  #|       id: String(credential.id),
  #|       rawId: bufferToBase64URLString(credential.rawId),
  #|       response: {
  #|         authenticatorData: bufferToBase64URLString(response.authenticatorData),
  #|         clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
  #|         signature: bufferToBase64URLString(response.signature),
  #|       },
  #|       type: String(credential.type || "public-key"),
  #|       clientExtensionResults:
  #|         typeof credential.getClientExtensionResults === "function"
  #|           ? credential.getClientExtensionResults()
  #|           : {},
  #|     };
  #|
  #|     if (response.userHandle) {
  #|       result.response.userHandle = bufferToBase64URLString(response.userHandle);
  #|     }
  #|     if (typeof credential.authenticatorAttachment === "string") {
  #|       result.authenticatorAttachment = credential.authenticatorAttachment;
  #|     }
  #|
  #|     return ok(result);
  #|   } catch (error) {
  #|     const mapped = mapRuntimeError(error);
  #|     const code = mapped.code === "dom_error" ? mapped.code : "invalid_input";
  #|     return err(code, mapped.message);
  #|   }
  #| }

///|
/// Begin authenticator authentication via browser WebAuthn APIs.
pub async fn start_authentication(
  input : StartAuthenticationInput,
) -> Result[@types.AuthenticationResponseJSON, BrowserError] {
  let options_json = input.options_json.to_json().stringify()
  let raw_result = ffi_start_authentication(
    options_json,
    input.use_browser_autofill,
    input.verify_browser_autofill_input,
  ).wait() catch {
    _ => return Err(Unknown("Browser authentication bridge failed"))
  }

  let value_json = match parse_browser_result(raw_result) {
    Ok(value) => value
    Err(error) => return Err(error)
  }

  let response : @types.AuthenticationResponseJSON = @json.from_json(value_json) catch {
    decode_error =>
      return Err(
        InvalidResponse(
          "Failed to decode authentication response: \{decode_error.to_string()}",
        ),
      )
  }

  Ok(response)
}
