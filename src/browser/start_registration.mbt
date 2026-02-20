///|
pub struct StartRegistrationInput {
  options_json : @types.PublicKeyCredentialCreationOptionsJSON
  use_auto_register : Bool
} derive(Show, Eq)

///|
pub fn StartRegistrationInput::new(
  options_json : @types.PublicKeyCredentialCreationOptionsJSON,
  use_auto_register? : Bool = false,
) -> StartRegistrationInput {
  { options_json, use_auto_register }
}

///|
extern "js" fn ffi_start_registration(
  options_json : String,
  use_auto_register : Bool,
) -> @js.Promise[String] =
  #| async (options_json, use_auto_register) => {
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
  #|     const publicKey = {
  #|       ...optionsJSON,
  #|       challenge: base64URLStringToBuffer(optionsJSON.challenge),
  #|       user: {
  #|         ...optionsJSON.user,
  #|         id: base64URLStringToBuffer(optionsJSON.user.id),
  #|       },
  #|       excludeCredentials: optionsJSON.excludeCredentials?.map(
  #|         toPublicKeyCredentialDescriptor,
  #|       ),
  #|     };
  #|
  #|     const createOptions = {
  #|       publicKey,
  #|     };
  #|     if (use_auto_register) {
  #|       createOptions.mediation = "conditional";
  #|     }
  #|     if (typeof AbortController === "function") {
  #|       createOptions.signal = createNewAbortSignal();
  #|     }
  #|
  #|     let credential;
  #|     try {
  #|       credential = await navigator.credentials.create(createOptions);
  #|     } catch (error) {
  #|       const mapped = mapRuntimeError(error);
  #|       return err(mapped.code, mapped.message);
  #|     }
  #|
  #|     if (!credential) {
  #|       return err("invalid_response", "Registration was not completed");
  #|     }
  #|     if (!credential.response) {
  #|       return err("invalid_response", "Credential response is missing");
  #|     }
  #|
  #|     const response = credential.response;
  #|     if (!response.attestationObject || !response.clientDataJSON) {
  #|       return err("invalid_response", "Attestation response is missing required fields");
  #|     }
  #|
  #|     let transports;
  #|     if (typeof response.getTransports === "function") {
  #|       transports = response.getTransports();
  #|     }
  #|
  #|     let publicKeyAlgorithm;
  #|     if (typeof response.getPublicKeyAlgorithm === "function") {
  #|       try {
  #|         publicKeyAlgorithm = response.getPublicKeyAlgorithm();
  #|       } catch (_error) {
  #|         publicKeyAlgorithm = undefined;
  #|       }
  #|     }
  #|
  #|     let publicKeyRaw;
  #|     if (typeof response.getPublicKey === "function") {
  #|       try {
  #|         const keyBuffer = response.getPublicKey();
  #|         if (keyBuffer !== null && keyBuffer !== undefined) {
  #|           publicKeyRaw = bufferToBase64URLString(keyBuffer);
  #|         }
  #|       } catch (_error) {
  #|         publicKeyRaw = undefined;
  #|       }
  #|     }
  #|
  #|     let authenticatorData;
  #|     if (typeof response.getAuthenticatorData === "function") {
  #|       try {
  #|         authenticatorData = bufferToBase64URLString(response.getAuthenticatorData());
  #|       } catch (_error) {
  #|         authenticatorData = undefined;
  #|       }
  #|     }
  #|
  #|     const result = {
  #|       id: String(credential.id),
  #|       rawId: bufferToBase64URLString(credential.rawId),
  #|       response: {
  #|         attestationObject: bufferToBase64URLString(response.attestationObject),
  #|         clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
  #|       },
  #|       type: String(credential.type || "public-key"),
  #|       clientExtensionResults:
  #|         typeof credential.getClientExtensionResults === "function"
  #|           ? credential.getClientExtensionResults()
  #|           : {},
  #|     };
  #|
  #|     if (transports !== undefined) {
  #|       result.response.transports = transports;
  #|     }
  #|     if (publicKeyAlgorithm !== undefined) {
  #|       result.response.publicKeyAlgorithm = publicKeyAlgorithm;
  #|     }
  #|     if (publicKeyRaw !== undefined) {
  #|       result.response.publicKey = publicKeyRaw;
  #|     }
  #|     if (authenticatorData !== undefined) {
  #|       result.response.authenticatorData = authenticatorData;
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
/// Begin authenticator registration via browser WebAuthn APIs.
pub async fn start_registration(
  input : StartRegistrationInput,
) -> Result[@types.RegistrationResponseJSON, BrowserError] {
  let options_json = input.options_json.to_json().stringify()
  let raw_result = ffi_start_registration(options_json, input.use_auto_register).wait() catch {
    _ => return Err(Unknown("Browser registration bridge failed"))
  }

  let value_json = match parse_browser_result(raw_result) {
    Ok(value) => value
    Err(error) => return Err(error)
  }

  let response : @types.RegistrationResponseJSON = @json.from_json(value_json) catch {
    decode_error =>
      return Err(
        InvalidResponse(
          "Failed to decode registration response: \{decode_error.to_string()}",
        ),
      )
  }

  Ok(response)
}
