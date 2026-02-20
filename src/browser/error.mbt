///|
/// Errors emitted by browser-side WebAuthn helpers.
pub suberror BrowserError {
  NotSupported(String)
  AutofillNotSupported(String)
  MissingAutofillInput(String)
  CeremonyAborted(String)
  InvalidResponse(String)
  InvalidInput(String)
  DomError(String)
  Unknown(String)
}

///|
fn browser_error_from_code(code : String, message : String) -> BrowserError {
  match code {
    "not_supported" => NotSupported(message)
    "autofill_not_supported" => AutofillNotSupported(message)
    "missing_autofill_input" => MissingAutofillInput(message)
    "ceremony_aborted" => CeremonyAborted(message)
    "invalid_response" => InvalidResponse(message)
    "invalid_input" => InvalidInput(message)
    "dom_error" => DomError(message)
    _ => Unknown(message)
  }
}

///|
fn parse_browser_result(result_json : String) -> Result[Json, BrowserError] {
  let parsed = @json.parse(result_json) catch {
    _ => return Err(Unknown("Failed to parse browser result payload"))
  }

  guard parsed is Json::Object(obj) else {
    return Err(InvalidResponse("Browser result payload must be an object"))
  }

  let ok = match obj.get("ok") {
    Some(value) => @json.from_json(value) catch { _ => false }
    None => false
  }

  if ok {
    match obj.get("value") {
      Some(value) => Ok(value)
      None => Err(InvalidResponse("Browser result payload is missing value"))
    }
  } else {
    let code = match obj.get("code") {
      Some(Json::String(value)) => value
      _ => "unknown"
    }
    let message = match obj.get("message") {
      Some(Json::String(value)) => value
      _ => "Unknown browser error"
    }
    Err(browser_error_from_code(code, message))
  }
}
