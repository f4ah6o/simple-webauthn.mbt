///|
/// Metadata and settings services inspired by SimpleWebAuthn server exports.
///
/// This file adds practical equivalents of SettingsService / MetadataService.

///|
/// Verification behavior for unknown AAGUIDs.
pub(all) enum VerificationMode {
  Permissive
  Strict
} derive(Show, Eq)

///|
/// Root certificate store identifiers.
pub(all) enum RootCertIdentifier {
  NoneAttestation
  Packed
  FidoU2F
  TPM
  AndroidKey
  AndroidSafetyNet
  Apple
  Mds
} derive(Show, Eq)

///|
pub fn RootCertIdentifier::to_string(self : RootCertIdentifier) -> String {
  match self {
    NoneAttestation => "none"
    Packed => "packed"
    FidoU2F => "fido-u2f"
    TPM => "tpm"
    AndroidKey => "android-key"
    AndroidSafetyNet => "android-safetynet"
    Apple => "apple"
    Mds => "mds"
  }
}

///|
/// Minimal metadata statement cache entry.
pub struct MetadataStatement {
  aaguid : String
  raw : Json
} derive(Show, Eq)

///|
pub fn MetadataStatement::new(
  aaguid : String,
  raw : Json,
) -> MetadataStatement {
  { aaguid, raw }
}

///|
/// Status report entry from MDS payload.
pub struct StatusReport {
  status : String
  effective_date : String?
  certificate : String?
} derive(Show, Eq)

///|
/// Cached BLOB entry information.
pub struct MetadataBlobEntry {
  aaguid : String
  metadata_statement : MetadataStatement
  status_reports : Array[StatusReport]
  time_of_last_status_change : String?
} derive(Show, Eq)

///|
/// Options to initialize metadata cache.
pub struct MetadataServiceInitializeOptions {
  mds_servers : Array[String]?
  statements : Array[MetadataStatement]?
  verification_mode : VerificationMode?
} derive(Show, Eq)

///|
pub fn MetadataServiceInitializeOptions::new(
  mds_servers? : Array[String]? = None,
  statements? : Array[MetadataStatement]? = None,
  verification_mode? : VerificationMode? = None,
) -> MetadataServiceInitializeOptions {
  { mds_servers, statements, verification_mode }
}

///|
/// Errors from metadata service operations.
pub suberror MetadataServiceError {
  FetchFailed(String)
  InvalidJWT(String)
  InvalidPayload(String)
  StatementNotFound(String)
  InvalidAAGUID(String)
}

///|
/// Internal mutable settings state.
priv struct SettingsServiceState {
  root_certs : Map[String, Array[String]]
}

///|
let settings_service_state : SettingsServiceState = {
  root_certs: {},
}

///|
/// Replace root certificates for one identifier.
pub fn set_root_certificates(
  identifier : RootCertIdentifier,
  certificates : Array[String],
) -> Unit {
  settings_service_state.root_certs[identifier.to_string()] = certificates
}

///|
/// Read configured root certificates for one identifier.
pub fn get_root_certificates(
  identifier : RootCertIdentifier,
) -> Array[String] {
  match settings_service_state.root_certs.get(identifier.to_string()) {
    Some(certs) => certs
    None => []
  }
}

///|
/// Clear root certificates for one identifier.
pub fn clear_root_certificates(identifier : RootCertIdentifier) -> Unit {
  settings_service_state.root_certs.remove(identifier.to_string())
}

///|
/// Internal mutable metadata state.
priv struct MetadataServiceState {
  mut statement_cache : Map[String, MetadataStatement]
  mut blob_cache : Map[String, MetadataBlobEntry]
  mut mds_servers : Array[String]
  mut verification_mode : VerificationMode
}

///|
let metadata_service_state : MetadataServiceState = {
  statement_cache: {},
  blob_cache: {},
  mds_servers: [],
  verification_mode: VerificationMode::Strict,
}

///|
let default_mds_server : String = "https://mds.fidoalliance.org/"

///|
/// Fetch and parse metadata statements from configured sources.
///
/// Local statements are always loaded first, then MDS servers are fetched.
pub async fn metadata_service_initialize(
  options? : MetadataServiceInitializeOptions? = None,
) -> Result[Unit, MetadataServiceError] {
  let resolved = match options {
    Some(v) => v
    None => MetadataServiceInitializeOptions::new()
  }

  metadata_service_state.statement_cache = {}
  metadata_service_state.blob_cache = {}

  metadata_service_state.verification_mode = match resolved.verification_mode {
    Some(mode) => mode
    None => VerificationMode::Strict
  }

  match resolved.statements {
    Some(statements) =>
      for statement in statements {
        metadata_service_state.statement_cache[statement.aaguid] = statement
      }
    None => ()
  }

  let servers = match resolved.mds_servers {
    Some(s) => s
    None => [default_mds_server]
  }
  metadata_service_state.mds_servers = servers

  for url in servers {
    let fetch_text = ffi_fetch_text(url).wait() catch { _ => None }
    let jwt = match fetch_text {
      Some(text) => text
      None => return Err(FetchFailed("Failed to fetch metadata BLOB from \{url}"))
    }
    let payload_str = match ffi_extract_jwt_payload(jwt) {
      Some(v) => v
      None => return Err(InvalidJWT("Failed to decode JWT payload from \{url}"))
    }
    let entries = parse_mds_payload_entries(payload_str) catch {
      err => return Err(err)
    }
    for entry in entries {
      metadata_service_state.blob_cache[entry.aaguid] = entry
      metadata_service_state.statement_cache[entry.aaguid] = entry.metadata_statement
    }
  }

  Ok(())
}

///|
/// Refresh metadata from previously configured servers.
pub async fn metadata_service_refresh() -> Result[Unit, MetadataServiceError] {
  metadata_service_initialize(
    options=Some(MetadataServiceInitializeOptions::new(
      mds_servers=Some(metadata_service_state.mds_servers),
      verification_mode=Some(metadata_service_state.verification_mode),
    )),
  )
}

///|
/// Get a metadata statement by AAGUID string.
pub fn metadata_service_get_statement(
  aaguid : String,
) -> MetadataStatement? raise MetadataServiceError {
  if aaguid.length() == 0 {
    raise InvalidAAGUID("aaguid must not be empty")
  }

  match metadata_service_state.statement_cache.get(aaguid) {
    Some(statement) => Some(statement)
    None =>
      match metadata_service_state.verification_mode {
        VerificationMode::Strict => raise StatementNotFound(aaguid)
        VerificationMode::Permissive => None
      }
  }
}

///|
/// Get a metadata statement by binary AAGUID bytes.
pub fn metadata_service_get_statement_bytes(
  aaguid : Bytes,
) -> MetadataStatement? raise MetadataServiceError {
  let aaguid_str = aaguid_bytes_to_string(aaguid) catch {
    err => raise err
  }
  metadata_service_get_statement(aaguid_str)
}

///|
fn aaguid_bytes_to_string(aaguid : Bytes) -> String raise MetadataServiceError {
  if aaguid.length() != 16 {
    raise InvalidAAGUID("aaguid must be exactly 16 bytes")
  }

  let p1 = @helpers.bytes_slice(aaguid, 0, 4) catch {
    _ => raise InvalidAAGUID("invalid aaguid bytes")
  }
  let p2 = @helpers.bytes_slice(aaguid, 4, 2) catch {
    _ => raise InvalidAAGUID("invalid aaguid bytes")
  }
  let p3 = @helpers.bytes_slice(aaguid, 6, 2) catch {
    _ => raise InvalidAAGUID("invalid aaguid bytes")
  }
  let p4 = @helpers.bytes_slice(aaguid, 8, 2) catch {
    _ => raise InvalidAAGUID("invalid aaguid bytes")
  }
  let p5 = @helpers.bytes_slice(aaguid, 10, 6) catch {
    _ => raise InvalidAAGUID("invalid aaguid bytes")
  }

  "\{@helpers.bytes_to_hex(p1)}-\{@helpers.bytes_to_hex(p2)}-\{@helpers.bytes_to_hex(p3)}-\{@helpers.bytes_to_hex(p4)}-\{@helpers.bytes_to_hex(p5)}"
}

///|
fn parse_mds_payload_entries(
  payload_str : String,
) -> Array[MetadataBlobEntry] raise MetadataServiceError {
  let payload_json = @json.parse(payload_str) catch {
    err => raise InvalidPayload("Invalid payload JSON: \{err.to_string()}")
  }

  guard payload_json is Json::Object(payload_obj) else {
    raise InvalidPayload("MDS payload must be a JSON object")
  }

  let entries_json = match payload_obj.get("entries") {
    Some(Json::Array(entries)) => entries
    Some(_) => raise InvalidPayload("entries must be an array")
    None => []
  }

  let parsed : Array[MetadataBlobEntry] = []
  for entry_json in entries_json {
    match parse_blob_entry(entry_json) {
      Some(entry) => parsed.push(entry)
      None => ()
    }
  }

  parsed
}

///|
fn parse_blob_entry(entry_json : Json) -> MetadataBlobEntry? {
  guard entry_json is Json::Object(entry_obj) else { return None }

  let aaguid = match entry_obj.get("aaguid") {
    Some(Json::String(v)) if v.length() > 0 => v
    _ => return None
  }

  let metadata_raw = match entry_obj.get("metadataStatement") {
    Some(v) => v
    None => Json::object({})
  }

  let status_reports = parse_status_reports(entry_obj.get("statusReports"))
  let time_of_last_status_change = match entry_obj.get("timeOfLastStatusChange") {
    Some(Json::String(v)) => Some(v)
    _ => None
  }

  Some({
    aaguid,
    metadata_statement: { aaguid, raw: metadata_raw },
    status_reports,
    time_of_last_status_change,
  })
}

///|
fn parse_status_reports(value : Json?) -> Array[StatusReport] {
  match value {
    Some(Json::Array(reports_json)) => {
      let reports : Array[StatusReport] = []
      for report_json in reports_json {
        guard report_json is Json::Object(report_obj) else { continue }
        let status = match report_obj.get("status") {
          Some(Json::String(v)) => v
          _ => continue
        }
        let effective_date = match report_obj.get("effectiveDate") {
          Some(Json::String(v)) => Some(v)
          _ => None
        }
        let certificate = match report_obj.get("certificate") {
          Some(Json::String(v)) => Some(v)
          _ => None
        }
        reports.push({ status, effective_date, certificate })
      }
      reports
    }
    _ => []
  }
}

///|
extern "js" fn ffi_fetch_text(url : String) -> @js.Promise[String?] =
  #| async (url) => {
  #|   try {
  #|     const resp = await fetch(url);
  #|     if (!resp || !resp.ok) {
  #|       return undefined;
  #|     }
  #|     return await resp.text();
  #|   } catch (_e) {
  #|     return undefined;
  #|   }
  #| }

///|
extern "js" fn ffi_extract_jwt_payload(jwt : String) -> String? =
  #| (jwt) => {
  #|   try {
  #|     const parts = jwt.split('.');
  #|     if (parts.length < 2) {
  #|       return undefined;
  #|     }
  #|     const b64url = parts[1];
  #|     const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  #|     const pad = (4 - (b64.length % 4)) % 4;
  #|     const padded = b64 + '='.repeat(pad);
  #|     let jsonText;
  #|     if (typeof Buffer !== 'undefined') {
  #|       jsonText = Buffer.from(padded, 'base64').toString('utf8');
  #|     } else {
  #|       jsonText = decodeURIComponent(escape(atob(padded)));
  #|     }
  #|     const payload = JSON.parse(jsonText);
  #|     return JSON.stringify(payload);
  #|   } catch (_e) {
  #|     return undefined;
  #|   }
  #| }
