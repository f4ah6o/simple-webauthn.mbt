///|
/// WebCrypto FFI for ES256 signature verification.
///
/// This module provides async signature verification using the WebCrypto API.
/// It works in both browser and Node.js environments.
///
/// ## Design
///
/// - MoonBit ↔ JS boundary uses String (base64url encoded)
/// - All Bytes/Uint8Array conversions happen on the JS side
/// - Async via Promise + callback pattern
///
/// ## Browser/Node.js Compatibility
///
/// The JS shim ensures `globalThis.crypto.subtle` is available:
/// - Browser: Uses `window.crypto` (native)
/// - Node.js: Uses `require("crypto").webcrypto`

///|
/// Ensure WebCrypto is available (Node.js compatibility).
/// This injects Node's webcrypto into globalThis if needed.
extern "js" fn ffi_ensure_crypto() -> Unit =
  #| () => {
  #|   if (typeof globalThis.crypto === 'undefined' || !globalThis.crypto.subtle) {
  #|     try {
  #|       const nodeCrypto = require('crypto');
  #|       if (nodeCrypto.webcrypto) {
  #|         globalThis.crypto = nodeCrypto.webcrypto;
  #|       }
  #|     } catch (e) {
  #|       // Not in Node.js, crypto should be available in browser
  #|     }
  #|   }
  #| }

///|
/// Verify ES256 signature using WebCrypto.
/// 
/// All parameters are base64url encoded strings:
/// - x_b64u: X coordinate of public key (32 bytes)
/// - y_b64u: Y coordinate of public key (32 bytes)
/// - sig_b64u: Raw signature (64 bytes, r||s format)
/// - data_b64u: Data that was signed
///
/// Returns a Promise that resolves to true if valid, false otherwise.
extern "js" fn ffi_verify_es256(
  x_b64u : String,
  y_b64u : String,
  sig_b64u : String,
  data_b64u : String,
) -> @js.Promise[Bool] =
  #| async (x_b64u, y_b64u, sig_b64u, data_b64u) => {
  #|   // Base64URL decode helper
  #|   const b64uDecode = (s) => {
  #|     const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  #|     const pad = (4 - (b64.length % 4)) % 4;
  #|     const padded = b64 + '='.repeat(pad);
  #|     const binary = atob(padded);
  #|     const bytes = new Uint8Array(binary.length);
  #|     for (let i = 0; i < binary.length; i++) {
  #|       bytes[i] = binary.charCodeAt(i);
  #|     }
  #|     return bytes;
  #|   };
  #|
  #|   try {
  #|     const x = b64uDecode(x_b64u);
  #|     const y = b64uDecode(y_b64u);
  #|     const sig = b64uDecode(sig_b64u);
  #|     const data = b64uDecode(data_b64u);
  #|
  #|     // Import public key using JWK format
  #|     const jwk = {
  #|       kty: 'EC',
  #|       crv: 'P-256',
  #|       x: x_b64u,
  #|       y: y_b64u,
  #|     };
  #|     
  #|     const key = await globalThis.crypto.subtle.importKey(
  #|       'jwk',
  #|       jwk,
  #|       { name: 'ECDSA', namedCurve: 'P-256' },
  #|       false,
  #|       ['verify']
  #|     );
  #|
  #|     // Verify signature
  #|     const result = await globalThis.crypto.subtle.verify(
  #|       { name: 'ECDSA', hash: 'SHA-256' },
  #|       key,
  #|       sig,
  #|       data
  #|     );
  #|
  #|     return result;
  #|   } catch (e) {
  #|     // Key import or verification failed
  #|     return false;
  #|   }
  #| }

///|
/// Verify ES256 signature using WebCrypto (async version).
///
/// This is the recommended function for signature verification.
/// It handles all the WebCrypto API details internally.
///
/// ## Parameters
/// - public_key: Parsed EC2 public key (x, y coordinates)
/// - signature: Raw signature bytes (64 bytes, r||s format)
/// - data: Data that was signed (authenticatorData || SHA256(clientDataJSON))
///
/// ## Returns
/// - true if signature is valid
/// - false if signature is invalid or verification failed
///
/// ## Example
/// ```
/// let is_valid = verify_es256_async(public_key, signature, data).wait()
/// ```
pub async fn verify_es256_async(
  public_key : EC2PublicKey,
  signature : Bytes,
  data : Bytes,
) -> Bool {
  // Ensure WebCrypto is available
  ffi_ensure_crypto()
  // Normalize signature to raw format (in case it's DER-encoded)
  let raw_sig = normalize_signature(signature) catch { _ => return false }
  // Encode everything to base64url for JS boundary
  let x_b64u = @helpers.base64url_encode(public_key.x)
  let y_b64u = @helpers.base64url_encode(public_key.y)
  let sig_b64u = @helpers.base64url_encode(raw_sig)
  let data_b64u = @helpers.base64url_encode(data)
  // Call WebCrypto via FFI
  let result = ffi_verify_es256(x_b64u, y_b64u, sig_b64u, data_b64u).wait() catch {
    _ => false
  }
  result
}
