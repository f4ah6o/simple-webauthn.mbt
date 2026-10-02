# Upstream feature tracking

Reviewed against [SimpleWebAuthn v14.0.3](https://github.com/MasterKale/SimpleWebAuthn/tree/787ca8209e39bc5f868a6a42f6b98a1bc1c06206),
commit `787ca8209e39bc5f868a6a42f6b98a1bc1c06206` (2026-10-02 review).
This is a partial MoonBit port; the version is a comparison baseline, not a claim
of complete v14 compatibility.

| Upstream feature | MoonBit status | Boundary |
| --- | --- | --- |
| Authentication `expectedTopOrigin` | Implemented in this update | Single/list builders; shared sync/async client-data validation |
| `getBrowserCapabilities()` | Implemented in this update | Nine tri-state capabilities, with UVPAA and conditional-get fallbacks |
| `browserSupportsPasskeys()` | Implemented in this update | True if platform passkeys, hybrid transport, or UVPAA is supported |
| `sendSignal()` | Pending | Capability fields report support; they do not send signals |
| PQC ML-DSA and runtime-dependent default algorithms | Pending | Cryptographic verification remains ES256 only |
| Certificate attestation, cross-signed paths, trust-anchor/CRL updates | Pending | The port does not implement the upstream certificate verification stack |
| Metadata service logger and MDS blob verification | Pending | Full upstream metadata verification/service behavior is outside this update |
| Free-form transport strings | Pending | Existing MoonBit transport types remain unchanged |

## Cross-origin authentication

Add the embedding site's **top-level** origin to the existing options:

```moonbit
let options = @server.VerifyAuthenticationOptions::new(
  challenge, "https://login.example.com", "example.com", credential,
).with_expected_top_origin("https://app.example.com")
// Or: options.with_expected_top_origins([
//   "https://app.example.com", "https://portal.example.com",
// ])
```

`origin` still has to match `expected_origins`, and the challenge, RP ID,
authenticator flags, signature and counter checks remain separate requirements.
Reported nonempty `topOrigin` values must match the configured allowlist exactly
when `crossOrigin` is true. A reported nonempty `topOrigin` with `crossOrigin`
false or absent is rejected. An empty allowlist authorizes no reported origin.

Upstream currently allows cross-origin responses that omit `topOrigin` for Safari
compatibility, even when an expected top origin is configured. The port follows
that behavior; the allowlist cannot prove the embedding origin when it is absent.
Empty strings and JSON `null` are treated as unreported values. Other non-string
`topOrigin` values are rejected by the port's typed parser.

The existing constructors retain their call signatures. `ClientData` now includes
`top_origin : String?`, and `VerifyAuthenticationOptions` includes
`expected_top_origins : Array[String]?`; downstream code constructing these
records directly must provide the new fields (usually `None`).

## Browser capability detection

The exported support enum is `Supported`, `Unsupported`, or `Unknown`. A missing
`getClientCapabilities()` API produces an all-unknown set, even if older fallback
methods are available. With the client-capability API present, unknown
`userVerifyingPlatformAuthenticator` and `conditionalGet` fields may be resolved
through their equivalent older APIs. Explicit `true` and `false` values take
precedence over fallbacks. Passkey support describes browser functionality; it
does not establish that the user has a credential.

The port conservatively returns unknown when the capability API fails. Malformed
field values are treated as unknown; the two eligible fields can still be resolved
by a successful fallback. A failed fallback leaves that field unknown. Upstream
can throw in these cases. This intentional error handling adaptation matches the
port's existing feature-detection helpers.

## Reviewing future upstream releases

1. Compare the pinned baseline with upstream's release changelog and changed
   server/browser APIs.
2. Update this matrix with implemented, pending and deliberately adapted behavior.
3. Port behavior-focused fixtures, including rejection cases, before changing
   algorithm offerings or verification support.
4. Run `moon fmt --check`, `moon info`, `moon check --target js`,
   `moon test --target js` and the [mutation gate](mutation-testing.md).
5. Record the exact upstream and turtles revisions alongside the test results.
