# AIA Chaser — Technical Requirements Document

Reasons are given for every non-obvious choice. The recurring constraints behind them: **one solo maintainer, free open-source distribution, security-critical code, and a platform (`dart:io` + Android WebView) with hard API limits.**

---

## 1. Key design correction (read first)

`HttpClient.badCertificateCallback` is **synchronous**: `bool Function(X509Certificate cert, String host, int port)`. It cannot `await` a method-channel call or an HTTP fetch. A design where the callback asks Kotlin "is this chain valid?" cannot work.

So the `dart:io` path uses a **validate-ahead model**:

1. Validation (AIA fetch, chain build, system trust check) runs **asynchronously in native code**, producing a verdict for `(host, leaf SHA-256)`.
2. Verdicts are stored in an in-memory **ValidatedLeafStore** on the Dart side.
3. The synchronous callback only does a store lookup (microseconds) and returns `true` for a leaf that native code already validated.
4. Verdicts are produced either by **prewarm** at startup (so the first request succeeds) or by **learn-on-failure** (callback returns `false`, schedules validation, wrappers retry once).

The WebView path has no such limit: `setOnSSlAuthError` handlers are async, so validation can complete inside the handler.

## 2. Architecture overview

```
 App code
   │
   ├── dart:io HttpClient ──(HttpOverrides)──► AiaHttpOverrides ┐
   ├── Dio ──► aia_chaser_dio adapter ──────────────────────────┤
   ├── package:http ──► aia_chaser_http client ─────────────────┤──► aia_chaser (core, Dart)
   └── WebView ──► aia_chaser_webview ──────────────────────────┘      │ policy engine
                                                                        │ ValidatedLeafStore (sync)
                                                                        │ single-flight dispatcher
                                                                        ▼
                                                           Pigeon channel (async)
                                                                        ▼
                                  ┌──────────────────── Android (Kotlin) ───────────────────┐
                                  │ ChainBuilder  AiaFetcher  IssuerCache  HostnameMatcher    │
                                  │ TrustValidator (X509TrustManagerExtensions)  Prober       │
                                  └───────────────────────────────────────────────────────────┘
                                  ┌──────── iOS / macOS (Swift, conditional on F13) ──────────┐
                                  │ SecTrust-based validation, same Pigeon contract           │
                                  └───────────────────────────────────────────────────────────┘
```

**Why four packages instead of one:** Dart has no optional dependencies. A single package would force every consumer to depend on `dio`, `http`, and `webview_flutter_android`. Splitting keeps the core dependency-light and lets each adapter version independently. **Cost:** a melos monorepo and four release cycles. Mitigated by the adapters being roughly 50–150 lines each.

## 3. Repository layout

```
aia_chaser/                       (monorepo, melos)
├── packages/
│   ├── aia_chaser/               core + Android/iOS plugin implementations
│   │   ├── lib/                  public API, policy engine, store, overrides
│   │   ├── android/              Kotlin
│   │   ├── ios/ macos/           Swift (conditional)
│   │   └── pigeons/              Pigeon definitions
│   ├── aia_chaser_webview/
│   ├── aia_chaser_dio/
│   └── aia_chaser_http/
├── example/                      Playground app (see UI/UX brief)
├── tool/fixtures/                broken-chain test server + cert generation scripts
├── docs/                         threat model, migration guide, diagnosis guide
└── SECURITY.md  LICENSE  melos.yaml
```

## 4. Frontend (Dart/Flutter) stack

- Dart and Flutter: latest stable at 0.1.0 and the previous two stable releases. Reason: a security package should not support stale toolchains; widening later is cheaper than narrowing.
- Dependencies (core): `meta`, `plugin_platform_interface`, `crypto` (SHA-256 of DER, the only crypto Dart does). Dev: `pigeon`, `test`, `flutter_test`, `mocktail`, `melos`.
- **No ASN.1 or X.509 parsing in Dart.** Reason: parsing untrusted certificate bytes is where TLS libraries get CVEs; delegate to JDK and Security.framework.
- Adapter dependencies: `webview_flutter_android` (lower bound = first release exposing `setOnSSlAuthError` and certificate bytes, confirmed in Phase 0), `dio ^5`, `http ^1`.

## 5. Native (backend-equivalent) stack

| Layer | Choice | Reason |
|---|---|---|
| Android language | Kotlin, JVM 17 target, `minSdk 24` for the plugin | Kotlin is the Flutter plugin default; API 24 covers Android 7+, the line where network-security-config behaviors stabilized |
| Android deps | **None** beyond Android SDK and JDK | No supply-chain surface, tiny APK impact |
| Certificate parsing | `java.security.cert.CertificateFactory`, `X509Certificate` | Platform parser handles DER, PEM, and PKCS#7 (`.p7c`) |
| AIA HTTP fetch | `HttpURLConnection` | No dependency; explicit timeouts; no OkHttp needed for a GET of a few KB |
| Chain trust | `X509TrustManagerExtensions.checkServerTrusted(chain, authType, host)` over the default `X509TrustManager` | Uses the same system store and app network-security-config the WebView and platform use |
| Threading | Bounded `ExecutorService` (4 threads) + Pigeon async callbacks | Avoids a coroutines dependency; bounded to prevent runaway fetch storms |
| iOS language | Swift, Security.framework (`SecTrustCreateWithCertificates`, `SecTrustEvaluateWithError`) | Only built if F13 evaluation says Dart on Apple platforms needs it |

## 6. Storage

- **Issuer cache**: DER files plus a JSON index under the app's `cacheDir/aia_chaser/v1/` (see Backend Schema). Reason: simple, inspectable, no SQLite dependency; at most ~64 small entries.
- **Validation cache**: in memory only, on both sides. Reason: persisted "trust verdicts" are tamperable and outlive CA distrust events. Persisted *issuer certificates* are safe because they are re-verified against the system store on every use; tampering cannot forge trust.
- **Authentication:** not applicable (no accounts). The equivalent concern is the *trust model*, specified in §10.

## 7. Public Dart API (sketch, normative for names)

```dart
await AiaChaser.initialize(AiaConfig(
  hosts: {
    'booking.example.com': HostPolicy.chase(),
    '*.cdn.example.com': HostPolicy.chase(
      onFailure: FailurePolicy.pinFallback({Pin.spkiSha256('base64...')}),
    ),
    'staging.example.com': HostPolicy.chase(
      onFailure: FailurePolicy.unsafeAllow(), // debug builds only by default
    ),
  },
  unlistedHosts: HostPolicy.passthrough,      // default: package does nothing
  fetch: AiaFetchOptions(
    connectTimeout: Duration(seconds: 3),
    readTimeout: Duration(seconds: 3),
    maxDepth: 4,
    maxBytes: 64 * 1024,
    maxRedirects: 3,
    blockPrivateAddresses: true,
  ),
  cache: AiaCacheOptions(
    issuerDiskCache: true,
    issuerTtl: Duration(days: 30),
    validationTtl: Duration(hours: 24),
    seedAssets: ['assets/certs/le_intermediates.pem'],
  ),
  prewarm: PrewarmMode.background,            // none | background | await
));

HttpOverrides.global = AiaHttpOverrides();                // dart:io, global
final client = AiaHttpClientFactory.create();             // dart:io, scoped
AiaWebViewHandler.install(androidNavigationDelegate);     // aia_chaser_webview
dio.httpClientAdapter = AiaDioAdapter();                  // aia_chaser_dio
final http = AiaHttpClient();                             // aia_chaser_http
final report = await AiaChaser.diagnose('booking.example.com');
AiaChaser.events.listen(print);                           // Stream<AiaEvent>
```

**Host pattern rules:** exact hostname, or `*.suffix` matching any depth of subdomain (this is a config convenience, unlike certificate wildcards, which are one label). Hostnames are lowercased and IDNA-normalized. IP literals match exactly only. Most specific pattern wins; ties are a configuration error raised at `initialize`.

**Failure policies:**

| Policy | Behavior on validation failure | Notes |
|---|---|---|
| `reject` (default) | Connection fails / WebView cancels | |
| `pinFallback(pins)` | Accept if chain linkage and hostname/date checks pass and a pin matches (SPKI of any chain cert, or leaf cert SHA-256) | Chain linkage is verified by signature, not by system store |
| `unsafeAllow` | Accept unconditionally | Throws in release builds unless `allowInRelease: true`; logs a warning each use; emits `PolicyDecision` event |

## 8. Platform API (Pigeon)

```
class ValidationRequest { String host; int port; Uint8List leafDer; NativeOptions options; }
class ValidationResult  { ValidationOutcome outcome; List<String> chainSha256;
                          List<String> fetchedUrls; int durationMs; String? detail; }
class ChainReport       { String host; int port; List<CertInfo> serverSent; List<CertInfo> completed;
                          ValidationOutcome outcome; String cause; String suggestedFix; }

@HostApi AiaChaserHostApi {
  void configure(NativeConfig c);
  @async ValidationResult validate(ValidationRequest r);
  @async ValidationResult prewarm(String host, int port);
  @async ChainReport diagnose(String host, int port, int timeoutMs);
  CacheStats cacheStats();
  void clearCaches(ClearScope scope);
}
@FlutterApi AiaChaserFlutterApi { void onEvent(NativeEvent e); }
```

**`ValidationOutcome`** (single enum used everywhere: results, events, reports, schema): `validated`, `validatedByPin`, `rejectedUntrusted`, `rejectedHostname`, `rejectedExpired`, `aiaUnavailable`, `aiaFetchFailed`, `maxDepthExceeded`, `noCertificate`, `policyUnsafeAllowed`, `notConfigured`.

## 9. Validation pipeline (native)

```
validate(host, port, leafDer):
 1. lookup validation cache (host, sha256(leaf))        → hit & fresh: return cached outcome
 2. parse leaf; if unparseable                           → noCertificate
 3. hostname match against SAN (DNS, IP)                 → rejectedHostname
 4. leaf validity dates                                  → rejectedExpired
 5. pool = {leaf} ∪ seeds ∪ issuerCache
 6. loop (depth ≤ maxDepth, no repeated cert):
      a. try system trust check on current chain         → validated  (stop)
      b. take top cert's AIA caIssuers URIs
      c. candidate from pool whose subject == top.issuer and whose key verifies top's signature
         else fetch URI (allowed schemes, address checks, size/time caps)
      d. issuer must be CA:true (basicConstraints) and signature-verify the top cert
      e. append issuer, continue
 7. policy: pinFallback? verify linkage + pin match      → validatedByPin
 8. else                                                  → rejectedUntrusted / aiaFetchFailed / maxDepthExceeded
 9. store in validation cache (TTL = min(validationTtl, earliest notAfter in chain))
```

Notes:
- **Step 6a runs before any fetch.** If the platform already trusts the chain (or the server sent a complete one), no network is used.
- **Fetching never grants trust.** A fetched certificate only enters the chain; trust comes from the system store (step 6a) or an explicit pin (step 7).
- Hostname matching follows RFC 6125: SAN only (CN ignored when SAN exists), wildcard only as the entire left-most label, no partial wildcards, IP addresses via IP SAN.
- `authType` for `checkServerTrusted` is derived from the leaf public key algorithm. Confirmed in Phase 0 that Conscrypt accepts it.
- **Single-flight:** concurrent validations of the same `(host, leaf sha256)` share one execution; concurrent fetches of the same URL share one request.

## 10. Security requirements

### Threat model

| Threat | Mitigation |
|---|---|
| Network attacker presents arbitrary cert for a configured host | Cert must chain to a system root or an explicit pin, with hostname and date checks |
| Attacker-supplied AIA URL used for SSRF (internal network probing) | Only `http`/`https`; resolve host and reject loopback, link-local, private, and unique-local addresses (incl. IPv4-mapped IPv6); re-check each redirect hop; no credentials in URLs |
| Oversized or endless AIA response | Hard `maxBytes` (64 KiB), total deadline per validation (default 8 s), per-connection timeouts |
| AIA loops, depth bombs | Max depth 4, visited-set by certificate hash |
| Malicious certificate bytes | Parsed by JDK `CertificateFactory`; parse errors map to `noCertificate` / `aiaFetchFailed`, never crash the host app |
| Tampered on-disk cache | Cache holds only public certs; each use re-verified by signature and system trust. Validation verdicts are never persisted |
| Downgrade by redirecting AIA https→http | Allowed deliberately: AIA content is authenticated by signature, not transport |
| Policy misconfiguration (`unsafeAllow` in production) | Release-build guard, warning logs, event emitted, documented as migration crutch only |
| Log leakage | Events carry hostnames and fingerprints only, never certificate bodies; `AiaDiagnosticsView` reports are redacted by default |
| Supply chain | Zero native deps; Dart deps pinned by constraint and reviewed; pub.dev verified publisher, 2FA, publishing via GitHub OIDC; `SECURITY.md` with private disclosure |
| Trust divergence between Kotlin and `dart:io` | Kotlin trusts per the app's network-security-config (may include user CAs); Dart's own store does not. Documented; `trustUserCaCerts: false` option makes Kotlin ignore user CAs |
| Play Store scanner | The package contributes no native `onReceivedSslError` implementation; it uses the WebView plugin's callback. Policy-text check before 1.0 |

### Unsafe-API rules
`unsafeAllow` and any code path returning `true` without validation is covered by dedicated tests and a code-review checklist item.

## 11. Performance requirements

| Requirement | Target |
|---|---|
| Warm decision (store/cache hit) | p95 < 5 ms |
| Cold validation with one fetch | p95 < 1.5 s on 4G; hard deadline 8 s |
| Main-thread work | None beyond Pigeon marshalling |
| Memory | < 2 MB steady state |
| APK size impact | < 150 KB |
| Prewarm | Non-blocking by default; must not delay `runApp` |
| Fetch concurrency | ≤ 4 simultaneous AIA fetches |

## 12. Compatibility matrix

| Dimension | Supported |
|---|---|
| Android | API 24–35 (test devices/emulators: 24, 28, 29, 31, 33, 35) |
| WebView certificate bytes | Guaranteed on API 29+ if the WebView plugin provides them; on lower APIs a missing certificate yields `noCertificate` and the failure policy applies |
| iOS / macOS | Per F13 outcome; v1.0 documents the result either way |
| Not supported | Windows, Linux, web (documented no-ops) |

## 13. Third-party integrations and external services

| Integration | Use | Risk |
|---|---|---|
| CA AIA endpoints (e.g. Let's Encrypt issuer URLs) | Fetch issuer certs | Availability; mitigated by caching, seeds, timeouts |
| `webview_flutter_android` | SSL error hook | API drift; adapter isolated in its own package |
| `dio`, `http` | Adapters | Stable APIs; adapters are thin |
| GitHub Actions | CI, publishing | Pin actions by commit SHA |
| pub.dev | Distribution | Name availability (assumption) |

No AI models or cloud services are involved.

## 14. Cloud / deployment / release

- **CI** (GitHub Actions): `melos analyze`, `format --set-exit-if-changed`, unit tests, Kotlin unit tests (Robolectric-free where possible), instrumentation tests on an emulator matrix (reactivecircus/android-emulator-runner), fixture-server integration tests, README snippet compile check.
- **Fixture server** (`tool/fixtures`): scripted generation of root, intermediate, and leaf certs; a Dart `SecureServer` serving deliberately incomplete chains; an HTTP server serving AIA responses (including slow, oversized, looping, and private-address-redirect variants). Emulator reaches the host at `10.0.2.2`; a debug-only `allowPrivateAiaForTesting` flag exists for exactly this and is compiled out of release.
- **Release:** semantic versioning, `0.x` while the API settles; changelog via conventional commits; tags trigger publish via OIDC. Pre-1.0 releases are marked as such in the README.
- **Docs:** dartdoc API reference on pub.dev, long-form docs in `/docs`, no hosted backend.

## 15. Testing strategy

1. **Unit (Dart):** policy resolution, host pattern matching, store expiry, single-flight, retry logic, config validation.
2. **Unit (Kotlin):** AIA extension parsing, hostname matcher (RFC 6125 table tests), fetcher limits, chain builder cycle/depth, pin matching.
3. **Fixture integration:** every row of the success-metric matrix, over real TLS against the fixture server.
4. **Device matrix:** the Android API list above, including a real device for Android 10–13 (the originating failure).
5. **Security tests:** negative tests that fail the build if any path returns acceptance without validation; fuzz the Pigeon inputs and certificate bytes.
6. **Regression:** the original incident (Let's Encrypt chain, incomplete) as a named fixture.

## 16. Phase-0 verification items (must be confirmed before building on them)

| ID | Question | If false |
|---|---|---|
| A-1 | `setOnSSlAuthError` handlers may be async (await before `proceed()`) | Pre-validate on page start, or contribute upstream |
| A-2 | `AndroidSslAuthError.certificate` returns DER bytes on Android 10–13 | Fallback: reject unless pinned by host |
| A-3 | `X509Certificate.der` available in supported Dart versions | Use `.pem` and decode |
| A-4 | Conscrypt `checkServerTrusted` accepts the completed chain and authType derivation | Adjust authType mapping |
| A-5 | Dart's BoringSSL accepts a trusted intermediate in a `SecurityContext` without its root (alternative to the store approach) | Store approach remains primary; drop alternative |
| A-6 | Dio/http retry after a handshake failure is safe (request body not yet consumed) | Restrict retry to replayable bodies |
| A-7 | Does Dart on iOS/macOS fail on incomplete chains? | F13 becomes documented no-op |
| A-8 | Which `webview_flutter_android` version first exposes these APIs | Sets dependency lower bound |

## 17. Decision log

| Decision | Reason |
|---|---|
| Validate-ahead store for `dart:io` | Synchronous callback (see §1) |
| All parsing in native code | Parser quality; solo-maintainer risk |
| No persisted verdicts | Persisted trust is attack surface |
| Zero native dependencies | Supply chain, size, solo upkeep |
| Declarative per-host policies | The user chose per-host control; also the only form compatible with a sync callback |
| Four packages | No optional deps in Dart; adapters stay optional |
| Issuer disk cache + seeds | Offline resilience and first-request speed |
| Unlisted hosts untouched | Minimal blast radius; opt-in by host |
