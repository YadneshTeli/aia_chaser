# AIA Chaser — Implementation Plan

This plan builds exactly the v1.0 scope in the PRD (F1–F15), with the stack in the TRD, against the data model in the Backend Schema. Estimates assume one developer at roughly 10 hours per week; the whole plan is about **18–20 weeks** to 1.0. Phases are ordered so the riskiest unknowns die first and the security-critical code gets the longest soak.

---

## Ordering logic

1. **Spike first.** The design leans on eight unverified platform facts (TRD §16). Verifying them costs one week and can change the design, so nothing else starts before it.
2. **Native core before Dart plumbing.** Chain building and validation are the hard, security-critical part; Dart is plumbing around them.
3. **`dart:io` and WebView before adapters.** They prove the two fundamentally different integration paths (sync store vs async handler). Dio and `http` are thin once those work.
4. **Test harness grows alongside code**, starting in Phase 1, rather than being a late phase.
5. **iOS evaluation is a bounded experiment** (Phase 8) so it can't swallow the schedule.
6. **Hardening and external review last** but reserved, not optional.

## Phases

### Phase 0: Spike and verification (≈ 1 week)
**Build:** a throwaway Android app against `incomplete-chain`-style fixtures (and the original Printpack host).
**Verify TRD items A-1 to A-8:** async WebView handler, certificate bytes on Android 10–13, `X509Certificate.der`, Conscrypt `checkServerTrusted` with a completed chain, trusted-intermediate behavior in Dart's `SecurityContext`, retry safety, iOS behavior, and the first plugin version exposing the needed API. Also check the pub.dev name and search for existing packages.
**Deliverable:** a one-page results note; TRD updated where a fact turned out false.
**Exit:** go/no-go. If A-1 or A-2 fail, redesign the WebView path before continuing.

### Phase 1: Native core, Android (≈ 2.5 weeks)
**Build (Kotlin):** `HostnameMatcher` (RFC 6125), `AiaFetcher` (schemes, address blocking, size/time caps, redirects, DER/PEM/PKCS#7), `ChainBuilder` (pool lookup by DN, signature verification, CA:true check, depth and cycle limits), `TrustValidator` (`X509TrustManagerExtensions`), pin matching, `validation_cache` with single-flight.
**Test:** Kotlin unit tests for every row of the TRD threat table; first fixtures from `tool/fixtures` (cert generation scripts, local AIA server).
**Deliverable:** pure-Kotlin validation library passing the fixture matrix without any Flutter code.
**Exit:** negative tests prove no acceptance path without validation or pin.

### Phase 2: Pigeon contract, Dart core, policy engine (≈ 2 weeks)
**Build:** Pigeon definitions (`validate`, `prewarm`, `diagnose`, `cacheStats`, `clearCaches`, events); `AiaConfig`, `HostPolicy`, `FailurePolicy`, `Pin`; host-pattern resolver and ambiguity detection; `ValidatedLeafStore`; single-flight dispatcher; `AiaChaser.initialize`; release-build guard for `unsafeAllow`.
**Deliverable:** `aia_chaser` core package with unit tests; Android plugin registered and callable.
**Exit:** Dart unit tests cover policy resolution and store expiry; round-trip `validate` works on a device.

### Phase 3: `dart:io` integration (≈ 1.5 weeks)
**Build:** `AiaHttpOverrides` (sync callback logic from the App Flow), `AiaHttpClientFactory`, prewarm (`none`/`background`/`await`), learn-on-failure scheduling.
**Test:** fixture integration: `HttpClient`, `CachedNetworkImage`, and a PDF download against a broken-chain host; prewarmed vs cold behavior documented by test.
**Deliverable:** release **0.1.0-alpha** (core + dart:io, Android).
**Exit:** originating Printpack scenario passes for images and PDFs with no bypass code.

### Phase 4: WebView integration (≈ 1.5 weeks)
**Build:** `aia_chaser_webview` with `AiaWebViewHandler.install(AndroidNavigationDelegate)`, composition with an app-supplied fallback handler, handling of missing certificate bytes.
**Test:** emulator + real-device runs on API 29, 31, 33 against fixture pages; negative tests (wrong host, expired, unreachable AIA → page blocked).
**Deliverable:** **0.1.0** (core + dart:io + WebView).
**Exit:** blank-white-screen scenario resolved with zero unconditional `proceed()` in app code.

### Phase 5: Adapters (≈ 1.5 weeks)
**Build:** `aia_chaser_dio` (adapter wrapping `IOHttpClientAdapter`, retry-once on handshake failure after pending validation), `aia_chaser_http` (`BaseClient` wrapper, same retry). Scoped use without global overrides.
**Test:** retry safety (A-6) with GET and POST bodies; adapters leave unlisted hosts untouched.
**Deliverable:** both packages building and tested; melos publishing configured.
**Exit:** Dio and `http` fixtures pass; unlisted-host passthrough verified.

### Phase 6: Caching, seeds, resilience (≈ 2 weeks)
**Build:** persistent `issuer_cache` (files + `index.json`, LRU, schema version), `seed_certificate` loading from assets, negative-result TTL, offline behavior, `cacheStats` and `clearCaches`.
**Test:** offline-after-first-success, corrupted index, schema bump, eviction; confirm tampering with cache files cannot cause acceptance.
**Deliverable:** **0.2.0**.
**Exit:** cold validation with warm disk cache needs zero network; performance targets measured and recorded.

### Phase 7: Diagnostics (≈ 2 weeks)
**Build:** `diagnose` (capture-only probe, never used for acceptance), `ChainReport` with cause and suggested fix text, `AiaChaser.events` stream, redacted report export, `AiaDiagnosticsView` widget following the UI/UX brief, message formatting rules (what / host / why / next).
**Test:** golden tests for the widget (light/dark, text scale 200%); report text tests for each `ValidationOutcome`; redaction tests.
**Deliverable:** **0.3.0**.
**Exit:** every non-success outcome produces a message with a "Next:" line and a docs anchor.

### Phase 8: Isolate support and iOS/macOS outcome (≈ 2 weeks)
**Build:** background-isolate install using `BackgroundIsolateBinaryMessenger` and `RootIsolateToken`; **iOS/macOS:** act on A-7. If Dart on Apple platforms fails on incomplete chains, implement the same Pigeon contract with Security.framework (`SecTrustCreateWithCertificates`, `SecTrustEvaluateWithError`) and run the same fixtures. If not, ship an explicit documented no-op with a test proving passthrough.
**Time-box:** hard stop at 2 weeks; unfinished iOS work becomes a post-1.0 issue, not a delay.
**Deliverable:** **0.4.0**.
**Exit:** isolate tests pass; F13 outcome documented either way.

### Phase 9: Test matrix and CI hardening (≈ 1.5 weeks, partly parallel from Phase 1)
**Build:** full fixture matrix (incomplete chain, wrong host, expired leaf and intermediate, self-signed, unreachable AIA, private-address AIA, oversized response, AIA loop, depth bomb); GitHub Actions: analyze, format, unit tests, emulator matrix (API 24, 28, 29, 31, 33, 35), fixture integration, README snippet compile check, coverage gates (≥ 90% Dart core, ≥ 80% Kotlin); pinned action SHAs.
**Deliverable:** green CI on every supported API level.
**Exit:** matrix is a required check for merging.

### Phase 10: Playground app and documentation (≈ 2.5 weeks)
**Build:** the Playground app exactly per the App Flow (Hosts, Add Host, Host Detail, Chain Report, Policy Editor, Lab with four stack tabs, Events, Settings); README, threat model, diagnosis guide (per-outcome anchors), migration guide from `proceed()` / `badCertificateCallback`, privacy statement, `SECURITY.md`, CHANGELOG.
**Deliverable:** Playground installable from a fresh checkout in under 10 minutes; docs complete.
**Exit:** a developer unfamiliar with the project follows the README and gets a broken-chain host working.

### Phase 11: Security review, 1.0 freeze, launch (≈ 2 weeks)
**Do:** external review of the Kotlin validation path and unsafe-API rules; fix findings; check Google Play policy text on SSL error handling; API freeze; pub.dev score check (160/160); verified publisher, 2FA, OIDC publishing; publish 1.0.0; write the launch blog post ("why Flutter has three network stacks and how one certificate issue breaks all of them").
**Deliverable:** **1.0.0** on pub.dev plus blog post.
**Exit:** all PRD success-metric gates met.

## Traceability: PRD → TRD → Schema → Phase

| PRD feature | TRD section | Schema | Built in |
|---|---|---|---|
| F1 AIA chain completion | §9 pipeline | `issuer_cache` | Phase 1 |
| F2 Platform-grade validation | §9, §10 | `validation_cache` | Phase 1 |
| F3 Per-host policy | §7 | `host_policy` | Phase 2 |
| F4 `dart:io` integration | §1, §7 | `validation_cache` (Dart side) | Phase 3 |
| F5 WebView integration | §2 | `validation_cache` | Phase 4 |
| F6 Dio adapter | §2, §7 | none | Phase 5 |
| F7 `package:http` client | §2, §7 | none | Phase 5 |
| F8 Pinning fallback | §7, §10 | `pin` | Phases 1–2 |
| F9 Unsafe escape hatch | §7, §10 | `host_policy.allow_unsafe_in_release` | Phase 2 |
| F10 Caching | §6 | `issuer_cache`, `seed_certificate` | Phase 6 |
| F11 Diagnostics | §8 | `diag_event`, `chain_report` | Phase 7 |
| F12 Prewarm / learn-on-failure | §1 | `validation_cache` | Phase 3 |
| F13 iOS/macOS | §5, A-7 | same | Phase 8 |
| F14 Isolate support | §3 | none | Phase 8 |
| F15 Docs, example, fixtures | §14, §15 | none | Phases 1, 9, 10 |

## Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| WebView handler can't await (A-1) | Medium | High | Phase 0 spike; fallback: pre-validate at page start or upstream PR |
| Certificate bytes missing on some Android versions (A-2) | Medium | Medium | `noCertificate` outcome + failure policy; document |
| `webview_flutter_android` API changes | Medium | Medium | Isolated adapter package; pinned lower bound; CI against latest |
| Security bug in validation path | Low | **Critical** | Negative-test suite, external review, zero native deps |
| Play Store scanner flags the approach | Low–Medium | High | No native `onReceivedSslError` code; verify policy text; document the validated-proceed design |
| Solo-maintainer burnout / schedule slip | Medium | Medium | Time-boxed iOS phase; iOS and extra adapters are post-1.0 if needed |
| CA changes AIA hosting | Low | Low | Seeds + disk cache; configurable fetch options |
| Behavior divergence between Kotlin and Dart trust stores | Medium | Medium | `trustUserCaCerts` option, documentation, fixture covering user-CA case |
| Package name unavailable | Low | Low | Check in Phase 0; rename is cheap before 0.1.0 |

## Definition of done (every phase)

1. Code merged with tests; CI green on the supported matrix.
2. No new path returns acceptance without validation, pin, or guarded `unsafeAllow` (checked by the negative-test suite).
3. Public API documented with dartdoc; README snippets compile.
4. CHANGELOG updated.
5. Threat model reviewed if the phase touched native code.

## Release checklist for 1.0.0

- [ ] All Phase 0 verification items resolved and reflected in TRD
- [ ] Fixture matrix green on API 24, 28, 29, 31, 33, 35 plus a real Android 10–13 device
- [ ] External security review complete, findings closed
- [ ] Play policy text re-checked
- [ ] pub.dev score 160/160, verified publisher, OIDC publishing
- [ ] Playground app builds from a fresh checkout
- [ ] Migration guide tested against the original incident code
- [ ] Blog post drafted and published
- [ ] `SECURITY.md` contact verified
