# AIA Chaser — Product Requirements Document

**Package family:** `aia_chaser`, `aia_chaser_webview`, `aia_chaser_dio`, `aia_chaser_http` (names are placeholders until checked on pub.dev)
**One-line description:** A Flutter plugin that fixes "unable to get local issuer certificate" and WebView `SSL_UNTRUSTED` errors on Android by fetching missing intermediate certificates through AIA, validating the full chain against the system trust store, and only then letting the connection proceed.
**Release target:** v1.0 (full scope). Alphas ship along the way, but nothing in this document is deferred to "later MVP".
**License / model:** BSD-3-Clause, free, open source, published on pub.dev.

---

## 1. Problem

Servers regularly send only their leaf certificate, or a chain that older devices cannot complete. Desktop browsers hide this by doing AIA chasing: they read the leaf's Authority Information Access extension and download the missing issuer. Android's platform TLS stack, `dart:io`, and Android WebView do not. The result in a Flutter app is that one server misconfiguration breaks three separate network stacks differently:

| Stack | Symptom |
|---|---|
| `dart:io` `HttpClient` (images, PDFs, `CachedNetworkImage`, most packages) | `HandshakeException: CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate` |
| Dio / `package:http` | Same exception, wrapped |
| Android `WebView` | Blank white page, `SSL_UNTRUSTED` / `ERR_CERT_AUTHORITY_INVALID` |

The common workarounds are all bad:

- `badCertificateCallback => true` and `SslErrorHandler.proceed()` disable validation. Any network attacker presenting any certificate for that host is accepted.
- Google Play flags unsafe `onReceivedSslError` implementations and can block releases.
- The proper fix is on the server (send `fullchain.pem`), but app developers, agencies, and freelancers often don't control it, and fixing the server does nothing for already-shipped app versions.
- The fix is currently duplicated by hand in `main.dart`, every WebView screen, and every HTTP client, and nobody gets it all three times.

**Origin:** this package comes from a real production incident (an exhibition-booking app on Android 10–13 failing on a Let's Encrypt chain). Diagnosis took far longer than the fix, which is why diagnostics are a first-class feature here.

## 2. Target users

| Persona | Situation | What they need |
|---|---|---|
| **Integrator** (primary): Flutter app developer | Sees the handshake error or white WebView, often found via Stack Overflow; may not own the server | A 10-line fix that is safe, covers all stacks, and doesn't need ASN.1 knowledge |
| **Agency / freelance dev** | Client's server is misconfigured and slow to fix | A defensible, documented client-side mitigation to show the client and a security reviewer |
| **Security reviewer** | Reviews an app that currently calls `proceed()` | Evidence that nothing is accepted without full chain, hostname and expiry validation |
| **Server/DevOps owner** (indirect) | Owns the TLS config | A diagnostic report that says exactly what to change on the server |
| **Contributor / maintainer** | Wants to extend or audit the package | Small codebase, clear threat model, reproducible test fixtures |

## 3. Main features

| ID | Feature | Summary |
|---|---|---|
| F1 | AIA chain completion (Android) | Parse the leaf's AIA `caIssuers` URIs, fetch issuer certificates (DER, PEM, or PKCS#7), repeat up to a depth limit |
| F2 | Platform-grade validation | Validate the completed chain with Android's system trust manager, plus hostname (SAN) and validity-date checks |
| F3 | Per-host policy | App declares which hosts are handled, whether to chase, per-host timeouts, and what to do when validation fails |
| F4 | `dart:io` integration | `AiaHttpOverrides` for global coverage (`CachedNetworkImage`, PDF downloaders) and `AiaHttpClientFactory` for scoped use |
| F5 | WebView integration | `aia_chaser_webview` wires `webview_flutter_android`'s SSL auth error callback to the validator |
| F6 | Dio adapter | `aia_chaser_dio` for apps that want per-client scoping instead of a global override |
| F7 | `package:http` client | `aia_chaser_http` equivalent |
| F8 | Pinning fallback | Pin a leaf (SHA-256) or SPKI (SHA-256) for hosts whose CA is absent from the device store |
| F9 | Unsafe escape hatch | `UnsafeAllow` policy, named and guarded: debug-only by default, loud logging, explicit release opt-in |
| F10 | Caching | Persistent issuer-certificate cache, in-memory validation cache, optional bundled seed certificates |
| F11 | Diagnostics | `diagnose(host)` chain report with plain-language cause and suggested server fix, a typed event stream, and a drop-in `AiaDiagnosticsView` widget |
| F12 | Prewarm and learn-on-failure | Validate known hosts at startup; for unknown failures, validate in the background and retry once |
| F13 | iOS / macOS handling | Evaluate whether Apple platforms need the same fix; implement via Security.framework only if the evaluation says yes, otherwise explicit documented no-op |
| F14 | Isolate support | Install and use the validator from background isolates |
| F15 | Docs, example, fixtures | README, migration guide from `proceed()` workarounds, example "Playground" app, local broken-chain test server |

## 4. User roles

- **Integrator**: configures and installs the package. Only role that touches the API.
- **Reviewer**: reads docs, threat model, and diagnostics output; may run the Playground app.
- **Server owner**: consumes diagnostic reports (copy-pasted, redacted); never touches the package.
- **Maintainer**: owns releases and the security policy.
- **End user** (of the integrator's app): never sees the package, only pages that load.

## 5. User stories

1. As an integrator, I want to list my API and CDN hosts once so that every network stack in my app stops failing on the incomplete chain.
2. As an integrator, I want `CachedNetworkImage` and my PDF downloader to work without modifying either, so that I don't have to fork or wrap third-party packages.
3. As an integrator, I want my WebView to load the affected page without a blanket `proceed()` call, so that my app passes security review.
4. As an integrator using Dio, I want to attach an adapter to one client instead of overriding globally, so that unrelated traffic is untouched.
5. As an integrator using `package:http`, I want a drop-in `Client` that handles the issue, so that I don't change call sites.
6. As an integrator, I want to choose per host what happens on failure (reject, pin, or unsafe allow), so that production hosts are strict while a staging host can be lenient in debug.
7. As an integrator, I want the first request to a host to succeed, not fail once and then work, so that users don't see a broken first screen.
8. As an integrator, I want a report saying "the server sent 1 of 3 certificates; the issuer was fetched from X; the system store trusts the result", so that I know whether the problem is the server or the device.
9. As a server owner, I want a copy-pasteable report that names the missing certificate and the exact fix (serve the full chain), so that I can fix the root cause.
10. As a security reviewer, I want to see that a fetched certificate is never trusted unless it chains to a system root (or an explicit pin), so that I can approve the package.
11. As a security reviewer, I want AIA fetching to be unable to reach private network addresses, so that a malicious certificate can't turn the app into an SSRF probe.
12. As an integrator, I want results cached so that later requests add no noticeable latency and survive being offline after the first success.
13. As an integrator, I want to use the package from a background isolate, so that downloads in `compute()` or workmanager callbacks also work.
14. As an integrator on a flaky network, I want sensible timeouts and a defined failure outcome, so that a dead AIA server never hangs my app.
15. As a maintainer, I want a local test server that serves deliberately broken chains, so that every release is tested against real failure modes.
16. As an integrator, I want a migration guide from my `badCertificateCallback` / `proceed()` code, so that I can delete it with confidence.

## 6. Success metrics

**Correctness and safety (gates for v1.0)**
- 0 known paths that accept a certificate without chain, hostname, and expiry validation (or an explicit pin / explicit `UnsafeAllow`).
- 100% pass on the broken-chain fixture matrix (incomplete chain, wrong host, expired leaf, expired intermediate, self-signed, unreachable AIA, malicious AIA URL, oversized AIA response, AIA loop, depth bomb) on the supported Android device matrix.
- External security review of the Kotlin validation path by at least one person other than the author before 1.0.

**Quality**
- pub.dev score 160/160.
- Line coverage ≥ 90% Dart core, ≥ 80% Kotlin.
- Every README snippet compiles (checked in CI).

**Performance** (measured on a mid-tier Android device)
- Warm decision (cache hit) p95 < 5 ms.
- Cold validation including one AIA fetch p95 < 1.5 s on 4G.
- No work on the Android main thread beyond argument marshalling.

**Adoption** (indicators, not gates)
- Playground app runs end-to-end on a fresh checkout in under 10 minutes.
- First external issue or PR within 90 days of 1.0.
- Blog post and one community write-up published at launch.

## 7. Release scope: v1.0 (full)

Everything in F1–F15, delivered through staged pre-releases:

| Release | Contents |
|---|---|
| 0.1.0 | F1, F2, F3, F4, F5 (core + `dart:io` + WebView), Android only, in-memory cache |
| 0.2.0 | F6, F7, F8, F10 (disk cache, seeds), F12 |
| 0.3.0 | F11 (diagnose, events, widget), F14 |
| 0.4.0 | F13 outcome (implementation or documented no-op), full fixture matrix |
| 1.0.0 | API freeze, security review, docs, Playground, migration guide, F15 complete |

## 8. Explicitly excluded from v1.0

| Excluded | Reason |
|---|---|
| Revocation checking (OCSP, CRL) | The platform stacks this package replaces don't do it either by default; adding it would expand the network surface and latency. Document as a known limitation. |
| Windows, Linux, web | Different TLS stacks and different failure modes. Browsers already chase AIA. Revisit after 1.0 with real demand. |
| `flutter_inappwebview` and other WebView plugins | Each needs its own SSL hook. Ship the `webview_flutter_android` adapter first; the core API is designed so other adapters can be added. |
| Replacing Dart's TLS stack or patching BoringSSL | Out of reach for a solo maintainer and makes the package unmaintainable. |
| Server-side tooling (ACME hooks, auto-fixing chains) | The package mitigates on the client; fixing servers is a different product. The diagnostics only tell the server owner what to change. |
| Trust-on-first-use | Silently trusting what was first seen is the same weakness as the bypass this package exists to replace. |
| Certificate Transparency checks | No platform-level support to build on; large scope for little practical gain here. |
| Telemetry or crash reporting | The package collects and sends nothing except AIA GET requests. This is a trust feature. |
| Pure-Dart ASN.1 / X.509 parsing | All parsing is done by the platform's parser (JDK, Security.framework), which is better tested than anything this package could write. |
| Custom async failure callback in `dart:io` | `badCertificateCallback` is synchronous, so an async decision hook cannot work there. Policies are declarative instead. |
| User-installed CA handling beyond platform defaults | Follows the app's network security config; the package adds no extra trust. |

## 9. Assumptions and open questions

1. The package name and namespace are free on pub.dev (to be checked before any code is published).
2. `webview_flutter_android` exposes the leaf certificate bytes in `AndroidSslAuthError` on the versions supported (to be confirmed in the Phase 0 spike).
3. Android WebView only supplies the leaf certificate; the package treats the leaf as its only input and builds the rest itself.
4. Whether Dart on iOS/macOS fails on incomplete chains is unconfirmed; F13 is gated on a real-device test.
5. Whether Google Play's automated scanners treat a validated `proceed()` differently from an unconditional one is unconfirmed. The package adds no native `onReceivedSslError` code of its own; it relies on the WebView plugin's existing callback.

## 10. Glossary

- **AIA**: Authority Information Access, an X.509 extension whose `caIssuers` entry gives a URL for the issuer's certificate.
- **AIA chasing**: fetching the issuer certificates named in AIA to complete a chain.
- **Intermediate**: a CA certificate between the leaf and a trusted root.
- **SPKI pin**: SHA-256 of a certificate's SubjectPublicKeyInfo; survives certificate renewal if the key is reused.
