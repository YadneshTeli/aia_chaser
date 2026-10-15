## 0.1.0

* First stable release of `aia_chaser`.
* Clean standalone example app resolution for pub.dev analysis.
* Full chain reconstruction and system trust store validation.
* Prewarming support (`AiaChaser.prewarm`) for zero-latency cold-start requests.
* Host policies with wildcard subdomain support (`*.example.com`).
* Certificate pinning fallback (`PinType.certSha256`, `PinType.spkiSha256`).
* Rich diagnostic reporting (`AiaChaser.diagnose`) and Flutter Material 3 `AiaDiagnosticsView` widget.

## 0.1.0-alpha.1

* Initial alpha release of `aia_chaser`.
* Automatically resolves `CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate` by chasing missing intermediate certificates via AIA extensions.
* Full chain reconstruction and validation against Android's system trust store (`X509TrustManagerExtensions`).
* Synchronous `badCertificateCallback` integration via `AiaHttpOverrides` using microsecond in-memory leaf store.
* Prewarming support (`AiaChaser.prewarm`) for zero-latency cold-start requests.
* Host policies with wildcard subdomain support (`*.example.com`).
* Certificate pinning fallback (`PinType.certSha256`, `PinType.spkiSha256`).
* Rich diagnostic reporting (`AiaChaser.diagnose`) and Flutter Material 3 `AiaDiagnosticsView` widget.
