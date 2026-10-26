## 0.1.1

* Added full Swift Package Manager (SPM) support on iOS (`ios/aia_chaser/Package.swift`) alongside CocoaPods (`ios/aia_chaser.podspec`) dual-support structure for Flutter 3.24+.
* Implemented native Apple `Security` framework evaluation (`SecTrust`, `SecPolicyCreateSSL`, `SecTrustEvaluateWithError`, `SecTrustSetNetworkFetchAllowed`) for cryptographic trust verification, active TLS prewarming, and detailed chain diagnostics on iOS.
* Upgraded iOS minimum deployment target to iOS 13.0 across podspec and SwiftPM.
* Fixed `AiaCacheOptions.seedAssets`: assets are now loaded with `rootBundle` and passed to native as bytes (previously the asset keys were treated as file paths and silently ignored).
* iOS: probe sessions now cancel on failed trust, are invalidated after use, and network failures are reported as `aiaFetchFailed` instead of an untrusted-chain verdict.
* Android: the worker executor is recreated when the plugin is re-attached to an engine.
* Android: removed the redundant `package` attribute from the library manifest (namespace is set in Gradle).
* Added a GitHub Actions workflow that builds the iOS example with both Swift Package Manager and CocoaPods.

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
