# AIA Chaser

A Flutter plugin that fixes `"HandshakeException: CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate"` and Android WebView `SSL_UNTRUSTED` (`ERR_CERT_AUTHORITY_INVALID`) errors by fetching missing intermediate certificates via **Authority Information Access (AIA)**, validating the complete chain against Android's system trust store, and only then permitting the connection.

---

## The Problem

Web servers regularly send incomplete TLS certificate chains (for example, sending only `cert.pem` instead of `fullchain.pem`). Desktop browsers quietly resolve this by inspecting the leaf certificate's AIA extension, downloading the missing intermediate issuer over HTTP (`caIssuers`), and finishing the chain. 

Android's platform TLS engine (BoringSSL/Conscrypt), Dart's `dart:io`, and Android WebView **do not chase AIA**. When a server is misconfigured, a Flutter app fails across all network stacks:

| Network Stack | Error Symptom |
|---|---|
| **`dart:io` `HttpClient`** (`Image.network`, `CachedNetworkImage`, PDF viewers) | `HandshakeException: CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate` |
| **`Dio`** / **`package:http`** | Same handshake failure, wrapped |
| **Android `WebView`** | Blank white screen, `onReceivedSslError` (`SSL_UNTRUSTED`) |

### Insecure Workarounds vs. AIA Chaser

- `badCertificateCallback = (cert, host, port) => true` disables all certificate verification. Any network attacker presenting any certificate for that host is accepted.
- `SslErrorHandler.proceed()` unconditionally trusts untrusted web connections and violates Google Play policies.
- **AIA Chaser** downloads the missing intermediate certificate, reconstructs the chain, and cryptographically checks it using Android's system trust store (`X509TrustManagerExtensions`), RFC 6125 hostname matching, and validity dates. Connections are **never** permitted without full chain verification.

---

## Diagnose in 30 Seconds

Before writing any configuration, diagnose your host to see whether the problem is an incomplete server chain or an untrusted CA:

```dart
import 'package:aia_chaser/aia_chaser.dart';

void main() async {
  final report = await AiaChaser.diagnose('booking.example.com');
  print(report.toFormattedString());
}
```

The diagnostic report outputs the exact cause and suggested fix:
```
[AiaChaser] Diagnostic Report for booking.example.com:443
--------------------------------------------------------------------------------
Outcome:      VALIDATED
Duration:     342ms
Server Sent:  1 certificate(s)
Completed:    3 certificate(s)
--------------------------------------------------------------------------------
Root Cause:
  Server sent an incomplete chain (1 certs). AIA Chaser completed the chain 
  by fetching 1 intermediate certificate(s).

Suggested Fix:
  Configure your web server to serve the full chain bundle (e.g. 'fullchain.pem' 
  instead of 'cert.pem') to eliminate client-side AIA fetching.
================================================================================
```

---

## Quick Start (10 Lines)

Add `aia_chaser` to your `pubspec.yaml`:
```yaml
dependencies:
  aia_chaser: ^0.1.0
```

Initialize AIA Chaser in your `main()` before `runApp()`:

```dart
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:aia_chaser/aia_chaser.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await AiaChaser.initialize(AiaConfig(
    hosts: {
      'api.example.com': const HostPolicy.chase(),
      '*.cdn.example.com': const HostPolicy.chase(),
    },
    prewarm: PrewarmMode.background, // Pre-validates exact hosts at startup
  ));

  // Install global dart:io overrides (covers CachedNetworkImage, PDF viewers, etc.)
  HttpOverrides.global = AiaHttpOverrides();

  runApp(const MyApp());
}
```

---

## Per-Stack Integration

### 1. `dart:io` (`HttpClient`)
```dart
// Global application-wide override
HttpOverrides.global = AiaHttpOverrides();

// Or scoped client creation
final client = AiaHttpClientFactory.create();
```

### 2. Android WebView (`aia_chaser_webview`)
```yaml
dependencies:
  aia_chaser_webview: ^0.1.0
```

```dart
import 'package:aia_chaser_webview/aia_chaser_webview.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

// Inside your WebView controller initialization:
if (controller.platform is AndroidWebViewController) {
  final androidController = controller.platform as AndroidWebViewController;
  // Intercepts SSL_UNTRUSTED, chases missing intermediate certs, and safely proceeds
  AiaWebViewHandler.install(androidController);
}
```

### 3. Dio (`aia_chaser_dio`)
```yaml
dependencies:
  aia_chaser_dio: ^0.1.0
```

```dart
import 'package:dio/dio.dart';
import 'package:aia_chaser_dio/aia_chaser_dio.dart';

final dio = Dio();
dio.httpClientAdapter = AiaDioAdapter(); // Handles AIA chasing and automatic retry-once
```

### 4. `package:http` (`aia_chaser_http`)
```yaml
dependencies:
  aia_chaser_http: ^0.1.0
```

```dart
import 'package:aia_chaser_http/aia_chaser_http.dart';

final client = AiaHttpClient(); // Drop-in replacement for http.Client
```

---

## Policy Engine Reference

| Policy | Behavior on Failure | Use Case |
|---|---|---|
| `HostPolicy.chase()` | Chases missing intermediate via AIA; rejects if unverified. | **Production (Recommended)** |
| `HostPolicy.pinOnly(pins)` | Bypasses system store; validates signature linkage & pin match. | Private CAs absent from device trust store. |
| `FailurePolicy.pinFallback(pins)` | Chases AIA; if system root is missing, falls back to pin. | Migration from legacy root CAs. |
| `FailurePolicy.unsafeAllow()` | Accepts unconditionally (throws in release unless explicit). | Debugging only. Emits security warning log. |
| `HostPolicy.passthrough` | AIA Chaser leaves host untouched; platform handles TLS. | Unconfigured default. |

---

## Is This Safe? (Threat Model Summary)

- **Zero-Trust Ingestion**: Certificates downloaded over AIA are untrusted network inputs. They enter the candidate pool and must be authenticated against Android's system trust store (`X509TrustManagerExtensions`), RFC 6125 SAN hostname matching, and validity dates.
- **SSRF Hardening**: `AiaFetcher` resolves hostnames and checks all resolved IP addresses before opening sockets. Requests to loopback (`127.0.0.0/8`, `::1`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), link-local (`169.254.0.0/16`, `fe80::/10`), or carrier-grade NAT IPs are blocked immediately. Redirect targets are re-validated before every hop.
- **Payload & Loop Limits**: Hard response cap of 64 KiB, chain depth limit of 4, and certificate hash tracking to eliminate infinite certificate loops.
- **No Persisted Trust**: Verdicts live solely in memory ($TTL \le 24\text{h}$). Persistent on-disk caches hold only public intermediate certificates (`<cacheDir>/aia_chaser/v1/`) which must be cryptographically re-evaluated on every use.

---

## Performance

- **Warm Verdict ($O(1)$ Memory Hit)**: p95 $< 5\text{ ms}$.
- **Cold AIA Fetch**: p95 $< 1.5\text{ s}$ on 4G LTE.
- **Android Main Thread**: Zero cryptographic or network operations on UI thread.
- **APK Footprint**: $< 150\text{ KB}$ (zero native third-party dependencies).

---

## License

BSD 3-Clause License. See [LICENSE](LICENSE) for details.
