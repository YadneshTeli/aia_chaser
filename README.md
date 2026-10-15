# AIA Chaser Monorepo

[![CI Pipeline](https://github.com/YadneshTeli/aia_chaser/actions/workflows/ci.yml/badge.svg)](https://github.com/YadneshTeli/aia_chaser/actions/workflows/ci.yml)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Melos](https://img.shields.io/badge/maintained%20with-melos-f700ff.svg)](https://github.com/invertase/melos)

> **Zero-trust Authority Information Access (AIA) intermediate certificate chasing for Flutter and Dart.**
> Eliminates `"unable to get local issuer certificate"` and Android WebView `SSL_UNTRUSTED` errors without compromising on TLS security or resorting to insecure `badCertificateCallback => true`.

---

## The Problem

When a web server is misconfigured to serve only its leaf certificate and omits intermediate Certificate Authority (CA) certificates:
- **Desktop Browsers (Chrome, Safari):** Silently fetch missing intermediate certificates using the **Authority Information Access (AIA)** extension embedded in the leaf certificate.
- **Dart TLS Engine (`SecurityContext`, `dart:io`) & Android WebView:** Do not implement AIA intermediate chasing. They immediately abort the connection with `CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`.

Developers frequently resort to dangerous bypasses:
```dart
// ❌ CRITICAL SECURITY VULNERABILITY!
// Bypasses all validation, allowing trivial Man-in-the-Middle (MitM) attacks.
client.badCertificateCallback = (cert, host, port) => true;
```

**AIA Chaser fixes this safely** by dynamically chasing missing intermediate certificates over AIA, verifying signatures and RFC 6125 Subject Alternative Names, and validating complete chains against the Android Conscrypt trust store and native OS root certificates.

---

## Monorepo Packages

| Package | Version | Description |
| :--- | :--- | :--- |
| [`packages/aia_chaser`](./packages/aia_chaser) | `0.1.0` | **Core Engine:** Native Android engine, Pigeon IPC, Dart policy manager, LRU disk cache, isolate worker support, and diagnostic visualizer. |
| [`packages/aia_chaser_webview`](./packages/aia_chaser_webview) | `0.1.0` | **WebView Integration:** Intercepts Android WebView `onReceivedSslError`, validating chains before calling `proceed()`. |
| [`packages/aia_chaser_dio`](./packages/aia_chaser_dio) | `0.1.0` | **Dio Adapter:** Custom `HttpClientAdapter` wrapping `IOHttpClientAdapter` with transparent retry-once resilience. |
| [`packages/aia_chaser_http`](./packages/aia_chaser_http) | `0.1.0` | **HTTP Client:** Drop-in `http.BaseClient` for `package:http` with automatic AIA recovery. |

---

## Architecture Overview

```mermaid
flowchart TD
    App[Flutter Application] -->|Requests| Adapters[AiaHttpOverrides / Dio / Http / WebView]
    Adapters -->|Check Verdict Cache| MemoryStore[ValidatedLeafStore: O(1) Memory Cache]
    MemoryStore -->|Cached & Valid| AllowFastPath[TLS Handshake Approved < 0.1ms]
    MemoryStore -->|Uncached / Miss| NativeEngine[Native Android Engine: dev.aiachaser]
    
    subgraph NativeEngine [AIA Chaser Native Engine]
        Dispatcher[4-Thread Bounded Executor + Single-Flight]
        Prober[TLS Socket Prober]
        Fetcher[AiaFetcher: SSRF Filter, 64 KiB Cap, Redirect Limits]
        ASN1Parser[ChainBuilder: ASN.1 AIA Parser + Loop Detection]
        DiskCache[DiskIssuerCache: <cacheDir>/aia_chaser/v1/]
        TrustValidator[TrustValidator: Conscrypt X509TrustManagerExtensions]
        
        Dispatcher --> Prober
        Prober --> ASN1Parser
        ASN1Parser -->|Lookup Intermediate| DiskCache
        ASN1Parser -->|Fetch Missing Intermediate| Fetcher
        Fetcher --> ASN1Parser
        ASN1Parser --> TrustValidator
    end
    
    TrustValidator -->|Validation Result| MemoryStore
```

---

## Zero-Trust Security Guarantees

AIA Chaser treats all data fetched over AIA URLs as **strictly untrusted**:
1. **Anti-SSRF IP Address Blocking:** All resolved IP addresses for AIA URLs are inspected. Connections to loopback (`127.0.0.0/8`, `::1`), RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local, and cloud metadata services (`169.254.169.254`) are rejected immediately.
2. **Payload Size Caps:** Fetches are capped at **64 KiB** per intermediate certificate to prevent memory exhaustion and DoS attacks.
3. **Loop & Depth Limits:** Chain construction enforces a maximum depth of **3 intermediates** and detects circular issuer loops.
4. **Strict Trust Anchor Validation:** Even if signatures match across the intermediate chain, the root certificate must anchor in the official Android/OS system trust store.
5. **No Unsafe Fallbacks by Default:** Unlisted hosts are rejected by default. The `unsafeAllow` mode is strictly opt-in and logs prominent warnings.

---

## Quick Start

### 1. Configure AIA Chaser
```dart
import 'package:aia_chaser/aia_chaser.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await AiaChaser.initialize(AiaConfig(
    hosts: {
      'api.example.com': const HostPolicy.chase(),
      '*.internal.org': const HostPolicy.chase(),
    },
    prewarm: PrewarmMode.background,
  ));

  // Install global HttpOverrides (handles dart:io HttpClient, Image.network, etc.)
  HttpOverrides.global = AiaHttpOverrides();

  runApp(const MyApp());
}
```

### 2. Diagnose Misconfigured Domains
```dart
final report = await AiaChaser.diagnose('incomplete-chain.badssl.com');
print('Trust Status: ${report.trustStatus}');
print('Recommended Fix: ${report.recommendedFix}');
```

---

## Detailed Documentation

- [Migration Guide: Eliminating `badCertificateCallback => true`](./docs/MIGRATION.md)
- [Threat Model & Zero-Trust Security Spec](./docs/THREAT_MODEL.md)
- [Diagnostic & Troubleshooting Guide](./docs/DIAGNOSIS.md)

---

## Developer Workflow

This repository uses **Dart Pub Workspaces** and **Melos 8**.

```bash
# Analyze all workspace packages
dart run melos run analyze

# Run unit and integration tests across all packages
dart run melos run test

# Re-generate Pigeon IPC bindings
dart run melos run pigeon

# Verify code formatting
dart format --output=none --set-exit-if-changed .
```

---

## License

This project is licensed under the **BSD-3-Clause License**. See the [LICENSE](./LICENSE) file for details.
