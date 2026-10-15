# aia_chaser_dio

[![pub package](https://img.shields.io/pub/v/aia_chaser_dio.svg)](https://pub.dev/packages/aia_chaser_dio)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

A drop-in **Dio `HttpClientAdapter`** for **[aia_chaser](https://pub.dev/packages/aia_chaser)** that enables scoped Authority Information Access (AIA) certificate chasing and transparent retry-once resilience for Flutter and Dart.

---

## The Problem

When interacting with backend servers that omit intermediate CA certificates, Dio throws:

```
DioException [bad certificate]: HandshakeException: CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate
```

Standard workarounds like `validateCertificate: (cert, host, port) => true` expose applications to catastrophic Man-in-the-Middle (MitM) attacks.

`aia_chaser_dio` transparently connects with the native AIA Chaser engine to fetch missing intermediate certificates, validate the complete cryptographic trust path against the system trust store, and automatically retry failed requests once.

---

## Installation

Add `aia_chaser` and `aia_chaser_dio` to your `pubspec.yaml`:

```yaml
dependencies:
  aia_chaser: ^0.1.0
  aia_chaser_dio: ^0.1.0
  dio: ^5.7.0
```

---

## Quick Start

### 1. Initialize AIA Chaser
```dart
import 'package:aia_chaser/aia_chaser.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await AiaChaser.initialize(AiaConfig(
    hosts: {
      'api.example.com': const HostPolicy(
        chase: true,
        retryOnce: true, // Transparently retry upon validation
      ),
    },
  ));

  runApp(const MyApp());
}
```

### 2. Attach Adapter to Dio
```dart
import 'package:aia_chaser_dio/aia_chaser_dio.dart';
import 'package:dio/dio.dart';

final dio = Dio();
dio.httpClientAdapter = AiaDioAdapter();

// All requests now benefit from AIA resolution and auto-retry!
final response = await dio.get('https://api.example.com/v1/profile');
```

---

## How It Works

1. **Fast-Path Verification:** If the target host has already been validated or prewarmed, the TLS connection succeeds immediately with $O(1)$ memory overhead.
2. **Failure Interception:** When a handshake fails with `CERTIFICATE_VERIFY_FAILED`, `AiaDioAdapter` intercepts the exception.
3. **AIA Resolution:** The native engine fetches missing intermediate certificates via AIA, verifies signatures, and validates trust against the Android Conscrypt trust store.
4. **Retry Once:** If the chain validates successfully, the request is transparently re-attempted once.
