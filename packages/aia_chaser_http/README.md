# aia_chaser_http

[![pub package](https://img.shields.io/pub/v/aia_chaser_http.svg)](https://pub.dev/packages/aia_chaser_http)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

A drop-in **`http.Client`** implementation for **[aia_chaser](https://pub.dev/packages/aia_chaser)** that enables scoped Authority Information Access (AIA) intermediate certificate chasing and transparent retry-once resilience for Flutter and Dart.

---

## The Problem

When interacting with backend servers that omit intermediate CA certificates, `package:http` throws:

```
ClientException: HandshakeException: CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate
```

`aia_chaser_http` safely resolves this by chasing intermediate certificates via AIA, validating against the system root store, and retrying failed requests once upon successful chain completion.

---

## Installation

Add `aia_chaser` and `aia_chaser_http` to your `pubspec.yaml`:

```yaml
dependencies:
  aia_chaser: ^0.1.0
  aia_chaser_http: ^0.1.0
  http: ^1.2.0
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

### 2. Use `AiaHttpClient`
```dart
import 'package:aia_chaser_http/aia_chaser_http.dart';

final client = AiaHttpClient();

// Safe requests with automatic AIA recovery
final response = await client.get(Uri.parse('https://api.example.com/v1/data'));
print(response.body);

client.close();
```

You can also pass an existing `http.Client` to wrap:
```dart
final customClient = AiaHttpClient(myExistingClient);
```
