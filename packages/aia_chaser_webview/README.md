# aia_chaser_webview

[![pub package](https://img.shields.io/pub/v/aia_chaser_webview.svg)](https://pub.dev/packages/aia_chaser_webview)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

Safe **Android WebView SSL error interception** for **[aia_chaser](https://pub.dev/packages/aia_chaser)**, eliminating insecure `proceed()` calls by dynamically resolving `SSL_UNTRUSTED` via Authority Information Access (AIA) intermediate certificate chasing.

---

## The Danger of `handler.proceed()`

When an Android WebView navigates to an HTTPS domain with an incomplete certificate chain, Android raises an `onReceivedSslError` event with `SSL_UNTRUSTED`.

Many applications naively do:

```dart
// ❌ CRITICAL SECURITY VULNERABILITY!
// Bypasses all SSL verification for every certificate error, including spoofing and MitM attacks.
onReceivedSslError: (controller, error) {
  error.proceed(); 
}
```

This vulnerability leads to immediate security audit failure and Google Play Store rejection.

`aia_chaser_webview` replaces blind `proceed()` with **cryptographic verification**: it intercepts the SSL error, probes and verifies the complete certificate chain through AIA against the Android system trust store, and only calls `proceed()` if the chain is proven valid.

---

## Installation

Add `aia_chaser` and `aia_chaser_webview` to your `pubspec.yaml`:

```yaml
dependencies:
  aia_chaser: ^0.1.0
  aia_chaser_webview: ^0.1.0
  webview_flutter: ^4.10.0
  webview_flutter_android: ^4.7.0
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
      'portal.example.com': const HostPolicy.chase(),
    },
  ));

  runApp(const MyApp());
}
```

### 2. Attach Handler to WebView NavigationDelegate
```dart
import 'package:aia_chaser_webview/aia_chaser_webview.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

final controller = WebViewController();

if (controller.platform is AndroidWebViewController) {
  final androidController = controller.platform as AndroidWebViewController;
  
  // Attach AIA Chaser SSL error handler
  AiaWebViewHandler.install(
    androidController.navigationDelegate as AndroidNavigationDelegate,
    fallbackHandler: (error) {
      // Optional: Handle true untrusted errors (e.g. self-signed, hostname mismatch)
      error.cancel();
    },
  );
}

controller.loadRequest(Uri.parse('https://portal.example.com'));
```
