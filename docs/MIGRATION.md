# Migration Guide: Eliminating Insecure TLS Bypasses

This guide walks you through migrating from insecure workarounds (`badCertificateCallback = (c, h, p) => true` and `SslErrorHandler.proceed()`) to safe, authenticated TLS using **AIA Chaser**.

---

## 1. Migrating from `dart:io` `badCertificateCallback`

### The Problematic Code
Developers frequently encounter `HandshakeException: CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate` and add an unconditional bypass:

```dart
// ❌ INSECURE: Disables TLS authentication for all hosts!
class MyHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    final client = super.createHttpClient(context);
    client.badCertificateCallback = (cert, host, port) => true; // Vulnerable to MITM!
    return client;
  }
}
```

### The AIA Chaser Replacement
Remove the insecure override class entirely and initialize `AiaChaser`:

```dart
// ✅ SECURE: Automatically completes intermediate chains and validates with system roots
void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await AiaChaser.initialize(AiaConfig(
    hosts: {
      'api.example.com': const HostPolicy.chase(),
      '*.cdn.example.com': const HostPolicy.chase(),
    },
    prewarm: PrewarmMode.background,
  ));

  // Installs safe validate-ahead badCertificateCallback
  HttpOverrides.global = AiaHttpOverrides();

  runApp(const MyApp());
}
```

---

## 2. Migrating from Android WebView `proceed()`

### The Problematic Code
When Android WebView encounters an incomplete server certificate chain, it shows a blank white page and triggers `onReceivedSslError`. Many apps bypass this by calling `handler.proceed()`:

```dart
// ❌ INSECURE: Unconditionally approves invalid or forged certificates
controller.setPlatformNavigationDelegate(
  AndroidNavigationDelegate(
    const AndroidNavigationDelegateCreationParams(),
  )..setOnSSlAuthError((error) {
      final androidError = error as AndroidSslAuthError;
      androidError.proceed(); // Fails security audits & Google Play Store checks!
    }),
);
```

### The AIA Chaser Replacement
Install `AiaWebViewHandler`:

```dart
import 'package:aia_chaser_webview/aia_chaser_webview.dart';

// ✅ SECURE: Chases missing intermediates and only calls proceed() when validated
if (controller.platform is AndroidWebViewController) {
  final androidController = controller.platform as AndroidWebViewController;
  AiaWebViewHandler.install(androidController);
}
```

---

## 3. Migrating Scoped Dio Clients

### The Problematic Code
```dart
// ❌ INSECURE
final dio = Dio();
(dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => true;
  return client;
};
```

### The AIA Chaser Replacement
```dart
import 'package:aia_chaser_dio/aia_chaser_dio.dart';

// ✅ SECURE
final dio = Dio();
dio.httpClientAdapter = AiaDioAdapter();
```

---

## 4. Verification Checklist

- [ ] All occurrences of `badCertificateCallback = ... => true` removed from the codebase.
- [ ] All unconditional `androidError.proceed()` calls removed.
- [ ] Known exact hosts declared in `AiaConfig.hosts`.
- [ ] App run in debug mode to verify no security warning logs (`unsafeAllow`) are triggered.
- [ ] Run `AiaChaser.diagnose('your-host.com')` to verify that the completed chain reaches a trusted system root.
