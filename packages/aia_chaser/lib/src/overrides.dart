import 'dart:io';
import 'package:crypto/crypto.dart';

import '../aia_chaser.dart';

/// Global or scoped HttpOverrides for dart:io HttpClient.
/// Installs a synchronous badCertificateCallback that queries ValidatedLeafStore
/// and triggers background validation on misses.
class AiaHttpOverrides extends HttpOverrides {
  final AiaEngine? _engine;

  AiaHttpOverrides([this._engine]);

  bool handleBadCertificate(X509Certificate cert, String host, int port) {
    final engine = _engine ?? AiaChaser.engine;
    final policy = engine.resolvePolicy(host);

    // If policy is passthrough, keep platform rejection
    if (!policy.chase &&
        policy.onFailure.type == FailurePolicyType.reject &&
        policy.onFailure.pins.isEmpty) {
      return false;
    }

    final leafSha256 = sha256.convert(cert.der).toString();

    // 1. In-memory validated store lookup (microsecond O(1))
    if (engine.store.isValidated(host, leafSha256)) {
      return true;
    }

    // 1b. If the host is already verified, accept this certificate in the chain
    if (engine.store.isHostValidated(host)) {
      engine.store.put(host, leafSha256, ValidationOutcome.validated);
      return true;
    }

    // 2. Pin fallback check
    if (policy.onFailure.type == FailurePolicyType.pinFallback) {
      for (final pin in policy.onFailure.pins) {
        if (pin.type == PinType.certSha256 &&
            pin.value.trim().toLowerCase() == leafSha256.toLowerCase()) {
          return true;
        }
      }
    }

    // 3. Unsafe escape hatch check
    if (policy.onFailure.type == FailurePolicyType.unsafeAllow) {
      engine.logUnsafeWarning(host);
      return true;
    }

    // 4. Learn-on-failure: schedule background validation
    engine.scheduleValidation(host, port, cert.der);

    return false;
  }

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    final client = super.createHttpClient(context);
    client.badCertificateCallback = handleBadCertificate;
    return client;
  }
}

/// Factory for creating scoped HttpClient instances wired with AIA Chaser validation.
class AiaHttpClientFactory {
  static HttpClient create({SecurityContext? context, AiaEngine? engine}) {
    final overrides = AiaHttpOverrides(engine);
    return overrides.createHttpClient(context);
  }
}
