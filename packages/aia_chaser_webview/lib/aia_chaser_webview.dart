import 'package:aia_chaser/aia_chaser.dart';
import 'package:flutter/foundation.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

/// SSL error interception handler for Android WebView.
class AiaWebViewHandler {
  /// Installs the AIA Chaser SSL error handler onto an [AndroidNavigationDelegate].
  ///
  /// When WebView encounters an SSL error (e.g. SSL_UNTRUSTED), this handler
  /// intercepts the event, validates the server's chain through AIA chasing,
  /// and only calls [AndroidSslAuthError.proceed] if the chain is verified or
  /// allowed by the configured policy.
  static void install(
    AndroidNavigationDelegate delegate, {
    void Function(AndroidSslAuthError error)? fallbackHandler,
  }) {
    delegate.setOnSSlAuthError((error) async {
      final androidError = error is AndroidSslAuthError ? error : null;
      if (androidError == null) return;
      final uri = Uri.tryParse(androidError.url);
      final host = uri?.host ?? '';
      final port = uri?.port ?? 443;

      if (host.isEmpty) {
        if (fallbackHandler != null) {
          fallbackHandler(androidError);
        } else {
          androidError.cancel();
        }
        return;
      }

      final policy = AiaChaser.engine.resolvePolicy(host);

      // Check if policy is passthrough / disabled
      if (!policy.chase &&
          policy.onFailure.type == FailurePolicyType.reject &&
          policy.onFailure.pins.isEmpty) {
        if (fallbackHandler != null) {
          fallbackHandler(androidError);
        } else {
          androidError.cancel();
        }
        return;
      }

      // Check unsafe allow escape hatch
      if (policy.onFailure.type == FailurePolicyType.unsafeAllow) {
        AiaChaser.engine.logUnsafeWarning(host);
        androidError.proceed();
        return;
      }

      try {
        // Validate via AIA Chaser native engine
        final result = await AiaChaser.prewarm(host, port: port);

        if (result.outcome == ValidationOutcome.validated ||
            result.outcome == ValidationOutcome.validatedByPin) {
          debugPrint(
              '[AiaChaser WebView] Successfully validated chain for "$host". Proceeding.');
          androidError.proceed();
        } else {
          debugPrint(
              '[AiaChaser WebView] Validation rejected for "$host" (${result.outcome.name}): ${result.detail}');
          if (fallbackHandler != null) {
            fallbackHandler(androidError);
          } else {
            androidError.cancel();
          }
        }
      } catch (e) {
        debugPrint('[AiaChaser WebView] Validation error for "$host": $e');
        if (fallbackHandler != null) {
          fallbackHandler(androidError);
        } else {
          androidError.cancel();
        }
      }
    });
  }
}
